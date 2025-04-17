using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using OpenRelay.Models;
using OpenRelay.Services;
using OpenRelay.UI;

namespace OpenRelay
{
    public partial class Form1 : Form
    {
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private ToolStripMenuItem statusItem;

        // Services
        private readonly EncryptionService _encryptionService;
        private readonly DeviceManager _deviceManager;
        private readonly ClipboardService _clipboardService;
        private readonly NetworkService _networkService;

        // Cancellation token source for network operations
        private System.Threading.CancellationTokenSource? _cts;

        public Form1()
        {
            InitializeComponent();

            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Set up the system tray icon
            SetupTrayIcon();

            // Make the form invisible
            this.ShowInTaskbar = false;
            this.WindowState = FormWindowState.Minimized;
            this.FormBorderStyle = FormBorderStyle.FixedToolWindow;
            this.Hide();

            // Initialize services
            try
            {
                _encryptionService = new EncryptionService();
                _deviceManager = new DeviceManager(_encryptionService);
                _clipboardService = new ClipboardService();
                _networkService = new NetworkService(_deviceManager, _encryptionService);

                // Register services in the ServiceLocator
                ServiceLocator.RegisterService(_clipboardService);
                ServiceLocator.RegisterService(_networkService);
                ServiceLocator.RegisterService(_deviceManager);
                ServiceLocator.RegisterService(_encryptionService);

                // Set up event handlers
                _deviceManager.PairingRequestReceived += DeviceManager_PairingRequestReceived;
                _deviceManager.DeviceAdded += DeviceManager_DeviceAdded;
                _deviceManager.DeviceRemoved += DeviceManager_DeviceRemoved;

                _clipboardService.ClipboardChanged += ClipboardService_ClipboardChanged;

                _networkService.ClipboardDataReceived += NetworkService_ClipboardDataReceived;

                // Start services
                _clipboardService.Start();

                _cts = new System.Threading.CancellationTokenSource();
                Task.Run(async () => await StartNetworkServiceAsync(), _cts.Token);

                // Update status
                UpdateStatus("Connected");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing services: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                UpdateStatus("Error");
            }
        }

        private void SetupTrayIcon()
        {
            trayMenu = new ContextMenuStrip();
            statusItem = new ToolStripMenuItem("Status: Starting...");
            statusItem.Enabled = false;
            trayMenu.Items.Add(statusItem);
            trayMenu.Items.Add("Devices...", null, DevicesItem_Click);
            trayMenu.Items.Add("Add Device", null, AddDeviceItem_Click);
            trayMenu.Items.Add("Debug", null, DebugItem_Click);
            trayMenu.Items.Add("-"); // Separator
            trayMenu.Items.Add("Exit", null, ExitItem_Click);

            trayIcon = new NotifyIcon();
            trayIcon.Text = "OpenRelay";
            trayIcon.Icon = System.Drawing.SystemIcons.Application; // Consider adding a custom icon
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.Visible = true;

            trayIcon.DoubleClick += TrayIcon_DoubleClick;
        }

        private async Task StartNetworkServiceAsync()
        {
            try
            {
                await _networkService.StartAsync();
                UpdateStatus("Connected");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error starting network service: {ex.Message}");
                UpdateStatus("Offline");
            }
        }

        private void DeviceManager_PairingRequestReceived(object sender, PairingRequestEventArgs e)
        {
            // Need to show UI on the UI thread
            if (InvokeRequired)
            {
                Invoke(new Action<object, PairingRequestEventArgs>(DeviceManager_PairingRequestReceived), sender, e);
                return;
            }

            System.Diagnostics.Debug.WriteLine($"Showing pairing dialog for device {e.DeviceName}");

            // Show pairing request dialog
            using (var dialog = new PairingRequestDialog(e.DeviceName, e.DeviceId, e.IpAddress))
            {
                dialog.ShowDialog();

                // Set the result
                e.Accepted = dialog.Accepted;
                System.Diagnostics.Debug.WriteLine($"Pairing request {(e.Accepted ? "accepted" : "declined")}");
            }
        }

        private void DeviceManager_DeviceAdded(object sender, DeviceEventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<object, DeviceEventArgs>(DeviceManager_DeviceAdded), sender, e);
                return;
            }

            trayIcon.ShowBalloonTip(
                2000,
                "Device Paired",
                $"Device {e.Device.DeviceName} has been paired successfully!",
                ToolTipIcon.Info
            );
        }

        private void DeviceManager_DeviceRemoved(object sender, string deviceId)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<object, string>(DeviceManager_DeviceRemoved), sender, deviceId);
                return;
            }

            var device = _deviceManager.GetDeviceById(deviceId);
            string deviceName = device?.DeviceName ?? deviceId;

            trayIcon.ShowBalloonTip(
                2000,
                "Device Removed",
                $"Device {deviceName} has been unpaired.",
                ToolTipIcon.Info
            );
        }

        private void ClipboardService_ClipboardChanged(object sender, ClipboardChangedEventArgs e)
        {
            // Handle clipboard clear
            if (e.IsCleared)
            {
                System.Diagnostics.Debug.WriteLine("[SYNC] Clipboard cleared locally, sending clear to paired devices");

                // Send clipboard clear to paired devices
                if (_cts != null && !_cts.IsCancellationRequested)
                {
                    // Get number of paired devices
                    var devices = _deviceManager.GetPairedDevices();
                    if (devices.Count == 0)
                    {
                        System.Diagnostics.Debug.WriteLine("[SYNC] No paired devices to send clear to");
                        return;
                    }

                    Task.Run(async () =>
                    {
                        try
                        {
                            await _networkService.SendClipboardClearAsync(_cts.Token);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[SYNC] Error sending clipboard clear: {ex}");
                        }
                    });
                }

                return;
            }

            // Skip if we're updating the clipboard ourselves or no data
            if (e.Data == null)
                return;

            System.Diagnostics.Debug.WriteLine($"[SYNC] Clipboard changed locally: {e.Data.Format}, sending to paired devices");

            // Send clipboard data to paired devices
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                // Get number of paired devices
                var devices = _deviceManager.GetPairedDevices();
                if (devices.Count == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[SYNC] No paired devices to send to");
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"[SYNC] Sending to {devices.Count} devices");
                Task.Run(async () =>
                {
                    try
                    {
                        await _networkService.SendClipboardDataAsync(e.Data, _cts.Token);
                        System.Diagnostics.Debug.WriteLine("[SYNC] Clipboard data sent successfully");
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[SYNC] Error sending clipboard data: {ex}");
                    }
                });
            }
        }

        private void NetworkService_ClipboardDataReceived(object sender, ClipboardDataReceivedEventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<object, ClipboardDataReceivedEventArgs>(NetworkService_ClipboardDataReceived), sender, e);
                return;
            }

            if (e.Data == null)
            {
                System.Diagnostics.Debug.WriteLine($"Clipboard clear received from {e.Device.DeviceName}");

                // Clear local clipboard
                _clipboardService.ClearClipboard();

                trayIcon.ShowBalloonTip(
                    2000,
                    "Clipboard Cleared",
                    $"Clipboard cleared by {e.Device.DeviceName}",
                    ToolTipIcon.Info
                );
                return;
            }

            System.Diagnostics.Debug.WriteLine($"Clipboard data received from {e.Device.DeviceName}");

            // Update local clipboard
            _clipboardService.UpdateClipboard(e.Data);

            trayIcon.ShowBalloonTip(
                2000,
                "Clipboard Received",
                $"Clipboard data received from {e.Device.DeviceName}",
                ToolTipIcon.Info
            );
        }

        private void UpdateStatus(string status)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<string>(UpdateStatus), status);
                return;
            }

            statusItem.Text = $"Status: {status}";
        }

        private void TrayIcon_DoubleClick(object? sender, EventArgs e)
        {
            // Show devices window
            ShowDevices();
        }

        private void DevicesItem_Click(object? sender, EventArgs e)
        {
            ShowDevices();
        }

        private void AddDeviceItem_Click(object? sender, EventArgs e)
        {
            // Show IP input dialog
            using (var dialog = new TextInputDialog("Add Device", "Enter the IP address of the device to pair with:"))
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    string ipAddress = dialog.InputText;

                    // Send pairing request
                    Task.Run(async () =>
                    {
                        bool success = await _networkService.SendPairingRequestAsync(ipAddress);

                        if (InvokeRequired)
                        {
                            Invoke(new Action<bool>(ShowPairingResult), success);
                        }
                        else
                        {
                            ShowPairingResult(success);
                        }
                    });
                }
            }
        }

        private void ShowPairingResult(bool success)
        {
            if (success)
            {
                MessageBox.Show(
                    "Device paired successfully!",
                    "Pairing Successful",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show(
                    "Pairing failed. The device may have declined the request or wasn't reachable.",
                    "Pairing Failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void DebugItem_Click(object? sender, EventArgs e)
        {
            // Show debug info
            var devices = _deviceManager.GetPairedDevices();
            if (devices.Count == 0)
            {
                MessageBox.Show("No paired devices found. Add a device to get started.", "Devices",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var devicesText = "Paired Devices:\n\n";
            foreach (var device in devices)
            {
                devicesText += $"{device.DeviceName} ({device.Platform})\n";
                devicesText += $"IP: {device.IpAddress}:{device.Port}\n";
                devicesText += $"Last seen: {device.LastSeen}\n\n";
            }

            MessageBox.Show(devicesText, "Paired Devices", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ShowDevices()
        {
            // Show paired devices
            var devices = _deviceManager.GetPairedDevices();
            if (devices.Count == 0)
            {
                MessageBox.Show("No paired devices found. Add a device to get started.", "Devices",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var devicesText = "Paired Devices:\n\n";
            foreach (var device in devices)
            {
                devicesText += $"{device.DeviceName} ({device.Platform})\n";
                devicesText += $"Last seen: {device.LastSeen}\n\n";
            }

            MessageBox.Show(devicesText, "Paired Devices", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ExitItem_Click(object? sender, EventArgs e)
        {
            // Clean up and exit
            Application.Exit();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Cancel network operations
            _cts?.Cancel();

            // Clean up services
            _networkService?.Dispose();
            _clipboardService?.Dispose();
            _encryptionService?.Dispose();

            // Clean up tray icon
            trayIcon.Visible = false;
            trayIcon.Dispose();

            base.OnFormClosing(e);
        }
    }
}