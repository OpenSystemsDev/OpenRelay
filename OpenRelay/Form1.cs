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

        // Timer for key rotation checks
        private System.Threading.Timer? _keyRotationTimer;

        public Form1()
        {
            InitializeComponent();

            // Enable better DPI scaling
            // TODO this doesnt work well on 1440p sadly
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Set up the system tray icon
            SetupTrayIcon();

            // Make the form completely invisible
            this.ShowInTaskbar = false;
            this.FormBorderStyle = FormBorderStyle.FixedToolWindow;
            this.Opacity = 0;
            this.Hide();

            // Initialize services
            try
            {
                _encryptionService = new EncryptionService();
                _deviceManager = new DeviceManager(_encryptionService);
                _clipboardService = new ClipboardService();
                _networkService = new NetworkService(_deviceManager, _encryptionService);

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

                // Create a timer to check for key rotations
                _keyRotationTimer = new System.Threading.Timer(
                    async _ => await CheckKeyRotationAsync(),
                    null,
                    TimeSpan.FromSeconds(5), // Wait 5 seconds
                    TimeSpan.FromSeconds(7 * 24 * 60 * 60)
                );

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
            trayMenu.Items.Add("-");
            trayMenu.Items.Add("Rotate Keys", null, RotateKeysItem_Click);
            trayMenu.Items.Add("-");
            trayMenu.Items.Add("Exit", null, ExitItem_Click);

            trayIcon = new NotifyIcon();
            trayIcon.Text = "OpenRelay";
            trayIcon.Icon = System.Drawing.SystemIcons.Application;
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

        /// <summary>
        /// Check if key rotation is needed
        /// </summary>
        private async Task CheckKeyRotationAsync()
        {
            try
            {
                System.Diagnostics.Debug.WriteLine("[KEY] Checking if key rotation is needed");
                bool needsRotation = _encryptionService.ShouldRotateKey();

                if (needsRotation)
                {
                    System.Diagnostics.Debug.WriteLine("[KEY] Key rotation needed, performing rotation");
                    await _networkService.CheckAndHandleKeyRotationAsync();
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[KEY] No key rotation needed at this time");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[KEY] Error checking key rotation: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle manual key rotation from menu
        /// </summary>
        private async void RotateKeysItem_Click(object? sender, EventArgs e)
        {
            try
            {
                // Create a new rotation key
                uint newKeyId = _encryptionService.CreateRotationKey();
                if (newKeyId == 0)
                {
                    MessageBox.Show("Failed to rotate keys", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Send key rotation update to all devices
                await _networkService.CheckAndHandleKeyRotationAsync();

                MessageBox.Show($"Keys rotated successfully. New key ID: {newKeyId}", "Success",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error rotating keys: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
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
            // Skip if we're updating the clipboard ourselves
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
                devicesText += $"Key ID: {device.CurrentKeyId}\n";
                devicesText += $"Last seen: {device.LastSeen}\n\n";
            }

            // Add encryption info
            devicesText += $"Current Key ID: {_encryptionService.GetCurrentKeyId()}\n";
            devicesText += $"Key Rotation Needed: {(_encryptionService.ShouldRotateKey() ? "Yes" : "No")}\n";

            MessageBox.Show(devicesText, "Debug Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void ShowDevices()
        {
            // Show paired devices using the new management dialog
            var devices = _deviceManager.GetPairedDevices();
            if (devices.Count == 0)
            {
                MessageBox.Show("No paired devices found. Add a device to get started.", "Devices",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (var dialog = new DeviceManagementDialog(_deviceManager))
            {
                dialog.ShowDialog();
            }
        }

        private void ExitItem_Click(object? sender, EventArgs e)
        {
            // Clean up and exit
            Application.Exit();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Cancel key rotation timer
            _keyRotationTimer?.Dispose();

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