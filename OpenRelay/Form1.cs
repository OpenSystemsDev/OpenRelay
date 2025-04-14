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
        private readonly DeviceManagerService deviceManager;
        private readonly ClipboardService clipboardService;

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

            // Test P/Invoke functionality
            TestDll.TestPInvoke();

            // Initialize services
            try
            {
                System.Diagnostics.Debug.WriteLine("Initializing services in Form1...");

                // Check if the DLL exists in the output directory
                string dllPath = System.IO.Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    "openrelay_core.dll");

                if (!System.IO.File.Exists(dllPath))
                {
                    string message = $"The Rust DLL was not found at: {dllPath}\n" +
                                     "Please make sure to copy the DLL to the application directory.";
                    System.Diagnostics.Debug.WriteLine(message);
                    MessageBox.Show(message, "DLL Not Found", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    UpdateStatus("DLL Missing");
                    return;
                }

                // Initialize device manager first
                deviceManager = new DeviceManagerService();
                deviceManager.PairingRequestReceived += DeviceManager_PairingRequestReceived;
                deviceManager.DeviceAdded += DeviceManager_DeviceAdded;
                deviceManager.DeviceRemoved += DeviceManager_DeviceRemoved;

                System.Diagnostics.Debug.WriteLine("Device manager initialized");

                // Initialize clipboard service
                clipboardService = new ClipboardService();
                clipboardService.ClipboardDataReceived += ClipboardService_ClipboardDataReceived;

                System.Diagnostics.Debug.WriteLine("Clipboard service initialized");

                // Update status
                UpdateStatus("Connected");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in Form1 constructor: {ex}");
                MessageBox.Show($"Error initializing services: {ex.Message}\n\nStack trace: {ex.StackTrace}", "Error",
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

        private void DeviceManager_PairingRequestReceived(object sender, PairingRequestEventArgs e)
        {
            try
            {
                // Need to show UI on the UI thread
                if (InvokeRequired)
                {
                    Invoke(new Action<object, PairingRequestEventArgs>(DeviceManager_PairingRequestReceived), sender, e);
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"Handling pairing request for {e.DeviceName} on UI thread");

                // For testing, let's just accept all pairing requests automatically
                // This bypasses the UI dialog that might be causing problems
                e.Accepted = true;
                System.Diagnostics.Debug.WriteLine($"Auto-accepting pairing request");

                trayIcon.ShowBalloonTip(
                    3000,
                    "Pairing Request",
                    $"Paired with {e.DeviceName} ({e.IpAddress})",
                    ToolTipIcon.Info
                );

                /*
                // This part is commented out for testing - we'll bypass the dialog
                try
                {
                    using (var dialog = new PairingRequestDialog(e.DeviceName, e.DeviceId, e.IpAddress))
                    {
                        dialog.ShowDialog();
                        
                        // Set the result
                        e.Accepted = dialog.Accepted;
                        System.Diagnostics.Debug.WriteLine($"Pairing request {(e.Accepted ? "accepted" : "declined")}");
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error showing pairing dialog: {ex}");
                    e.Accepted = false; // Decline on error
                }
                */
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in PairingRequestReceived: {ex}");
                // Make sure to set Accepted to some value even on error
                e.Accepted = true; // For testing, accept even on error
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

        private void DeviceManager_DeviceRemoved(object sender, DeviceRemovedEventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<object, DeviceRemovedEventArgs>(DeviceManager_DeviceRemoved), sender, e);
                return;
            }

            var device = deviceManager.GetDeviceById(e.DeviceId);
            string deviceName = device?.DeviceName ?? e.DeviceId;

            trayIcon.ShowBalloonTip(
                2000,
                "Device Removed",
                $"Device {deviceName} has been unpaired.",
                ToolTipIcon.Info
            );
        }

        private void ClipboardService_ClipboardDataReceived(object sender, ClipboardEventArgs e)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<object, ClipboardEventArgs>(ClipboardService_ClipboardDataReceived), sender, e);
                return;
            }

            trayIcon.ShowBalloonTip(
                2000,
                "Clipboard Received",
                $"Format: {e.Data.Format}",
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
                        bool success = await deviceManager.SendPairingRequestAsync(ipAddress);

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
            // Show simplified debug info
            var devices = deviceManager.GetPairedDevices();
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
            var devices = deviceManager.GetPairedDevices();
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
            // Clean up services
            clipboardService?.Dispose();
            deviceManager?.Dispose();

            // Clean up tray icon
            trayIcon.Visible = false;
            trayIcon.Dispose();

            base.OnFormClosing(e);
        }
    }
}