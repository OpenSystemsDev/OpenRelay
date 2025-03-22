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
        private ClipboardMonitorService clipboardMonitor;
        private DeviceManager deviceManager;
        private EncryptionService encryptionService;
        private NetworkService networkService;
        
        // Flag to prevent clipboard loops
        private bool isUpdatingClipboard = false;
        
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
            InitializeServices();
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
        
        // Replace this section in the InitializeServices method of Form1.cs

        private void InitializeServices()
        {
            try
            {
                // Initialize device manager first
                deviceManager = new DeviceManager();
        
                // Handle pairing requests
                deviceManager.PairingRequestReceived += DeviceManager_PairingRequestReceived;
        
                // Then encryption service
                encryptionService = new EncryptionService();
        
                // Start network service
                networkService = new NetworkService(deviceManager, encryptionService);
        
                // Finally, start clipboard monitoring
                StartClipboardMonitoring();
        
                // Start network service
                Task.Run(async () => 
                {
                    try
                    {
                        await networkService.StartAsync();
                        UpdateStatus("Connected");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error starting network service: {ex.Message}");
                        UpdateStatus("Offline");
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing services: {ex.Message}", "Error", 
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
            
            // Show pairing request dialog
            using (var dialog = new PairingRequestDialog(e.DeviceName, e.DeviceId, e.IpAddress))
            {
                dialog.ShowDialog();
                
                // Set the result
                e.Accepted = dialog.Accepted;
                
                // If accepted, add the device with a new shared key
                if (e.Accepted)
                {
                    // Generate a shared key
                    string sharedKey = encryptionService.GenerateSharedKey();
                    
                    // Create and add the device
                    var device = new PairedDevice
                    {
                        DeviceId = e.DeviceId,
                        DeviceName = e.DeviceName,
                        IpAddress = e.IpAddress,
                        Port = e.Port,
                        Platform = "Unknown", // Could be determined later
                        SharedKey = sharedKey
                    };
                    
                    deviceManager.AddOrUpdateDevice(device);
                }
            }
        }
        
        private void StartClipboardMonitoring()
        {
            try
            {
                clipboardMonitor = new ClipboardMonitorService();
                clipboardMonitor.ClipboardChanged += ClipboardMonitor_ClipboardChanged;
                clipboardMonitor.Start();
                
                // Set up callback for receiving clipboard data
                networkService.SetOnClipboardDataReceivedCallback(OnClipboardDataReceived);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting clipboard monitoring: {ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        private void ClipboardMonitor_ClipboardChanged(object? sender, ClipboardChangedEventArgs e)
        {
            // Skip if we're the ones updating the clipboard
            if (isUpdatingClipboard)
                return;
                
            // Handle clipboard change here
            if (e.Data != null)
            {
                // Send clipboard data to paired devices
                networkService.SendClipboardData(e.Data);
                
                // Show notification (for testing)
                trayIcon.ShowBalloonTip(
                    2000, 
                    "Clipboard Updated", 
                    $"Format: {e.Data.Format}", 
                    ToolTipIcon.Info
                );
            }
        }
        
        private void OnClipboardDataReceived(ClipboardData data)
        {
            // Update the clipboard with received data
            try
            {
                if (InvokeRequired)
                {
                    Invoke(new Action<ClipboardData>(OnClipboardDataReceived), data);
                    return;
                }
                
                // Set flag to prevent loops
                isUpdatingClipboard = true;
                
                if (data.Format == "text/plain" && data.TextData != null)
                {
                    Clipboard.SetText(data.TextData);
                }
                else if (data.Format == "image/png" && data.BinaryData != null)
                {
                    using (var ms = new System.IO.MemoryStream(data.BinaryData))
                    {
                        var image = System.Drawing.Image.FromStream(ms);
                        Clipboard.SetImage(image);
                    }
                }
                
                // Show notification
                trayIcon.ShowBalloonTip(
                    2000, 
                    "Clipboard Received", 
                    $"Format: {data.Format}", 
                    ToolTipIcon.Info
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating clipboard: {ex.Message}");
            }
            finally
            {
                // Reset flag after a short delay to ensure clipboard events are processed
                Task.Delay(100).ContinueWith(_ => 
                {
                    if (InvokeRequired)
                    {
                        Invoke(new Action(() => isUpdatingClipboard = false));
                    }
                    else
                    {
                        isUpdatingClipboard = false;
                    }
                });
            }
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
                        bool success = await networkService.SendPairingRequestAsync(ipAddress);
                        
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
            clipboardMonitor?.Stop();
            clipboardMonitor?.Dispose();
            
            networkService?.Dispose();
            
            // Clean up tray icon
            trayIcon.Visible = false;
            trayIcon.Dispose();
            
            base.OnFormClosing(e);
        }
    }
}