using System;
using System.Threading.Tasks;
using System.Windows.Forms;
using OpenRelay.Models;
using OpenRelay.Services;

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
            trayMenu.Items.Add("Key Tool", null, KeyToolItem_Click);
            trayMenu.Items.Add("Generate Keys", null, GenerateKeysItem_Click);
            trayMenu.Items.Add("-"); // Separator
            trayMenu.Items.Add("Exit", null, ExitItem_Click);
            
            trayIcon = new NotifyIcon();
            trayIcon.Text = "OpenRelay";
            trayIcon.Icon = System.Drawing.SystemIcons.Application; // Consider adding a custom icon
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.Visible = true;
            
            trayIcon.DoubleClick += TrayIcon_DoubleClick;
        }
        
        private void InitializeServices()
        {
            try
            {
                // Initialize device manager first
                deviceManager = new DeviceManager();
                
                // Then encryption service (depends on device manager)
                encryptionService = new EncryptionService(deviceManager);
                
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
                System.Threading.Tasks.Task.Delay(100).ContinueWith(_ => 
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
            // Show pairing UI
            using (var pairingForm = new UI.PairingForm(deviceManager, deviceManager.LocalDeviceId, encryptionService.PublicKey))
            {
                if (pairingForm.ShowDialog() == DialogResult.OK)
                {
                    // The device has been added in the form
                    ShowDevices();
                }
            }
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
        
        private void DebugItem_Click(object? sender, EventArgs e)
        {
            // Show debug form
            using (var debugForm = new UI.DebugForm(deviceManager, encryptionService))
            {
                debugForm.ShowDialog();
            }
        }
        
        private void KeyToolItem_Click(object? sender, EventArgs e)
        {
            // Show key conversion tool
            using (var keyTool = new UI.KeyConversionForm())
            {
                keyTool.ShowDialog();
            }
        }
        
        private void GenerateKeysItem_Click(object? sender, EventArgs e)
        {
            // Show key generator
            using (var keyGenerator = new UI.KeyGeneratorForm())
            {
                keyGenerator.ShowDialog();
            }
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
            encryptionService?.Dispose();
            
            // Clean up tray icon
            trayIcon.Visible = false;
            trayIcon.Dispose();
            
            base.OnFormClosing(e);
        }
    }
}