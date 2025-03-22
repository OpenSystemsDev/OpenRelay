using OpenRelay.Models;
using OpenRelay.Services;

namespace OpenRelay
{
    public partial class Form1 : Form
    {
        private NotifyIcon? _trayIcon;
        private ContextMenuStrip? _trayMenu;
        private ToolStripMenuItem? _statusItem;

        // Services
        private ClipboardMonitorService? _clipboardMonitor;
        private DeviceManager? _deviceManager;
        private EncryptionService? _encryptionService;
        private NetworkService? _networkService;
        
        public Form1()
        {
            InitializeComponent();
            
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
            _trayMenu = new ContextMenuStrip();
            _statusItem = new ToolStripMenuItem("Status: Starting...");
            _statusItem.Enabled = false;
            _trayMenu.Items.Add(_statusItem);
            _trayMenu.Items.Add("Devices...", null, DevicesItem_Click);
            _trayMenu.Items.Add("Add Device", null, AddDeviceItem_Click);
            _trayMenu.Items.Add("-"); // Separator
            _trayMenu.Items.Add("Exit", null, ExitItem_Click);
            
            _trayIcon = new NotifyIcon();
            _trayIcon.Text = "OpenRelay";
            _trayIcon.Icon = System.Drawing.SystemIcons.Application; // Consider adding a custom icon
            _trayIcon.ContextMenuStrip = _trayMenu;
            _trayIcon.Visible = true;
            
            _trayIcon.DoubleClick += TrayIcon_DoubleClick;
        }
        
        private void InitializeServices()
        {
            try
            {
                // Initialize device manager first
                _deviceManager = new DeviceManager();
                
                // Then encryption service (depends on device manager)
                _encryptionService = new EncryptionService(_deviceManager);
                
                // Start network service
                _networkService = new NetworkService(_deviceManager, _encryptionService);
                
                // Finally, start clipboard monitoring
                StartClipboardMonitoring();
                
                // Start network service
                Task.Run(async () => 
                {
                    try
                    {
                        await _networkService.StartAsync();
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
                _clipboardMonitor = new ClipboardMonitorService();
                _clipboardMonitor.ClipboardChanged += ClipboardMonitor_ClipboardChanged;
                _clipboardMonitor.Start();
                
                // Set up callback for receiving clipboard data
                _networkService.SetOnClipboardDataReceivedCallback(OnClipboardDataReceived);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting clipboard monitoring: {ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        private void ClipboardMonitor_ClipboardChanged(object? sender, ClipboardChangedEventArgs e)
        {
            // Handle clipboard change here
            if (e.Data != null)
            {
                // Send clipboard data to paired devices
                _networkService.SendClipboardData(e.Data);
                
                // Show notification (for testing)
                _trayIcon.ShowBalloonTip(
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
                _trayIcon.ShowBalloonTip(
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
        }
        
        private void UpdateStatus(string status)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<string>(UpdateStatus), status);
                return;
            }
            
            _statusItem.Text = $"Status: {status}";
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
            using (var pairingForm = new UI.PairingForm(_deviceManager, _deviceManager.LocalDeviceId, _encryptionService.PublicKey))
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
            // Clean up services
            _clipboardMonitor?.Stop();
            _clipboardMonitor?.Dispose();
            
            _networkService?.Dispose();
            _encryptionService?.Dispose();
            
            // Clean up tray icon
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            
            base.OnFormClosing(e);
        }
    }
}