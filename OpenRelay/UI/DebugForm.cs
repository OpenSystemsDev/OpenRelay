using System;
using System.Windows.Forms;
using OpenRelay.Services;
using OpenRelay.Models;

namespace OpenRelay.UI
{
    public partial class DebugForm : Form
    {
        private DeviceManager _deviceManager;
        private EncryptionService _encryptionService;
        private ListBox _devicesList;
        private TextBox _outputText;
        
        public DebugForm(DeviceManager deviceManager, EncryptionService encryptionService)
        {
            InitializeComponent();
            
            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;
            
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
            
            this.Text = "Debug Connections";
            this.ClientSize = new System.Drawing.Size(600, 500);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            // Use TableLayoutPanel for scalable layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Padding = new System.Windows.Forms.Padding(10)
            };
            
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 60));
            
            // Top panel with devices list and action buttons
            var topPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1
            };
            
            topPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            topPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            
            // Devices list
            _devicesList = new ListBox
            {
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 0, 10, 0)
            };
            
            // Buttons panel
            var buttonsPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4
            };
            
            buttonsPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            buttonsPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            buttonsPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            buttonsPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            
            var refreshButton = new Button
            {
                Text = "Refresh Devices",
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 3, 0, 3)
            };
            refreshButton.Click += (s, e) => RefreshDeviceList();
            
            var deleteButton = new Button
            {
                Text = "Delete Selected Device",
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 3, 0, 3)
            };
            deleteButton.Click += (s, e) => 
            {
                if (_devicesList.SelectedItem != null)
                {
                    var device = (PairedDevice)_devicesList.SelectedItem;
                    _deviceManager.RemoveDevice(device.DeviceId);
                    RefreshDeviceList();
                }
            };
            
            var testSignButton = new Button
            {
                Text = "Test Signature",
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 3, 0, 3)
            };
            testSignButton.Click += TestSignature;
            
            var testConnectButton = new Button
            {
                Text = "Test Connection",
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 3, 0, 3)
            };
            testConnectButton.Click += TestConnection;
            
            // Add buttons to panel
            buttonsPanel.Controls.Add(refreshButton, 0, 0);
            buttonsPanel.Controls.Add(deleteButton, 0, 1);
            buttonsPanel.Controls.Add(testSignButton, 0, 2);
            buttonsPanel.Controls.Add(testConnectButton, 0, 3);
            
            // Add to top panel
            topPanel.Controls.Add(_devicesList, 0, 0);
            topPanel.Controls.Add(buttonsPanel, 1, 0);
            
            // Bottom panel with output log
            var bottomPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2
            };
            
            bottomPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            bottomPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            
            var outputLabel = new Label
            {
                Text = "Log Output:",
                Dock = DockStyle.Fill,
                TextAlign = System.Drawing.ContentAlignment.MiddleLeft
            };
            
            _outputText = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                ReadOnly = true
            };
            
            bottomPanel.Controls.Add(outputLabel, 0, 0);
            bottomPanel.Controls.Add(_outputText, 0, 1);
            
            // Add panels to main layout
            mainLayout.Controls.Add(topPanel, 0, 0);
            mainLayout.Controls.Add(bottomPanel, 0, 1);
            
            // Add to form
            this.Controls.Add(mainLayout);
            
            // Initial refresh
            RefreshDeviceList();
        }
        
        private void RefreshDeviceList()
        {
            _devicesList.Items.Clear();
            var devices = _deviceManager.GetPairedDevices();
            
            foreach (var device in devices)
            {
                _devicesList.Items.Add(device);
            }
            
            if (_devicesList.Items.Count > 0)
            {
                _devicesList.SelectedIndex = 0;
            }
        }
        
        private void TestSignature(object sender, EventArgs e)
        {
            if (_devicesList.SelectedItem == null)
                return;
                
            var device = (PairedDevice)_devicesList.SelectedItem;
            _outputText.AppendText($"Testing signature for {device.DeviceName}...\r\n");
            
            try
            {
                // Generate test data
                string testData = "test_message_" + DateTime.Now.Ticks;
                
                // Sign with our private key
                string signature = _encryptionService.SignData(testData);
                
                // Verify with the device's public key
                bool verified = _encryptionService.VerifySignature(testData, signature, device.PublicKey);
                
                _outputText.AppendText($"Signature verification: {verified}\r\n");
                _outputText.AppendText($"Test data: {testData}\r\n");
                _outputText.AppendText($"Signature: {signature}\r\n");
                
                if (!verified)
                {
                    _outputText.AppendText("Public key may be incorrect or corrupted!\r\n");
                }
            }
            catch (Exception ex)
            {
                _outputText.AppendText($"Error: {ex.Message}\r\n");
            }
        }
        
        private void TestConnection(object sender, EventArgs e)
        {
            if (_devicesList.SelectedItem == null)
                return;
                
            var device = (PairedDevice)_devicesList.SelectedItem;
            _outputText.AppendText($"Testing connection to {device.DeviceName} at {device.IpAddress}:{device.Port}\r\n");
            
            try
            {
                var ws = new WebSocketSharp.WebSocket($"ws://{device.IpAddress}:{device.Port}/clipboard");
                
                ws.OnOpen += (ss, ee) => 
                {
                    this.Invoke(new Action(() => _outputText.AppendText("Connection opened successfully!\r\n")));
                };
                
                ws.OnError += (ss, ee) => 
                {
                    this.Invoke(new Action(() => _outputText.AppendText($"Connection error: {ee.Message}\r\n")));
                };
                
                ws.OnClose += (ss, ee) => 
                {
                    this.Invoke(new Action(() => _outputText.AppendText($"Connection closed: {ee.Reason}\r\n")));
                };
                
                _outputText.AppendText("Attempting to connect...\r\n");
                ws.Connect();
            }
            catch (Exception ex)
            {
                _outputText.AppendText($"Error: {ex.Message}\r\n");
            }
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}