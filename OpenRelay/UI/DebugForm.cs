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
        
        public DebugForm(DeviceManager deviceManager, EncryptionService encryptionService)
        {
            InitializeComponent();
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
            
            this.Text = "Debug Connections";
            this.Size = new System.Drawing.Size(600, 500);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            // Create controls
            var listDevices = new ListBox
            {
                Dock = DockStyle.Top,
                Height = 200
            };
            
            var refreshButton = new Button
            {
                Text = "Refresh Devices",
                Dock = DockStyle.Top,
                Height = 30
            };
            refreshButton.Click += (s, e) => RefreshDeviceList(listDevices);
            
            var deleteButton = new Button
            {
                Text = "Delete Selected Device",
                Dock = DockStyle.Top,
                Height = 30
            };
            deleteButton.Click += (s, e) => 
            {
                if (listDevices.SelectedItem != null)
                {
                    var device = (PairedDevice)listDevices.SelectedItem;
                    _deviceManager.RemoveDevice(device.DeviceId);
                    RefreshDeviceList(listDevices);
                }
            };
            
            var outputLabel = new Label
            {
                Text = "Log Output:",
                Dock = DockStyle.Top,
                Height = 20
            };
            
            var outputText = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                ReadOnly = true
            };
            
            var testSignButton = new Button
            {
                Text = "Test Signature (Selected Device)",
                Dock = DockStyle.Top,
                Height = 30
            };
            testSignButton.Click += (s, e) => 
            {
                if (listDevices.SelectedItem != null)
                {
                    var device = (PairedDevice)listDevices.SelectedItem;
                    outputText.AppendText($"Testing signature for {device.DeviceName}...\r\n");
                    
                    try
                    {
                        // Generate test data
                        string testData = "test_message_" + DateTime.Now.Ticks;
                        
                        // Sign with our private key
                        string signature = _encryptionService.SignData(testData);
                        
                        // Verify with the device's public key
                        bool verified = _encryptionService.VerifySignature(testData, signature, device.PublicKey);
                        
                        outputText.AppendText($"Signature verification: {verified}\r\n");
                        outputText.AppendText($"Test data: {testData}\r\n");
                        outputText.AppendText($"Signature: {signature}\r\n");
                        
                        if (!verified)
                        {
                            outputText.AppendText("Public key may be incorrect or corrupted!\r\n");
                        }
                    }
                    catch (Exception ex)
                    {
                        outputText.AppendText($"Error: {ex.Message}\r\n");
                    }
                }
            };
            
            var testConnectButton = new Button
            {
                Text = "Test Connection (Selected Device)",
                Dock = DockStyle.Top,
                Height = 30
            };
            testConnectButton.Click += (s, e) => 
            {
                if (listDevices.SelectedItem != null)
                {
                    var device = (PairedDevice)listDevices.SelectedItem;
                    outputText.AppendText($"Testing connection to {device.DeviceName} at {device.IpAddress}:{device.Port}\r\n");
                    
                    try
                    {
                        var ws = new WebSocketSharp.WebSocket($"ws://{device.IpAddress}:{device.Port}/clipboard");
                        
                        ws.OnOpen += (ss, ee) => 
                        {
                            this.Invoke(new Action(() => outputText.AppendText("Connection opened successfully!\r\n")));
                        };
                        
                        ws.OnError += (ss, ee) => 
                        {
                            this.Invoke(new Action(() => outputText.AppendText($"Connection error: {ee.Message}\r\n")));
                        };
                        
                        ws.OnClose += (ss, ee) => 
                        {
                            this.Invoke(new Action(() => outputText.AppendText($"Connection closed: {ee.Reason}\r\n")));
                        };
                        
                        outputText.AppendText("Attempting to connect...\r\n");
                        ws.Connect();
                    }
                    catch (Exception ex)
                    {
                        outputText.AppendText($"Error: {ex.Message}\r\n");
                    }
                }
            };
            
            // Add controls
            this.Controls.Add(outputText);
            this.Controls.Add(outputLabel);
            this.Controls.Add(testConnectButton);
            this.Controls.Add(testSignButton);
            this.Controls.Add(deleteButton);
            this.Controls.Add(refreshButton);
            this.Controls.Add(listDevices);
            
            // Initial refresh
            RefreshDeviceList(listDevices);
        }
        
        private void RefreshDeviceList(ListBox listBox)
        {
            listBox.Items.Clear();
            var devices = _deviceManager.GetPairedDevices();
            
            foreach (var device in devices)
            {
                listBox.Items.Add(device);
            }
            
            if (listBox.Items.Count > 0)
            {
                listBox.SelectedIndex = 0;
            }
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}