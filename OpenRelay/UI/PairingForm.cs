using System;
using System.Drawing;
using System.Windows.Forms;
using OpenRelay.Models;
using OpenRelay.Services;

namespace OpenRelay.UI
{
    public partial class PairingForm : Form
    {
        private readonly DeviceManager _deviceManager;
        private readonly string _localDeviceId;
        private readonly string _publicKey;
        
        public PairingForm(DeviceManager deviceManager, string localDeviceId, string publicKey)
        {
            InitializeComponent();
            _deviceManager = deviceManager;
            _localDeviceId = localDeviceId;
            _publicKey = publicKey;
            
            InitializeUI();
        }
        
        private void InitializeUI()
        {
            // Setup form
            this.Text = "Pair New Device";
            this.Size = new Size(550, 500);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            // My Device section
            var myDeviceGroupBox = new GroupBox
            {
                Text = "This Device",
                Dock = DockStyle.Top,
                Height = 160,
                Padding = new Padding(10)
            };
            
            var idLabel = new Label
            {
                Text = "Device ID:",
                Location = new Point(15, 30),
                AutoSize = true
            };
            
            var idTextBox = new TextBox
            {
                Text = _localDeviceId,
                Location = new Point(120, 27),
                Width = 300,
                ReadOnly = true
            };
            
            var copyIdButton = new Button
            {
                Text = "Copy",
                Location = new Point(430, 25),
                Width = 70
            };
            copyIdButton.Click += (s, e) => Clipboard.SetText(_localDeviceId);
            
            var keyLabel = new Label
            {
                Text = "Public Key:",
                Location = new Point(15, 65),
                AutoSize = true
            };
            
            var keyTextBox = new TextBox
            {
                Text = _publicKey,
                Location = new Point(120, 62),
                Width = 300,
                Height = 50,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };
            
            var copyKeyButton = new Button
            {
                Text = "Copy",
                Location = new Point(430, 60),
                Width = 70
            };
            copyKeyButton.Click += (s, e) => Clipboard.SetText(_publicKey);
            
            var qrInfoLabel = new Label
            {
                Text = "Share this information with the device you want to pair with.",
                Location = new Point(120, 120),
                AutoSize = true
            };
            
            myDeviceGroupBox.Controls.AddRange(new Control[] { 
                idLabel, idTextBox, copyIdButton,
                keyLabel, keyTextBox, copyKeyButton,
                qrInfoLabel
            });
            
            // Add New Device section
            var addDeviceGroupBox = new GroupBox
            {
                Text = "Add Remote Device",
                Dock = DockStyle.Top,
                Height = 240,
                Top = 170,
                Padding = new Padding(10)
            };
            
            var remoteNameLabel = new Label
            {
                Text = "Device Name:",
                Location = new Point(15, 30),
                AutoSize = true
            };
            
            var remoteNameTextBox = new TextBox
            {
                Location = new Point(120, 27),
                Width = 380
            };
            
            var remoteIdLabel = new Label
            {
                Text = "Device ID:",
                Location = new Point(15, 65),
                AutoSize = true
            };
            
            var remoteIdTextBox = new TextBox
            {
                Location = new Point(120, 62),
                Width = 380
            };
            
            var remotePlatformLabel = new Label
            {
                Text = "Platform:",
                Location = new Point(15, 100),
                AutoSize = true
            };
            
            var remotePlatformComboBox = new ComboBox
            {
                Location = new Point(120, 97),
                Width = 380,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            remotePlatformComboBox.Items.AddRange(new string[] { "Android", "Windows", "iOS", "macOS" });
            remotePlatformComboBox.SelectedIndex = 0;
            
            var remoteIpLabel = new Label
            {
                Text = "IP Address:",
                Location = new Point(15, 135),
                AutoSize = true
            };
            
            var remoteIpTextBox = new TextBox
            {
                Location = new Point(120, 132),
                Width = 380
            };
            
            var remotePortLabel = new Label
            {
                Text = "Port:",
                Location = new Point(15, 170),
                AutoSize = true
            };
            
            var remotePortTextBox = new TextBox
            {
                Location = new Point(120, 167),
                Width = 380,
                Text = "9876"
            };
            
            var remoteKeyLabel = new Label
            {
                Text = "Public Key:",
                Location = new Point(15, 205),
                AutoSize = true
            };
            
            var remoteKeyTextBox = new TextBox
            {
                Location = new Point(120, 202),
                Width = 380,
                Height = 50,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical
            };
            
            addDeviceGroupBox.Controls.AddRange(new Control[] { 
                remoteNameLabel, remoteNameTextBox,
                remoteIdLabel, remoteIdTextBox,
                remotePlatformLabel, remotePlatformComboBox,
                remoteIpLabel, remoteIpTextBox,
                remotePortLabel, remotePortTextBox,
                remoteKeyLabel, remoteKeyTextBox
            });
            
            // Buttons
            var cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Location = new Point(345, 420),
                Width = 90
            };
            
            var addButton = new Button
            {
                Text = "Add Device",
                DialogResult = DialogResult.OK,
                Location = new Point(445, 420),
                Width = 90
            };
            addButton.Click += (s, e) => {
                try {
                    // Create and add the device
                    var device = new PairedDevice
                    {
                        DeviceId = remoteIdTextBox.Text,
                        DeviceName = remoteNameTextBox.Text,
                        Platform = remotePlatformComboBox.SelectedItem?.ToString() ?? "Windows",
                        IpAddress = remoteIpTextBox.Text,
                        Port = int.Parse(remotePortTextBox.Text),
                        PublicKey = remoteKeyTextBox.Text,
                        LastSeen = DateTime.Now
                    };
                    
                    _deviceManager.AddOrUpdateDevice(device);
                    MessageBox.Show($"Device '{device.DeviceName}' added successfully!", "Success", 
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex) {
                    MessageBox.Show($"Error adding device: {ex.Message}", "Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.DialogResult = DialogResult.None;
                }
            };
            
            // Add all controls to form
            this.Controls.AddRange(new Control[] { 
                myDeviceGroupBox, 
                addDeviceGroupBox,
                cancelButton, 
                addButton 
            });
            
            this.AcceptButton = addButton;
            this.CancelButton = cancelButton;
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}