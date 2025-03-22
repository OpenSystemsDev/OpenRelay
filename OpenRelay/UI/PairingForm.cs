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
            
            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;
            
            _deviceManager = deviceManager;
            _localDeviceId = localDeviceId;
            _publicKey = publicKey;
            
            InitializeUI();
        }
        
        private void InitializeUI()
        {
            // Setup form
            this.Text = "Pair New Device";
            this.ClientSize = new Size(550, 550);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            // Use TableLayoutPanel for better scaling
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(10),
            };
            
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 35));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 10));
            
            // My Device section
            var myDeviceGroupBox = new GroupBox
            {
                Text = "This Device",
                Dock = DockStyle.Fill,
                Padding = new Padding(10),
                Margin = new Padding(0, 0, 0, 10)
            };
            
            var myDeviceLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 4,
                ColumnStyles = 
                {
                    new ColumnStyle(SizeType.Absolute, 100),
                    new ColumnStyle(SizeType.Percent, 100),
                    new ColumnStyle(SizeType.Absolute, 80)
                }
            };
            
            // Row 0: ID
            var idLabel = new Label
            {
                Text = "Device ID:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var idTextBox = new TextBox
            {
                Text = _localDeviceId,
                Dock = DockStyle.Fill,
                ReadOnly = true
            };
            
            var copyIdButton = new Button
            {
                Text = "Copy",
                Dock = DockStyle.Fill
            };
            copyIdButton.Click += (s, e) => Clipboard.SetText(_localDeviceId);
            
            myDeviceLayout.Controls.Add(idLabel, 0, 0);
            myDeviceLayout.Controls.Add(idTextBox, 1, 0);
            myDeviceLayout.Controls.Add(copyIdButton, 2, 0);
            
            // Row 1: Public Key
            var keyLabel = new Label
            {
                Text = "Public Key:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var keyTextBox = new TextBox
            {
                Text = _publicKey,
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };
            
            var copyKeyButton = new Button
            {
                Text = "Copy",
                Dock = DockStyle.Fill
            };
            copyKeyButton.Click += (s, e) => Clipboard.SetText(_publicKey);
            
            myDeviceLayout.Controls.Add(keyLabel, 0, 1);
            myDeviceLayout.Controls.Add(keyTextBox, 1, 1);
            myDeviceLayout.Controls.Add(copyKeyButton, 2, 1);
            
            // Row 2-3: Info 
            var qrInfoLabel = new Label
            {
                Text = "Share this information with the device you want to pair with.",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };
            
            myDeviceLayout.Controls.Add(qrInfoLabel, 1, 3);
            
            // Set row heights
            myDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            myDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            myDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 10));
            myDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            
            myDeviceGroupBox.Controls.Add(myDeviceLayout);
            
            // Add New Device section
            var addDeviceGroupBox = new GroupBox
            {
                Text = "Add Remote Device",
                Dock = DockStyle.Fill,
                Padding = new Padding(10),
                Margin = new Padding(0, 0, 0, 10)
            };
            
            var addDeviceLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 6,
                ColumnStyles = 
                {
                    new ColumnStyle(SizeType.Absolute, 100),
                    new ColumnStyle(SizeType.Percent, 100),
                }
            };
            
            // Add controls with proper positioning
            var remoteNameLabel = new Label
            {
                Text = "Device Name:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remoteNameTextBox = new TextBox
            {
                Dock = DockStyle.Fill
            };
            
            var remoteIdLabel = new Label
            {
                Text = "Device ID:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remoteIdTextBox = new TextBox
            {
                Dock = DockStyle.Fill
            };
            
            var remotePlatformLabel = new Label
            {
                Text = "Platform:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remotePlatformComboBox = new ComboBox
            {
                Dock = DockStyle.Fill,
                DropDownStyle = ComboBoxStyle.DropDownList
            };
            remotePlatformComboBox.Items.AddRange(new string[] { "Android", "Windows", "iOS", "macOS" });
            remotePlatformComboBox.SelectedIndex = 0;
            
            var remoteIpLabel = new Label
            {
                Text = "IP Address:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remoteIpTextBox = new TextBox
            {
                Dock = DockStyle.Fill
            };
            
            var remotePortLabel = new Label
            {
                Text = "Port:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remotePortTextBox = new TextBox
            {
                Dock = DockStyle.Fill,
                Text = "9876"
            };
            
            var remoteKeyLabel = new Label
            {
                Text = "Public Key:",
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                AutoSize = true
            };
            
            var remoteKeyTextBox = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical
            };
            
            // Row heights for device form
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            addDeviceLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            
            // Add controls to layout
            addDeviceLayout.Controls.Add(remoteNameLabel, 0, 0);
            addDeviceLayout.Controls.Add(remoteNameTextBox, 1, 0);
            addDeviceLayout.Controls.Add(remoteIdLabel, 0, 1);
            addDeviceLayout.Controls.Add(remoteIdTextBox, 1, 1);
            addDeviceLayout.Controls.Add(remotePlatformLabel, 0, 2);
            addDeviceLayout.Controls.Add(remotePlatformComboBox, 1, 2);
            addDeviceLayout.Controls.Add(remoteIpLabel, 0, 3);
            addDeviceLayout.Controls.Add(remoteIpTextBox, 1, 3);
            addDeviceLayout.Controls.Add(remotePortLabel, 0, 4);
            addDeviceLayout.Controls.Add(remotePortTextBox, 1, 4);
            addDeviceLayout.Controls.Add(remoteKeyLabel, 0, 5);
            addDeviceLayout.Controls.Add(remoteKeyTextBox, 1, 5);
            
            addDeviceGroupBox.Controls.Add(addDeviceLayout);
            
            // Buttons panel
            var buttonsPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false
            };
            
            var addButton = new Button
            {
                Text = "Add Device",
                DialogResult = DialogResult.OK,
                AutoSize = true,
                Margin = new Padding(10, 0, 0, 0)
            };
            addButton.Click += (s, e) => {
                try {
                    // Create and add the device
                    var device = new PairedDevice
                    {
                        DeviceId = remoteIdTextBox.Text,
                        DeviceName = remoteNameTextBox.Text,
                        Platform = remotePlatformComboBox.SelectedItem.ToString(),
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
            
            var cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                AutoSize = true
            };
            
            buttonsPanel.Controls.Add(addButton);
            buttonsPanel.Controls.Add(cancelButton);
            
            // Add everything to the main layout
            mainLayout.Controls.Add(myDeviceGroupBox, 0, 0);
            mainLayout.Controls.Add(addDeviceGroupBox, 0, 1);
            mainLayout.Controls.Add(buttonsPanel, 0, 2);
            
            // Add layout to form
            this.Controls.Add(mainLayout);
            
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