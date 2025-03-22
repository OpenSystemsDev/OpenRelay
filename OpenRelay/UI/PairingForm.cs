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
        
        private readonly TextBox _remoteIdTextBox;
        private readonly TextBox _remoteNameTextBox;
        private readonly TextBox _remoteKeyTextBox;
        private readonly TextBox _remoteIpTextBox;
        
        public PairingForm(DeviceManager deviceManager, string localDeviceId, string publicKey)
        {
            InitializeComponent();
            
            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;
            
            _deviceManager = deviceManager;
            _localDeviceId = localDeviceId;
            _publicKey = publicKey;
            
            // Setup form
            this.Text = "Device Pairing";
            this.ClientSize = new Size(600, 520);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            var mainPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(10)
            };
            
            // Step 1: Information about bidirectional pairing
            var infoLabel = new Label
            {
                Text = "Step 1: Both devices must add each other for pairing to work.\r\n" +
                       "For example, if Computer A wants to sync with Computer B:\r\n" +
                       "• Computer A must add Computer B to its paired devices\r\n" +
                       "• Computer B must add Computer A to its paired devices\r\n\r\n" +
                       "Follow the steps below to complete the pairing process.",
                Dock = DockStyle.Fill,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleLeft
            };
            
            // Step 2: This device's information
            var thisDeviceGroup = new GroupBox
            {
                Text = "Step 2: Share this device's information",
                Dock = DockStyle.Fill,
                Padding = new Padding(10)
            };
            
            var thisDevicePanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 3
            };
            
            thisDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            thisDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            thisDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            
            var idLabel = new Label { Text = "Device ID:", Anchor = AnchorStyles.Left };
            var idTextBox = new TextBox { Text = _localDeviceId, ReadOnly = true, Dock = DockStyle.Fill };
            var copyIdButton = new Button { Text = "Copy", Dock = DockStyle.Fill };
            copyIdButton.Click += (s, e) => { Clipboard.SetText(_localDeviceId); };
            
            var nameLabel = new Label { Text = "Device Name:", Anchor = AnchorStyles.Left };
            var nameTextBox = new TextBox { Text = Environment.MachineName, ReadOnly = true, Dock = DockStyle.Fill };
            var copyNameButton = new Button { Text = "Copy", Dock = DockStyle.Fill };
            copyNameButton.Click += (s, e) => { Clipboard.SetText(Environment.MachineName); };
            
            var keyLabel = new Label { Text = "Public Key:", Anchor = AnchorStyles.Left };
            var keyTextBox = new TextBox { Text = _publicKey, ReadOnly = true, Multiline = true, Dock = DockStyle.Fill };
            var copyKeyButton = new Button { Text = "Copy", Dock = DockStyle.Fill };
            copyKeyButton.Click += (s, e) => { Clipboard.SetText(_publicKey); };
            
            thisDevicePanel.Controls.Add(idLabel, 0, 0);
            thisDevicePanel.Controls.Add(idTextBox, 1, 0);
            thisDevicePanel.Controls.Add(copyIdButton, 2, 0);
            
            thisDevicePanel.Controls.Add(nameLabel, 0, 1);
            thisDevicePanel.Controls.Add(nameTextBox, 1, 1);
            thisDevicePanel.Controls.Add(copyNameButton, 2, 1);
            
            thisDevicePanel.Controls.Add(keyLabel, 0, 2);
            thisDevicePanel.Controls.Add(keyTextBox, 1, 2);
            thisDevicePanel.Controls.Add(copyKeyButton, 2, 2);
            
            thisDevicePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            thisDevicePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            thisDevicePanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            
            thisDeviceGroup.Controls.Add(thisDevicePanel);
            
            // Step 3: Remote device's information
            var remoteDeviceGroup = new GroupBox
            {
                Text = "Step 3: Enter remote device's information",
                Dock = DockStyle.Fill,
                Padding = new Padding(10)
            };
            
            var remoteDevicePanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 4
            };
            
            remoteDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            remoteDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            remoteDevicePanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            
            var remoteIdLabel = new Label { Text = "Device ID:", Anchor = AnchorStyles.Left };
            _remoteIdTextBox = new TextBox { Dock = DockStyle.Fill };
            var pasteIdButton = new Button { Text = "Paste", Dock = DockStyle.Fill };
            pasteIdButton.Click += (s, e) => { _remoteIdTextBox.Text = Clipboard.GetText(); };
            
            var remoteNameLabel = new Label { Text = "Device Name:", Anchor = AnchorStyles.Left };
            _remoteNameTextBox = new TextBox { Dock = DockStyle.Fill };
            var pasteNameButton = new Button { Text = "Paste", Dock = DockStyle.Fill };
            pasteNameButton.Click += (s, e) => { _remoteNameTextBox.Text = Clipboard.GetText(); };
            
            var remoteKeyLabel = new Label { Text = "Public Key:", Anchor = AnchorStyles.Left };
            _remoteKeyTextBox = new TextBox { Multiline = true, Dock = DockStyle.Fill };
            var pasteKeyButton = new Button { Text = "Paste", Dock = DockStyle.Fill };
            pasteKeyButton.Click += (s, e) => { _remoteKeyTextBox.Text = Clipboard.GetText(); };
            
            var remoteIpLabel = new Label { Text = "IP Address:", Anchor = AnchorStyles.Left };
            _remoteIpTextBox = new TextBox { Dock = DockStyle.Fill };
            
            remoteDevicePanel.Controls.Add(remoteIdLabel, 0, 0);
            remoteDevicePanel.Controls.Add(_remoteIdTextBox, 1, 0);
            remoteDevicePanel.Controls.Add(pasteIdButton, 2, 0);
            
            remoteDevicePanel.Controls.Add(remoteNameLabel, 0, 1);
            remoteDevicePanel.Controls.Add(_remoteNameTextBox, 1, 1);
            remoteDevicePanel.Controls.Add(pasteNameButton, 2, 1);
            
            remoteDevicePanel.Controls.Add(remoteKeyLabel, 0, 2);
            remoteDevicePanel.Controls.Add(_remoteKeyTextBox, 1, 2);
            remoteDevicePanel.Controls.Add(pasteKeyButton, 2, 2);
            
            remoteDevicePanel.Controls.Add(remoteIpLabel, 0, 3);
            remoteDevicePanel.Controls.Add(_remoteIpTextBox, 1, 3);
            
            remoteDevicePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            remoteDevicePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            remoteDevicePanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            remoteDevicePanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            
            remoteDeviceGroup.Controls.Add(remoteDevicePanel);
            
            // Step 4: Buttons
            var buttonPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.RightToLeft
            };
            
            var addButton = new Button
            {
                Text = "Add Device",
                AutoSize = true,
                Padding = new Padding(10, 5, 10, 5),
                Margin = new Padding(10, 0, 0, 0)
            };
            addButton.Click += AddButton_Click;
            
            var cancelButton = new Button
            {
                Text = "Cancel",
                AutoSize = true,
                Padding = new Padding(10, 5, 10, 5)
            };
            cancelButton.Click += (s, e) => { this.DialogResult = DialogResult.Cancel; };
            
            buttonPanel.Controls.Add(addButton);
            buttonPanel.Controls.Add(cancelButton);
            
            // Add all to main panel
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 100));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            
            mainPanel.Controls.Add(infoLabel, 0, 0);
            mainPanel.Controls.Add(thisDeviceGroup, 0, 1);
            mainPanel.Controls.Add(remoteDeviceGroup, 0, 2);
            mainPanel.Controls.Add(buttonPanel, 0, 3);
            
            this.Controls.Add(mainPanel);
        }
        
        private void AddButton_Click(object sender, EventArgs e)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(_remoteIdTextBox.Text))
                {
                    MessageBox.Show("Device ID is required.", "Validation Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                
                if (string.IsNullOrWhiteSpace(_remoteNameTextBox.Text))
                {
                    MessageBox.Show("Device Name is required.", "Validation Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                
                if (string.IsNullOrWhiteSpace(_remoteKeyTextBox.Text))
                {
                    MessageBox.Show("Public Key is required.", "Validation Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                
                if (string.IsNullOrWhiteSpace(_remoteIpTextBox.Text))
                {
                    MessageBox.Show("IP Address is required.", "Validation Error", 
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                
                // Create the device
                var device = new PairedDevice
                {
                    DeviceId = _remoteIdTextBox.Text.Trim(),
                    DeviceName = _remoteNameTextBox.Text.Trim(),
                    Platform = "Windows", // Assuming Windows for now
                    IpAddress = _remoteIpTextBox.Text.Trim(),
                    Port = 9876, // Default port
                    PublicKey = _remoteKeyTextBox.Text.Trim(),
                    LastSeen = DateTime.Now
                };
                
                // Add to device manager
                _deviceManager.AddOrUpdateDevice(device);
                
                MessageBox.Show(
                    "Device added successfully!\n\n" +
                    "IMPORTANT: Make sure to also add this device's information on the other device.\n\n" +
                    "Device ID, name, and public key have been copied to your clipboard for easy sharing.",
                    "Pairing Successful",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                
                this.DialogResult = DialogResult.OK;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error adding device: {ex.Message}", "Error", 
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}