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
            // Setup form - allow resizing and calculate adaptive size
            this.Text = "Pair New Device";
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = true;
            this.MinimizeBox = true;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimumSize = new Size(550, 500);

            // Set initial size based on screen resolution
            Screen currentScreen = Screen.FromControl(this);
            int width = Math.Min(700, (int)(currentScreen.WorkingArea.Width * 0.6));
            int height = Math.Min(600, (int)(currentScreen.WorkingArea.Height * 0.7));
            this.Size = new Size(width, height);

            // Create a panel to allow scrolling if form gets too small
            var mainPanel = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true
            };
            this.Controls.Add(mainPanel);

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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 170,
                ReadOnly = true
            };

            var copyIdButton = new Button
            {
                Text = "Copy",
                Location = new Point(width - 120, 25),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 170,
                Height = 50,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical
            };

            var copyKeyButton = new Button
            {
                Text = "Copy",
                Location = new Point(width - 120, 60),
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Width = 70
            };
            copyKeyButton.Click += (s, e) => Clipboard.SetText(_publicKey);

            var qrInfoLabel = new Label
            {
                Text = "Share this information with the device you want to pair with.",
                Location = new Point(120, 120),
                AutoSize = true
            };

            myDeviceGroupBox.Controls.AddRange(new Control[]
            {
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150,
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150,
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
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
                Width = width - 150,
                Height = 50,
                Multiline = true,
                ScrollBars = ScrollBars.Vertical
            };

            addDeviceGroupBox.Controls.AddRange(new Control[]
            {
                remoteNameLabel, remoteNameTextBox,
                remoteIdLabel, remoteIdTextBox,
                remotePlatformLabel, remotePlatformComboBox,
                remoteIpLabel, remoteIpTextBox,
                remotePortLabel, remotePortTextBox,
                remoteKeyLabel, remoteKeyTextBox
            });

            // Buttons panel with fixed padding from bottom
            var buttonPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 50
            };

            var cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Width = 90,
                Height = 30
            };
            cancelButton.Location = new Point(buttonPanel.Width - 200, 10);

            var addButton = new Button
            {
                Text = "Add Device",
                DialogResult = DialogResult.OK,
                Anchor = AnchorStyles.Top | AnchorStyles.Right,
                Width = 90,
                Height = 30
            };
            addButton.Location = new Point(buttonPanel.Width - 100, 10);

            addButton.Click += (s, e) =>
            {
                try
                {
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
                catch (Exception ex)
                {
                    MessageBox.Show($"Error adding device: {ex.Message}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    this.DialogResult = DialogResult.None;
                }
            };

            buttonPanel.Controls.AddRange(new Control[] { cancelButton, addButton });

            // Handle resize for button panel
            this.Resize += (s, e) =>
            {
                cancelButton.Location = new Point(buttonPanel.Width - 200, 10);
                addButton.Location = new Point(buttonPanel.Width - 100, 10);
            };

            // Add all controls to form
            mainPanel.Controls.AddRange(new Control[]
            {
                myDeviceGroupBox,
                addDeviceGroupBox
            });
            this.Controls.Add(buttonPanel);

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