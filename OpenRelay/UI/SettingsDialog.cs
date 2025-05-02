using System;
using System.Drawing;
using System.Windows.Forms;
using OpenRelay.Services;

namespace OpenRelay.UI
{
    public class SettingsDialog : Form
    {
        private readonly SettingsManager _settingsManager;
        private Settings _settings;

        private CheckBox _useRelayServerCheckBox;
        private CheckBox _exposeToRelayNetworkCheckBox;
        private TextBox _relayServerUriTextBox;
        private Label _relayServerUriLabel;
        private Button _saveButton;
        private Button _cancelButton;

        // New controls for device ID
        private Label _deviceIdLabel;
        private TextBox _deviceIdTextBox;
        private Button _copyDeviceIdButton;
        private NetworkService _networkService;

        public SettingsDialog(SettingsManager settingsManager, NetworkService networkService)
        {
            _settingsManager = settingsManager;
            _settings = _settingsManager.GetSettings();
            _networkService = networkService;

            InitializeComponents();
            LoadSettings();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "OpenRelay Settings";
            this.Size = new Size(500, 300); // Increased height for new controls
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Create layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 7, // Increased row count for new controls
                ColumnCount = 2,
                Padding = new Padding(20)
            };

            // Row styles
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); // Device ID label
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40)); // Device ID controls
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));

            // Column styles
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
            mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 70));

            // Create controls
            _useRelayServerCheckBox = new CheckBox
            {
                Text = "Use OpenRelay Server",
                Checked = _settings.UseRelayServer,
                Dock = DockStyle.Fill
            };

            _exposeToRelayNetworkCheckBox = new CheckBox
            {
                Text = "Expose this device to the OpenRelay network",
                Checked = _settings.ExposeToRelayNetwork,
                Dock = DockStyle.Fill,
                Enabled = _settings.UseRelayServer
            };

            _relayServerUriLabel = new Label
            {
                Text = "Server Address:",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            _relayServerUriTextBox = new TextBox
            {
                Text = _settings.RelayServerUri,
                Dock = DockStyle.Fill,
                Enabled = _settings.UseRelayServer
            };

            // Device ID controls
            _deviceIdLabel = new Label
            {
                Text = "Your Relay Device ID:",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            _deviceIdTextBox = new TextBox
            {
                ReadOnly = true,
                Dock = DockStyle.Fill,
                Text = _networkService != null && _networkService.IsConnectedToRelayServer && _networkService._relayConnection != null ?
                      _networkService._relayConnection.RelayDeviceId : "Not connected to relay server",
                Enabled = _networkService != null && _networkService.IsConnectedToRelayServer
            };

            _copyDeviceIdButton = new Button
            {
                Text = "Copy",
                Dock = DockStyle.Right,
                Width = 60,
                Enabled = _networkService != null && _networkService.IsConnectedToRelayServer
            };

            _copyDeviceIdButton.Click += (s, e) => {
                if (!string.IsNullOrEmpty(_deviceIdTextBox.Text) && _deviceIdTextBox.Text != "Not connected to relay server")
                {
                    Clipboard.SetText(_deviceIdTextBox.Text);
                    MessageBox.Show("Device ID copied to clipboard!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };

            // Create buttons panel
            var buttonsPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Fill
            };

            _saveButton = new Button
            {
                Text = "Save",
                Width = 100,
                Height = 30
            };

            _cancelButton = new Button
            {
                Text = "Cancel",
                Width = 100,
                Height = 30,
                DialogResult = DialogResult.Cancel
            };

            // Add event handlers
            _useRelayServerCheckBox.CheckedChanged += (s, e) =>
            {
                _exposeToRelayNetworkCheckBox.Enabled = _useRelayServerCheckBox.Checked;
                _relayServerUriTextBox.Enabled = _useRelayServerCheckBox.Checked;
            };

            _saveButton.Click += SaveButton_Click;
            _cancelButton.Click += (s, e) => this.Close();

            // Add controls to buttons panel
            buttonsPanel.Controls.Add(_saveButton);
            buttonsPanel.Controls.Add(_cancelButton);

            // Add controls to layout
            mainLayout.Controls.Add(_useRelayServerCheckBox, 0, 0);
            mainLayout.SetColumnSpan(_useRelayServerCheckBox, 2);

            mainLayout.Controls.Add(_exposeToRelayNetworkCheckBox, 0, 1);
            mainLayout.SetColumnSpan(_exposeToRelayNetworkCheckBox, 2);

            mainLayout.Controls.Add(_relayServerUriLabel, 0, 2);
            mainLayout.Controls.Add(_relayServerUriTextBox, 1, 2);

            // Add device ID controls
            mainLayout.Controls.Add(_deviceIdLabel, 0, 3);

            var deviceIdPanel = new Panel { Dock = DockStyle.Fill };
            deviceIdPanel.Controls.Add(_deviceIdTextBox);
            deviceIdPanel.Controls.Add(_copyDeviceIdButton);
            _deviceIdTextBox.Dock = DockStyle.Fill;
            _copyDeviceIdButton.Dock = DockStyle.Right;

            mainLayout.Controls.Add(deviceIdPanel, 1, 3);

            // Add info label
            var infoLabel = new Label
            {
                Text = "The OpenRelay server allows secure clipboard sharing between devices " +
                       "that aren't on the same network. All data is end-to-end encrypted.",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = SystemColors.GrayText
            };

            mainLayout.Controls.Add(infoLabel, 0, 5);
            mainLayout.SetColumnSpan(infoLabel, 2);

            mainLayout.Controls.Add(buttonsPanel, 0, 6);
            mainLayout.SetColumnSpan(buttonsPanel, 2);

            // Set up form
            this.Controls.Add(mainLayout);
            this.AcceptButton = _saveButton;
            this.CancelButton = _cancelButton;
        }

        private void LoadSettings()
        {
            _useRelayServerCheckBox.Checked = _settings.UseRelayServer;
            _exposeToRelayNetworkCheckBox.Checked = _settings.ExposeToRelayNetwork;
            _relayServerUriTextBox.Text = _settings.RelayServerUri;

            // Update control states
            _exposeToRelayNetworkCheckBox.Enabled = _settings.UseRelayServer;
            _relayServerUriTextBox.Enabled = _settings.UseRelayServer;

            // Update device ID textbox
            if (_networkService != null && _networkService.IsConnectedToRelayServer && _networkService._relayConnection != null)
            {
                _deviceIdTextBox.Text = _networkService._relayConnection.RelayDeviceId;
                _deviceIdTextBox.Enabled = true;
                _copyDeviceIdButton.Enabled = true;
            }
            else
            {
                _deviceIdTextBox.Text = "Not connected to relay server";
                _deviceIdTextBox.Enabled = false;
                _copyDeviceIdButton.Enabled = false;
            }
        }

        private void SaveButton_Click(object sender, EventArgs e)
        {
            // Validate server URI
            string uri = _relayServerUriTextBox.Text.Trim();
            if (_useRelayServerCheckBox.Checked && !uri.StartsWith("wss://"))
            {
                MessageBox.Show(
                    "Server address must start with 'wss://'",
                    "Invalid Server Address",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            // Update settings
            _settings.UseRelayServer = _useRelayServerCheckBox.Checked;
            _settings.ExposeToRelayNetwork = _exposeToRelayNetworkCheckBox.Checked;
            _settings.RelayServerUri = uri;

            // Save settings
            _settingsManager.UpdateSettings(_settings);

            // If relay is enabled, connect
            if (_settings.UseRelayServer)
            {
                Task.Run(async () =>
                {
                    await _networkService.ConnectToRelayServerAsync();

                    // Update the device ID field if connected
                    if (_networkService.IsConnectedToRelayServer && _networkService._relayConnection != null)
                    {
                        if (InvokeRequired)
                        {
                            Invoke(new Action(() => {
                                _deviceIdTextBox.Text = _networkService._relayConnection.RelayDeviceId;
                                _deviceIdTextBox.Enabled = true;
                                _copyDeviceIdButton.Enabled = true;
                            }));
                        }
                        else
                        {
                            _deviceIdTextBox.Text = _networkService._relayConnection.RelayDeviceId;
                            _deviceIdTextBox.Enabled = true;
                            _copyDeviceIdButton.Enabled = true;
                        }
                    }
                });
            }
            else if (_networkService.IsConnectedToRelayServer)
            {
                // Disconnect if relay is disabled
                Task.Run(async () => await _networkService.DisconnectFromRelayServerAsync());

                // Update UI
                _deviceIdTextBox.Text = "Not connected to relay server";
                _deviceIdTextBox.Enabled = false;
                _copyDeviceIdButton.Enabled = false;
            }

            // Close dialog
            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}