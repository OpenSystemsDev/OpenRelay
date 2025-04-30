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

        public SettingsDialog(SettingsManager settingsManager)
        {
            _settingsManager = settingsManager;
            _settings = _settingsManager.GetSettings();

            InitializeComponents();
            LoadSettings();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "OpenRelay Settings";
            this.Size = new Size(500, 250);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Create layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                RowCount = 5,
                ColumnCount = 2,
                Padding = new Padding(20)
            };

            // Row styles
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
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

            mainLayout.Controls.Add(buttonsPanel, 0, 4);
            mainLayout.SetColumnSpan(buttonsPanel, 2);

            // Add info label
            var infoLabel = new Label
            {
                Text = "The OpenRelay server allows secure clipboard sharing between devices " +
                       "that aren't on the same network. All data is end-to-end encrypted.",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = SystemColors.GrayText
            };

            mainLayout.Controls.Add(infoLabel, 0, 3);
            mainLayout.SetColumnSpan(infoLabel, 2);

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

            // Close dialog
            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }
}