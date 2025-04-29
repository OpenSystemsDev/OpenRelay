using System;
using System.Drawing;
using System.Windows.Forms;

namespace OpenRelay.UI
{
    public class RelayDeviceInputDialog : Form
    {
        private TextBox _deviceIdTextBox;
        public string DeviceId => _deviceIdTextBox.Text;

        public RelayDeviceInputDialog()
        {
            InitializeComponents();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "Connect to Relay Device";
            this.Size = new Size(400, 200);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Create layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(20)
            };

            // Instructions label
            var instructionsLabel = new Label
            {
                Text = "Enter the Relay Device ID of the device you want to pair with.",
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill
            };

            // ID Label
            var idLabel = new Label
            {
                Text = "Relay Device ID:",
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill
            };

            // Text box for device ID
            _deviceIdTextBox = new TextBox
            {
                Dock = DockStyle.Fill
            };

            // Buttons panel
            var buttonsPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Fill
            };

            // Connect button
            var connectButton = new Button
            {
                Text = "Connect",
                DialogResult = DialogResult.OK,
                Width = 100,
                Height = 30
            };

            // Cancel button
            var cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Width = 100,
                Height = 30,
                Margin = new Padding(10, 0, 0, 0)
            };

            // Add buttons to panel
            buttonsPanel.Controls.Add(connectButton);
            buttonsPanel.Controls.Add(cancelButton);

            // Row styles
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));

            // Add controls to layout
            mainLayout.Controls.Add(instructionsLabel, 0, 0);
            mainLayout.Controls.Add(idLabel, 0, 1);
            mainLayout.Controls.Add(_deviceIdTextBox, 0, 2);
            mainLayout.Controls.Add(buttonsPanel, 0, 3);

            // Connect button click handler
            connectButton.Click += (s, e) =>
            {
                // Validate input
                if (string.IsNullOrWhiteSpace(_deviceIdTextBox.Text))
                {
                    MessageBox.Show(
                        "Please enter a valid Relay Device ID.",
                        "Invalid Input",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    this.DialogResult = DialogResult.None;
                    return;
                }

                this.DialogResult = DialogResult.OK;
                this.Close();
            };

            // Set up form
            this.Controls.Add(mainLayout);
            this.AcceptButton = connectButton;
            this.CancelButton = cancelButton;
        }
    }
}