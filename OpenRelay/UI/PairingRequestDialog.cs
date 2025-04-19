using System;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;

namespace OpenRelay.UI
{
    public partial class PairingRequestDialog : Form
    {
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        [Browsable(false)]
        public bool Accepted { get; private set; } = false;

        public PairingRequestDialog(string deviceName, string deviceId, string ipAddress)
        {
            InitializeComponent();

            // Enable better DPI scaling 
            // TODO this doesnt work well on 1440p sadly
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Setup form
            this.Text = "Pairing Request";
            this.ClientSize = new Size(400, 200);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.TopMost = true;

            // Layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(20)
            };

            var iconLabel = new Label
            {
                Image = SystemIcons.Question.ToBitmap(),
                ImageAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill
            };

            var messageLabel = new Label
            {
                Text = $"Device \"{deviceName}\" ({ipAddress}) wants to pair with your device.\n\nDevice ID: {deviceId}\n\nAllow this device to receive your clipboard contents?",
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill
            };

            var buttonsPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Fill
            };

            var acceptButton = new Button
            {
                Text = "Accept",
                DialogResult = DialogResult.OK,
                Width = 100,
                Height = 30
            };
            acceptButton.Click += (s, e) =>
            {
                Accepted = true;
                this.Close();
            };

            var declineButton = new Button
            {
                Text = "Decline",
                DialogResult = DialogResult.Cancel,
                Width = 100,
                Height = 30,
                Margin = new Padding(10, 0, 0, 0)
            };
            declineButton.Click += (s, e) =>
            {
                Accepted = false;
                this.Close();
            };

            buttonsPanel.Controls.Add(acceptButton);
            buttonsPanel.Controls.Add(declineButton);

            // Add to layout
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));

            mainLayout.Controls.Add(iconLabel, 0, 0);
            mainLayout.Controls.Add(messageLabel, 0, 1);
            mainLayout.Controls.Add(buttonsPanel, 0, 2);

            this.Controls.Add(mainLayout);
            this.AcceptButton = acceptButton;
            this.CancelButton = declineButton;

            // Play a sound to alert the user
            System.Media.SystemSounds.Question.Play();
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}