using System;
using System.Drawing;
using System.Windows.Forms;

namespace OpenRelay.UI
{
    public partial class TextInputDialog : Form
    {
        private TextBox _inputTextBox;

        public string InputText => _inputTextBox.Text;

        public TextInputDialog(string title, string prompt)
        {
            InitializeComponent();

            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Setup form
            this.Text = title;
            this.ClientSize = new Size(350, 150);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;
            this.MinimizeBox = false;

            // Create layout
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Padding = new Padding(10)
            };

            var promptLabel = new Label
            {
                Text = prompt,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft
            };

            _inputTextBox = new TextBox
            {
                Dock = DockStyle.Fill
            };

            var buttonsPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Fill
            };

            var okButton = new Button
            {
                Text = "OK",
                DialogResult = DialogResult.OK,
                Width = 80,
                Height = 30
            };

            var cancelButton = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Width = 80,
                Height = 30,
                Margin = new Padding(10, 0, 0, 0)
            };

            buttonsPanel.Controls.Add(okButton);
            buttonsPanel.Controls.Add(cancelButton);

            // Add to layout
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 40));

            mainLayout.Controls.Add(promptLabel, 0, 0);
            mainLayout.Controls.Add(_inputTextBox, 0, 1);
            mainLayout.Controls.Add(buttonsPanel, 0, 2);

            this.Controls.Add(mainLayout);
            this.AcceptButton = okButton;
            this.CancelButton = cancelButton;
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}