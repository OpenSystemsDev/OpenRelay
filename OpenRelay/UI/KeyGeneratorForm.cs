using System;
using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace OpenRelay.UI
{
    public partial class KeyGeneratorForm : Form
    {
        private TextBox _publicKeyTextBox;
        private TextBox _deviceIdTextBox;
        
        public KeyGeneratorForm()
        {
            InitializeComponent();
            
            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;
            
            // Setup form
            this.Text = "Key Generator";
            this.ClientSize = new Size(600, 400);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(10)
            };
            
            var titleLabel = new Label
            {
                Text = "Generate New Keys for Pairing",
                Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter,
                Dock = DockStyle.Fill
            };
            
            var instructionsLabel = new Label
            {
                Text = "This tool will generate a fresh set of keys that you can use for pairing.\n" +
                      "1. Generate a new device ID and public key\n" +
                      "2. Use these when pairing on BOTH devices\n" +
                      "3. Make sure to use exactly the same values on both sides",
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill
            };
            
            // Device ID section
            var idPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1
            };
            
            idPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            idPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            idPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
            
            var idLabel = new Label
            {
                Text = "Device ID:",
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill
            };
            
            _deviceIdTextBox = new TextBox
            {
                ReadOnly = true,
                Dock = DockStyle.Fill
            };
            
            var copyIdButton = new Button
            {
                Text = "Copy",
                Dock = DockStyle.Fill
            };
            copyIdButton.Click += (s, e) => 
            {
                if (!string.IsNullOrEmpty(_deviceIdTextBox.Text))
                    Clipboard.SetText(_deviceIdTextBox.Text);
            };
            
            idPanel.Controls.Add(idLabel, 0, 0);
            idPanel.Controls.Add(_deviceIdTextBox, 1, 0);
            idPanel.Controls.Add(copyIdButton, 2, 0);
            
            // Public key section
            var keyPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 2
            };
            
            keyPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
            keyPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            
            keyPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 25));
            keyPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            
            var keyLabel = new Label
            {
                Text = "Public Key:",
                TextAlign = ContentAlignment.MiddleLeft,
                Dock = DockStyle.Fill
            };
            
            var copyKeyButton = new Button
            {
                Text = "Copy Public Key",
                Dock = DockStyle.Fill
            };
            copyKeyButton.Click += (s, e) => 
            {
                if (!string.IsNullOrEmpty(_publicKeyTextBox.Text))
                    Clipboard.SetText(_publicKeyTextBox.Text);
            };
            
            _publicKeyTextBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                ReadOnly = true,
                Dock = DockStyle.Fill
            };
            
            keyPanel.Controls.Add(keyLabel, 0, 0);
            keyPanel.Controls.Add(copyKeyButton, 1, 0);
            keyPanel.Controls.Add(_publicKeyTextBox, 0, 1);
            keyPanel.SetColumnSpan(_publicKeyTextBox, 2);
            
            // Buttons panel
            var buttonsPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight
            };
            
            var generateButton = new Button
            {
                Text = "Generate New Keys",
                Width = 150,
                Height = 30
            };
            generateButton.Click += GenerateButton_Click;
            
            var closeButton = new Button
            {
                Text = "Close",
                Width = 100,
                Height = 30,
                Margin = new Padding(10, 0, 0, 0)
            };
            closeButton.Click += (s, e) => Close();
            
            buttonsPanel.Controls.Add(generateButton);
            buttonsPanel.Controls.Add(closeButton);
            
            // Add to main layout
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 70));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 30));
            
            mainLayout.Controls.Add(titleLabel, 0, 0);
            mainLayout.Controls.Add(instructionsLabel, 0, 1);
            
            var keyAndIdPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Margin = new Padding(0)
            };
            
            keyAndIdPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
            keyAndIdPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            
            keyAndIdPanel.Controls.Add(idPanel, 0, 0);
            keyAndIdPanel.Controls.Add(keyPanel, 0, 1);
            
            mainLayout.Controls.Add(keyAndIdPanel, 0, 2);
            mainLayout.Controls.Add(buttonsPanel, 0, 3);
            
            this.Controls.Add(mainLayout);
            
            // Generate initial keys
            GenerateKeys();
        }
        
        private void GenerateButton_Click(object sender, EventArgs e)
        {
            GenerateKeys();
        }
        
        private void GenerateKeys()
        {
            try
            {
                // Generate a new device ID
                string deviceId = Guid.NewGuid().ToString();
                _deviceIdTextBox.Text = deviceId;
                
                // Generate a new RSA key pair
                using (var rsa = RSA.Create(2048))
                {
                    // Export the public key in SubjectPublicKeyInfo format (X.509)
                    byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
                    string publicKeyBase64 = Convert.ToBase64String(publicKeyBytes);
                    
                    _publicKeyTextBox.Text = publicKeyBase64;
                }
                
                MessageBox.Show(
                    "New keys generated successfully!\n\n" +
                    "IMPORTANT: Use these EXACT SAME values on both devices when pairing.",
                    "Success",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error generating keys: {ex.Message}",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}