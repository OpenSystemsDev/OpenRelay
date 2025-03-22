using System;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace OpenRelay.UI
{
    public partial class KeyConversionForm : Form
    {
        private readonly TextBox _inputKeyTextBox;
        private readonly TextBox _outputKeyTextBox;
        private readonly TextBox _logTextBox;
        
        public KeyConversionForm()
        {
            InitializeComponent();
            
            // Enable better DPI scaling
            this.AutoScaleMode = AutoScaleMode.Dpi;
            
            // Setup form
            this.Text = "RSA Key Conversion Tool";
            this.ClientSize = new Size(700, 600);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            
            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 4,
                Padding = new Padding(10)
            };
            
            // Input Section
            var inputGroup = new GroupBox
            {
                Text = "Input Key (Base64)",
                Dock = DockStyle.Fill
            };
            
            _inputKeyTextBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                Height = 100
            };
            
            var inputButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 40,
                FlowDirection = FlowDirection.LeftToRight
            };
            
            var pasteButton = new Button
            {
                Text = "Paste",
                Width = 100
            };
            pasteButton.Click += (s, e) => _inputKeyTextBox.Text = Clipboard.GetText();
            
            var clearButton = new Button
            {
                Text = "Clear",
                Width = 100,
                Margin = new Padding(10, 0, 0, 0)
            };
            clearButton.Click += (s, e) => _inputKeyTextBox.Text = string.Empty;
            
            inputButtons.Controls.Add(pasteButton);
            inputButtons.Controls.Add(clearButton);
            
            inputGroup.Controls.Add(_inputKeyTextBox);
            inputGroup.Controls.Add(inputButtons);
            
            // Output Section
            var outputGroup = new GroupBox
            {
                Text = "Converted Key",
                Dock = DockStyle.Fill
            };
            
            _outputKeyTextBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                Height = 100,
                ReadOnly = true
            };
            
            var outputButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                Height = 40,
                FlowDirection = FlowDirection.LeftToRight
            };
            
            var copyButton = new Button
            {
                Text = "Copy",
                Width = 100
            };
            copyButton.Click += (s, e) => 
            {
                if (!string.IsNullOrEmpty(_outputKeyTextBox.Text))
                    Clipboard.SetText(_outputKeyTextBox.Text);
            };
            
            outputButtons.Controls.Add(copyButton);
            
            outputGroup.Controls.Add(_outputKeyTextBox);
            outputGroup.Controls.Add(outputButtons);
            
            // Conversion Options
            var optionsPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight
            };
            
            var convertSubjectInfoButton = new Button
            {
                Text = "Convert to SubjectPublicKeyInfo",
                Width = 200
            };
            convertSubjectInfoButton.Click += (s, e) => ConvertKey(KeyFormat.SubjectPublicKeyInfo);
            
            var convertPkcs1Button = new Button
            {
                Text = "Convert to PKCS#1",
                Width = 150,
                Margin = new Padding(10, 0, 0, 0)
            };
            convertPkcs1Button.Click += (s, e) => ConvertKey(KeyFormat.Pkcs1);
            
            var testSignatureButton = new Button
            {
                Text = "Test Signature",
                Width = 150,
                Margin = new Padding(10, 0, 0, 0)
            };
            testSignatureButton.Click += (s, e) => TestSignature();
            
            optionsPanel.Controls.Add(convertSubjectInfoButton);
            optionsPanel.Controls.Add(convertPkcs1Button);
            optionsPanel.Controls.Add(testSignatureButton);
            
            // Log Section
            var logGroup = new GroupBox
            {
                Text = "Log",
                Dock = DockStyle.Fill
            };
            
            _logTextBox = new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                ReadOnly = true
            };
            
            logGroup.Controls.Add(_logTextBox);
            
            // Add to main layout
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 25));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 50));
            
            mainLayout.Controls.Add(inputGroup, 0, 0);
            mainLayout.Controls.Add(outputGroup, 0, 1);
            mainLayout.Controls.Add(optionsPanel, 0, 2);
            mainLayout.Controls.Add(logGroup, 0, 3);
            
            this.Controls.Add(mainLayout);
        }
        
        private void Log(string message)
        {
            _logTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\r\n");
        }
        
        private enum KeyFormat
        {
            SubjectPublicKeyInfo,
            Pkcs1
        }
        
        private void ConvertKey(KeyFormat targetFormat)
        {
            try
            {
                string inputKey = _inputKeyTextBox.Text.Trim();
                if (string.IsNullOrEmpty(inputKey))
                {
                    Log("Error: No input key provided.");
                    return;
                }
                
                Log($"Attempting to convert key to {targetFormat} format...");
                
                // Step 1: Try to import the key
                byte[] keyBytes;
                try
                {
                    keyBytes = Convert.FromBase64String(inputKey);
                    Log($"Successfully decoded Base64 input (length: {keyBytes.Length} bytes)");
                }
                catch (Exception ex)
                {
                    Log($"Error decoding Base64 input: {ex.Message}");
                    return;
                }
                
                // Step 2: Create an RSA provider to import and export the key
                using (var rsa = RSA.Create())
                {
                    // Try different import methods
                    try
                    {
                        // Try to import as SubjectPublicKeyInfo first
                        rsa.ImportSubjectPublicKeyInfo(keyBytes, out int bytesRead);
                        Log($"Successfully imported key as SubjectPublicKeyInfo (bytes read: {bytesRead})");
                    }
                    catch (Exception ex1)
                    {
                        Log($"Failed to import as SubjectPublicKeyInfo: {ex1.Message}");
                        
                        try
                        {
                            // Try to import as PKCS#1
                            rsa.ImportRSAPublicKey(keyBytes, out int bytesRead);
                            Log($"Successfully imported key as PKCS#1 (bytes read: {bytesRead})");
                        }
                        catch (Exception ex2)
                        {
                            Log($"Failed to import as PKCS#1: {ex2.Message}");
                            Log("Could not import the key in any supported format.");
                            return;
                        }
                    }
                    
                    // Step 3: Export in the requested format
                    byte[] exportedKey;
                    if (targetFormat == KeyFormat.SubjectPublicKeyInfo)
                    {
                        exportedKey = rsa.ExportSubjectPublicKeyInfo();
                        Log("Exported key in SubjectPublicKeyInfo format");
                    }
                    else // PKCS#1
                    {
                        exportedKey = rsa.ExportRSAPublicKey();
                        Log("Exported key in PKCS#1 format");
                    }
                    
                    // Convert to Base64 and display
                    string outputKey = Convert.ToBase64String(exportedKey);
                    _outputKeyTextBox.Text = outputKey;
                    
                    Log($"Conversion successful. Output key length: {outputKey.Length} characters");
                    Log("Use this key for pairing with the other device.");
                }
            }
            catch (Exception ex)
            {
                Log($"Error during conversion: {ex.Message}");
            }
        }
        
        private void TestSignature()
        {
            try
            {
                string inputKey = _inputKeyTextBox.Text.Trim();
                if (string.IsNullOrEmpty(inputKey))
                {
                    Log("Error: No input key provided.");
                    return;
                }
                
                Log("Testing signature with the provided key...");
                
                // Create test data and signature
                string testData = "Test_message_" + DateTime.Now.Ticks;
                
                // Create a new RSA provider for testing
                using (var rsaSigner = RSA.Create())
                {
                    // Sign the test data
                    byte[] dataBytes = Encoding.UTF8.GetBytes(testData);
                    byte[] signature = rsaSigner.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    
                    Log($"Created test data: {testData}");
                    Log($"Created signature length: {signature.Length} bytes");
                    
                    // Try to verify with the provided key
                    using (var rsaVerifier = RSA.Create())
                    {
                        byte[] keyBytes = Convert.FromBase64String(inputKey);
                        
                        try
                        {
                            // Try to import as SubjectPublicKeyInfo first
                            rsaVerifier.ImportSubjectPublicKeyInfo(keyBytes, out int bytesRead);
                            Log($"Imported key as SubjectPublicKeyInfo (bytes read: {bytesRead})");
                        }
                        catch (Exception ex1)
                        {
                            Log($"Failed to import as SubjectPublicKeyInfo: {ex1.Message}");
                            
                            try
                            {
                                // Try to import as PKCS#1
                                rsaVerifier.ImportRSAPublicKey(keyBytes, out int bytesRead);
                                Log($"Imported key as PKCS#1 (bytes read: {bytesRead})");
                            }
                            catch (Exception ex2)
                            {
                                Log($"Failed to import as PKCS#1: {ex2.Message}");
                                Log("Could not import the key in any supported format.");
                                return;
                            }
                        }
                        
                        // Try to verify with different parameters
                        bool verified = false;
                        
                        try
                        {
                            verified = rsaVerifier.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            Log($"Signature verification with SHA256/PKCS1: {verified}");
                        }
                        catch (Exception ex)
                        {
                            Log($"Verification error: {ex.Message}");
                        }
                        
                        if (verified)
                        {
                            Log("SUCCESS: The key can be used for signature verification!");
                        }
                        else
                        {
                            Log("WARNING: The key failed signature verification test!");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"Error during signature test: {ex.Message}");
            }
        }
        
        private void InitializeComponent()
        {
            this.SuspendLayout();
            this.ResumeLayout(false);
        }
    }
}