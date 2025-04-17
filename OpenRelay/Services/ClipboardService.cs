using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class ClipboardChangedEventArgs : EventArgs
    {
        public ClipboardData Data { get; }

        public ClipboardChangedEventArgs(ClipboardData data)
        {
            Data = data;
        }
    }

    /// <summary>
    /// Monitors and manages clipboard content
    /// </summary>
    public class ClipboardService : IDisposable
    {
        // Win32 API constants and imports for clipboard monitoring
        private const int WM_CLIPBOARDUPDATE = 0x031D;

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AddClipboardFormatListener(IntPtr hwnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);

        // Event for clipboard changes
        public event EventHandler<ClipboardChangedEventArgs>? ClipboardChanged;

        // Flag to prevent clipboard loops
        private bool _isUpdatingClipboard = false;

        // Store last content hash for deduplication
        private string? _lastContentHash = null;

        // Form for clipboard monitoring
        private ClipboardMonitorForm? _monitorForm;

        /// <summary>
        /// Start monitoring clipboard changes
        /// </summary>
        public void Start()
        {
            if (_monitorForm != null)
                return;

            _monitorForm = new ClipboardMonitorForm();
            _monitorForm.ClipboardUpdate += (s, e) => OnClipboardChanged();
            _monitorForm.Show();
            _monitorForm.Hide(); // Keep the form hidden but running
        }

        /// <summary>
        /// Stop monitoring clipboard changes
        /// </summary>
        public void Stop()
        {
            if (_monitorForm == null)
                return;

            _monitorForm.Close();
            _monitorForm.Dispose();
            _monitorForm = null;
        }

        /// <summary>
        /// Update the clipboard content
        /// </summary>
        public void UpdateClipboard(ClipboardData data)
        {
            if (data == null)
                return;

            try
            {
                _isUpdatingClipboard = true;

                if (data.Format == "text/plain" && data.TextData != null)
                {
                    Clipboard.SetText(data.TextData);
                }
                else if (data.Format == "image/png" && data.BinaryData != null)
                {
                    using (var ms = new MemoryStream(data.BinaryData))
                    {
                        var image = System.Drawing.Image.FromStream(ms);
                        Clipboard.SetImage(image);
                    }
                }

                // Update last content hash
                _lastContentHash = CalculateContentHash(data);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error updating clipboard: {ex.Message}");
            }
            finally
            {
                // Reset flag after a short delay to ensure clipboard events are processed
                Task.Delay(100).ContinueWith(_ => _isUpdatingClipboard = false);
            }
        }

        private void OnClipboardChanged()
        {
            if (_isUpdatingClipboard)
            {
                System.Diagnostics.Debug.WriteLine("Skipping clipboard change because we're updating it ourselves");
                return;
            }

            try
            {
                var data = GetClipboardContent();
                if (data != null)
                {
                    // Check for duplicates using hash
                    string newHash = CalculateContentHash(data);
                    if (newHash == _lastContentHash)
                    {
                        System.Diagnostics.Debug.WriteLine("[CLIPBOARD] Skipping duplicate clipboard content");
                        return;
                    }

                    // Update last content hash
                    _lastContentHash = newHash;

                    System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Detected change: Format={data.Format}, Size={data.TextData?.Length ?? data.BinaryData?.Length ?? 0}");
                    ClipboardChanged?.Invoke(this, new ClipboardChangedEventArgs(data));
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting clipboard content: {ex.Message}");
            }
        }

        private ClipboardData? GetClipboardContent()
        {
            try
            {
                // Skip if the clipboard is empty or in unsupported format
                if (!Clipboard.ContainsText() && !Clipboard.ContainsImage() && !Clipboard.ContainsFileDropList())
                {
                    return null;
                }

                // Handle text data
                if (Clipboard.ContainsText())
                {
                    string text = Clipboard.GetText();
                    return ClipboardData.CreateText(text);
                }
                // Handle image data
                else if (Clipboard.ContainsImage())
                {
                    using (var ms = new MemoryStream())
                    {
                        var image = Clipboard.GetImage();
                        if (image != null)
                        {
                            image.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                            return ClipboardData.CreateImage(ms.ToArray());
                        }
                    }
                }
                // Handle file drops - convert to text
                else if (Clipboard.ContainsFileDropList())
                {
                    var files = Clipboard.GetFileDropList();
                    string fileList = string.Join(Environment.NewLine, files.Cast<string>());
                    return ClipboardData.CreateText(fileList);
                }

                return null;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting clipboard content: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Calculate a hash for clipboard content to detect duplicates
        /// </summary>
        private string CalculateContentHash(ClipboardData data)
        {
            try
            {
                byte[] hashInput;

                if (data.Format == "text/plain" && data.TextData != null)
                {
                    hashInput = System.Text.Encoding.UTF8.GetBytes(data.TextData);
                }
                else if (data.Format == "image/png" && data.BinaryData != null)
                {
                    hashInput = data.BinaryData;
                }
                else
                {
                    return Guid.NewGuid().ToString(); // Fallback unique string
                }

                using (var md5 = MD5.Create())
                {
                    byte[] hashBytes = md5.ComputeHash(hashInput);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return Guid.NewGuid().ToString(); // Fallback unique string
            }
        }

        /// <summary>
        /// Dispose the clipboard service
        /// </summary>
        public void Dispose()
        {
            Stop();
        }

        /// <summary>
        /// Hidden form class to receive clipboard notifications
        /// </summary>
        private class ClipboardMonitorForm : Form
        {
            public event EventHandler? ClipboardUpdate;

            public ClipboardMonitorForm()
            {
                // Create a hidden form
                this.FormBorderStyle = FormBorderStyle.None;
                this.ShowInTaskbar = false;
                this.Size = new System.Drawing.Size(1, 1);
                this.Load += (s, e) =>
                {
                    this.Hide();
                    // Register for clipboard updates
                    AddClipboardFormatListener(this.Handle);
                };

                this.FormClosing += (s, e) =>
                {
                    // Unregister clipboard listener
                    RemoveClipboardFormatListener(this.Handle);
                };
            }

            protected override void WndProc(ref Message m)
            {
                // Listen for clipboard update messages
                if (m.Msg == WM_CLIPBOARDUPDATE)
                {
                    ClipboardUpdate?.Invoke(this, EventArgs.Empty);
                }
                base.WndProc(ref m);
            }
        }
    }
}