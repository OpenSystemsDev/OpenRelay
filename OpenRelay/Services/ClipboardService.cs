using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using OpenRelay.Models;
using System.Collections.Concurrent;

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

        // Track recently seen content hashes to avoid ping-pong updates
        private ConcurrentDictionary<string, DateTime> _recentlySeen = new ConcurrentDictionary<string, DateTime>();

        // Manage "cool-down" period after a local change
        private DateTime _lastLocalChangeTime = DateTime.MinValue;
        private static readonly TimeSpan CooldownPeriod = TimeSpan.FromMilliseconds(150);

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

            // Start a periodic cleanup task for the recently seen dictionary
            Task.Run(async () => {
                while (true)
                {
                    CleanupRecentlySeen();
                    await Task.Delay(TimeSpan.FromMinutes(1));
                }
            });
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
        /// Update the clipboard content from a remote device
        /// </summary>
        public void UpdateClipboard(ClipboardData data)
        {
            if (data == null)
                return;

            try
            {
                string dataHash = CalculateContentHash(data);

                // Check if this update was recently seen
                if (_recentlySeen.TryGetValue(dataHash, out var lastSeen) &&
                    (DateTime.Now - lastSeen) < TimeSpan.FromSeconds(3))
                {
                    System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Ignoring recently seen remote update {dataHash.Substring(0, 8)}");
                    return;
                }

                // Check if we're in cooldown period after a local change
                var timeSinceLocalChange = DateTime.Now - _lastLocalChangeTime;
                if (timeSinceLocalChange < CooldownPeriod)
                {
                    if (dataHash == _lastContentHash)
                    {
                        // This is an echo of our own change, just mark it as seen
                        System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Detected echo of our own local change during cooldown, ignoring");
                        _recentlySeen[dataHash] = DateTime.Now;
                        return;
                    }
                    else
                    {
                        // This is a different update that arrived during our cooldown period
                        // Let's delay it a bit to give priority to our local change
                        System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Remote update during cooldown period, delaying");
                        Task.Delay(CooldownPeriod - timeSinceLocalChange).ContinueWith(_ =>
                            UpdateClipboard(data)
                        );
                        return;
                    }
                }

                // Check against the last hash for duplication
                if (dataHash == _lastContentHash)
                {
                    System.Diagnostics.Debug.WriteLine("[CLIPBOARD] Skipping duplicate clipboard content");
                    return;
                }

                // Mark this hash as recently seen
                _recentlySeen[dataHash] = DateTime.Now;

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
                _lastContentHash = dataHash;
                System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Applied remote clipboard update {dataHash.Substring(0, 8)}");
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
                    // Calculate hash for this content
                    string newHash = CalculateContentHash(data);

                    // Check if this is a duplicate of our last update
                    if (newHash == _lastContentHash)
                    {
                        System.Diagnostics.Debug.WriteLine("[CLIPBOARD] Skipping duplicate local clipboard content");
                        return;
                    }

                    // Check if this update was recently seen (came from another device)
                    if (_recentlySeen.TryGetValue(newHash, out var lastSeen) &&
                        (DateTime.Now - lastSeen) < TimeSpan.FromSeconds(1))
                    {
                        System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Local change matches recently seen remote update, ignoring");
                        return;
                    }

                    // Update hash first so we can detect our own updates
                    _lastContentHash = newHash;

                    // Mark as recently seen to prevent echo
                    _recentlySeen[newHash] = DateTime.Now;

                    // Record timestamp of local change
                    _lastLocalChangeTime = DateTime.Now;

                    System.Diagnostics.Debug.WriteLine($"[CLIPBOARD] Detected local change: {newHash.Substring(0, 8)}, Format={data.Format}, Size={data.TextData?.Length ?? data.BinaryData?.Length ?? 0}");

                    // Notify listeners with a small delay to prevent race conditions
                    Task.Delay(10).ContinueWith(_ => {
                        ClipboardChanged?.Invoke(this, new ClipboardChangedEventArgs(data));
                    });
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
        /// Clean up old entries from the recently seen dictionary
        /// </summary>
        private void CleanupRecentlySeen()
        {
            var cutoff = DateTime.Now.AddMinutes(-2);
            foreach (var key in _recentlySeen.Keys)
            {
                if (_recentlySeen.TryGetValue(key, out var timestamp) && timestamp < cutoff)
                {
                    _recentlySeen.TryRemove(key, out _);
                }
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