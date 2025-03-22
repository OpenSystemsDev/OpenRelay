using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using System.IO;
using System.Drawing;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class ClipboardChangedEventArgs : EventArgs
    {
        public ClipboardData? Data { get; }

        public ClipboardChangedEventArgs(ClipboardData? data)
        {
            Data = data;
        }
    }

    public class ClipboardMonitorService : IDisposable
    {
        // Win32 API constants and imports
        private const int WM_CLIPBOARDUPDATE = 0x031D;
        
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AddClipboardFormatListener(IntPtr hwnd);
        
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
        
        // Hidden form to receive clipboard notifications
        private ClipboardForm? _clipboardForm;
        private Thread? _formThread;
        private readonly ManualResetEvent _formReadyEvent = new ManualResetEvent(false);
        private bool _isMonitoring = false;
        
        // Event for clipboard changes
        public event EventHandler<ClipboardChangedEventArgs>? ClipboardChanged;
        
        public ClipboardMonitorService()
        {
        }
        
        public void Start()
        {
            if (_isMonitoring) return;
            
            // Create the form on a separate UI thread
            _formThread = new Thread(() =>
            {
                _clipboardForm = new ClipboardForm();
                _clipboardForm.ClipboardUpdate += (s, e) => OnClipboardChanged();
                _formReadyEvent.Set();
                Application.Run(_clipboardForm);
            });
            
            _formThread.SetApartmentState(ApartmentState.STA);
            _formThread.IsBackground = true;
            _formThread.Start();
            
            // Wait for the form to be ready
            _formReadyEvent.WaitOne();
            _isMonitoring = true;
        }
        
        public void Stop()
        {
            if (!_isMonitoring) return;
            
            if (_clipboardForm != null && !_clipboardForm.IsDisposed)
            {
                _clipboardForm.BeginInvoke(new Action(() =>
                {
                    _clipboardForm.Close();
                }));
            }
            
            _isMonitoring = false;
        }
        
        private void OnClipboardChanged()
        {
            try
            {
                var data = GetClipboardContent();
                ClipboardChanged?.Invoke(this, new ClipboardChangedEventArgs(data));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling clipboard change: {ex.Message}");
            }
        }
        
        private ClipboardData? GetClipboardContent()
        {
            try
            {
                // This must run on a thread with a message pump (STA thread)
                if (_clipboardForm == null || _clipboardForm.IsDisposed)
                    return null;
                
                ClipboardData? result = null;
                
                _clipboardForm.Invoke(new Action(() =>
                {
                    // Skip if the clipboard is empty or in unsupported format
                    if (!Clipboard.ContainsText() && !Clipboard.ContainsImage() && !Clipboard.ContainsFileDropList())
                    {
                        result = null;
                        return;
                    }
                    
                    result = new ClipboardData
                    {
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    };
                    
                    // Handle text data
                    if (Clipboard.ContainsText())
                    {
                        result.Format = "text/plain";
                        result.TextData = Clipboard.GetText();
                    }
                    // Handle image data
                    else if (Clipboard.ContainsImage())
                    {
                        result.Format = "image/png";
                        var image = Clipboard.GetImage();
                        if (image != null)
                        {
                            using (var ms = new MemoryStream())
                            {
                                image.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                                result.BinaryData = ms.ToArray();
                            }
                        }
                    }
                    // Handle file drops
                    else if (Clipboard.ContainsFileDropList())
                    {
                        result.Format = "files/paths";
                        var files = Clipboard.GetFileDropList();
                        result.TextData = string.Join("\n", files.Cast<string>());
                    }
                }));
                
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error getting clipboard content: {ex.Message}");
                return null;
            }
        }
        
        public void Dispose()
        {
            Stop();
            _formReadyEvent.Dispose();
            GC.SuppressFinalize(this);
        }
        
        // Hidden form class to receive clipboard notifications
        private class ClipboardForm : Form
        {
            public event EventHandler? ClipboardUpdate;
            
            public ClipboardForm()
            {
                // Create a hidden form
                this.FormBorderStyle = FormBorderStyle.None;
                this.ShowInTaskbar = false;
                this.Size = new Size(1, 1);
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