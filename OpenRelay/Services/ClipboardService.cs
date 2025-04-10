using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Newtonsoft.Json;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class ClipboardEventArgs : EventArgs
    {
        public ClipboardData Data { get; }

        public ClipboardEventArgs(ClipboardData data)
        {
            Data = data;
        }
    }

    public class ClipboardService : IDisposable
    {
        public event EventHandler<ClipboardEventArgs>? ClipboardDataReceived;

        // Flag to prevent clipboard loops
        private bool _isUpdatingClipboard = false;

        // Callback for the Rust library
        private NativeMethods.ClipboardChangedCallback _clipboardChangedCallback;

        public ClipboardService()
        {
            _clipboardChangedCallback = new NativeMethods.ClipboardChangedCallback(OnClipboardChanged);

            // Register callback with the Rust library
            NativeMethods.openrelay_set_clipboard_changed_callback(_clipboardChangedCallback);
        }

        private void OnClipboardChanged(IntPtr jsonDataPtr, IntPtr binaryDataPtr, UIntPtr binaryLength)
        {
            if (_isUpdatingClipboard)
                return;

            try
            {
                // Parse JSON data
                string jsonData = Marshal.PtrToStringAnsi(jsonDataPtr) ?? "{}";
                var data = JsonConvert.DeserializeObject<JsonClipboardData>(jsonData);

                if (data == null)
                    return;

                // Create clipboard data
                var clipboardData = new ClipboardData
                {
                    Format = data.Format,
                    TextData = data.TextData,
                    Timestamp = data.Timestamp
                };

                // Copy binary data if present
                if (binaryDataPtr != IntPtr.Zero && binaryLength.ToUInt64() > 0)
                {
                    clipboardData.BinaryData = new byte[binaryLength.ToUInt64()];
                    Marshal.Copy(binaryDataPtr, clipboardData.BinaryData, 0, clipboardData.BinaryData.Length);
                }

                // Notify listeners
                ClipboardDataReceived?.Invoke(this, new ClipboardEventArgs(clipboardData));

                // Update the clipboard
                UpdateClipboard(clipboardData);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling clipboard change: {ex.Message}");
            }
        }

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
                    using (var ms = new System.IO.MemoryStream(data.BinaryData))
                    {
                        var image = System.Drawing.Image.FromStream(ms);
                        Clipboard.SetImage(image);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating clipboard: {ex.Message}");
            }
            finally
            {
                // Reset flag after a short delay to ensure clipboard events are processed
                Task.Delay(100).ContinueWith(_ => _isUpdatingClipboard = false);
            }
        }

        public void Dispose()
        {
            // Nothing specific to dispose, but implementing IDisposable for consistency
        }
    }
}