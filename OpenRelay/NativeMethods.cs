using System;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenRelay
{
    internal static class NativeMethods
    {
        // Explicitly specify the DLL path and name
        private const string DllName = "openrelay_core";

        // Callback delegates with explicit marshaling
        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate void ClipboardChangedCallback(IntPtr jsonData, IntPtr binaryData, UIntPtr binaryLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate int PairingRequestCallback(IntPtr deviceId, IntPtr deviceName, IntPtr ipAddress, int port, IntPtr requestId);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate void DeviceAddedCallback(IntPtr deviceId, IntPtr deviceName, IntPtr ipAddress, int port);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public delegate void DeviceRemovedCallback(IntPtr deviceId);

        // Initialize the library
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int openrelay_init();

        // Set the clipboard changed callback
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_set_clipboard_changed_callback(ClipboardChangedCallback callback);

        // Set the pairing request callback
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_set_pairing_request_callback(PairingRequestCallback callback);

        // Set the device added callback
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_set_device_added_callback(DeviceAddedCallback callback);

        // Set the device removed callback
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_set_device_removed_callback(DeviceRemovedCallback callback);

        // Start the OpenRelay services
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int openrelay_start();

        // Get local device ID
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr openrelay_get_local_device_id();

        // Get local device name
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr openrelay_get_local_device_name();

        // Get paired devices as JSON
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr openrelay_get_paired_devices();

        // Send pairing request (explicitly specify string marshaling)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int openrelay_send_pairing_request(
            [MarshalAs(UnmanagedType.LPStr)] string ipAddress, int port);

        // Remove paired device (explicitly specify string marshaling)
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int openrelay_remove_device(
            [MarshalAs(UnmanagedType.LPStr)] string deviceId);

        // Cleanup and shut down
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_cleanup();

        // Free a C string allocated by Rust
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void openrelay_free_string(IntPtr ptr);

        // Helper method to convert an IntPtr to a string and free the memory
        // Rust likely uses UTF-8, so we'll try both UTF-8 and ANSI
        public static string PtrToStringAndFree(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return string.Empty;

            try
            {
                // Try UTF-8 first
                string result = PtrToStringUTF8(ptr);
                openrelay_free_string(ptr);
                return result;
            }
            catch
            {
                try
                {
                    // Fall back to ANSI
                    string result = Marshal.PtrToStringAnsi(ptr);
                    openrelay_free_string(ptr);
                    return result;
                }
                catch
                {
                    // Last resort - try not to free if it fails
                    return string.Empty;
                }
            }
        }

        // Helper for UTF-8 string conversion
        public static string PtrToStringUTF8(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return string.Empty;

            int len = 0;
            while (Marshal.ReadByte(ptr, len) != 0) len++;
            byte[] buffer = new byte[len];
            Marshal.Copy(ptr, buffer, 0, buffer.Length);
            return Encoding.UTF8.GetString(buffer);
        }
    }
}