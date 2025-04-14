using System;
using System.Runtime.InteropServices;

namespace OpenRelay.Services
{
    /// <summary>
    /// Provides P/Invoke declarations for the Rust encryption library
    /// </summary>
    internal static class NativeMethods
    {
        private const string DllName = "openrelay_core";

        /// <summary>
        /// Initialize the encryption service
        /// </summary>
        /// <returns>0 on success, non-zero on error</returns>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int encryption_init();

        /// <summary>
        /// Generate a new encryption key
        /// </summary>
        /// <param name="keySize">On return, contains the size of the key in bytes</param>
        /// <returns>Pointer to the key buffer, or IntPtr.Zero on error</returns>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr encryption_generate_key(ref UIntPtr keySize);

        /// <summary>
        /// Encrypt data with the given key
        /// </summary>
        /// <param name="data">Pointer to the data to encrypt</param>
        /// <param name="dataSize">Size of the data in bytes</param>
        /// <param name="key">Pointer to the key</param>
        /// <param name="keySize">Size of the key in bytes</param>
        /// <param name="encryptedSize">On return, contains the size of the encrypted data in bytes</param>
        /// <returns>Pointer to the encrypted data buffer, or IntPtr.Zero on error</returns>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr encryption_encrypt(
            IntPtr data,
            UIntPtr dataSize,
            IntPtr key,
            UIntPtr keySize,
            ref UIntPtr encryptedSize);

        /// <summary>
        /// Decrypt data with the given key
        /// </summary>
        /// <param name="encryptedData">Pointer to the encrypted data</param>
        /// <param name="encryptedSize">Size of the encrypted data in bytes</param>
        /// <param name="key">Pointer to the key</param>
        /// <param name="keySize">Size of the key in bytes</param>
        /// <param name="decryptedSize">On return, contains the size of the decrypted data in bytes</param>
        /// <returns>Pointer to the decrypted data buffer, or IntPtr.Zero on error</returns>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr encryption_decrypt(
            IntPtr encryptedData,
            UIntPtr encryptedSize,
            IntPtr key,
            UIntPtr keySize,
            ref UIntPtr decryptedSize);

        /// <summary>
        /// Free a buffer allocated by the encryption functions
        /// </summary>
        /// <param name="buffer">Pointer to the buffer</param>
        /// <param name="bufferSize">Size of the buffer in bytes</param>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void encryption_free_buffer(
            IntPtr buffer,
            UIntPtr bufferSize);

        /// <summary>
        /// Cleanup and free all resources
        /// </summary>
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void encryption_cleanup();
    }
}