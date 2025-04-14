using System;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenRelay.Services
{
    /// <summary>
    /// Provides encryption and decryption services using the Rust encryption library
    /// </summary>
    public class EncryptionService : IDisposable
    {
        private bool _initialized;
        private bool _disposed;

        /// <summary>
        /// Initialize the encryption service
        /// </summary>
        public EncryptionService()
        {
            int result = NativeMethods.encryption_init();
            if (result != 0)
            {
                throw new InvalidOperationException($"Failed to initialize encryption service. Error code: {result}");
            }
            _initialized = true;
        }

        /// <summary>
        /// Generate a new encryption key
        /// </summary>
        /// <returns>The generated key as a Base64 string</returns>
        public string GenerateKey()
        {
            if (!_initialized || _disposed)
            {
                throw new InvalidOperationException("Encryption service is not initialized or has been disposed");
            }

            UIntPtr keySize = UIntPtr.Zero;
            IntPtr keyPtr = NativeMethods.encryption_generate_key(ref keySize);

            if (keyPtr == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to generate encryption key");
            }

            try
            {
                // Copy the key to a managed array
                byte[] key = new byte[keySize.ToUInt64()];
                Marshal.Copy(keyPtr, key, 0, key.Length);

                // Convert to Base64 for easy storage
                return Convert.ToBase64String(key);
            }
            finally
            {
                // Free the unmanaged key buffer
                NativeMethods.encryption_free_buffer(keyPtr, keySize);
            }
        }

        /// <summary>
        /// Encrypt text data with the given key
        /// </summary>
        /// <param name="plainText">The text to encrypt</param>
        /// <param name="keyBase64">The encryption key as a Base64 string</param>
        /// <returns>The encrypted data as a Base64 string</returns>
        public string EncryptText(string plainText, string keyBase64)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return string.Empty;
            }

            if (!_initialized || _disposed)
            {
                throw new InvalidOperationException("Encryption service is not initialized or has been disposed");
            }

            // Convert text to bytes
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Encrypt the data
            byte[] encryptedBytes = EncryptData(plainBytes, Convert.FromBase64String(keyBase64));

            // Convert to Base64 for easy storage/transmission
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Decrypt text data with the given key
        /// </summary>
        /// <param name="encryptedBase64">The encrypted data as a Base64 string</param>
        /// <param name="keyBase64">The encryption key as a Base64 string</param>
        /// <returns>The decrypted text</returns>
        public string DecryptText(string encryptedBase64, string keyBase64)
        {
            if (string.IsNullOrEmpty(encryptedBase64))
            {
                return string.Empty;
            }

            if (!_initialized || _disposed)
            {
                throw new InvalidOperationException("Encryption service is not initialized or has been disposed");
            }

            // Convert from Base64
            byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);

            // Decrypt the data
            byte[] decryptedBytes = DecryptData(encryptedBytes, Convert.FromBase64String(keyBase64));

            // Convert bytes to text
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// Encrypt binary data with the given key
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The encrypted data</returns>
        public byte[] EncryptData(byte[] data, byte[] key)
        {
            if (data == null || data.Length == 0)
            {
                return Array.Empty<byte>();
            }

            if (!_initialized || _disposed)
            {
                throw new InvalidOperationException("Encryption service is not initialized or has been disposed");
            }

            // Allocate unmanaged memory for the data
            IntPtr dataPtr = Marshal.AllocHGlobal(data.Length);
            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);

            try
            {
                // Copy data to unmanaged memory
                Marshal.Copy(data, 0, dataPtr, data.Length);
                Marshal.Copy(key, 0, keyPtr, key.Length);

                // Encrypt the data
                UIntPtr encryptedSize = UIntPtr.Zero;
                IntPtr encryptedPtr = NativeMethods.encryption_encrypt(
                    dataPtr,
                    (UIntPtr)data.Length,
                    keyPtr,
                    (UIntPtr)key.Length,
                    ref encryptedSize);

                if (encryptedPtr == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Encryption failed");
                }

                try
                {
                    // Copy the encrypted data to a managed array
                    byte[] encryptedData = new byte[encryptedSize.ToUInt64()];
                    Marshal.Copy(encryptedPtr, encryptedData, 0, encryptedData.Length);

                    return encryptedData;
                }
                finally
                {
                    // Free the unmanaged encrypted data buffer
                    NativeMethods.encryption_free_buffer(encryptedPtr, encryptedSize);
                }
            }
            finally
            {
                // Free the unmanaged data and key buffers
                Marshal.FreeHGlobal(dataPtr);
                Marshal.FreeHGlobal(keyPtr);
            }
        }

        /// <summary>
        /// Decrypt binary data with the given key
        /// </summary>
        /// <param name="encryptedData">The encrypted data</param>
        /// <param name="key">The encryption key</param>
        /// <returns>The decrypted data</returns>
        public byte[] DecryptData(byte[] encryptedData, byte[] key)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return Array.Empty<byte>();
            }

            if (!_initialized || _disposed)
            {
                throw new InvalidOperationException("Encryption service is not initialized or has been disposed");
            }

            // Allocate unmanaged memory for the data
            IntPtr encryptedPtr = Marshal.AllocHGlobal(encryptedData.Length);
            IntPtr keyPtr = Marshal.AllocHGlobal(key.Length);

            try
            {
                // Copy data to unmanaged memory
                Marshal.Copy(encryptedData, 0, encryptedPtr, encryptedData.Length);
                Marshal.Copy(key, 0, keyPtr, key.Length);

                // Decrypt the data
                UIntPtr decryptedSize = UIntPtr.Zero;
                IntPtr decryptedPtr = NativeMethods.encryption_decrypt(
                    encryptedPtr,
                    (UIntPtr)encryptedData.Length,
                    keyPtr,
                    (UIntPtr)key.Length,
                    ref decryptedSize);

                if (decryptedPtr == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Decryption failed");
                }

                try
                {
                    // Copy the decrypted data to a managed array
                    byte[] decryptedData = new byte[decryptedSize.ToUInt64()];
                    Marshal.Copy(decryptedPtr, decryptedData, 0, decryptedData.Length);

                    return decryptedData;
                }
                finally
                {
                    // Free the unmanaged decrypted data buffer
                    NativeMethods.encryption_free_buffer(decryptedPtr, decryptedSize);
                }
            }
            finally
            {
                // Free the unmanaged encrypted data and key buffers
                Marshal.FreeHGlobal(encryptedPtr);
                Marshal.FreeHGlobal(keyPtr);
            }
        }

        /// <summary>
        /// Dispose of the encryption service
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                if (_initialized)
                {
                    NativeMethods.encryption_cleanup();
                    _initialized = false;
                }

                _disposed = true;
            }
        }
    }
}