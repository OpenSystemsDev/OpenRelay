using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;

namespace OpenRelay.Services
{
    /// <summary>
    /// Provides encryption and decryption services using the Rust encryption library
    /// </summary>
    public class EncryptionService : IDisposable
    {
        private bool _initialized;
        private bool _disposed;

        private uint _currentKeyId = 1;  // Start with key ID 1
        private DateTime _lastKeyRotation;
        private readonly TimeSpan _keyRotationInterval = TimeSpan.FromSeconds( 7 * 24 * 60 * 60); // 7 days

     
        private readonly Dictionary<uint, string> _encryptionKeys = new Dictionary<uint, string>();

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
            _lastKeyRotation = DateTime.Now;

            // Generate the initial key
            string initialKey = GenerateRawKey();
            _encryptionKeys[_currentKeyId] = initialKey;

            // Try to load key rotation info
            LoadKeyRotationInfo();
        }

        /// <summary>
        /// Load key rotation information from storage
        /// </summary>
        private void LoadKeyRotationInfo()
        {
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var appFolder = Path.Combine(appData, "OpenRelay");
                var keyInfoPath = Path.Combine(appFolder, "key_rotation.dat");
                var keysStorePath = Path.Combine(appFolder, "encryption_keys.dat");

                if (File.Exists(keyInfoPath))
                {
                    // Read key info
                    string[] lines = File.ReadAllLines(keyInfoPath);
                    if (lines.Length >= 2)
                    {
                        if (uint.TryParse(lines[0], out uint keyId))
                        {
                            _currentKeyId = keyId;
                        }

                        if (DateTime.TryParse(lines[1], out DateTime lastRotation))
                        {
                            _lastKeyRotation = lastRotation;
                        }
                    }
                }

                // Load encryption keys
                if (File.Exists(keysStorePath))
                {
                    try
                    {
                        // Create a temporary master key for encrypting the keys
                        string masterKeyPath = Path.Combine(appFolder, "master_key.bin");
                        string masterKey;

                        if (File.Exists(masterKeyPath))
                        {
                            masterKey = SecureRetrieveString(masterKeyPath);
                        }
                        else
                        {
                            masterKey = GenerateRawKey();
                            SecureStoreString(masterKeyPath, masterKey);
                        }

                        // Decrypt the keys
                        byte[] encryptedKeys = File.ReadAllBytes(keysStorePath);
                        byte[] decryptedKeys = DecryptData(encryptedKeys, Convert.FromBase64String(masterKey));
                        string keysJson = Encoding.UTF8.GetString(decryptedKeys);

                        var keyPairs = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(keysJson);
                        if (keyPairs != null)
                        {
                            _encryptionKeys.Clear();
                            foreach (var pair in keyPairs)
                            {
                                if (uint.TryParse(pair.Key, out uint keyId))
                                {
                                    _encryptionKeys[keyId] = pair.Value;
                                }
                            }

                            System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Loaded {_encryptionKeys.Count} encryption keys");
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Error loading encryption keys: {ex.Message}");
                    }
                }

                // Ensure we have a key for the current key ID
                if (!_encryptionKeys.ContainsKey(_currentKeyId))
                {
                    string newKey = GenerateRawKey();
                    _encryptionKeys[_currentKeyId] = newKey;
                    SaveEncryptionKeys();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading key rotation info: {ex.Message}");
                // Use defaults if loading fails
            }
        }

        /// <summary>
        /// Save encryption keys securely
        /// </summary>
        private void SaveEncryptionKeys()
        {
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var appFolder = Path.Combine(appData, "OpenRelay");
                var keysStorePath = Path.Combine(appFolder, "encryption_keys.dat");
                var masterKeyPath = Path.Combine(appFolder, "master_key.bin");

                if (!Directory.Exists(appFolder))
                {
                    Directory.CreateDirectory(appFolder);
                }

                // Get or create master key
                string masterKey;
                if (File.Exists(masterKeyPath))
                {
                    masterKey = SecureRetrieveString(masterKeyPath);
                }
                else
                {
                    masterKey = GenerateRawKey();
                    SecureStoreString(masterKeyPath, masterKey);
                }

                // Convert keys dictionary to string-string for serialization
                var keyPairs = new Dictionary<string, string>();
                foreach (var pair in _encryptionKeys)
                {
                    keyPairs[pair.Key.ToString()] = pair.Value;
                }

                // Serialize
                string keysJson = System.Text.Json.JsonSerializer.Serialize(keyPairs);

                // Encrypt
                byte[] jsonBytes = Encoding.UTF8.GetBytes(keysJson);
                byte[] encryptedData = EncryptData(jsonBytes, Convert.FromBase64String(masterKey));

                // Save the encrypted data
                File.WriteAllBytes(keysStorePath, encryptedData);

                System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Saved {_encryptionKeys.Count} encryption keys");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Error saving encryption keys: {ex.Message}");
            }
        }

        /// <summary>
        /// Save key rotation information to storage
        /// </summary>
        private void SaveKeyRotationInfo()
        {
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var appFolder = Path.Combine(appData, "OpenRelay");

                if (!Directory.Exists(appFolder))
                {
                    Directory.CreateDirectory(appFolder);
                }

                var keyInfoPath = Path.Combine(appFolder, "key_rotation.dat");

                // Write key info
                File.WriteAllLines(keyInfoPath, new[]
                {
                    _currentKeyId.ToString(),
                    _lastKeyRotation.ToString("o")
                });

                // Also save encryption keys
                SaveEncryptionKeys();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving key rotation info: {ex.Message}");
            }
        }

        /// <summary>
        /// Securely store a string using DPAPI or similar
        /// </summary>
        private void SecureStoreString(string path, string data)
        {
            try
            {
#if WINDOWS
                // Use Windows DPAPI
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                byte[] protectedData = System.Security.Cryptography.ProtectedData.Protect(
                    dataBytes,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, protectedData);
#else
                // For non-Windows platforms, encrypt using our own service
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                
                // Create a device-specific key based on machine ID and user
                string deviceSpecificInfo = Environment.MachineName + Environment.UserName;
                byte[] deviceKeyBytes = System.Security.Cryptography.SHA256.Create()
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceSpecificInfo));
                
                // Encrypt with this key
                byte[] encryptedData = EncryptData(dataBytes, deviceKeyBytes);
                File.WriteAllBytes(path, encryptedData);
#endif
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error securely storing data: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Securely retrieve a string using DPAPI or similar
        /// </summary>
        private string SecureRetrieveString(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    throw new FileNotFoundException("Secure data file not found", path);
                }

                byte[] protectedData = File.ReadAllBytes(path);

#if WINDOWS
                // Use Windows DPAPI
                byte[] dataBytes = System.Security.Cryptography.ProtectedData.Unprotect(
                    protectedData,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return System.Text.Encoding.UTF8.GetString(dataBytes);
#else
                // For non-Windows platforms, decrypt using our own service
                string deviceSpecificInfo = Environment.MachineName + Environment.UserName;
                byte[] deviceKeyBytes = System.Security.Cryptography.SHA256.Create()
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceSpecificInfo));
                
                // Decrypt with this key
                byte[] decryptedData = DecryptData(protectedData, deviceKeyBytes);
                return System.Text.Encoding.UTF8.GetString(decryptedData);
#endif
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error securely retrieving data: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Generate a raw encryption key
        /// </summary>
        private string GenerateRawKey()
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
        /// Generate a new encryption key
        /// </summary>
        /// <returns>The generated key as a Base64 string</returns>
        public string GenerateKey()
        {
            return GenerateRawKey();
        }

        /// <summary>
        /// Get the current encryption key
        /// </summary>
        private string GetCurrentKey()
        {
            if (_encryptionKeys.TryGetValue(_currentKeyId, out string key))
            {
                return key;
            }

            // If key not found, generate a new one
            string newKey = GenerateRawKey();
            _encryptionKeys[_currentKeyId] = newKey;
            SaveEncryptionKeys();

            return newKey;
        }

        /// <summary>
        /// Get a specific encryption key by ID
        /// </summary>
        private string GetKeyById(uint keyId)
        {
            if (_encryptionKeys.TryGetValue(keyId, out string key))
            {
                return key;
            }

            throw new KeyNotFoundException($"Encryption key with ID {keyId} not found");
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

            // Convert to Base64 for easy management
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
        /// Get the current key ID
        /// </summary>
        public uint GetCurrentKeyId()
        {
            return _currentKeyId;
        }

        /// <summary>
        /// Check if the current key should be rotated
        /// </summary>
        public bool ShouldRotateKey()
        {
            // Check if it's been more than the rotation interval since the last rotation
            return DateTime.Now - _lastKeyRotation > _keyRotationInterval;
        }

        /// <summary>
        /// Create a new rotation key
        /// </summary>
        public uint CreateRotationKey()
        {
            // Increment the key ID
            _currentKeyId++;

            // And generate a new key
            string newKey = GenerateRawKey();
            _encryptionKeys[_currentKeyId] = newKey;
            _lastKeyRotation = DateTime.Now;
            SaveKeyRotationInfo();

            System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Created new rotation key with ID {_currentKeyId}");
            return _currentKeyId;
        }

        /// <summary>
        /// Get a key update package
        /// </summary>
        public byte[] GetKeyUpdatePackage(uint lastKnownId)
        {
            // Create a package with key information for all keys since lastKnownId
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                // Write the current key ID
                writer.Write(_currentKeyId);

                // Write the last rotation timestamp
                writer.Write((long)(_lastKeyRotation - DateTime.UnixEpoch).TotalSeconds);

                // Count keys to include
                int keysToInclude = 0;
                foreach (var keyId in _encryptionKeys.Keys)
                {
                    if (keyId > lastKnownId)
                    {
                        keysToInclude++;
                    }
                }

                // Write the number of keys
                writer.Write(keysToInclude);

                // Write each key that is newer than lastKnownId
                foreach (var key in _encryptionKeys)
                {
                    if (key.Key > lastKnownId)
                    {
                        writer.Write(key.Key);
                        byte[] keyBytes = Convert.FromBase64String(key.Value);
                        writer.Write(keyBytes.Length);
                        writer.Write(keyBytes);
                    }
                }

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Import a key update package
        /// </summary>
        public uint ImportKeyUpdatePackage(byte[] package)
        {
            if (package == null || package.Length < 16)
            {
                return 0;
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(package))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    // Read the current key ID
                    _currentKeyId = reader.ReadUInt32();

                    // Read the last rotation timestamp
                    long timestamp = reader.ReadInt64();
                    _lastKeyRotation = DateTime.UnixEpoch.AddSeconds(timestamp);

                    // Read the number of keys
                    int keyCount = reader.ReadInt32();

                    // Read each key
                    for (int i = 0; i < keyCount; i++)
                    {
                        uint keyId = reader.ReadUInt32();
                        int keyLength = reader.ReadInt32();
                        byte[] keyBytes = reader.ReadBytes(keyLength);

                        // Store the key
                        _encryptionKeys[keyId] = Convert.ToBase64String(keyBytes);
                    }

                    // Save the key rotation info
                    SaveKeyRotationInfo();

                    System.Diagnostics.Debug.WriteLine($"[ENCRYPTION] Imported {keyCount} keys, current key ID is now {_currentKeyId}");
                    return _currentKeyId;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error importing key update package: {ex.Message}");
                return 0;
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