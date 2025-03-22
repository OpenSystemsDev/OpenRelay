using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OpenRelay.Services
{
    public class EncryptionService : IDisposable
    {
        // RSA provider for signing and key exchange
        private RSA _rsaProvider;
        
        // AES key size
        private const int AES_KEY_SIZE = 256;
        
        // Device manager to get paired device info
        private DeviceManager _deviceManager;
        
        // Public key for this device
        public string PublicKey { get; private set; }
        
        public EncryptionService(DeviceManager deviceManager)
        {
            _deviceManager = deviceManager;
            _rsaProvider = RSA.Create(2048);
            
            // Export public key
            PublicKey = Convert.ToBase64String(_rsaProvider.ExportSubjectPublicKeyInfo());
        }
        
        public string SignData(string data)
        {
            var dataBytes = Encoding.UTF8.GetBytes(data);
            var signature = _rsaProvider.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
        
        public bool VerifySignature(string data, string signatureBase64, string publicKeyBase64)
        {
            try
            {
                var dataBytes = Encoding.UTF8.GetBytes(data);
                var signature = Convert.FromBase64String(signatureBase64);
                var publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
                
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
                    return rsa.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verifying signature: {ex.Message}");
                return false;
            }
        }
        
        public string EncryptData(string data, string recipientPublicKey)
        {
            try
            {
                // Get device's shared key
                var device = _deviceManager.GetDeviceByPublicKey(recipientPublicKey);
                if (device == null)
                {
                    throw new InvalidOperationException("Device not found");
                }
                
                // Encrypt with AES
                using (var aes = Aes.Create())
                {
                    aes.KeySize = AES_KEY_SIZE;
                    aes.GenerateKey();
                    aes.GenerateIV();
                    
                    // Store the key for this device
                    _deviceManager.StoreEncryptionKey(device.DeviceId, aes.Key);
                    
                    // Encrypt the key with RSA
                    byte[] encryptedKey;
                    using (var recipientRsa = RSA.Create())
                    {
                        recipientRsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(recipientPublicKey), out _);
                        encryptedKey = recipientRsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
                    }
                    
                    // Encrypt the data with AES
                    byte[] encryptedData;
                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(data);
                        }
                        encryptedData = ms.ToArray();
                    }
                    
                    // Create the final message
                    using (var ms = new MemoryStream())
                    {
                        // Write the encrypted key length
                        ms.Write(BitConverter.GetBytes(encryptedKey.Length), 0, 4);
                        
                        // Write the encrypted key
                        ms.Write(encryptedKey, 0, encryptedKey.Length);
                        
                        // Write the IV
                        ms.Write(aes.IV, 0, aes.IV.Length);
                        
                        // Write the encrypted data
                        ms.Write(encryptedData, 0, encryptedData.Length);
                        
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error encrypting data: {ex.Message}");
                throw;
            }
        }
        
        public string EncryptBinaryData(byte[] data, string recipientPublicKey)
        {
            try
            {
                // Get device's shared key
                var device = _deviceManager.GetDeviceByPublicKey(recipientPublicKey);
                if (device == null)
                {
                    throw new InvalidOperationException("Device not found");
                }
                
                // Encrypt with AES
                using (var aes = Aes.Create())
                {
                    aes.KeySize = AES_KEY_SIZE;
                    aes.GenerateKey();
                    aes.GenerateIV();
                    
                    // Store the key for this device
                    _deviceManager.StoreEncryptionKey(device.DeviceId, aes.Key);
                    
                    // Encrypt the key with RSA
                    byte[] encryptedKey;
                    using (var recipientRsa = RSA.Create())
                    {
                        recipientRsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(recipientPublicKey), out _);
                        encryptedKey = recipientRsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
                    }
                    
                    // Encrypt the data with AES
                    byte[] encryptedData;
                    using (var encryptor = aes.CreateEncryptor())
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(data, 0, data.Length);
                        }
                        encryptedData = ms.ToArray();
                    }
                    
                    // Create the final message
                    using (var ms = new MemoryStream())
                    {
                        // Write the encrypted key length
                        ms.Write(BitConverter.GetBytes(encryptedKey.Length), 0, 4);
                        
                        // Write the encrypted key
                        ms.Write(encryptedKey, 0, encryptedKey.Length);
                        
                        // Write the IV
                        ms.Write(aes.IV, 0, aes.IV.Length);
                        
                        // Write the encrypted data
                        ms.Write(encryptedData, 0, encryptedData.Length);
                        
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error encrypting binary data: {ex.Message}");
                throw;
            }
        }
        
        public string DecryptData(string encryptedDataBase64)
        {
            try
            {
                var encryptedFullData = Convert.FromBase64String(encryptedDataBase64);
                
                using (var ms = new MemoryStream(encryptedFullData))
                {
                    // Read the encrypted key length
                    var keyLengthBytes = new byte[4];
                    ms.Read(keyLengthBytes, 0, 4);
                    var keyLength = BitConverter.ToInt32(keyLengthBytes, 0);
                    
                    // Read the encrypted key
                    var encryptedKey = new byte[keyLength];
                    ms.Read(encryptedKey, 0, keyLength);
                    
                    // Decrypt the key with our private key
                    var key = _rsaProvider.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
                    
                    // Read the IV
                    var iv = new byte[16]; // AES block size
                    ms.Read(iv, 0, iv.Length);
                    
                    // Read the encrypted data
                    var encryptedData = new byte[encryptedFullData.Length - 4 - keyLength - iv.Length];
                    ms.Read(encryptedData, 0, encryptedData.Length);
                    
                    // Decrypt the data
                    using (var aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;
                        
                        using (var decryptor = aes.CreateDecryptor())
                        using (var decryptedMs = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(decryptedMs, decryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedData, 0, encryptedData.Length);
                            }
                            
                            return Encoding.UTF8.GetString(decryptedMs.ToArray());
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decrypting data: {ex.Message}");
                throw;
            }
        }
        
        public byte[] DecryptBinaryData(string encryptedDataBase64)
        {
            try
            {
                var encryptedFullData = Convert.FromBase64String(encryptedDataBase64);
                
                using (var ms = new MemoryStream(encryptedFullData))
                {
                    // Read the encrypted key length
                    var keyLengthBytes = new byte[4];
                    ms.Read(keyLengthBytes, 0, 4);
                    var keyLength = BitConverter.ToInt32(keyLengthBytes, 0);
                    
                    // Read the encrypted key
                    var encryptedKey = new byte[keyLength];
                    ms.Read(encryptedKey, 0, keyLength);
                    
                    // Decrypt the key with our private key
                    var key = _rsaProvider.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
                    
                    // Read the IV
                    var iv = new byte[16]; // AES block size
                    ms.Read(iv, 0, iv.Length);
                    
                    // Read the encrypted data
                    var encryptedData = new byte[encryptedFullData.Length - 4 - keyLength - iv.Length];
                    ms.Read(encryptedData, 0, encryptedData.Length);
                    
                    // Decrypt the data
                    using (var aes = Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;
                        
                        using (var decryptor = aes.CreateDecryptor())
                        using (var decryptedMs = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(decryptedMs, decryptor, CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedData, 0, encryptedData.Length);
                            }
                            
                            return decryptedMs.ToArray();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decrypting binary data: {ex.Message}");
                throw;
            }
        }
        
        public void Dispose()
        {
            _rsaProvider.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}