using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace OpenRelay.Services
{
    public class EncryptionService : IDisposable
    {
        // AES key size must be 128, 192, or 256 bits
        private const int KEY_SIZE_BYTES = 32; // 256 bits = 32 bytes
        
        /// <summary>
        /// Generates a new shared key for device pairing
        /// </summary>
        public string GenerateSharedKey()
        {
            try
            {
                // Generate random bytes for the key (fixed size)
                byte[] key = new byte[KEY_SIZE_BYTES];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }
                
                // Return the key as a Base64 string
                Console.WriteLine($"Generated key of length {key.Length} bytes");
                return Convert.ToBase64String(key);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error generating shared key: {ex.Message}");
                throw;
            }
        }
        
        public string EncryptString(string plainText, string base64Key)
        {
            // Convert key from Base64
            byte[] key = Convert.FromBase64String(base64Key);
            Console.WriteLine($"[ENCRYPT] Key length: {key.Length} bytes");
            
            if (string.IsNullOrEmpty(plainText))
            {
                Console.WriteLine("[ENCRYPT] WARNING: Empty text to encrypt");
                return string.Empty;
            }
            
            // Create and configure AES algorithm
            using (Aes aes = Aes.Create())
            {
                // Ensure key size is valid (16, 24, or 32 bytes)
                if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                {
                    throw new ArgumentException($"Key must be 16, 24, or 32 bytes, but was {key.Length} bytes");
                }
                
                aes.Key = key;
                aes.GenerateIV(); // Generate random IV
                Console.WriteLine($"[ENCRYPT] Generated IV length: {aes.IV.Length} bytes");
                
                using (MemoryStream ms = new MemoryStream())
                {
                    // First write the length of the IV
                    byte[] ivLengthBytes = BitConverter.GetBytes(aes.IV.Length);
                    ms.Write(ivLengthBytes, 0, ivLengthBytes.Length);
                    Console.WriteLine($"[ENCRYPT] Wrote IV length bytes: {ivLengthBytes.Length} bytes");
                    
                    // Then write the IV
                    ms.Write(aes.IV, 0, aes.IV.Length);
                    Console.WriteLine($"[ENCRYPT] Wrote IV: {aes.IV.Length} bytes");
                    
                    using (CryptoStream cs = new CryptoStream(
                        ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        // Convert the plaintext to bytes
                        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                        Console.WriteLine($"[ENCRYPT] Plaintext length: {plaintextBytes.Length} bytes");
                        
                        // Write the plaintext to the CryptoStream
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cs.FlushFinalBlock(); // Important to flush
                    }
                    
                    byte[] encryptedData = ms.ToArray();
                    Console.WriteLine($"[ENCRYPT] Final encrypted data length: {encryptedData.Length} bytes");
                    
                    // Return as Base64
                    return Convert.ToBase64String(encryptedData);
                }
            }
        }
        
        public string DecryptString(string base64Ciphertext, string base64Key)
        {
            if (string.IsNullOrEmpty(base64Ciphertext))
            {
                Console.WriteLine("[DECRYPT] WARNING: Empty ciphertext to decrypt");
                return string.Empty;
            }
            
            // Convert key from Base64
            byte[] key = Convert.FromBase64String(base64Key);
            Console.WriteLine($"[DECRYPT] Key length: {key.Length} bytes");
            
            // Convert ciphertext from Base64
            byte[] ciphertext = Convert.FromBase64String(base64Ciphertext);
            Console.WriteLine($"[DECRYPT] Ciphertext length: {ciphertext.Length} bytes");
            
            // Ensure we have enough data
            if (ciphertext.Length <= 4)
            {
                throw new ArgumentException("Ciphertext is too short to contain IV length");
            }
            
            using (MemoryStream ms = new MemoryStream(ciphertext))
            {
                // First read the length of the IV
                byte[] ivLengthBytes = new byte[4]; // Int32 size
                ms.Read(ivLengthBytes, 0, ivLengthBytes.Length);
                int ivLength = BitConverter.ToInt32(ivLengthBytes, 0);
                Console.WriteLine($"[DECRYPT] Read IV length: {ivLength} bytes");
                
                // Validate IV length
                if (ivLength <= 0 || ivLength > 16 || ivLength + 4 > ciphertext.Length)
                {
                    throw new ArgumentException($"Invalid IV length: {ivLength}");
                }
                
                // Read the IV
                byte[] iv = new byte[ivLength];
                ms.Read(iv, 0, ivLength);
                Console.WriteLine($"[DECRYPT] Read IV of length: {iv.Length} bytes");
                
                // Create and configure AES algorithm
                using (Aes aes = Aes.Create())
                {
                    // Ensure key size is valid (16, 24, or 32 bytes)
                    if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                    {
                        throw new ArgumentException($"Key must be 16, 24, or 32 bytes, but was {key.Length} bytes");
                    }
                    
                    aes.Key = key;
                    aes.IV = iv;
                    
                    // The remaining bytes in the memory stream are the encrypted data
                    int encryptedDataLength = (int)ms.Length - 4 - ivLength;
                    Console.WriteLine($"[DECRYPT] Encrypted data length: {encryptedDataLength} bytes");
                    
                    // Create a crypto stream to decrypt the data
                    using (CryptoStream cs = new CryptoStream(
                        ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        // Read the decrypted data
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
        
        /// <summary>
        /// Encrypts data using a shared key
        /// </summary>
        public string EncryptData(string data, string sharedKeyBase64)
        {
            try
            {
                return EncryptString(data, sharedKeyBase64);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error encrypting data: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Encrypts binary data using a shared key
        /// </summary>
        public string EncryptBinaryData(byte[] data, string sharedKeyBase64)
        {
            try
            {
                // Convert binary data to Base64 string and encrypt that
                // (slightly inefficient but ensures consistent handling)
                string base64Data = Convert.ToBase64String(data);
                return EncryptString(base64Data, sharedKeyBase64);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error encrypting binary data: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Decrypts data using a shared key
        /// </summary>
        public string DecryptData(string encryptedDataBase64, string sharedKeyBase64)
        {
            try
            {
                return DecryptString(encryptedDataBase64, sharedKeyBase64);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decrypting data: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Decrypts binary data using a shared key
        /// </summary>
        public byte[] DecryptBinaryData(string encryptedDataBase64, string sharedKeyBase64)
        {
            try
            {
                // Decrypt to Base64 string, then convert back to binary
                string base64Data = DecryptString(encryptedDataBase64, sharedKeyBase64);
                return Convert.FromBase64String(base64Data);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decrypting binary data: {ex.Message}");
                throw;
            }
        }
        
        public void Dispose()
        {
            // Nothing to dispose
            GC.SuppressFinalize(this);
        }
    }
}