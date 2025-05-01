using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class PairingRequestEventArgs : EventArgs
    {
        public string DeviceId { get; }
        public string DeviceName { get; }
        public string IpAddress { get; }
        public int Port { get; }
        public bool Accepted { get; set; }
        public string Platform { get; }
        public string HardwareId { get; }
        public string Challenge { get; }
        public string PublicKey { get; }

        public PairingRequestEventArgs(string deviceId, string deviceName, string ipAddress, int port, string platform = "Windows", string hardwareId = "", string challenge = "", string publicKey = "")
        {
            DeviceId = deviceId;
            DeviceName = deviceName;
            IpAddress = ipAddress;
            Port = port;
            Platform = platform;
            HardwareId = hardwareId;
            Challenge = challenge;
            PublicKey = publicKey;
            Accepted = false;
        }
    }

    public class DeviceEventArgs : EventArgs
    {
        public PairedDevice Device { get; }

        public DeviceEventArgs(PairedDevice device)
        {
            Device = device;
        }
    }

    /// <summary>
    /// Manages paired devices and device discovery
    /// </summary>
    public class DeviceManager : IDisposable
    {
        // Events
        public event EventHandler<PairingRequestEventArgs>? PairingRequestReceived;
        public event EventHandler<DeviceEventArgs>? DeviceAdded;
        public event EventHandler<DeviceEventArgs>? DeviceUpdated;
        public event EventHandler<string>? DeviceRemoved;

        // Cryptographic challenge events
        public event EventHandler<ChallengeEventArgs>? ChallengeReceived;
        public event EventHandler<ChallengeResponseEventArgs>? ChallengeResponseReceived;
        public event EventHandler<AuthVerifyEventArgs>? AuthVerifyReceived;
        public event EventHandler<AuthSuccessEventArgs>? AuthSuccessReceived;

        // Collection of paired devices
        private readonly List<PairedDevice> _pairedDevices = new List<PairedDevice>();

        // Store active authentication sessions
        private readonly Dictionary<string, AuthenticationSession> _authSessions = new Dictionary<string, AuthenticationSession>();

        // Local device information
        public string LocalDeviceId { get; }
        public string LocalDeviceName { get; }
        public string LocalPlatform { get; } = "Windows";
        public string LocalHardwareId { get; }

        // File path for storing paired devices
        private readonly string _storageFilePath;
        private readonly string _secureStorageFilePath;

        private readonly EncryptionService _encryptionService;

        // Key pair for challenge-response authentication
        private readonly RSA _rsaKeyPair;
        private readonly string _publicKeyBase64;

        /// <summary>
        /// Initialize the device manager
        /// </summary>
        public DeviceManager(EncryptionService encryptionService)
        {
            _encryptionService = encryptionService;

            // Generate a unique ID for this device if it doesn't exist
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var appFolder = Path.Combine(appData, "OpenRelay");

            // Create directory if it doesn't exist
            if (!Directory.Exists(appFolder))
            {
                Directory.CreateDirectory(appFolder);
            }

            _storageFilePath = Path.Combine(appFolder, "paired_devices.json");
            _secureStorageFilePath = Path.Combine(appFolder, "secured_device_data.bin");

            // Try to load device ID from file if it exists
            var deviceIdFilePath = Path.Combine(appFolder, "device_id.txt");
            if (File.Exists(deviceIdFilePath))
            {
                var lines = File.ReadAllLines(deviceIdFilePath);
                if (lines.Length >= 2)
                {
                    LocalDeviceId = lines[0];
                    LocalDeviceName = lines[1];
                }
                else
                {
                    LocalDeviceId = Guid.NewGuid().ToString();
                    LocalDeviceName = Environment.MachineName;
                    File.WriteAllLines(deviceIdFilePath, new[] { LocalDeviceId, LocalDeviceName });
                }
            }
            else
            {
                LocalDeviceId = Guid.NewGuid().ToString();
                LocalDeviceName = Environment.MachineName;
                File.WriteAllLines(deviceIdFilePath, new[] { LocalDeviceId, LocalDeviceName });
            }

            // Get hardware ID
            LocalHardwareId = HardwareIdProvider.GetHardwareId();

            // Generate or load RSA key pair for challenge-response authentication
            var keyPairFilePath = Path.Combine(appFolder, "auth_keypair.bin");
            if (File.Exists(keyPairFilePath))
            {
                try
                {
                    byte[] encryptedKeyPair = File.ReadAllBytes(keyPairFilePath);
                    byte[] keyPairBytes = ProtectedData.Unprotect(encryptedKeyPair, null, DataProtectionScope.CurrentUser);
                    _rsaKeyPair = RSA.Create();
                    _rsaKeyPair.ImportRSAPrivateKey(keyPairBytes, out _);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[DEVICE] Error loading key pair: {ex.Message}, generating new one");
                    _rsaKeyPair = RSA.Create(2048);
                    SaveKeyPair(_rsaKeyPair, keyPairFilePath);
                }
            }
            else
            {
                _rsaKeyPair = RSA.Create(2048);
                SaveKeyPair(_rsaKeyPair, keyPairFilePath);
            }

            // Export public key 
            _publicKeyBase64 = Convert.ToBase64String(_rsaKeyPair.ExportRSAPublicKey());

            LoadPairedDevices();
        }

        /// <summary>
        /// Save the RSA key pair to file
        /// </summary>
        private void SaveKeyPair(RSA keyPair, string filePath)
        {
            try
            {
                byte[] keyPairBytes = keyPair.ExportRSAPrivateKey();
                byte[] encryptedKeyPair = ProtectedData.Protect(keyPairBytes, null, DataProtectionScope.CurrentUser);
                File.WriteAllBytes(filePath, encryptedKeyPair);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] Error saving key pair: {ex.Message}");
            }
        }

        /// <summary>
        /// Get the public key for challenge-response authentication
        /// </summary>
        public string GetPublicKey()
        {
            return _publicKeyBase64;
        }

        /// <summary>
        /// Generate a random challenge for authentication
        /// </summary>
        public string GenerateChallenge()
        {
            var challenge = new byte[32]; // 256 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(challenge);
            }
            return Convert.ToBase64String(challenge);
        }

        /// <summary>
        /// Sign a challenge with our private key
        /// </summary>
        public string SignChallenge(string challenge)
        {
            try
            {
                byte[] challengeBytes = Convert.FromBase64String(challenge);
                byte[] signature = _rsaKeyPair.SignData(challengeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signature);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] Error signing challenge: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// Verify a challenge response with a device's public key
        /// </summary>
        public bool VerifyChallengeResponse(string challenge, string response, string publicKey)
        {
            try
            {
                byte[] challengeBytes = Convert.FromBase64String(challenge);
                byte[] responseBytes = Convert.FromBase64String(response);
                byte[] publicKeyBytes = Convert.FromBase64String(publicKey);

                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                return rsa.VerifyData(challengeBytes, responseBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] Error verifying challenge response: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Handle a challenge request from another device
        /// </summary>
        public string HandleChallengeRequest(string deviceId, string challenge, string publicKey, string hardwareId)
        {
            // Store the challenge session
            var session = new AuthenticationSession
            {
                DeviceId = deviceId,
                TheirChallenge = challenge,
                TheirPublicKey = publicKey,
                HardwareId = hardwareId,
                OurChallenge = GenerateChallenge(),
                State = AuthenticationState.ReceivedChallenge
            };

            _authSessions[deviceId] = session;

            // Notify listeners
            ChallengeReceived?.Invoke(this, new ChallengeEventArgs
            {
                DeviceId = deviceId,
                Challenge = challenge,
                PublicKey = publicKey,
                HardwareId = hardwareId
            });

            // Sign their challenge
            string response = SignChallenge(challenge);

            return response;
        }

        /// <summary>
        /// Handle a challenge response from another device
        /// </summary>
        public bool HandleChallengeResponse(string deviceId, string challengeResponse, string theirChallenge, string hardwareId)
        {
            if (!_authSessions.TryGetValue(deviceId, out var session))
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] No authentication session for device {deviceId}");
                return false;
            }

            // Verify their response to our challenge
            if (session.State == AuthenticationState.SentChallenge)
            {
                bool isValid = VerifyChallengeResponse(session.OurChallenge, challengeResponse, session.TheirPublicKey);

                if (isValid)
                {
                    session.State = AuthenticationState.VerifiedTheirResponse;
                    session.TheirChallenge = theirChallenge;

                    // Notify listeners
                    ChallengeResponseReceived?.Invoke(this, new ChallengeResponseEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        NewChallenge = theirChallenge,
                        HardwareId = hardwareId,
                        IsValid = true
                    });

                    return true;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[DEVICE] Invalid challenge response from {deviceId}");
                    _authSessions.Remove(deviceId);

                    // Notify listeners
                    ChallengeResponseReceived?.Invoke(this, new ChallengeResponseEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        NewChallenge = theirChallenge,
                        HardwareId = hardwareId,
                        IsValid = false
                    });

                    return false;
                }
            }
            else if (session.State == AuthenticationState.ReceivedChallenge)
            {
                // We received their challenge first, now we're getting their response to our challenge
                bool isValid = VerifyChallengeResponse(session.TheirChallenge, challengeResponse, session.TheirPublicKey);

                if (isValid)
                {
                    session.State = AuthenticationState.VerifiedTheirResponse;

                    // Notify listeners
                    ChallengeResponseReceived?.Invoke(this, new ChallengeResponseEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        NewChallenge = theirChallenge,
                        HardwareId = hardwareId,
                        IsValid = true
                    });

                    return true;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[DEVICE] Invalid challenge response from {deviceId}");
                    _authSessions.Remove(deviceId);

                    // Notify listeners
                    ChallengeResponseReceived?.Invoke(this, new ChallengeResponseEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        NewChallenge = theirChallenge,
                        HardwareId = hardwareId,
                        IsValid = false
                    });

                    return false;
                }
            }

            return false;
        }

        /// <summary>
        /// Handle authentication verification from another device
        /// </summary>
        public bool HandleAuthVerify(string deviceId, string challengeResponse, string hardwareId)
        {
            if (!_authSessions.TryGetValue(deviceId, out var session))
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] No authentication session for device {deviceId}");
                return false;
            }

            // Verify their response to our challenge
            bool isValid = VerifyChallengeResponse(session.OurChallenge, challengeResponse, session.TheirPublicKey);

            if (isValid)
            {
                session.State = AuthenticationState.FullyVerified;

                // Notify listeners
                AuthVerifyReceived?.Invoke(this, new AuthVerifyEventArgs
                {
                    DeviceId = deviceId,
                    ChallengeResponse = challengeResponse,
                    HardwareId = hardwareId,
                    IsValid = true
                });

                // Mark the device as authenticated if it exists
                var device = GetDeviceById(deviceId);
                if (device != null)
                {
                    device.IsAuthenticated = true;
                    device.HardwareId = hardwareId;
                    device.PublicKey = session.TheirPublicKey;
                    UpdateDevice(device);
                }

                return true;
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[DEVICE] Invalid authentication verification from {deviceId}");
                _authSessions.Remove(deviceId);

                // Notify listeners
                AuthVerifyReceived?.Invoke(this, new AuthVerifyEventArgs
                {
                    DeviceId = deviceId,
                    ChallengeResponse = challengeResponse,
                    HardwareId = hardwareId,
                    IsValid = false
                });

                return false;
            }
        }

        /// <summary>
        /// Handle authentication success from another device
        /// </summary>
        public void HandleAuthSuccess(string deviceId, bool trusted, string hardwareId)
        {
            // Notify listeners
            AuthSuccessReceived?.Invoke(this, new AuthSuccessEventArgs
            {
                DeviceId = deviceId,
                Trusted = trusted,
                HardwareId = hardwareId
            });

            // Clean up the session
            _authSessions.Remove(deviceId);

            // Mark the device as authenticated if it exists and we trust it
            if (trusted)
            {
                var device = GetDeviceById(deviceId);
                if (device != null)
                {
                    device.IsAuthenticated = true;
                    device.HardwareId = hardwareId;
                    UpdateDevice(device);
                }
            }
        }

        /// <summary>
        /// Load paired devices from storage securely
        /// </summary>
        private void LoadPairedDevices()
        {
            try
            {
                // First check for secure storage file
                if (File.Exists(_secureStorageFilePath))
                {
                    try
                    {
                        // Read the encrypted data
                        byte[] encryptedData = File.ReadAllBytes(_secureStorageFilePath);

                        // Create a master device key if we don't have one
                        if (!File.Exists(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin")))
                        {
                            var master_key = _encryptionService.GenerateKey();
                            SecureStoreString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"), master_key);
                        }

                        string masterKey = SecureRetrieveString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"));

                        // Decrypt 
                        byte[] decryptedData = _encryptionService.DecryptData(encryptedData, Convert.FromBase64String(masterKey));
                        string json = System.Text.Encoding.UTF8.GetString(decryptedData);

                        // Deserialize 
                        var devices = JsonSerializer.Deserialize<List<PairedDevice>>(json);
                        if (devices != null)
                        {
                            _pairedDevices.Clear();
                            _pairedDevices.AddRange(devices);

                            System.Diagnostics.Debug.WriteLine($"[DEVICE] Loaded {devices.Count} devices from secure storage");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[DEVICE] Error loading secure storage: {ex.Message}");
                        // Fallback to regular storage
                    }
                }

                // Fallback to regular storage
                if (File.Exists(_storageFilePath))
                {
                    var json = File.ReadAllText(_storageFilePath);
                    var devices = JsonSerializer.Deserialize<List<PairedDevice>>(json);

                    if (devices != null)
                    {
                        _pairedDevices.Clear();
                        _pairedDevices.AddRange(devices);

                        // Migrate to secure storage
                        SavePairedDevices();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading paired devices: {ex.Message}");
            }
        }

        /// <summary>
        /// Save paired devices to secure storage
        /// </summary>
        private void SavePairedDevices()
        {
            try
            {
                var options = new JsonSerializerOptions
                {
                    WriteIndented = true
                };

                var json = JsonSerializer.Serialize(_pairedDevices, options);

                // Create a master device key if we don't have one
                if (!File.Exists(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin")))
                {
                    var master_key = _encryptionService.GenerateKey();
                    SecureStoreString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"), master_key);
                }

                string masterKey = SecureRetrieveString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"));

                // Encrypt
                byte[] jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);
                byte[] encryptedData = _encryptionService.EncryptData(jsonBytes, Convert.FromBase64String(masterKey));

                // Save the encrypted data
                File.WriteAllBytes(_secureStorageFilePath, encryptedData);

                System.Diagnostics.Debug.WriteLine($"[DEVICE] Saved {_pairedDevices.Count} devices to secure storage");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving paired devices securely: {ex.Message}");

                // Fall back to regular storage
                try
                {
                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true
                    };

                    var json = JsonSerializer.Serialize(_pairedDevices, options);
                    File.WriteAllText(_storageFilePath, json);
                }
                catch (Exception fallbackEx)
                {
                    System.Diagnostics.Debug.WriteLine($"Error in fallback device save: {fallbackEx.Message}");
                }
            }
        }

        /// <summary>
        /// Securely store a string using DPAPI or similar
        /// </summary>
        private void SecureStoreString(string path, string data)
        {
            try
            {
                // Use Windows DPAPI
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                byte[] protectedData = System.Security.Cryptography.ProtectedData.Protect(
                    dataBytes,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, protectedData);
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

                // Use Windows DPAPI
                byte[] dataBytes = System.Security.Cryptography.ProtectedData.Unprotect(
                    protectedData,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return System.Text.Encoding.UTF8.GetString(dataBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error securely retrieving data: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Get all paired devices
        /// </summary>
        public IReadOnlyList<PairedDevice> GetPairedDevices()
        {
            return _pairedDevices.AsReadOnly();
        }

        /// <summary>
        /// Get a device by ID
        /// </summary>
        public PairedDevice? GetDeviceById(string deviceId)
        {
            return _pairedDevices.FirstOrDefault(d => d.DeviceId == deviceId);
        }

        /// <summary>
        /// Get a device by hardware ID
        /// </summary>
        public PairedDevice? GetDeviceByHardwareId(string hardwareId)
        {
            return _pairedDevices.FirstOrDefault(d => d.HardwareId == hardwareId);
        }

        /// <summary>
        /// Get a device by IP address
        /// </summary>
        public PairedDevice? GetDeviceByIp(string ipAddress)
        {
            return _pairedDevices.FirstOrDefault(d => d.IpAddress == ipAddress);
        }

        /// <summary>
        /// Check if a device is paired
        /// </summary>
        public bool IsPairedDevice(string deviceId)
        {
            return _pairedDevices.Any(d => d.DeviceId == deviceId);
        }

        /// <summary>
        /// Check if a hardware ID is paired
        /// </summary>
        public bool IsPairedHardwareId(string hardwareId)
        {
            return _pairedDevices.Any(d => d.HardwareId == hardwareId);
        }

        /// <summary>
        /// Add or update a device
        /// </summary>
        public void AddOrUpdateDevice(PairedDevice device)
        {
            var existingDevice = _pairedDevices.FirstOrDefault(d => d.DeviceId == device.DeviceId);

            if (existingDevice != null)
            {
                // Update existing device
                existingDevice.DeviceName = device.DeviceName;
                existingDevice.IpAddress = device.IpAddress;
                existingDevice.Port = device.Port;
                existingDevice.Platform = device.Platform;
                existingDevice.SharedKey = device.SharedKey;
                existingDevice.CurrentKeyId = device.CurrentKeyId;
                existingDevice.LastSeen = DateTime.Now;
                existingDevice.HardwareId = device.HardwareId;
                existingDevice.PublicKey = device.PublicKey;
                existingDevice.IsAuthenticated = device.IsAuthenticated;

                // Notify listeners
                DeviceUpdated?.Invoke(this, new DeviceEventArgs(existingDevice));
            }
            else
            {
                // Add new device
                device.LastSeen = DateTime.Now;
                _pairedDevices.Add(device);

                // Notify listeners
                DeviceAdded?.Invoke(this, new DeviceEventArgs(device));
            }

            // Save changes
            SavePairedDevices();
        }

        /// <summary>
        /// Update a device
        /// </summary>
        public void UpdateDevice(PairedDevice device)
        {
            var existingDevice = _pairedDevices.FirstOrDefault(d => d.DeviceId == device.DeviceId);
            if (existingDevice != null)
            {
                // Find the index of the existing device
                int index = _pairedDevices.IndexOf(existingDevice);

                // Replace with the updated device
                _pairedDevices[index] = device;

                // Notify listeners
                DeviceUpdated?.Invoke(this, new DeviceEventArgs(device));

                // Save changes
                SavePairedDevices();
            }
        }

        /// <summary>
        /// Remove a device
        /// </summary>
        public void RemoveDevice(string deviceId)
        {
            var device = _pairedDevices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device != null)
            {
                _pairedDevices.Remove(device);

                // Notify listeners
                DeviceRemoved?.Invoke(this, deviceId);

                // Save changes
                SavePairedDevices();
            }
        }

        /// <summary>
        /// Update a device's last seen time
        /// </summary>
        public void UpdateDeviceLastSeen(string deviceId)
        {
            var device = _pairedDevices.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device != null)
            {
                device.LastSeen = DateTime.Now;
                SavePairedDevices();
            }
        }

        /// <summary>
        /// Extract platform info from a pairing request
        /// </summary>
        private string ExtractPlatform(JsonElement root)
        {
            // Try to extract platform from the message
            if (root.TryGetProperty("platform", out var platformElement))
            {
                return platformElement.GetString() ?? "Windows";
            }

            // Default to Windows if not specified
            return "Windows";
        }

        /// <summary>
        /// Handle a pairing request
        /// </summary>
        public bool HandlePairingRequest(string deviceId, string deviceName, string ipAddress, int port, string platform = "Windows", string hardwareId = "", string challenge = "", string publicKey = "")
        {
            // Check if already paired by device ID
            if (IsPairedDevice(deviceId))
            {
                UpdateDeviceLastSeen(deviceId);
                return true; // Already paired
            }

            // Check if already paired by hardware ID (prevents re-pairing after reinstall)
            if (!string.IsNullOrEmpty(hardwareId) && IsPairedHardwareId(hardwareId))
            {
                var existingDevice = _pairedDevices.FirstOrDefault(d => d.HardwareId == hardwareId);
                if (existingDevice != null)
                {
                    // Update the existing device with the new device ID
                    existingDevice.DeviceId = deviceId;
                    existingDevice.DeviceName = deviceName;
                    existingDevice.LastSeen = DateTime.Now;
                    UpdateDevice(existingDevice);
                    return true; // Already paired by hardware ID
                }
            }

            // Create event args
            var args = new PairingRequestEventArgs(deviceId, deviceName, ipAddress, port, platform, hardwareId, challenge, publicKey);

            // Notify listeners
            PairingRequestReceived?.Invoke(this, args);

            // If accepted, generate a key and add the device
            if (args.Accepted)
            {
                var device = new PairedDevice
                {
                    DeviceId = deviceId,
                    DeviceName = deviceName,
                    IpAddress = ipAddress,
                    Port = port,
                    Platform = platform,
                    SharedKey = _encryptionService.GenerateKey(),
                    CurrentKeyId = _encryptionService.GetCurrentKeyId(), // Set current key ID
                    LastSeen = DateTime.Now,
                    HardwareId = hardwareId,
                    PublicKey = publicKey,
                    IsAuthenticated = false // Will be set to true after challenge-response
                };

                AddOrUpdateDevice(device);

                // Start challenge-response authentication if we have the necessary info
                if (!string.IsNullOrEmpty(challenge) && !string.IsNullOrEmpty(publicKey))
                {
                    var session = new AuthenticationSession
                    {
                        DeviceId = deviceId,
                        TheirChallenge = challenge,
                        TheirPublicKey = publicKey,
                        HardwareId = hardwareId,
                        OurChallenge = GenerateChallenge(),
                        State = AuthenticationState.ReceivedChallenge
                    };

                    _authSessions[deviceId] = session;
                }
            }

            return args.Accepted;
        }

        /// <summary>
        /// Dispose the device manager
        /// </summary>
        public void Dispose()
        {
            // Clean up resources
            _rsaKeyPair.Dispose();
        }
    }

    /// <summary>
    /// Authentication session state
    /// </summary>
    public enum AuthenticationState
    {
        New,
        SentChallenge,
        ReceivedChallenge,
        VerifiedTheirResponse,
        FullyVerified
    }

    /// <summary>
    /// Authentication session
    /// </summary>
    public class AuthenticationSession
    {
        public string DeviceId { get; set; } = string.Empty;
        public string TheirPublicKey { get; set; } = string.Empty;
        public string TheirChallenge { get; set; } = string.Empty;
        public string OurChallenge { get; set; } = string.Empty;
        public string HardwareId { get; set; } = string.Empty;
        public AuthenticationState State { get; set; } = AuthenticationState.New;
    }

    /// <summary>
    /// Challenge event arguments
    /// </summary>
    public class ChallengeEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public string Challenge { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
        public string HardwareId { get; set; } = string.Empty;
    }

    /// <summary>
    /// Challenge response event arguments
    /// </summary>
    public class ChallengeResponseEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public string ChallengeResponse { get; set; } = string.Empty;
        public string NewChallenge { get; set; } = string.Empty;
        public string HardwareId { get; set; } = string.Empty;
        public bool IsValid { get; set; } = false;
    }

    /// <summary>
    /// Authentication verification event arguments
    /// </summary>
    public class AuthVerifyEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public string ChallengeResponse { get; set; } = string.Empty;
        public string HardwareId { get; set; } = string.Empty;
        public bool IsValid { get; set; } = false;
    }

    /// <summary>
    /// Authentication success event arguments
    /// </summary>
    public class AuthSuccessEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public bool Trusted { get; set; } = false;
        public string HardwareId { get; set; } = string.Empty;
    }
}