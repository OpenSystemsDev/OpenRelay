using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
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

        public PairingRequestEventArgs(string deviceId, string deviceName, string ipAddress, int port)
        {
            DeviceId = deviceId;
            DeviceName = deviceName;
            IpAddress = ipAddress;
            Port = port;
            Accepted = false; // Default to not accepted
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

        // Collection of paired devices
        private readonly List<PairedDevice> _pairedDevices = new List<PairedDevice>();

        // Local device information
        public string LocalDeviceId { get; }
        public string LocalDeviceName { get; }

        // File path for storing paired devices
        private readonly string _storageFilePath;
        private readonly string _secureStorageFilePath;

        // Encryption service for generating keys
        private readonly EncryptionService _encryptionService;

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

            // Load paired devices
            LoadPairedDevices();
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

                        // Get the master key
                        string masterKey = SecureRetrieveString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"));

                        // Decrypt the data
                        byte[] decryptedData = _encryptionService.DecryptData(encryptedData, Convert.FromBase64String(masterKey));
                        string json = System.Text.Encoding.UTF8.GetString(decryptedData);

                        // Deserialize the devices
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
                        // Fall back to regular storage
                    }
                }

                // Fall back to regular storage
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

                // Get the master key
                string masterKey = SecureRetrieveString(Path.Combine(Path.GetDirectoryName(_secureStorageFilePath), "master_key.bin"));

                // Encrypt the data
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
                // with a key derived from a system-specific value
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                
                // Create a device-specific key based on machine ID and user
                string deviceSpecificInfo = Environment.MachineName + Environment.UserName;
                byte[] deviceKeyBytes = System.Security.Cryptography.SHA256.Create()
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceSpecificInfo));
                
                // Encrypt with this key
                byte[] encryptedData = _encryptionService.EncryptData(dataBytes, deviceKeyBytes);
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
                // with a key derived from a system-specific value
                string deviceSpecificInfo = Environment.MachineName + Environment.UserName;
                byte[] deviceKeyBytes = System.Security.Cryptography.SHA256.Create()
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceSpecificInfo));
                
                // Decrypt with this key
                byte[] decryptedData = _encryptionService.DecryptData(protectedData, deviceKeyBytes);
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
        /// Handle a pairing request
        /// </summary>
        public bool HandlePairingRequest(string deviceId, string deviceName, string ipAddress, int port)
        {
            // Check if already paired
            if (IsPairedDevice(deviceId))
            {
                UpdateDeviceLastSeen(deviceId);
                return true; // Already paired, accept automatically
            }

            // Create event args
            var args = new PairingRequestEventArgs(deviceId, deviceName, ipAddress, port);

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
                    Platform = "Unknown", // Could be determined later
                    SharedKey = _encryptionService.GenerateKey(),
                    CurrentKeyId = _encryptionService.GetCurrentKeyId(), // Set current key ID
                    LastSeen = DateTime.Now
                };

                AddOrUpdateDevice(device);
            }

            return args.Accepted;
        }

        /// <summary>
        /// Dispose the device manager
        /// </summary>
        public void Dispose()
        {
            // No special cleanup needed
        }
    }
}