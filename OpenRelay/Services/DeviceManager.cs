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
        /// Load paired devices from storage
        /// </summary>
        private void LoadPairedDevices()
        {
            try
            {
                if (File.Exists(_storageFilePath))
                {
                    var json = File.ReadAllText(_storageFilePath);
                    var devices = JsonSerializer.Deserialize<List<PairedDevice>>(json);

                    if (devices != null)
                    {
                        _pairedDevices.Clear();
                        _pairedDevices.AddRange(devices);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading paired devices: {ex.Message}");
            }
        }

        /// <summary>
        /// Save paired devices to storage
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
                File.WriteAllText(_storageFilePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving paired devices: {ex.Message}");
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