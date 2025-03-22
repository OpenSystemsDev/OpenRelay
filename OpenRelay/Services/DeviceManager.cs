using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    /// <summary>
    /// Manages paired devices and device discovery
    /// </summary>
    public class DeviceManager
    {
        // Event for when a new pairing request arrives
        public event EventHandler<PairingRequestEventArgs> PairingRequestReceived;
        
        // List of paired devices
        private List<PairedDevice> _pairedDevices = new List<PairedDevice>();
        
        // Local device information
        public string LocalDeviceId { get; private set; }
        public string LocalDeviceName { get; private set; }
        
        // File path for storing paired devices
        private string _storageFilePath;
        
        public DeviceManager()
        {
            // Generate a unique ID for this device
            LocalDeviceId = Guid.NewGuid().ToString();
            LocalDeviceName = Environment.MachineName;
            
            // Set up storage path
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
                try
                {
                    var lines = File.ReadAllLines(deviceIdFilePath);
                    if (lines.Length >= 2)
                    {
                        LocalDeviceId = lines[0];
                        LocalDeviceName = lines[1];
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error loading device ID: {ex.Message}");
                }
            }
            else
            {
                // Save the new device ID
                try
                {
                    File.WriteAllLines(deviceIdFilePath, new[] { LocalDeviceId, LocalDeviceName });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error saving device ID: {ex.Message}");
                }
            }
            
            // Load paired devices
            LoadPairedDevices();
        }
        
        private void LoadPairedDevices()
        {
            try
            {
                if (File.Exists(_storageFilePath))
                {
                    var json = File.ReadAllText(_storageFilePath);
                    var devices = JsonConvert.DeserializeObject<List<PairedDevice>>(json);
                    
                    if (devices != null)
                    {
                        _pairedDevices = devices;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading paired devices: {ex.Message}");
            }
        }
        
        private void SavePairedDevices()
        {
            try
            {
                var json = JsonConvert.SerializeObject(_pairedDevices, Formatting.Indented);
                File.WriteAllText(_storageFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving paired devices: {ex.Message}");
            }
        }
        
        public List<PairedDevice> GetPairedDevices()
        {
            return new List<PairedDevice>(_pairedDevices);
        }
        
        public PairedDevice? GetDeviceById(string deviceId)
        {
            return _pairedDevices.Find(d => d.DeviceId == deviceId);
        }
        
        public PairedDevice? GetDeviceByIp(string ipAddress)
        {
            return _pairedDevices.Find(d => d.IpAddress == ipAddress);
        }
        
        public bool IsPairedDevice(string deviceId)
        {
            return _pairedDevices.Exists(d => d.DeviceId == deviceId);
        }
        
        public void AddOrUpdateDevice(PairedDevice device)
        {
            var existingDevice = _pairedDevices.Find(d => d.DeviceId == device.DeviceId);
            
            if (existingDevice != null)
            {
                // Update existing device
                existingDevice.DeviceName = device.DeviceName;
                existingDevice.IpAddress = device.IpAddress;
                existingDevice.Port = device.Port;
                existingDevice.SharedKey = device.SharedKey;
                existingDevice.LastSeen = DateTime.Now;
            }
            else
            {
                // Add new device
                device.LastSeen = DateTime.Now;
                _pairedDevices.Add(device);
            }
            
            // Save changes
            SavePairedDevices();
        }
        
        public void RemoveDevice(string deviceId)
        {
            _pairedDevices.RemoveAll(d => d.DeviceId == deviceId);
            
            // Save changes
            SavePairedDevices();
        }
        
        public void UpdateDeviceLastSeen(string deviceId)
        {
            var device = _pairedDevices.Find(d => d.DeviceId == deviceId);
            
            if (device != null)
            {
                device.LastSeen = DateTime.Now;
                SavePairedDevices();
            }
        }
        
        public bool HandlePairingRequest(string deviceId, string deviceName, string ipAddress, int port)
        {
            // Check if already paired
            if (IsPairedDevice(deviceId))
            {
                UpdateDeviceLastSeen(deviceId);
                return true; // Already paired, accept automatically
            }
            
            // Raise event for UI to handle
            var args = new PairingRequestEventArgs(deviceId, deviceName, ipAddress, port);
            PairingRequestReceived?.Invoke(this, args);
            
            // Return the result (might be synchronous or asynchronous depending on UI)
            return args.Accepted;
        }
    }
    
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
}