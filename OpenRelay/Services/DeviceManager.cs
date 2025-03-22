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
        // List of paired devices
        private List<PairedDevice> _pairedDevices = new List<PairedDevice>();
        
        // Dictionary of encryption keys for each device
        private Dictionary<string, byte[]> _encryptionKeys = new Dictionary<string, byte[]>();
        
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
        
        public PairedDevice? GetDeviceByPublicKey(string publicKey)
        {
            return _pairedDevices.Find(d => d.PublicKey == publicKey);
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
                existingDevice.PublicKey = device.PublicKey;
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
            _encryptionKeys.Remove(deviceId);
            
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
        
        public void StoreEncryptionKey(string deviceId, byte[] key)
        {
            _encryptionKeys[deviceId] = key;
        }
        
        public byte[]? GetEncryptionKey(string deviceId)
        {
            if (_encryptionKeys.TryGetValue(deviceId, out var key))
            {
                return key;
            }
            
            return null;
        }
    }
}