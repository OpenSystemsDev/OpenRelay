using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class PairingRequestEventArgs : EventArgs
    {
        public string DeviceId { get; }
        public string DeviceName { get; }
        public string IpAddress { get; }
        public int Port { get; }
        public string RequestId { get; }
        public bool Accepted { get; set; }

        public PairingRequestEventArgs(string deviceId, string deviceName, string ipAddress, int port, string requestId)
        {
            DeviceId = deviceId;
            DeviceName = deviceName;
            IpAddress = ipAddress;
            Port = port;
            RequestId = requestId;
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

    public class DeviceRemovedEventArgs : EventArgs
    {
        public string DeviceId { get; }

        public DeviceRemovedEventArgs(string deviceId)
        {
            DeviceId = deviceId;
        }
    }

    public class DeviceManagerService : IDisposable
    {
        // Events
        public event EventHandler<PairingRequestEventArgs>? PairingRequestReceived;
        public event EventHandler<DeviceEventArgs>? DeviceAdded;
        public event EventHandler<DeviceEventArgs>? DeviceUpdated;
        public event EventHandler<DeviceRemovedEventArgs>? DeviceRemoved;

        // Callbacks for the Rust library
        private NativeMethods.PairingRequestCallback _pairingRequestCallback;
        private NativeMethods.DeviceAddedCallback _deviceAddedCallback;
        private NativeMethods.DeviceRemovedCallback _deviceRemovedCallback;

        // Local device information
        private string _localDeviceId = string.Empty;
        private string _localDeviceName = string.Empty;

        public string LocalDeviceId => _localDeviceId;
        public string LocalDeviceName => _localDeviceName;

        public DeviceManagerService()
        {
            // Initialize callbacks and keep references to prevent garbage collection
            _pairingRequestCallback = new NativeMethods.PairingRequestCallback(OnPairingRequest);
            _deviceAddedCallback = new NativeMethods.DeviceAddedCallback(OnDeviceAdded);
            _deviceRemovedCallback = new NativeMethods.DeviceRemovedCallback(OnDeviceRemoved);

            // Register callbacks with the Rust library
            NativeMethods.openrelay_set_pairing_request_callback(_pairingRequestCallback);
            NativeMethods.openrelay_set_device_added_callback(_deviceAddedCallback);
            NativeMethods.openrelay_set_device_removed_callback(_deviceRemovedCallback);

            // Get local device information
            InitializeLocalDeviceInfo();
        }

        private void InitializeLocalDeviceInfo()
        {
            IntPtr deviceIdPtr = NativeMethods.openrelay_get_local_device_id();
            if (deviceIdPtr != IntPtr.Zero)
            {
                _localDeviceId = NativeMethods.PtrToStringAndFree(deviceIdPtr);
            }

            IntPtr deviceNamePtr = NativeMethods.openrelay_get_local_device_name();
            if (deviceNamePtr != IntPtr.Zero)
            {
                _localDeviceName = NativeMethods.PtrToStringAndFree(deviceNamePtr);
            }
        }

        public List<PairedDevice> GetPairedDevices()
        {
            var devices = new List<PairedDevice>();

            IntPtr devicesJsonPtr = NativeMethods.openrelay_get_paired_devices();
            if (devicesJsonPtr != IntPtr.Zero)
            {
                string devicesJson = NativeMethods.PtrToStringAndFree(devicesJsonPtr);
                if (!string.IsNullOrEmpty(devicesJson))
                {
                    try
                    {
                        devices = JsonConvert.DeserializeObject<List<PairedDevice>>(devicesJson) ?? new List<PairedDevice>();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error deserializing paired devices: {ex.Message}");
                    }
                }
            }

            return devices;
        }

        public PairedDevice? GetDeviceById(string deviceId)
        {
            return GetPairedDevices().Find(d => d.DeviceId == deviceId);
        }

        public PairedDevice? GetDeviceByIp(string ipAddress)
        {
            return GetPairedDevices().Find(d => d.IpAddress == ipAddress);
        }

        public bool IsPairedDevice(string deviceId)
        {
            return GetPairedDevices().Exists(d => d.DeviceId == deviceId);
        }

        public bool RemoveDevice(string deviceId)
        {
            int result = NativeMethods.openrelay_remove_device(deviceId);
            return result == 0;
        }

        public async Task<bool> SendPairingRequestAsync(string ipAddress, int port = 9876)
        {
            return await Task.Run(() => {
                try
                {
                    // Validate and normalize IP address
                    if (string.IsNullOrEmpty(ipAddress))
                    {
                        System.Diagnostics.Debug.WriteLine("IP address is null or empty");
                        return false;
                    }

                    // Check if this looks like an IPv4 address and normalize format if needed
                    if (ipAddress.Contains(".") && !ipAddress.Contains(":"))
                    {
                        // Make sure it has all 4 parts
                        var parts = ipAddress.Split('.');
                        if (parts.Length == 4)
                        {
                            // This looks like a valid IPv4 address
                            System.Diagnostics.Debug.WriteLine($"Using IPv4 address: {ipAddress}");
                        }
                        else if (parts.Length < 4)
                        {
                            System.Diagnostics.Debug.WriteLine($"IP address appears incomplete: {ipAddress}");
                            return false;
                        }
                    }

                    System.Diagnostics.Debug.WriteLine($"Sending pairing request to {ipAddress}:{port}");
                    int result = NativeMethods.openrelay_send_pairing_request(ipAddress, port);
                    System.Diagnostics.Debug.WriteLine($"Pairing request result: {result}");
                    return result > 0; // 1 = success, 0 = declined, negative = error
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Exception in SendPairingRequestAsync: {ex}");
                    return false;
                }
            });
        }

        // Callback methods for Rust
        private int OnPairingRequest(IntPtr deviceIdPtr, IntPtr deviceNamePtr, IntPtr ipAddressPtr, int port, IntPtr requestIdPtr)
        {
            try
            {
                // Convert pointers to strings more safely - use the base Marshal methods first
                string deviceId = "";
                string deviceName = "";
                string ipAddress = "";
                string requestId = "";

                try { deviceId = Marshal.PtrToStringAnsi(deviceIdPtr) ?? string.Empty; }
                catch { System.Diagnostics.Debug.WriteLine("Failed to convert deviceId"); }

                try { deviceName = Marshal.PtrToStringAnsi(deviceNamePtr) ?? string.Empty; }
                catch { System.Diagnostics.Debug.WriteLine("Failed to convert deviceName"); }

                try { ipAddress = Marshal.PtrToStringAnsi(ipAddressPtr) ?? string.Empty; }
                catch { System.Diagnostics.Debug.WriteLine("Failed to convert ipAddress"); }

                try { requestId = Marshal.PtrToStringAnsi(requestIdPtr) ?? string.Empty; }
                catch { System.Diagnostics.Debug.WriteLine("Failed to convert requestId"); }

                System.Diagnostics.Debug.WriteLine($"Pairing request from {deviceName} ({deviceId}) at {ipAddress}:{port}");

                // If already paired, accept automatically
                if (IsPairedDevice(deviceId))
                {
                    return 1; // Accept
                }

                // Create event args
                var args = new PairingRequestEventArgs(deviceId, deviceName, ipAddress, port, requestId);

                // Raise event
                try
                {
                    PairingRequestReceived?.Invoke(this, args);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error in PairingRequestReceived event: {ex}");
                }

                // Return 1 if accepted, 0 if not
                return args.Accepted ? 1 : 0;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in pairing request callback: {ex}");
                return 0; // Decline on error
            }
        }

        private void OnDeviceAdded(IntPtr deviceIdPtr, IntPtr deviceNamePtr, IntPtr ipAddressPtr, int port)
        {
            string deviceId = Marshal.PtrToStringAnsi(deviceIdPtr) ?? string.Empty;
            string deviceName = Marshal.PtrToStringAnsi(deviceNamePtr) ?? string.Empty;
            string ipAddress = Marshal.PtrToStringAnsi(ipAddressPtr) ?? string.Empty;

            var device = new PairedDevice
            {
                DeviceId = deviceId,
                DeviceName = deviceName,
                IpAddress = ipAddress,
                Port = port,
                LastSeen = DateTime.Now
            };

            DeviceAdded?.Invoke(this, new DeviceEventArgs(device));
        }

        private void OnDeviceRemoved(IntPtr deviceIdPtr)
        {
            string deviceId = Marshal.PtrToStringAnsi(deviceIdPtr) ?? string.Empty;

            DeviceRemoved?.Invoke(this, new DeviceRemovedEventArgs(deviceId));
        }

        public void Dispose()
        {
            // Nothing to dispose, but implementing IDisposable for consistency
        }
    }
}