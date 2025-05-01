using System;

namespace OpenRelay.Models
{
    /// <summary>
    /// Represents a device paired with this application
    /// </summary>
    public class PairedDevice
    {
        /// <summary>
        /// Unique identifier for the device
        /// </summary>
        public string DeviceId { get; set; } = string.Empty;

        /// <summary>
        /// User-friendly name of the device
        /// </summary>
        public string DeviceName { get; set; } = string.Empty;

        /// <summary>
        /// Platform (windows, android)
        /// </summary>
        public string Platform { get; set; } = string.Empty;

        /// <summary>
        /// IP address of the device on the local network
        /// </summary>
        public string IpAddress { get; set; } = string.Empty;

        /// <summary>
        /// Port for communication
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Shared encryption key for this device
        /// </summary>
        public string SharedKey { get; set; } = string.Empty;

        /// <summary>
        /// Current key ID for rotation
        /// </summary>
        public uint CurrentKeyId { get; set; }

        /// <summary>
        /// Last time this device was seen
        /// </summary>
        public DateTime LastSeen { get; set; }

        /// <summary>
        /// Encrypted storage data for this device
        /// </summary>
        public byte[]? EncryptedStorageData { get; set; }

        /// <summary>
        /// Whether this device is paired via the relay server
        /// </summary>
        public bool IsRelayPaired { get; set; } = false;

        /// <summary>
        /// Device ID on the relay server (may be different from local DeviceId)
        /// </summary>
        public string RelayDeviceId { get; set; } = string.Empty;

        /// <summary>
        /// Hardware ID hash for the device
        /// </summary>
        public string HardwareId { get; set; } = string.Empty;

        /// <summary>
        /// Public key for the device (used for challenge-response authentication)
        /// </summary>
        public string PublicKey { get; set; } = string.Empty;

        /// <summary>
        /// Whether the device has been authenticated via challenge-response
        /// </summary>
        public bool IsAuthenticated { get; set; } = false;

        public override string ToString()
        {
            return $"{DeviceName} ({(IsRelayPaired ? "Relay" : IpAddress)})";
        }
    }
}