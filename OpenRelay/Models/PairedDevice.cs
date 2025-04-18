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

        public override string ToString()
        {
            return $"{DeviceName} ({IpAddress})";
        }
    }
}