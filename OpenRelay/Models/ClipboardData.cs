using System;

namespace OpenRelay.Models
{
    /// <summary>
    /// Represents clipboard content for synchronization
    /// </summary>
    public class ClipboardData
    {
        /// <summary>
        /// Format of the clipboard data (e.g., "text/plain", "image/png")
        /// </summary>
        public string Format { get; set; } = string.Empty;
        
        /// <summary>
        /// Text content if Format is text/plain
        /// </summary>
        public string? TextData { get; set; }
        
        /// <summary>
        /// Binary data for non-text formats
        /// </summary>
        public byte[]? BinaryData { get; set; }
        
        /// <summary>
        /// Unix timestamp of when this data was copied
        /// </summary>
        public long Timestamp { get; set; }
    }
    
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
        /// Public key for verifying signatures
        /// </summary>
        public string PublicKey { get; set; } = string.Empty;
        
        /// <summary>
        /// Last time this device was seen
        /// </summary>
        public DateTime LastSeen { get; set; }
    }
    
    /// <summary>
    /// Message format for clipboard updates
    /// </summary>
    public class ClipboardMessage
    {
        /// <summary>
        /// Message type (e.g., "clipboard_update", "discovery", "pairing_request")
        /// </summary>
        public string Type { get; set; } = string.Empty;
        
        /// <summary>
        /// Device sending this message
        /// </summary>
        public string DeviceId { get; set; } = string.Empty;
        
        /// <summary>
        /// Unix timestamp
        /// </summary>
        public long Timestamp { get; set; }
        
        /// <summary>
        /// Format of the data
        /// </summary>
        public string Format { get; set; } = string.Empty;
        
        /// <summary>
        /// Encrypted data content (Base64 encoded)
        /// </summary>
        public string Data { get; set; } = string.Empty;
        
        /// <summary>
        /// Signature for verification (Base64 encoded)
        /// </summary>
        public string Signature { get; set; } = string.Empty;
    }
}