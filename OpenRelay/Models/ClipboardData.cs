using System;
using Newtonsoft.Json;

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
        /// Shared encryption key for this device
        /// </summary>
        public string SharedKey { get; set; } = string.Empty;

        /// <summary>
        /// Last time this device was seen
        /// </summary>
        public DateTime LastSeen { get; set; }

        public override string ToString()
        {
            return $"{DeviceName} ({IpAddress})";
        }
    }

    /// <summary>
    /// JSON structure for clipboard data from Rust
    /// </summary>
    internal class JsonClipboardData
    {
        [JsonProperty("format")]
        public string Format { get; set; } = string.Empty;

        [JsonProperty("text_data")]
        public string? TextData { get; set; }

        [JsonProperty("binary_length")]
        public int BinaryLength { get; set; }

        [JsonProperty("timestamp")]
        public long Timestamp { get; set; }
    }
}