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

        /// <summary>
        /// Create a new clipboard data instance with text
        /// </summary>
        public static ClipboardData CreateText(string text)
        {
            return new ClipboardData
            {
                Format = "text/plain",
                TextData = text,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
        }

        /// <summary>
        /// Create a new clipboard data instance with an image
        /// </summary>
        public static ClipboardData CreateImage(byte[] imageData)
        {
            return new ClipboardData
            {
                Format = "image/png",
                BinaryData = imageData,
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
        }
    }
}