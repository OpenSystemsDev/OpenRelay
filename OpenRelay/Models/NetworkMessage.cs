using System;
using System.Text.Json.Serialization;

namespace OpenRelay.Models
{
    /// <summary>
    /// Types of messages that can be exchanged between devices
    /// </summary>
    public enum MessageType
    {
        PairingRequest,
        PairingResponse,
        Auth,
        AuthSuccess,
        AuthFailed,
        ClipboardUpdate,
        ClipboardClear,
        KeyRotationUpdate,   // New message type for key rotation
        KeyRotationRequest,  // New message type for requesting key updates
        Error
    }

    /// <summary>
    /// Base class for all network messages
    /// </summary>
    public class NetworkMessage
    {
        /// <summary>
        /// Type of the message
        /// </summary>
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// Device ID sending the message
        /// </summary>
        [JsonPropertyName("device_id")]
        public string DeviceId { get; set; } = string.Empty;

        /// <summary>
        /// Device name for display purposes
        /// </summary>
        [JsonPropertyName("device_name")]
        public string DeviceName { get; set; } = string.Empty;

        /// <summary>
        /// Timestamp of the message
        /// </summary>
        [JsonPropertyName("timestamp")]
        public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    }

    /// <summary>
    /// Message for requesting pairing with another device
    /// </summary>
    public class PairingRequestMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new pairing request message
        /// </summary>
        public PairingRequestMessage()
        {
            Type = MessageType.PairingRequest.ToString();
        }

        /// <summary>
        /// Request ID for tracking the pairing request
        /// </summary>
        [JsonPropertyName("request_id")]
        public string RequestId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Public key for ECDH key exchange if used
        /// </summary>
        [JsonPropertyName("public_key")]
        public string? PublicKey { get; set; }
    }

    /// <summary>
    /// Message for responding to a pairing request
    /// </summary>
    public class PairingResponseMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new pairing response message
        /// </summary>
        public PairingResponseMessage()
        {
            Type = MessageType.PairingResponse.ToString();
        }

        /// <summary>
        /// Request ID that this response is for
        /// </summary>
        [JsonPropertyName("request_id")]
        public string RequestId { get; set; } = string.Empty;

        /// <summary>
        /// Whether the pairing request was accepted
        /// </summary>
        [JsonPropertyName("accepted")]
        public bool Accepted { get; set; }

        /// <summary>
        /// Public key for ECDH key exchange if used
        /// </summary>
        [JsonPropertyName("public_key")]
        public string? PublicKey { get; set; }

        /// <summary>
        /// Encrypted shared key for the device if accepted
        /// </summary>
        [JsonPropertyName("encrypted_shared_key")]
        public string? EncryptedSharedKey { get; set; }
    }

    /// <summary>
    /// Message for authenticating with a device
    /// </summary>
    public class AuthMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new auth message
        /// </summary>
        public AuthMessage()
        {
            Type = MessageType.Auth.ToString();
        }

        /// <summary>
        /// Current key ID this device is using
        /// </summary>
        [JsonPropertyName("key_id")]
        public uint KeyId { get; set; }
    }

    /// <summary>
    /// Message for successful authentication
    /// </summary>
    public class AuthSuccessMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new auth success message
        /// </summary>
        public AuthSuccessMessage()
        {
            Type = MessageType.AuthSuccess.ToString();
        }

        /// <summary>
        /// Current key ID this device is using
        /// </summary>
        [JsonPropertyName("key_id")]
        public uint KeyId { get; set; }
    }

    /// <summary>
    /// Message for failed authentication
    /// </summary>
    public class AuthFailedMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new auth failed message
        /// </summary>
        public AuthFailedMessage()
        {
            Type = MessageType.AuthFailed.ToString();
        }

        /// <summary>
        /// Reason for the authentication failure
        /// </summary>
        [JsonPropertyName("reason")]
        public string Reason { get; set; } = string.Empty;
    }

    /// <summary>
    /// Message for clipboard updates
    /// </summary>
    public class ClipboardUpdateMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new clipboard update message
        /// </summary>
        public ClipboardUpdateMessage()
        {
            Type = MessageType.ClipboardUpdate.ToString();
        }

        /// <summary>
        /// Format of the clipboard data
        /// </summary>
        [JsonPropertyName("format")]
        public string Format { get; set; } = string.Empty;

        /// <summary>
        /// The encrypted data
        /// </summary>
        [JsonPropertyName("data")]
        public string Data { get; set; } = string.Empty;

        /// <summary>
        /// Whether the data is binary (true) or text (false)
        /// </summary>
        [JsonPropertyName("is_binary")]
        public bool IsBinary { get; set; }

        /// <summary>
        /// Key ID used to encrypt this data
        /// </summary>
        [JsonPropertyName("key_id")]
        public uint KeyId { get; set; }
    }

    /// <summary>
    /// Message for clipboard clear operations
    /// </summary>
    public class ClipboardClearMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new clipboard clear message
        /// </summary>
        public ClipboardClearMessage()
        {
            Type = MessageType.ClipboardClear.ToString();
        }
    }

    /// <summary>
    /// Message for key rotation updates
    /// </summary>
    public class KeyRotationUpdateMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new key rotation update message
        /// </summary>
        public KeyRotationUpdateMessage()
        {
            Type = MessageType.KeyRotationUpdate.ToString();
        }

        /// <summary>
        /// The current key ID
        /// </summary>
        [JsonPropertyName("current_key_id")]
        public uint CurrentKeyId { get; set; }

        /// <summary>
        /// The encrypted key update package
        /// </summary>
        [JsonPropertyName("key_package")]
        public string KeyPackage { get; set; } = string.Empty;
    }

    /// <summary>
    /// Message for requesting key updates
    /// </summary>
    public class KeyRotationRequestMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new key rotation request message
        /// </summary>
        public KeyRotationRequestMessage()
        {
            Type = MessageType.KeyRotationRequest.ToString();
        }

        /// <summary>
        /// The last known key ID
        /// </summary>
        [JsonPropertyName("last_known_key_id")]
        public uint LastKnownKeyId { get; set; }
    }

    /// <summary>
    /// Message for errors
    /// </summary>
    public class ErrorMessage : NetworkMessage
    {
        /// <summary>
        /// Create a new error message
        /// </summary>
        public ErrorMessage()
        {
            Type = MessageType.Error.ToString();
        }

        /// <summary>
        /// Error message
        /// </summary>
        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;
    }
}