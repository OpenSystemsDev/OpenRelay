using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Authentication;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    /// <summary>
    /// Event args for when clipboard data is received
    /// </summary>
    public class ClipboardDataReceivedEventArgs : EventArgs
    {
        public ClipboardData Data { get; }
        public PairedDevice Device { get; }

        public ClipboardDataReceivedEventArgs(ClipboardData data, PairedDevice device)
        {
            Data = data;
            Device = device;
        }
    }

    /// <summary>
    /// Manages network communication with paired devices
    /// </summary>
    public class NetworkService : IDisposable
    {
        // Constants
        private const int DEFAULT_PORT = 9876;

        // Trusted Certificates
        private static readonly Dictionary<string, string> _trustedCertificates = new Dictionary<string, string>();

        // Events
        public event EventHandler<ClipboardDataReceivedEventArgs>? ClipboardDataReceived;
        public event EventHandler<bool>? RelayServerConnectionChanged;

        // Dependencies
        private readonly DeviceManager _deviceManager;
        private readonly EncryptionService _encryptionService;
        private readonly SettingsManager _settingsManager;

        // WebSocket server
        private HttpListener? _httpListener;
        private bool _isListening;
        private CancellationTokenSource? _cancellationTokenSource;

        // Connected clients
        private readonly Dictionary<string, WebSocket> _connectedClients = new Dictionary<string, WebSocket>();

        // Pending pairing requests
        private readonly Dictionary<string, TaskCompletionSource<bool>> _pairingRequests = new Dictionary<string, TaskCompletionSource<bool>>();

        // Store chunks for reassembly
        private readonly Dictionary<string, Dictionary<int, string>> _clipboardChunks = new Dictionary<string, Dictionary<int, string>>();
        private readonly Dictionary<string, (int count, string format, bool isBinary, uint keyId, long timestamp, string senderId, string senderName)> _chunkMetadata = new Dictionary<string, (int, string, bool, uint, long, string, string)>();


        // Relay server connection
        internal RelayConnection? _relayConnection;
        private bool _isConnectedToRelayServer = false;

        /// <summary>
        /// Initialize the network service
        /// </summary>
        public NetworkService(DeviceManager deviceManager, EncryptionService encryptionService, SettingsManager settingsManager)
        {
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
            _settingsManager = settingsManager;
        }

        /// <summary>
        /// Get whether connected to relay server
        /// </summary>
        public bool IsConnectedToRelayServer => _isConnectedToRelayServer;

        /// <summary>
        /// Start the WebSocket server with TLS enabled
        /// </summary>
        public async Task StartAsync()
        {
            if (_isListening)
                return;

            try
            {
                _cancellationTokenSource = new CancellationTokenSource();

                // Create certificate manager
                var certificateManager = new CertificateManager();
                var certificate = await certificateManager.GetOrCreateCertificateAsync();

                // Set up the certificate
                if (!TlsBindingManager.SetupCertificate(DEFAULT_PORT, certificate))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Warning: Could not set up TLS certificate binding");
                }

                _httpListener = new HttpListener();

                _httpListener.Prefixes.Add($"https://+:{DEFAULT_PORT}/");
                _httpListener.Start();

                _isListening = true;

                // Log server start
                System.Diagnostics.Debug.WriteLine($"[NETWORK] TLS WebSocket server started on port {DEFAULT_PORT}");

                // Start listening for connections
                await AcceptConnectionsAsync(_cancellationTokenSource.Token);

                // Connect to relay server if enabled
                var settings = _settingsManager.GetSettings();
                if (settings.UseRelayServer)
                {
                    await ConnectToRelayServerAsync(_cancellationTokenSource.Token);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error starting network service: {ex.Message}");
                StopAsync();
                throw;
            }
        }

        /// <summary>
        /// Stop the WebSocket server
        /// </summary>
        public void StopAsync()
        {
            if (!_isListening)
                return;

            // Cancel all operations
            _cancellationTokenSource?.Cancel();

            // Close all connections
            foreach (var client in _connectedClients.Values)
            {
                try
                {
                    client.Abort();
                    client.Dispose();
                }
                catch
                {
                    // Ignore errors
                }
            }

            _connectedClients.Clear();

            // Stop HTTP listener
            _httpListener?.Stop();
            _httpListener = null;

            _isListening = false;

            // Disconnect from relay server
            DisconnectFromRelayServerAsync().Wait();

            System.Diagnostics.Debug.WriteLine("[NETWORK] WebSocket server stopped");
        }

        /// <summary>
        /// Connect to the relay server
        /// </summary>
        public async Task<bool> ConnectToRelayServerAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Get settings
                var settings = _settingsManager.GetSettings();
                if (!settings.UseRelayServer)
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Relay server disabled in settings");
                    return false;
                }

                // Check if already connected
                if (_isConnectedToRelayServer && _relayConnection != null)
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Already connected to relay server");
                    return true;
                }

                // Disconnect existing connection if any
                await DisconnectFromRelayServerAsync();

                // Create new connection
                _relayConnection = new RelayConnection(
                    settings.RelayServerUri,
                    _deviceManager.LocalDeviceId,
                    _deviceManager.LocalDeviceName);

                // Set up event handlers
                _relayConnection.Connected += RelayConnection_Connected;
                _relayConnection.Disconnected += RelayConnection_Disconnected;
                _relayConnection.MessageReceived += RelayConnection_MessageReceived;

                // Connect to server
                bool connected = await _relayConnection.ConnectAsync(cancellationToken);
                if (!connected)
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Failed to connect to relay server");
                    await DisconnectFromRelayServerAsync();
                    return false;
                }

                _isConnectedToRelayServer = true;
                RelayServerConnectionChanged?.Invoke(this, true);

                System.Diagnostics.Debug.WriteLine("[NETWORK] Connected to relay server");
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error connecting to relay server: {ex.Message}");
                await DisconnectFromRelayServerAsync();
                return false;
            }
        }

        /// <summary>
        /// Disconnect from the relay server
        /// </summary>
        public async Task DisconnectFromRelayServerAsync()
        {
            if (_relayConnection != null)
            {
                // Remove event handlers
                _relayConnection.Connected -= RelayConnection_Connected;
                _relayConnection.Disconnected -= RelayConnection_Disconnected;
                _relayConnection.MessageReceived -= RelayConnection_MessageReceived;

                // Disconnect
                await _relayConnection.DisconnectAsync();
                _relayConnection.Dispose();
                _relayConnection = null;
            }

            _isConnectedToRelayServer = false;

            RelayServerConnectionChanged?.Invoke(this, false);

            System.Diagnostics.Debug.WriteLine("[NETWORK] Disconnected from relay server");
        }

        /// <summary>
        /// Handle relay server connection
        /// </summary>
        private void RelayConnection_Connected(object? sender, string relayDeviceId)
        {
            _isConnectedToRelayServer = true;
            RelayServerConnectionChanged?.Invoke(this, true);

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Connected to relay server with device ID: {relayDeviceId}");

            // Update status for paired devices that use relay
            foreach (var device in _deviceManager.GetPairedDevices())
            {
                if (device.IsRelayPaired)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Updating relay status for device: {device.DeviceName}");

                    // TODO: Send status update to relay-paired devices
                }
            }
        }

        /// <summary>
        /// Handle relay server disconnection
        /// </summary>
        private void RelayConnection_Disconnected(object? sender, EventArgs e)
        {
            _isConnectedToRelayServer = false;
            RelayServerConnectionChanged?.Invoke(this, false);

            System.Diagnostics.Debug.WriteLine("[NETWORK] Disconnected from relay server");
        }

        /// <summary>
        /// Handle relay server message
        /// </summary>
        private void RelayConnection_MessageReceived(object? sender, RelayMessageEventArgs e)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received relay message from {e.SenderId}, Hardware ID: {e.HardwareId}");

                // Validate hardware ID if provided
                if (!string.IsNullOrEmpty(e.HardwareId))
                {
                    // Check if device exists by hardware ID
                    var deviceByHwId = _deviceManager.GetDeviceByHardwareId(e.HardwareId);
                    if (deviceByHwId != null && deviceByHwId.DeviceId != e.SenderId)
                    {
                        // MODIFIED: Instead of rejecting, update the device ID mapping
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch detected: {e.HardwareId} now belongs to {e.SenderId} (was {deviceByHwId.DeviceId})");

                        // Update the device ID to match what the relay server is telling us
                        deviceByHwId.DeviceId = e.SenderId;

                        // IMPORTANT: Update the relay device ID as well to ensure proper relay connectivity
                        deviceByHwId.RelayDeviceId = e.SenderId;

                        _deviceManager.UpdateDevice(deviceByHwId);
                    }
                }

                // Try first to decode the message from base64 if it looks like base64
                bool isBase64 = e.EncryptedData.Length % 4 == 0 &&
                                System.Text.RegularExpressions.Regex.IsMatch(e.EncryptedData, @"^[a-zA-Z0-9\+/]*={0,3}$");

                string decodedContent = e.EncryptedData;
                if (isBase64)
                {
                    try
                    {
                        byte[] decodedBytes = Convert.FromBase64String(e.EncryptedData);
                        decodedContent = System.Text.Encoding.UTF8.GetString(decodedBytes);
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully decoded base64 content: {decodedContent.Substring(0, Math.Min(100, decodedContent.Length))}...");
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Failed to decode from base64: {ex.Message}");
                        // Keep original content if decoding fails
                    }
                }

                // Parse the message content (either original or decoded)
                try
                {
                    // Try to parse as JSON
                    var message = JsonDocument.Parse(decodedContent);
                    var root = message.RootElement;

                    if (root.TryGetProperty("type", out var typeProperty))
                    {
                        string messageType = typeProperty.GetString() ?? string.Empty;

                        // Process different message types
                        switch (messageType)
                        {
                            case "PairingRequest":
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received PairingRequest via relay");
                                ProcessRelayPairingRequest(root, e.SenderId, e.HardwareId);
                                break;

                            case "PairingResponse":
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received PairingResponse via relay");
                                ProcessRelayPairingResponse(root, e.SenderId, e.HardwareId);
                                break;

                            case "AuthRequest":
                                ProcessAuthRequestMessage(root, e.SenderId, e.HardwareId);
                                break;

                            case "AuthResponse":
                                ProcessAuthResponseMessage(root, e.SenderId, e.HardwareId);
                                break;

                            case "AuthVerify":
                                ProcessAuthVerifyMessage(root, e.SenderId, e.HardwareId);
                                break;

                            case "AuthSuccess":
                                ProcessAuthSuccessMessage(root, e.SenderId, e.HardwareId);
                                break;

                            case "ClipboardChunk":
                                ProcessClipboardChunk(root, e.SenderId, e.HardwareId);
                                break;

                            // ADD THIS CASE: Directly process ClipboardUpdate messages
                            case "ClipboardUpdate":
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received ClipboardUpdate via relay");
                                // Since this is already JSON, we can extract the data directly
                                try
                                {
                                    string format = root.GetProperty("format").GetString() ?? string.Empty;
                                    string data = root.GetProperty("data").GetString() ?? string.Empty;
                                    bool isBinary = root.TryGetProperty("is_binary", out var isBinaryElement) ?
                                        isBinaryElement.GetBoolean() : false;
                                    string deviceId = root.TryGetProperty("device_id", out var deviceIdElement) ?
                                        deviceIdElement.GetString() ?? e.SenderId : e.SenderId;

                                    // Find the device
                                    var device = _deviceManager.GetDeviceById(e.SenderId);
                                    if (device == null && !string.IsNullOrEmpty(e.HardwareId))
                                    {
                                        device = _deviceManager.GetDeviceByHardwareId(e.HardwareId);
                                    }

                                    if (device != null)
                                    {
                                        ClipboardData clipboardData = null;

                                        if (format == "text/plain" && !isBinary && !string.IsNullOrEmpty(data))
                                        {
                                            try
                                            {
                                                var decryptedText = _encryptionService.DecryptText(data, device.SharedKey);
                                                clipboardData = ClipboardData.CreateText(decryptedText);
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully decrypted text data, length: {decryptedText.Length}");
                                            }
                                            catch (Exception ex)
                                            {
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting text: {ex.Message}");
                                            }
                                        }
                                        else if (format == "image/png" && isBinary && !string.IsNullOrEmpty(data))
                                        {
                                            try
                                            {
                                                var encryptedBytes = Convert.FromBase64String(data);
                                                var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(device.SharedKey));
                                                clipboardData = ClipboardData.CreateImage(decryptedBytes);
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully decrypted image data, size: {decryptedBytes.Length} bytes");
                                            }
                                            catch (Exception ex)
                                            {
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting image: {ex.Message}");
                                            }
                                        }

                                        if (clipboardData != null)
                                        {
                                            // Update device last seen
                                            _deviceManager.UpdateDeviceLastSeen(device.DeviceId);

                                            // Notify listeners
                                            ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, device));
                                        }
                                    }
                                    else
                                    {
                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not find device for clipboard update: {e.SenderId}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing clipboard update: {ex.Message}");
                                }
                                break;

                            default:
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown relay message type: {messageType}, Full message: {decodedContent.Substring(0, Math.Min(200, decodedContent.Length))}...");
                                break;
                        }
                    }
                }
                catch (JsonException jsonEx)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error parsing JSON from relay message: {jsonEx.Message}");
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Content preview: {decodedContent.Substring(0, Math.Min(100, decodedContent.Length))}...");
                    // Not JSON or invalid JSON, try to process as encrypted clipboard data
                    ProcessEncryptedClipboardData(e.SenderId, e.EncryptedData, e.HardwareId);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling relay message: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Stack trace: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Process relay pairing response message
        /// </summary>
        private void ProcessRelayPairingResponse(JsonElement root, string senderId, string hardwareId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Processing pairing response: {JsonSerializer.Serialize(root)}");

                // First check if the response has a nested payload structure
                JsonElement payloadElement;
                if (root.TryGetProperty("payload", out var payload))
                {
                    payloadElement = payload;
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Using nested payload property");
                }
                else
                {
                    payloadElement = root;
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Using root as payload");
                }

                // Extract request ID - try different potential paths
                string requestId = string.Empty;
                if (payloadElement.TryGetProperty("request_id", out var reqIdElement))
                {
                    requestId = reqIdElement.GetString() ?? string.Empty;
                }
                else if (root.TryGetProperty("request_id", out var rootReqIdElement))
                {
                    requestId = rootReqIdElement.GetString() ?? string.Empty;
                }

                // Extract accepted status
                bool accepted = false;
                if (payloadElement.TryGetProperty("accepted", out var acceptedElement))
                {
                    accepted = acceptedElement.GetBoolean();
                }
                else if (root.TryGetProperty("accepted", out var rootAcceptedElement))
                {
                    accepted = rootAcceptedElement.GetBoolean();
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Relay pairing response for request {requestId}: {accepted}");

                // If we have a pending request for this ID, complete it
                if (!string.IsNullOrEmpty(requestId) && _pairingRequests.TryGetValue(requestId, out var tcs))
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Found pending pairing request: {requestId}");

                    // If accepted, get the device info and shared key
                    if (accepted)
                    {
                        string deviceId = string.Empty;
                        string deviceName = string.Empty;
                        string sharedKey = string.Empty;
                        string responseHardwareId = hardwareId; // Default to the passed in hardwareId

                        // Try to get these values from payload first, then from root
                        if (payloadElement.TryGetProperty("device_id", out var deviceIdElement))
                        {
                            deviceId = deviceIdElement.GetString() ?? string.Empty;
                        }
                        else if (root.TryGetProperty("device_id", out var rootDeviceIdElement))
                        {
                            deviceId = rootDeviceIdElement.GetString() ?? string.Empty;
                        }
                        else if (root.TryGetProperty("sender_id", out var senderIdElement))
                        {
                            deviceId = senderIdElement.GetString() ?? string.Empty;
                        }

                        if (payloadElement.TryGetProperty("device_name", out var deviceNameElement))
                        {
                            deviceName = deviceNameElement.GetString() ?? string.Empty;
                        }
                        else if (root.TryGetProperty("device_name", out var rootDeviceNameElement))
                        {
                            deviceName = rootDeviceNameElement.GetString() ?? string.Empty;
                        }
                        else if (root.TryGetProperty("sender_name", out var senderNameElement))
                        {
                            deviceName = senderNameElement.GetString() ?? string.Empty;
                        }

                        if (payloadElement.TryGetProperty("encrypted_shared_key", out var sharedKeyElement))
                        {
                            sharedKey = sharedKeyElement.GetString() ?? string.Empty;
                        }
                        else if (root.TryGetProperty("encrypted_shared_key", out var rootSharedKeyElement))
                        {
                            sharedKey = rootSharedKeyElement.GetString() ?? string.Empty;
                        }

                        // Try to get hardware ID from the message
                        if (payloadElement.TryGetProperty("hardware_id", out var hwIdElement))
                        {
                            responseHardwareId = hwIdElement.GetString() ?? responseHardwareId;
                        }
                        else if (root.TryGetProperty("hardware_id", out var rootHwIdElement))
                        {
                            responseHardwareId = rootHwIdElement.GetString() ?? responseHardwareId;
                        }

                        if (!string.IsNullOrEmpty(deviceId) && !string.IsNullOrEmpty(sharedKey))
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Creating paired device from relay pairing: {deviceName} ({deviceId}), Hardware ID: {responseHardwareId}");

                            // Create and add the device
                            var device = new PairedDevice
                            {
                                DeviceId = deviceId,
                                DeviceName = deviceName,
                                Platform = payloadElement.TryGetProperty("platform", out var platformElement) ?
                                    platformElement.GetString() ?? "Unknown" : "Unknown",
                                SharedKey = sharedKey,
                                CurrentKeyId = _encryptionService.GetCurrentKeyId(),
                                LastSeen = DateTime.Now,
                                HardwareId = responseHardwareId,
                                IsRelayPaired = true,
                                RelayDeviceId = senderId
                            };

                            // Check for challenge-response data
                            string challengeResponse = string.Empty;
                            string challenge = string.Empty;
                            string publicKey = string.Empty;

                            if (payloadElement.TryGetProperty("challenge_response", out var responseElement))
                            {
                                challengeResponse = responseElement.GetString() ?? string.Empty;
                            }
                            else if (root.TryGetProperty("challenge_response", out var rootResponseElement))
                            {
                                challengeResponse = rootResponseElement.GetString() ?? string.Empty;
                            }

                            if (payloadElement.TryGetProperty("challenge", out var challengeElement))
                            {
                                challenge = challengeElement.GetString() ?? string.Empty;
                            }
                            else if (root.TryGetProperty("challenge", out var rootChallengeElement))
                            {
                                challenge = rootChallengeElement.GetString() ?? string.Empty;
                            }

                            if (payloadElement.TryGetProperty("public_key", out var keyElement))
                            {
                                publicKey = keyElement.GetString() ?? string.Empty;
                            }
                            else if (root.TryGetProperty("public_key", out var rootKeyElement))
                            {
                                publicKey = rootKeyElement.GetString() ?? string.Empty;
                            }

                            // Store public key if available
                            if (!string.IsNullOrEmpty(publicKey))
                            {
                                device.PublicKey = publicKey;
                            }

                            _deviceManager.AddOrUpdateDevice(device);

                            // Debug message to verify hardware ID mapping
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Mapped Device ID {deviceId} to Hardware ID {responseHardwareId}");
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Missing required fields in pairing response. DeviceId: {deviceId}, SharedKey: {!string.IsNullOrEmpty(sharedKey)}");
                        }
                    }

                    // Complete the task
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Completing pairing request task with result: {accepted}");
                    tcs.TrySetResult(accepted);
                    _pairingRequests.Remove(requestId);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] No pending request found for ID: {requestId}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing relay pairing response: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Stack trace: {ex.StackTrace}");
            }
        }


        /// <summary>
        /// Process relay pairing request message
        /// </summary>
        async private void ProcessRelayPairingRequest(JsonElement root, string senderId, string hardwareId)
        {
            try
            {
                // Extract device ID and device name directly from the message root
                string deviceId = root.GetProperty("sender_id").GetString() ?? string.Empty;
                string deviceName = root.GetProperty("sender_name").GetString() ?? string.Empty;

                // Try to get request_id, public_key, challenge from the payload if present, otherwise from the root
                string requestId = string.Empty;
                string challenge = string.Empty;
                string publicKey = string.Empty;

                if (root.TryGetProperty("payload", out var payloadElement))
                {
                    // Extract from payload structure
                    requestId = payloadElement.TryGetProperty("request_id", out var reqIdElement) ?
                        reqIdElement.GetString() ?? string.Empty : string.Empty;

                    challenge = payloadElement.TryGetProperty("challenge", out var challengeElement) ?
                        challengeElement.GetString() ?? string.Empty : string.Empty;

                    publicKey = payloadElement.TryGetProperty("public_key", out var publicKeyElement) ?
                        publicKeyElement.GetString() ?? string.Empty : string.Empty;

                    // Try to get platform from payload
                    string platform = payloadElement.TryGetProperty("platform", out var platformElement) ?
                        platformElement.GetString() ?? "Unknown" : "Unknown";

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing request from {deviceName} ({deviceId}) via relay");

                    // Forward to the DeviceManager to handle the pairing request
                    bool accepted = _deviceManager.HandlePairingRequest(deviceId, deviceName, "relay", 0,
                        platform, hardwareId, challenge, publicKey);

                    // Send response back via relay
                    if (_relayConnection != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending pairing response: accepted={accepted}");

                        // If accepted, create a device and include the shared key
                        if (accepted)
                        {
                            var device = _deviceManager.GetDeviceById(deviceId);
                            if (device != null)
                            {
                                // Fix: On the receiving end of the pairing request, the device was not marking the device as a relay device, thus was trying to send
                                // clipboard updates via LAN
                                // So now we explicitly set it
                                device.IsRelayPaired = true;
                                device.RelayDeviceId = senderId;
                                device.IpAddress = "relay";
                                _deviceManager.UpdateDevice(device);

                                var response = new PairingResponseMessage
                                {
                                    DeviceId = _deviceManager.LocalDeviceId,
                                    DeviceName = _deviceManager.LocalDeviceName,
                                    RequestId = requestId,
                                    Accepted = true,
                                    HardwareId = _deviceManager.LocalHardwareId,
                                    EncryptedSharedKey = device.SharedKey
                                };

                                // Add challenge/response if we have them
                                if (!string.IsNullOrEmpty(challenge) && !string.IsNullOrEmpty(publicKey))
                                {
                                    string challengeResponse = _deviceManager.SignChallenge(challenge);
                                    string newChallenge = _deviceManager.GenerateChallenge();

                                    response.ChallengeResponse = challengeResponse;
                                    response.Challenge = newChallenge;
                                    response.PublicKey = _deviceManager.GetPublicKey();
                                }

                                await _relayConnection.SendMessageAsync(senderId, "PairingResponse", response, CancellationToken.None);
                            }
                        }
                        else
                        {
                            // Send rejected response
                            var response = new PairingResponseMessage
                            {
                                DeviceId = _deviceManager.LocalDeviceId,
                                DeviceName = _deviceManager.LocalDeviceName,
                                RequestId = requestId,
                                Accepted = false,
                                HardwareId = _deviceManager.LocalHardwareId
                            };

                            await _relayConnection.SendMessageAsync(senderId, "PairingResponse", response, CancellationToken.None);
                        }
                    }
                }
                else
                {
                    // Try to get values directly from root as fallback
                    requestId = root.TryGetProperty("request_id", out var rootReqIdElement) ?
                        rootReqIdElement.GetString() ?? string.Empty : string.Empty;

                    challenge = root.TryGetProperty("challenge", out var rootChallengeElement) ?
                        rootChallengeElement.GetString() ?? string.Empty : string.Empty;

                    publicKey = root.TryGetProperty("public_key", out var rootPublicKeyElement) ?
                        rootPublicKeyElement.GetString() ?? string.Empty : string.Empty;

                    string platform = root.TryGetProperty("platform", out var rootPlatformElement) ?
                        rootPlatformElement.GetString() ?? "Unknown" : "Unknown";

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing request (direct format) from {deviceName} ({deviceId}) via relay");

                    // Forward to the DeviceManager to handle the pairing request
                    bool accepted = _deviceManager.HandlePairingRequest(deviceId, deviceName, "relay", 0,
                        platform, hardwareId, challenge, publicKey);

                    // Send response back via relay
                    if (_relayConnection != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending pairing response: accepted={accepted}");

                        // If accepted, create a device and include the shared key
                        if (accepted)
                        {
                            var device = _deviceManager.GetDeviceById(deviceId);
                            if (device != null)
                            {
                                var response = new PairingResponseMessage
                                {
                                    DeviceId = _deviceManager.LocalDeviceId,
                                    DeviceName = _deviceManager.LocalDeviceName,
                                    RequestId = requestId,
                                    Accepted = true,
                                    HardwareId = _deviceManager.LocalHardwareId,
                                    EncryptedSharedKey = device.SharedKey
                                };

                                // Add challenge/response if we have them
                                if (!string.IsNullOrEmpty(challenge) && !string.IsNullOrEmpty(publicKey))
                                {
                                    string challengeResponse = _deviceManager.SignChallenge(challenge);
                                    string newChallenge = _deviceManager.GenerateChallenge();

                                    response.ChallengeResponse = challengeResponse;
                                    response.Challenge = newChallenge;
                                    response.PublicKey = _deviceManager.GetPublicKey();
                                }

                                await _relayConnection.SendMessageAsync(senderId, "PairingResponse", response, CancellationToken.None);
                            }
                        }
                        else
                        {
                            // Send rejected response
                            var response = new PairingResponseMessage
                            {
                                DeviceId = _deviceManager.LocalDeviceId,
                                DeviceName = _deviceManager.LocalDeviceName,
                                RequestId = requestId,
                                Accepted = false,
                                HardwareId = _deviceManager.LocalHardwareId
                            };

                            await _relayConnection.SendMessageAsync(senderId, "PairingResponse", response, CancellationToken.None);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing relay pairing request: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Stack trace: {ex.StackTrace}");
            }
        }


        /// <summary>
        /// Process authentication request message
        /// </summary>
        private void ProcessAuthRequestMessage(JsonElement root, string senderId, string senderHwId)
        {
            try
            {
                string challenge = root.GetProperty("challenge").GetString() ?? string.Empty;
                string publicKey = root.GetProperty("public_key").GetString() ?? string.Empty;

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth request from {senderId}, challenge: {challenge.Substring(0, 10)}...");

                // Get device by ID or create a new temporary one
                var device = _deviceManager.GetDeviceById(senderId);
                if (device == null)
                {
                    // If the hardware ID is known, look up by that
                    if (!string.IsNullOrEmpty(senderHwId))
                    {
                        device = _deviceManager.GetDeviceByHardwareId(senderHwId);
                    }

                    // If still not found, we can't process this request
                    if (device == null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device {senderId} for auth request");
                        return;
                    }
                }

                // Process the challenge
                string response = _deviceManager.HandleChallengeRequest(senderId, challenge, publicKey, senderHwId);

                // Generate our own challenge
                string ourChallenge = _deviceManager.GenerateChallenge();

                // Send the response with our challenge
                if (_relayConnection != null)
                {
                    _relayConnection.SendAuthResponseAsync(senderId, response, ourChallenge, CancellationToken.None);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing auth request: {ex.Message}");
            }
        }

        /// <summary>
        /// Process authentication response message
        /// </summary>
        private void ProcessAuthResponseMessage(JsonElement root, string senderId, string senderHwId)
        {
            try
            {
                string challengeResponse = root.GetProperty("challenge_response").GetString() ?? string.Empty;
                string newChallenge = root.GetProperty("challenge").GetString() ?? string.Empty;

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth response from {senderId}");

                // Get device
                var device = _deviceManager.GetDeviceById(senderId) ??
                             _deviceManager.GetDeviceByHardwareId(senderHwId);

                if (device == null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device {senderId} for auth response");
                    return;
                }

                // Verify the response and sign their challenge
                bool isValid = _deviceManager.HandleChallengeResponse(senderId, challengeResponse, newChallenge, senderHwId);

                if (isValid)
                {
                    // Sign their challenge
                    string signedResponse = _deviceManager.SignChallenge(newChallenge);

                    // Send verification
                    if (_relayConnection != null)
                    {
                        _relayConnection.SendAuthVerifyAsync(senderId, signedResponse, CancellationToken.None);
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Invalid challenge response from {senderId}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing auth response: {ex.Message}");
            }
        }

        /// <summary>
        /// Process authentication verify message
        /// </summary>
        private void ProcessAuthVerifyMessage(JsonElement root, string senderId, string senderHwId)
        {
            try
            {
                string challengeResponse = root.GetProperty("challenge_response").GetString() ?? string.Empty;

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth verification from {senderId}");

                // Get device
                var device = _deviceManager.GetDeviceById(senderId) ??
                             _deviceManager.GetDeviceByHardwareId(senderHwId);

                if (device == null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device {senderId} for auth verify");
                    return;
                }

                // Verify the response
                bool isValid = _deviceManager.HandleAuthVerify(senderId, challengeResponse, senderHwId);

                if (isValid)
                {
                    // Send success
                    if (_relayConnection != null)
                    {
                        _relayConnection.SendAuthSuccessAsync(senderId, true, CancellationToken.None);
                    }

                    // Update device as authenticated
                    device.IsAuthenticated = true;
                    device.HardwareId = senderHwId;
                    _deviceManager.UpdateDevice(device);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Invalid auth verification from {senderId}");

                    // Send failure
                    if (_relayConnection != null)
                    {
                        _relayConnection.SendAuthSuccessAsync(senderId, false, CancellationToken.None);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing auth verify: {ex.Message}");
            }
        }

        /// <summary>
        /// Process authentication success message
        /// </summary>
        private void ProcessAuthSuccessMessage(JsonElement root, string senderId, string senderHwId)
        {
            try
            {
                bool trusted = root.GetProperty("trusted").GetBoolean();

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth success from {senderId}, trusted: {trusted}");

                // Get device
                var device = _deviceManager.GetDeviceById(senderId) ??
                             _deviceManager.GetDeviceByHardwareId(senderHwId);

                if (device == null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device {senderId} for auth success");
                    return;
                }

                // Process the success
                _deviceManager.HandleAuthSuccess(senderId, trusted, senderHwId);

                if (trusted)
                {
                    // Update device as authenticated
                    device.IsAuthenticated = true;
                    device.HardwareId = senderHwId;
                    _deviceManager.UpdateDevice(device);

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {senderId} ({device.DeviceName}) authenticated successfully");
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {senderId} authentication failed");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing auth success: {ex.Message}");
            }
        }

        /// <summary>
        /// Process encrypted clipboard data
        /// </summary>
        private void ProcessEncryptedClipboardData(string senderId, string encryptedData, string senderHwId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Processing encrypted clipboard data from {senderId}, Hardware ID: {senderHwId}");

                // Find device first - declared at method scope level
                PairedDevice foundDevice = null;

                // Try to parse the JSON structure for clipboard data first - using base64 decoding
                try
                {
                    byte[] decodedBytes = Convert.FromBase64String(encryptedData);
                    string decodedText = Encoding.UTF8.GetString(decodedBytes);

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Decoded data preview: {decodedText.Substring(0, Math.Min(100, decodedText.Length))}...");

                    var jsonDoc = JsonDocument.Parse(decodedText);
                    var root = jsonDoc.RootElement;

                    if (root.TryGetProperty("type", out var typeProperty) &&
                        typeProperty.GetString() == "ClipboardUpdate")
                    {
                        // Use the decoded message's device ID and hardware ID if available
                        string deviceIdFromMessage = root.TryGetProperty("device_id", out var deviceIdElement) ?
                            deviceIdElement.GetString() ?? senderId : senderId;

                        string hwIdFromMessage = root.TryGetProperty("hardware_id", out var hwIdElement) ?
                            hwIdElement.GetString() ?? senderHwId : senderHwId;

                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Message contains device ID: {deviceIdFromMessage}, hardware ID: {hwIdFromMessage}");

                        // Try by hardware ID first (most reliable)
                        if (!string.IsNullOrEmpty(hwIdFromMessage))
                        {
                            foundDevice = _deviceManager.GetDeviceByHardwareId(hwIdFromMessage);

                            // If found by hardware ID but device ID doesn't match, update it
                            if (foundDevice != null && foundDevice.DeviceId != deviceIdFromMessage)
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Found device by hardware ID, updating device ID from {foundDevice.DeviceId} to {deviceIdFromMessage}");
                                foundDevice.DeviceId = deviceIdFromMessage;
                                _deviceManager.UpdateDevice(foundDevice);
                            }
                        }

                        // If not found by hardware ID, try by deviceID
                        if (foundDevice == null)
                        {
                            foundDevice = _deviceManager.GetDeviceById(deviceIdFromMessage);

                            // If found by device ID but hardware ID doesn't match or is empty, update it
                            if (foundDevice != null && !string.IsNullOrEmpty(hwIdFromMessage) &&
                                (string.IsNullOrEmpty(foundDevice.HardwareId) || foundDevice.HardwareId != hwIdFromMessage))
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Updating hardware ID from {foundDevice.HardwareId} to {hwIdFromMessage}");
                                foundDevice.HardwareId = hwIdFromMessage;
                                _deviceManager.UpdateDevice(foundDevice);
                            }
                        }

                        // Fallback: try with sender ID if different from device ID in message
                        if (foundDevice == null && deviceIdFromMessage != senderId)
                        {
                            foundDevice = _deviceManager.GetDeviceById(senderId);
                        }

                        if (foundDevice != null)
                        {
                            // Get clipboard data from the message
                            var format = root.GetProperty("format").GetString() ?? string.Empty;
                            var data = root.GetProperty("data").GetString() ?? string.Empty;
                            var isBinary = root.TryGetProperty("is_binary", out var isBinaryElement) ?
                                isBinaryElement.GetBoolean() : false;

                            // Decrypt the data
                            ClipboardData clipboardData = null;

                            if (format == "text/plain" && !isBinary && !string.IsNullOrEmpty(data))
                            {
                                try
                                {
                                    var decryptedText = _encryptionService.DecryptText(data, foundDevice.SharedKey);
                                    clipboardData = ClipboardData.CreateText(decryptedText);
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully decrypted text data, length: {decryptedText.Length}");
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting text: {ex.Message}");
                                }
                            }
                            else if (format == "image/png" && isBinary && !string.IsNullOrEmpty(data))
                            {
                                try
                                {
                                    var encryptedBytes = Convert.FromBase64String(data);
                                    var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(foundDevice.SharedKey));
                                    clipboardData = ClipboardData.CreateImage(decryptedBytes);
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully decrypted image data, size: {decryptedBytes.Length} bytes");
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting image: {ex.Message}");
                                }
                            }

                            if (clipboardData != null)
                            {
                                // Update device last seen
                                _deviceManager.UpdateDeviceLastSeen(foundDevice.DeviceId);

                                // Notify listeners
                                ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, foundDevice));
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Failed to create clipboard data");
                            }
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not find device for message. Sender: {senderId}, Message device ID: {deviceIdFromMessage}, Hardware ID: {hwIdFromMessage}");
                        }

                        return;
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decoding JSON clipboard data: {ex.Message}");
                    // Continue with standard processing
                }

                // Standard processing as fallback
                foundDevice = _deviceManager.GetDeviceById(senderId);
                if (foundDevice == null && !string.IsNullOrEmpty(senderHwId))
                {
                    foundDevice = _deviceManager.GetDeviceByHardwareId(senderHwId);

                    // If found by hardware ID, update its device ID to match the current sender
                    if (foundDevice != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Found device {foundDevice.DeviceName} by hardware ID, updating device ID from {foundDevice.DeviceId} to {senderId}");
                        foundDevice.DeviceId = senderId;
                        _deviceManager.UpdateDevice(foundDevice);
                    }
                }

                if (foundDevice == null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device for clipboard data: ID={senderId}, HwID={senderHwId}");
                    return;
                }

                // Update hardware ID if needed
                if (!string.IsNullOrEmpty(senderHwId) && (string.IsNullOrEmpty(foundDevice.HardwareId) || foundDevice.HardwareId != senderHwId))
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Updating hardware ID for device {foundDevice.DeviceName} ({foundDevice.DeviceId}): {senderHwId}");
                    foundDevice.HardwareId = senderHwId;
                    _deviceManager.UpdateDevice(foundDevice);
                }

                // Standard clipboard data deserialization and processing
                try
                {
                    var clipboardUpdate = JsonSerializer.Deserialize<ClipboardUpdateMessage>(Encoding.UTF8.GetString(Convert.FromBase64String(encryptedData)));
                    if (clipboardUpdate != null)
                    {
                        // Decrypt clipboard data
                        if (!string.IsNullOrEmpty(clipboardUpdate.Data) && !string.IsNullOrEmpty(foundDevice.SharedKey))
                        {
                            ClipboardData clipboardData;

                            if (clipboardUpdate.Format == "text/plain" && !clipboardUpdate.IsBinary)
                            {
                                // Decrypt text
                                var decryptedText = _encryptionService.DecryptText(clipboardUpdate.Data, foundDevice.SharedKey);
                                clipboardData = ClipboardData.CreateText(decryptedText);
                            }
                            else if (clipboardUpdate.Format == "image/png" && clipboardUpdate.IsBinary)
                            {
                                // Decrypt binary data
                                var encryptedBytes = Convert.FromBase64String(clipboardUpdate.Data);
                                var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(foundDevice.SharedKey));
                                clipboardData = ClipboardData.CreateImage(decryptedBytes);
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Unsupported clipboard format: {clipboardUpdate.Format}");
                                return;
                            }

                            // Update device last seen
                            _deviceManager.UpdateDeviceLastSeen(foundDevice.DeviceId);

                            // Notify listeners
                            ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, foundDevice));
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing clipboard data: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing encrypted data: {ex.Message}");
            }
        }


        /// <summary>
        /// Accept incoming WebSocket connections
        /// </summary>
        private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
        {
            if (_httpListener == null)
                return;

            try
            {
                while (_isListening && !cancellationToken.IsCancellationRequested)
                {
                    // Wait for a connection
                    var context = await _httpListener.GetContextAsync();

                    // Check if it's a WebSocket request
                    if (context.Request.IsWebSocketRequest)
                    {
                        // Process it
                        ProcessWebSocketRequest(context, cancellationToken);
                    }
                    else
                    {
                        // Not a WebSocket request, return 400
                        context.Response.StatusCode = 400;
                        context.Response.Close();
                    }
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException || cancellationToken.IsCancellationRequested)
            {
                // Canceled, just return
                System.Diagnostics.Debug.WriteLine("[NETWORK] WebSocket server canceled");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error accepting connections: {ex.Message}");
                StopAsync();
            }
        }

        /// <summary>
        /// Process a WebSocket request
        /// </summary>
        private async void ProcessWebSocketRequest(HttpListenerContext context, CancellationToken cancellationToken)
        {
            if (context == null)
                return;

            WebSocket? webSocket = null;
            string? deviceId = null;

            try
            {
                // Accept the WebSocket connection
                var webSocketContext = await context.AcceptWebSocketAsync(null);
                webSocket = webSocketContext.WebSocket;

                // Get the client's IP
                var ipAddress = context.Request.RemoteEndPoint.Address.ToString();
                System.Diagnostics.Debug.WriteLine($"[NETWORK] WebSocket connection from {ipAddress}");

                // Process messages
                await ProcessMessagesAsync(webSocket, ipAddress, cancellationToken);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing WebSocket request: {ex.Message}");

                if (webSocket != null && webSocket.State == WebSocketState.Open)
                {
                    try
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.InternalServerError, "Error processing request", cancellationToken);
                    }
                    catch
                    {
                        // Ignore errors
                    }
                }
            }
            finally
            {
                // Remove the client from connected clients
                if (deviceId != null && _connectedClients.ContainsKey(deviceId))
                {
                    _connectedClients.Remove(deviceId);
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Client {deviceId} disconnected");
                }

                // Dispose the WebSocket
                webSocket?.Dispose();
            }
        }

        /// <summary>
        /// Process messages from a WebSocket client
        /// </summary>
        private async Task ProcessMessagesAsync(WebSocket webSocket, string ipAddress, CancellationToken cancellationToken)
        {
            if (webSocket == null)
                return;

            var buffer = new byte[16384]; // 16KB buffer
            string? deviceId = null;
            PairedDevice? device = null;
            string? hardwareId = null;

            // Message reassembly state
            StringBuilder messageBuilder = new StringBuilder();

            try
            {
                while (webSocket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    // Receive a message
                    var receiveResult = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);

                    // Check if the client is closing the connection
                    if (receiveResult.MessageType == WebSocketMessageType.Close)
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", cancellationToken);
                        break;
                    }

                    // Process the message
                    if (receiveResult.MessageType == WebSocketMessageType.Text)
                    {
                        // Append this frame to the message builder
                        var frameText = Encoding.UTF8.GetString(buffer, 0, receiveResult.Count);
                        messageBuilder.Append(frameText);

                        // If this is the final frame of the message, process the complete message
                        if (receiveResult.EndOfMessage)
                        {
                            var message = messageBuilder.ToString();
                            messageBuilder.Clear(); // Reset for next message

                            // Log a snippet of the message
                            int logLength = Math.Min(100, message.Length);
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received complete message, length={message.Length}, starts with: {message.Substring(0, logLength)}...");

                            try
                            {
                                // Parse the message as JSON
                                var jsonDoc = JsonDocument.Parse(message);
                                var root = jsonDoc.RootElement;

                                // Check message type
                                if (root.TryGetProperty("type", out var typeProperty))
                                {
                                    var type = typeProperty.GetString() ?? string.Empty;

                                    if (Enum.TryParse<MessageType>(type, true, out var messageType))
                                    {
                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Received message of type {messageType}");

                                        // Save hardware ID if provided
                                        if (root.TryGetProperty("hardware_id", out var hwIdProperty))
                                        {
                                            hardwareId = hwIdProperty.GetString() ?? string.Empty;
                                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Message contains hardware ID: {hardwareId}");
                                        }

                                        // Handle messages of different types
                                        switch (messageType)
                                        {
                                            case MessageType.PairingRequest:
                                                await HandlePairingRequestAsync(webSocket, root, ipAddress, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.PairingResponse:
                                                await HandlePairingResponseAsync(root, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.Auth:
                                                // Try to authenticate the device
                                                deviceId = await HandleAuthAsync(webSocket, root, ipAddress, hardwareId, cancellationToken);

                                                // Get the device
                                                if (!string.IsNullOrEmpty(deviceId))
                                                {
                                                    device = _deviceManager.GetDeviceById(deviceId);
                                                    if (device != null)
                                                    {
                                                        // Add to connected clients
                                                        _connectedClients[deviceId] = webSocket;
                                                    }
                                                }
                                                break;

                                            case MessageType.AuthChallenge:
                                                await HandleAuthChallengeAsync(webSocket, root, ipAddress, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.AuthResponse:
                                                await HandleAuthResponseAsync(webSocket, root, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.AuthVerify:
                                                await HandleAuthVerifyAsync(webSocket, root, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.AuthSuccess:
                                                await HandleAuthSuccessAsync(webSocket, root, hardwareId, cancellationToken);
                                                break;

                                            case MessageType.ClipboardUpdate:
                                                // Only process clipboard updates from authenticated devices
                                                if (device != null)
                                                {
                                                    // Verify hardware ID if provided
                                                    if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                                                        hardwareId != device.HardwareId)
                                                    {
                                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch: {hardwareId} vs {device.HardwareId}");
                                                        continue;
                                                    }

                                                    await HandleClipboardUpdateAsync(root, device, cancellationToken);
                                                }
                                                break;

                                            case MessageType.KeyRotationUpdate:
                                                if (device != null)
                                                {
                                                    // Verify hardware ID if provided
                                                    if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                                                        hardwareId != device.HardwareId)
                                                    {
                                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch: {hardwareId} vs {device.HardwareId}");
                                                        continue;
                                                    }

                                                    await HandleKeyRotationUpdateAsync(root, device, cancellationToken);
                                                }
                                                break;

                                            case MessageType.KeyRotationRequest:
                                                if (device != null)
                                                {
                                                    // Verify hardware ID if provided
                                                    if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                                                        hardwareId != device.HardwareId)
                                                    {
                                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch: {hardwareId} vs {device.HardwareId}");
                                                        continue;
                                                    }

                                                    await HandleKeyRotationRequestAsync(webSocket, root, device, cancellationToken);
                                                }
                                                break;

                                            default:
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Unhandled message type: {messageType}");
                                                break;
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing message: {ex.Message}");

                                var errorMessage = new ErrorMessage
                                {
                                    DeviceId = _deviceManager.LocalDeviceId,
                                    DeviceName = _deviceManager.LocalDeviceName,
                                    HardwareId = _deviceManager.LocalHardwareId,
                                    Error = "Error processing message"
                                };

                                await SendMessageAsync(webSocket, errorMessage, cancellationToken);
                            }
                        }
                        else
                        {
                            // This is a continuation frame, just log that we're accumulating
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received partial message frame, size={receiveResult.Count}, accumulated={messageBuilder.Length}");
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException || cancellationToken.IsCancellationRequested)
            {
                // Canceled, just return
                System.Diagnostics.Debug.WriteLine("[NETWORK] WebSocket processing canceled");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing messages: {ex.Message}");

                if (webSocket.State == WebSocketState.Open)
                {
                    try
                    {
                        await webSocket.CloseAsync(WebSocketCloseStatus.InternalServerError, "Error processing messages", cancellationToken);
                    }
                    catch
                    {
                        // Ignore errors
                    }
                }
            }
        }

        /// <summary>
        /// Handle a pairing request
        /// </summary>
        private async Task HandlePairingRequestAsync(WebSocket webSocket, JsonElement root, string ipAddress, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var deviceName = root.GetProperty("device_name").GetString() ?? string.Empty;
            var requestId = root.GetProperty("request_id").GetString() ?? string.Empty;

            // Extract challenge and public key if available
            string challenge = string.Empty;
            string publicKey = string.Empty;

            if (root.TryGetProperty("challenge", out var challengeProperty))
            {
                challenge = challengeProperty.GetString() ?? string.Empty;
            }

            if (root.TryGetProperty("public_key", out var publicKeyProperty))
            {
                publicKey = publicKeyProperty.GetString() ?? string.Empty;
            }

            // Extract platform if possible
            string platform = "Windows";
            if (root.TryGetProperty("platform", out var platformElement))
            {
                platform = platformElement.GetString() ?? "Windows";
            }

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing request from {deviceName} ({deviceId}), platform: {platform}, HW ID: {hardwareId}");

            // Handle the pairing request
            var accepted = _deviceManager.HandlePairingRequest(deviceId, deviceName, ipAddress, DEFAULT_PORT, platform, hardwareId, challenge, publicKey);

            // Generate our challenge for authentication
            string ourChallenge = !string.IsNullOrEmpty(challenge) ? _deviceManager.GenerateChallenge() : string.Empty;

            // If device accepted, sign their challenge
            string challengeResponse = string.Empty;
            if (accepted && !string.IsNullOrEmpty(challenge))
            {
                challengeResponse = _deviceManager.SignChallenge(challenge);
            }

            // Send response
            var response = new PairingResponseMessage
            {
                DeviceId = _deviceManager.LocalDeviceId,
                DeviceName = _deviceManager.LocalDeviceName,
                RequestId = requestId,
                Accepted = accepted,
                HardwareId = _deviceManager.LocalHardwareId
            };

            // If accepted, include the shared key
            if (accepted)
            {
                var device = _deviceManager.GetDeviceById(deviceId);
                if (device != null)
                {
                    response.EncryptedSharedKey = device.SharedKey;

                    // Add challenge/response if we have them
                    if (!string.IsNullOrEmpty(challenge) && !string.IsNullOrEmpty(challengeResponse))
                    {
                        response.ChallengeResponse = challengeResponse;
                        response.Challenge = ourChallenge;
                        response.PublicKey = _deviceManager.GetPublicKey();
                    }
                }
            }

            await SendMessageAsync(webSocket, response, cancellationToken);
        }

        /// <summary>
        /// Handle a pairing response
        /// </summary>
        private async Task HandlePairingResponseAsync(JsonElement root, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract response information
            var requestId = root.GetProperty("request_id").GetString() ?? string.Empty;
            var accepted = root.GetProperty("accepted").GetBoolean();

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing response for request {requestId}: {accepted}");

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            // If we have a pending request for this ID, complete it
            if (_pairingRequests.TryGetValue(requestId, out var tcs))
            {
                // If accepted, get the device info and shared key
                if (accepted &&
                    root.TryGetProperty("device_id", out var deviceIdElement) &&
                    root.TryGetProperty("device_name", out var deviceNameElement) &&
                    root.TryGetProperty("encrypted_shared_key", out var sharedKeyElement))
                {
                    var deviceId = deviceIdElement.GetString() ?? string.Empty;
                    var deviceName = deviceNameElement.GetString() ?? string.Empty;
                    var sharedKey = sharedKeyElement.GetString() ?? string.Empty;

                    // Create and add the device
                    var device = new PairedDevice
                    {
                        DeviceId = deviceId,
                        DeviceName = deviceName,
                        IpAddress = root.TryGetProperty("ip_address", out var ipElement) ? ipElement.GetString() ?? string.Empty : string.Empty,
                        Port = root.TryGetProperty("port", out var portElement) ? portElement.GetInt32() : DEFAULT_PORT,
                        Platform = "Unknown",
                        SharedKey = sharedKey,
                        CurrentKeyId = _encryptionService.GetCurrentKeyId(), // Use our current key ID
                        LastSeen = DateTime.Now,
                        HardwareId = hardwareId ?? string.Empty
                    };

                    // Check for challenge-response data
                    if (root.TryGetProperty("challenge_response", out var responseElement) &&
                        root.TryGetProperty("challenge", out var challengeElement) &&
                        root.TryGetProperty("public_key", out var keyElement))
                    {
                        string challengeResponse = responseElement.GetString() ?? string.Empty;
                        string challenge = challengeElement.GetString() ?? string.Empty;
                        string publicKey = keyElement.GetString() ?? string.Empty;

                        // Store public key
                        device.PublicKey = publicKey;

                        // Process challenge-response (verify their response and sign their challenge)
                        if (!string.IsNullOrEmpty(challengeResponse) && !string.IsNullOrEmpty(challenge) && !string.IsNullOrEmpty(publicKey))
                        {
                            // Verify their response to our challenge
                            bool isValid = _deviceManager.HandleChallengeResponse(deviceId, challengeResponse, challenge, hardwareId ?? string.Empty);

                            if (isValid)
                            {
                                // Sign their challenge
                                string signedResponse = _deviceManager.SignChallenge(challenge);

                                // Send the verification
                                var authVerify = new AuthVerifyMessage
                                {
                                    DeviceId = _deviceManager.LocalDeviceId,
                                    DeviceName = _deviceManager.LocalDeviceName,
                                    HardwareId = _deviceManager.LocalHardwareId,
                                    ChallengeResponse = signedResponse
                                };

                                // Get the device WebSocket
                                if (_connectedClients.TryGetValue(deviceId, out var deviceWs))
                                {
                                    await SendMessageAsync(deviceWs, authVerify, cancellationToken);
                                }
                            }
                        }
                    }

                    _deviceManager.AddOrUpdateDevice(device);
                }

                // Complete the task
                tcs.TrySetResult(accepted);
                _pairingRequests.Remove(requestId);
            }
        }

        /// <summary>
        /// Handle an authentication challenge
        /// </summary>
        private async Task HandleAuthChallengeAsync(WebSocket webSocket, JsonElement root, string ipAddress, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var publicKey = root.GetProperty("public_key").GetString() ?? string.Empty;
            var challenge = root.GetProperty("challenge").GetString() ?? string.Empty;

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth challenge from {deviceId}");

            // Process the challenge
            string response = _deviceManager.HandleChallengeRequest(deviceId, challenge, publicKey, hardwareId ?? string.Empty);

            // Generate our own challenge
            string ourChallenge = _deviceManager.GenerateChallenge();

            // Send the response
            var authResponse = new AuthResponseMessage
            {
                DeviceId = _deviceManager.LocalDeviceId,
                DeviceName = _deviceManager.LocalDeviceName,
                HardwareId = _deviceManager.LocalHardwareId,
                ChallengeResponse = response,
                Challenge = ourChallenge
            };

            await SendMessageAsync(webSocket, authResponse, cancellationToken);
        }

        /// <summary>
        /// Handle an authentication response
        /// </summary>
        private async Task HandleAuthResponseAsync(WebSocket webSocket, JsonElement root, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var challengeResponse = root.GetProperty("challenge_response").GetString() ?? string.Empty;
            var challenge = root.GetProperty("challenge").GetString() ?? string.Empty;

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth response from {deviceId}");

            // Verify their response and sign their challenge
            bool isValid = _deviceManager.HandleChallengeResponse(deviceId, challengeResponse, challenge, hardwareId ?? string.Empty);

            if (isValid)
            {
                // Sign their challenge
                string signedResponse = _deviceManager.SignChallenge(challenge);

                // Send verification
                var authVerify = new AuthVerifyMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    ChallengeResponse = signedResponse
                };

                await SendMessageAsync(webSocket, authVerify, cancellationToken);
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Invalid challenge response from {deviceId}");
            }
        }

        /// <summary>
        /// Handle an authentication verification
        /// </summary>
        private async Task HandleAuthVerifyAsync(WebSocket webSocket, JsonElement root, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var challengeResponse = root.GetProperty("challenge_response").GetString() ?? string.Empty;

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth verification from {deviceId}");

            // Verify their response
            bool isValid = _deviceManager.HandleAuthVerify(deviceId, challengeResponse, hardwareId ?? string.Empty);

            // Send success or failure
            var authSuccess = new AuthSuccessMessage
            {
                DeviceId = _deviceManager.LocalDeviceId,
                DeviceName = _deviceManager.LocalDeviceName,
                HardwareId = _deviceManager.LocalHardwareId,
                Trusted = isValid
            };

            await SendMessageAsync(webSocket, authSuccess, cancellationToken);

            if (isValid)
            {
                // Get the device
                var device = _deviceManager.GetDeviceById(deviceId);
                if (device != null)
                {
                    // Update device as authenticated
                    device.IsAuthenticated = true;
                    device.HardwareId = hardwareId ?? string.Empty;
                    _deviceManager.UpdateDevice(device);
                }
            }
        }

        /// <summary>
        /// Handle an authentication success message
        /// </summary>
        private async Task HandleAuthSuccessAsync(WebSocket webSocket, JsonElement root, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var trusted = root.GetProperty("trusted").GetBoolean();

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth success from {deviceId}, trusted: {trusted}");

            // Process the success
            _deviceManager.HandleAuthSuccess(deviceId, trusted, hardwareId ?? string.Empty);

            // Update device if trusted
            if (trusted)
            {
                var device = _deviceManager.GetDeviceById(deviceId);
                if (device != null)
                {
                    // Update device as authenticated
                    device.IsAuthenticated = true;
                    device.HardwareId = hardwareId ?? string.Empty;
                    _deviceManager.UpdateDevice(device);
                }
            }
        }

        /// <summary>
        /// Handle an authentication request
        /// </summary>
        private async Task<string?> HandleAuthAsync(WebSocket webSocket, JsonElement root, string ipAddress, string? hardwareId, CancellationToken cancellationToken)
        {
            // Extract auth information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var deviceName = root.GetProperty("device_name").GetString() ?? string.Empty;

            // Get hardware ID from message or parameter
            if (string.IsNullOrEmpty(hardwareId) && root.TryGetProperty("hardware_id", out var hwIdElement))
            {
                hardwareId = hwIdElement.GetString() ?? string.Empty;
            }

            // Get key ID if available
            uint keyId = 0;
            if (root.TryGetProperty("key_id", out var keyIdElement))
            {
                keyId = keyIdElement.GetUInt32();
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth request from {deviceName} ({deviceId}) with key ID {keyId}");

            // Check if the device is paired by ID or hardware ID
            PairedDevice? device = _deviceManager.GetDeviceById(deviceId);

            // If not found by ID but hardware ID is provided, try that
            if (device == null && !string.IsNullOrEmpty(hardwareId))
            {
                device = _deviceManager.GetDeviceByHardwareId(hardwareId);

                // If found by hardware ID, update its device ID
                if (device != null)
                {
                    device.DeviceId = deviceId;
                    _deviceManager.UpdateDevice(device);
                }
            }

            if (device != null)
            {
                // Check if key rotation is needed
                bool needsKeyUpdate = false;

                // If device has a different key ID than us, we need to update
                if (keyId > 0 && keyId != _encryptionService.GetCurrentKeyId())
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device has key ID {keyId}, we have {_encryptionService.GetCurrentKeyId()}");
                    needsKeyUpdate = true;
                }

                // If our key is expired, we need to rotate
                if (_encryptionService.ShouldRotateKey())
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Our key needs rotation");
                    await CheckAndHandleKeyRotationAsync(cancellationToken);
                }

                // Update device info
                device.DeviceName = deviceName;
                device.IpAddress = ipAddress;
                device.CurrentKeyId = keyId;

                // Update hardware ID if provided
                if (!string.IsNullOrEmpty(hardwareId))
                {
                    device.HardwareId = hardwareId;
                }

                _deviceManager.UpdateDeviceLastSeen(deviceId);

                // Send success response
                var response = new AuthSuccessMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    KeyId = _encryptionService.GetCurrentKeyId(),
                    Trusted = true
                };

                await SendMessageAsync(webSocket, response, cancellationToken);

                // If key update is needed, send it
                if (needsKeyUpdate)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending key update package to {deviceName}");
                    await SendKeyUpdateToDeviceAsync(device, webSocket, cancellationToken);
                }

                // Add to connected clients
                _connectedClients[deviceId] = webSocket;

                return deviceId;
            }
            else
            {
                // Send failure response
                var response = new AuthFailedMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    Reason = "Device not paired"
                };

                await SendMessageAsync(webSocket, response, cancellationToken);

                return null;
            }
        }

        /// <summary>
        /// Connect to a device using secure WebSocket (WSS)
        /// </summary>
        private async Task<WebSocket?> ConnectToDeviceAsync(PairedDevice device, CancellationToken cancellationToken)
        {
            // If this is a relay-paired device, handle differently
            if (device.IsRelayPaired)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} is relay-paired, checking relay connection");

                // Check relay connection
                if (!_isConnectedToRelayServer || _relayConnection == null)
                {
                    // Try to connect to relay server
                    bool connected = await ConnectToRelayServerAsync(cancellationToken);
                    if (!connected)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Cannot connect to relay-paired device {device.DeviceName} - relay server not connected");
                        return null;
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Using relay connection for device {device.DeviceName} (ID: {device.DeviceId}, Relay ID: {device.RelayDeviceId})");

                // For relay devices, we use the relay connection
                return null; // No direct WebSocket connection for relay devices
            }

            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Connecting to {device.DeviceName} at {device.IpAddress}:{device.Port}");

                var uri = new Uri($"wss://{device.IpAddress}:{device.Port}/");
                var client = new ClientWebSocket();

                // Enhanced certificate validation with certificate pinning
                client.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => {
                    string thumbprint = certificate?.GetCertHashString() ?? string.Empty;

                    // First connection to this device
                    if (!_trustedCertificates.TryGetValue(device.IpAddress, out var storedThumbprint))
                    {
                        _trustedCertificates[device.IpAddress] = thumbprint;
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Trusting certificate {thumbprint} for {device.IpAddress}");
                        return true;
                    }

                    // For subsequent connections, verify it's the same certificate
                    bool isValid = string.Equals(thumbprint, storedThumbprint, StringComparison.OrdinalIgnoreCase);
                    if (!isValid)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Certificate mismatch for {device.IpAddress}!");
                    }
                    return isValid;
                };

                var timeoutToken = new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token;
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutToken);

                // Connect to the device
                await client.ConnectAsync(uri, linkedCts.Token);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Connected to {device.DeviceName}, sending auth message");

                // Create auth message with current key ID and hardware ID
                var authMessage = new AuthMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    KeyId = _encryptionService.GetCurrentKeyId()
                };

                // Send message
                var json = JsonSerializer.Serialize(authMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                await client.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, linkedCts.Token);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Auth message sent to {device.DeviceName}");

                // Start listening for responses
                _ = Task.Run(async () =>
                {
                    await ProcessWebSocketMessagesAsync(client, device);
                });

                // Add to connected clients
                _connectedClients[device.DeviceId] = client;

                // Update device last seen
                _deviceManager.UpdateDeviceLastSeen(device.DeviceId);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully connected to {device.DeviceName}");

                return client;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error connecting to {device.DeviceName}: {ex.Message}");
                return null;
            }
        }



        /// <summary>
        /// Process messages from a WebSocket connection
        /// </summary>
        private async Task ProcessWebSocketMessagesAsync(WebSocket webSocket, PairedDevice device)
        {
            var buffer = new byte[16384];
            StringBuilder messageBuilder = new StringBuilder();

            try
            {
                while (webSocket.State == WebSocketState.Open)
                {
                    var receiveResult = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                    // Check if the connection is closed
                    if (receiveResult.MessageType == WebSocketMessageType.Close)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Connection closed by {device.DeviceName}");

                        // Close our side of the connection
                        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Connection closed by peer", CancellationToken.None);

                        // Remove from connected clients
                        _connectedClients.Remove(device.DeviceId);
                        break;
                    }

                    // Handle text messages
                    if (receiveResult.MessageType == WebSocketMessageType.Text)
                    {
                        // Append this frame to the message builder
                        var frameText = Encoding.UTF8.GetString(buffer, 0, receiveResult.Count);
                        messageBuilder.Append(frameText);

                        // If this is the final frame of the message, process the complete message
                        if (receiveResult.EndOfMessage)
                        {
                            var message = messageBuilder.ToString();
                            messageBuilder.Clear(); // Reset for next message

                            int logLength = Math.Min(100, message.Length);
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received complete message from {device.DeviceName}, length={message.Length}, starts with: {message.Substring(0, logLength)}...");

                            // Now handle the message
                            try
                            {
                                var jsonDoc = JsonDocument.Parse(message);
                                var root = jsonDoc.RootElement;

                                if (root.TryGetProperty("type", out var typeProperty))
                                {
                                    var typeStr = typeProperty.GetString() ?? string.Empty;

                                    if (Enum.TryParse<MessageType>(typeStr, true, out var messageType))
                                    {
                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Message type: {messageType}");

                                        // Extract hardware ID if present
                                        string? hardwareId = null;
                                        if (root.TryGetProperty("hardware_id", out var hwIdProperty))
                                        {
                                            hardwareId = hwIdProperty.GetString();

                                            // Verify hardware ID if we know it
                                            if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                                                hardwareId != device.HardwareId)
                                            {
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch: {hardwareId} vs {device.HardwareId}");
                                                continue;
                                            }
                                        }

                                        switch (messageType)
                                        {
                                            case MessageType.AuthSuccess:
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Authentication successful with {device.DeviceName}");

                                                // Update key ID if available
                                                if (root.TryGetProperty("key_id", out var keyIdElement))
                                                {
                                                    var newKeyId = keyIdElement.GetUInt32();
                                                    if (newKeyId != device.CurrentKeyId)
                                                    {
                                                        device.CurrentKeyId = newKeyId;
                                                        _deviceManager.UpdateDevice(device);
                                                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Updated device key ID to {newKeyId}");
                                                    }
                                                }

                                                // Update hardware ID if available
                                                if (!string.IsNullOrEmpty(hardwareId))
                                                {
                                                    device.HardwareId = hardwareId;
                                                    _deviceManager.UpdateDevice(device);
                                                }
                                                break;

                                            case MessageType.AuthFailed:
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Authentication failed with {device.DeviceName}");
                                                await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Authentication failed", CancellationToken.None);
                                                _connectedClients.Remove(device.DeviceId);
                                                break;

                                            case MessageType.AuthChallenge:
                                                await HandleAuthChallengeAsync(webSocket, root, device.IpAddress, hardwareId, CancellationToken.None);
                                                break;

                                            case MessageType.AuthResponse:
                                                await HandleAuthResponseAsync(webSocket, root, hardwareId, CancellationToken.None);
                                                break;

                                            case MessageType.AuthVerify:
                                                await HandleAuthVerifyAsync(webSocket, root, hardwareId, CancellationToken.None);
                                                break;

                                            case MessageType.ClipboardUpdate:
                                                await HandleClipboardUpdateAsync(root, device, CancellationToken.None);
                                                break;

                                            case MessageType.KeyRotationUpdate:
                                                await HandleKeyRotationUpdateAsync(root, device, CancellationToken.None);
                                                break;

                                            case MessageType.KeyRotationRequest:
                                                await HandleKeyRotationRequestAsync(webSocket, root, device, CancellationToken.None);
                                                break;

                                            default:
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Unhandled message type: {messageType}");
                                                break;
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing message: {ex.Message}");
                            }
                        }
                        else
                        {
                            // This is a continuation frame, just log that we're accumulating
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received partial message frame from {device.DeviceName}, size={receiveResult.Count}, accumulated={messageBuilder.Length}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error in WebSocket processing: {ex.Message}");
            }
            finally
            {
                // Remove from connected clients if not already removed
                if (_connectedClients.ContainsKey(device.DeviceId))
                {
                    _connectedClients.Remove(device.DeviceId);
                }

                // Dispose the WebSocket
                webSocket.Dispose();
            }
        }

        /// <summary>
        /// Handle a clipboard update
        /// </summary>
        private async Task HandleClipboardUpdateAsync(JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Processing clipboard update from {device.DeviceName}");

                // Extract clipboard data
                var format = root.GetProperty("format").GetString() ?? string.Empty;
                var data = root.GetProperty("data").GetString() ?? string.Empty;
                var isBinary = root.TryGetProperty("is_binary", out var isBinaryElement) && isBinaryElement.GetBoolean();

                // Get key ID if available, otherwise use device's current key ID
                uint keyId = device.CurrentKeyId;
                if (root.TryGetProperty("key_id", out var keyIdElement))
                {
                    keyId = keyIdElement.GetUInt32();
                }

                // Get hardware ID if available
                string? hardwareId = null;
                if (root.TryGetProperty("hardware_id", out var hwIdProperty))
                {
                    hardwareId = hwIdProperty.GetString();

                    // Verify hardware ID if we know it
                    if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                        hardwareId != device.HardwareId)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch in clipboard update: {hardwareId} vs {device.HardwareId}");
                        return;
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Clipboard format: {format}, IsBinary: {isBinary}, Data length: {data.Length}, Key ID: {keyId}");

                // If key ID doesn't match, request an update
                if (keyId != _encryptionService.GetCurrentKeyId())
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Key ID mismatch: device={keyId}, local={_encryptionService.GetCurrentKeyId()}");

                    await RequestKeyUpdateAsync(device, cancellationToken);
                    return;
                }

                // Decrypt the data
                if (!string.IsNullOrEmpty(data) && !string.IsNullOrEmpty(device.SharedKey))
                {
                    try
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Decrypting data with shared key of length {device.SharedKey.Length}");

                        // Create clipboard data
                        ClipboardData clipboardData;

                        if (format == "text/plain" && !isBinary)
                        {
                            // Decrypt text
                            var decryptedText = _encryptionService.DecryptText(data, device.SharedKey);
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Decrypted text length: {decryptedText.Length}");
                            clipboardData = ClipboardData.CreateText(decryptedText);
                        }
                        else if (format == "image/png" && isBinary)
                        {
                            // Decrypt binary data
                            var encryptedBytes = Convert.FromBase64String(data);
                            var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(device.SharedKey));
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Decrypted binary length: {decryptedBytes.Length}");
                            clipboardData = ClipboardData.CreateImage(decryptedBytes);
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Unsupported clipboard format: {format}");
                            return;
                        }

                        // Notify listeners
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Notifying clipboard data received listeners");
                        ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, device));
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting clipboard data: {ex.Message}");
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] No data or shared key for decryption");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling clipboard update: {ex.Message}");
            }
        }

        /// <summary>
        /// Send a pairing request to a device using secure connection
        /// </summary>
        public async Task<bool> SendPairingRequestAsync(string ipAddress, bool useRelay = false, int port = DEFAULT_PORT, CancellationToken cancellationToken = default)
        {
            // Handle relay pairing differently
            if (useRelay)
            {
                return await SendRelayPairingRequestAsync(ipAddress, cancellationToken);
            }

            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending pairing request to {ipAddress}:{port}");

                // Create a secure WSS
                var uri = new Uri($"wss://{ipAddress}:{port}/");
                using var client = new ClientWebSocket();

                // Set up certificate validation with pinning
                client.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => {
                    string thumbprint = certificate?.GetCertHashString() ?? string.Empty;

                    // First connection to this IP address during pairing
                    if (!_trustedCertificates.TryGetValue(ipAddress, out var storedThumbprint))
                    {
                        // During pairing, we trust the first certificate encountered for this IP
                        // The user should verify this out-of-band if possible, or accept the risk
                        _trustedCertificates[ipAddress] = thumbprint;
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Pairing: Trusting certificate {thumbprint} for {ipAddress}");
                        return true;
                    }

                    // For subsequent connections (shouldn't happen during initial pairing request, but good practice)
                    bool isValid = string.Equals(thumbprint, storedThumbprint, StringComparison.OrdinalIgnoreCase);
                    if (!isValid)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Pairing: Certificate mismatch for {ipAddress}!");
                    }
                    return isValid;
                };

                // Set a connection timeout
                var timeoutToken = new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutToken);

                // Connect to the device
                await client.ConnectAsync(uri, linkedCts.Token);

                // Generate a challenge for secure pairing
                string challenge = _deviceManager.GenerateChallenge();
                string publicKey = _deviceManager.GetPublicKey();

                // Create a pairing request message
                var request = new PairingRequestMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    Platform = _deviceManager.LocalPlatform,
                    Challenge = challenge,
                    PublicKey = publicKey
                };

                // Create a task completion source for the response
                var tcs = new TaskCompletionSource<bool>();
                _pairingRequests[request.RequestId] = tcs;

                // Send the request
                await SendMessageAsync(client, request, linkedCts.Token);

                // Start listening for the response
                _ = Task.Run(async () =>
                {
                    var buffer = new byte[16384];

                    try
                    {
                        while (client.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                        {
                            // Receive a message
                            var receiveResult = await client.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);

                            // Check if the server is closing the connection
                            if (receiveResult.MessageType == WebSocketMessageType.Close)
                            {
                                await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", cancellationToken);
                                tcs.TrySetResult(false);
                                break;
                            }

                            // Process the message
                            if (receiveResult.MessageType == WebSocketMessageType.Text)
                            {
                                var message = Encoding.UTF8.GetString(buffer, 0, receiveResult.Count);

                                try
                                {
                                    // Parse the message as JSON
                                    var jsonDoc = JsonDocument.Parse(message);
                                    var root = jsonDoc.RootElement;

                                    // Check message type
                                    if (root.TryGetProperty("type", out var typeProperty))
                                    {
                                        var type = typeProperty.GetString() ?? string.Empty;

                                        if (type == MessageType.PairingResponse.ToString())
                                        {
                                            // Handle pairing response
                                            await HandlePairingResponseAsync(root, null, cancellationToken);

                                            // If there's challenge/response data, handle verification
                                            if (root.TryGetProperty("challenge_response", out var responseElement) &&
                                                root.TryGetProperty("challenge", out var challengeElement) &&
                                                root.TryGetProperty("public_key", out var keyElement))
                                            {
                                                string challengeResponse = responseElement.GetString() ?? string.Empty;
                                                string newChallenge = challengeElement.GetString() ?? string.Empty;
                                                string theirPublicKey = keyElement.GetString() ?? string.Empty;

                                                // Get device ID
                                                string deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;

                                                // Verify their response to our challenge
                                                if (!string.IsNullOrEmpty(challengeResponse) && !string.IsNullOrEmpty(newChallenge) &&
                                                    !string.IsNullOrEmpty(theirPublicKey))
                                                {
                                                    bool isValid = _deviceManager.VerifyChallengeResponse(challenge, challengeResponse, theirPublicKey);

                                                    if (isValid)
                                                    {
                                                        // Sign their challenge
                                                        string signedResponse = _deviceManager.SignChallenge(newChallenge);

                                                        // Send verification
                                                        var authVerify = new AuthVerifyMessage
                                                        {
                                                            DeviceId = _deviceManager.LocalDeviceId,
                                                            DeviceName = _deviceManager.LocalDeviceName,
                                                            HardwareId = _deviceManager.LocalHardwareId,
                                                            ChallengeResponse = signedResponse
                                                        };

                                                        await SendMessageAsync(client, authVerify, cancellationToken);
                                                    }
                                                }
                                            }

                                            // Close the connection
                                            await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Pairing complete", cancellationToken);
                                            break;
                                        }
                                        else if (type == MessageType.AuthVerify.ToString())
                                        {
                                            // Handle verification
                                            await HandleAuthVerifyAsync(client, root, null, cancellationToken);

                                            // Close the connection - pairing is complete
                                            await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Pairing complete", cancellationToken);
                                            break;
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing pairing response: {ex.Message}");
                                    tcs.TrySetResult(false);
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Error receiving pairing response: {ex.Message}");
                        tcs.TrySetResult(false);
                    }
                });

                // Wait for the response with a timeout
                if (await Task.WhenAny(tcs.Task, Task.Delay(30000, cancellationToken)) == tcs.Task)
                {
                    return await tcs.Task;
                }
                else
                {
                    // Timeout
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Pairing request timed out");
                    _pairingRequests.Remove(request.RequestId);
                    return false;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending pairing request: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send a pairing request via the relay server
        /// </summary>
        private async Task<bool> SendRelayPairingRequestAsync(string targetDeviceId, CancellationToken cancellationToken = default)
        {
            try
            {
                // Check if connected to relay server
                if (!_isConnectedToRelayServer || _relayConnection == null)
                {
                    // Try to connect
                    bool connected = await ConnectToRelayServerAsync(cancellationToken);
                    if (!connected)
                    {
                        System.Diagnostics.Debug.WriteLine("[NETWORK] Cannot send relay pairing request, not connected to relay server");
                        return false;
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending relay pairing request to {targetDeviceId}");

                // Generate a challenge for secure pairing
                string challenge = _deviceManager.GenerateChallenge();
                string publicKey = _deviceManager.GetPublicKey();

                // Create pairing request with a specific request ID
                string requestId = Guid.NewGuid().ToString();
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Created pairing request with ID: {requestId}");

                var request = new PairingRequestMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    Platform = _deviceManager.LocalPlatform,
                    Challenge = challenge,
                    PublicKey = publicKey,
                    RequestId = requestId // Make sure the request ID is set
                };

                // Create task completion source for response
                var tcs = new TaskCompletionSource<bool>();
                _pairingRequests[requestId] = tcs;

                // Debug output to verify the pending request was added
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Added pending request {requestId} to dictionary");

                // Send request via relay server
                await _relayConnection.SendMessageAsync(targetDeviceId, "PairingRequest", request);

                // Wait for response with timeout
                if (await Task.WhenAny(tcs.Task, Task.Delay(30000, cancellationToken)) == tcs.Task)
                {
                    return await tcs.Task;
                }
                else
                {
                    // Timeout
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Relay pairing request timed out");
                    _pairingRequests.Remove(requestId);
                    return false;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending relay pairing request: {ex.Message}");
                return false;
            }
        }


        /// <summary>
        /// Send a message to a WebSocket client
        /// </summary>
        private async Task SendMessageAsync(WebSocket webSocket, object message, CancellationToken cancellationToken)
        {
            if (webSocket == null || webSocket.State != WebSocketState.Open)
                return;

            try
            {
                // Serialize the message to JSON
                var json = JsonSerializer.Serialize(message);
                var buffer = Encoding.UTF8.GetBytes(json);

                // Log message size
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending message, size={buffer.Length} bytes");

                // For large messages send in chunks
                if (buffer.Length > 8192)
                {
                    int totalSent = 0;
                    while (totalSent < buffer.Length)
                    {
                        int chunkSize = Math.Min(8192, buffer.Length - totalSent);
                        bool isLastChunk = (totalSent + chunkSize) >= buffer.Length;

                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending chunk {totalSent}-{totalSent + chunkSize} of {buffer.Length}, isLastChunk={isLastChunk}");

                        await webSocket.SendAsync(
                            new ArraySegment<byte>(buffer, totalSent, chunkSize),
                            WebSocketMessageType.Text,
                            isLastChunk, // EndOfMessage flag
                            cancellationToken);

                        totalSent += chunkSize;
                    }

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Completed sending large message in chunks");
                }
                else
                {
                    // For small messages, send all at once
                    await webSocket.SendAsync(
                        new ArraySegment<byte>(buffer),
                        WebSocketMessageType.Text,
                        true, // EndOfMessage
                        cancellationToken);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending message: {ex.Message}");
            }
        }

        /// <summary>
        /// Send clipboard data to all connected devices
        /// </summary>
        public async Task SendClipboardDataAsync(ClipboardData data, CancellationToken cancellationToken = default)
        {
            if (data == null)
                return;

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Preparing to send clipboard data format={data.Format}");

            // Get all paired devices
            var devices = _deviceManager.GetPairedDevices();
            System.Diagnostics.Debug.WriteLine($"[NETWORK] Found {devices.Count} paired devices");

            int sentCount = 0;
            foreach (var device in devices)
            {
                try
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Processing device {device.DeviceName} ({device.DeviceId})");

                    // Handle relay devices separately
                    if (device.IsRelayPaired)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} is relay-paired with relay ID: {device.RelayDeviceId}");
                        await SendClipboardDataViaRelayAsync(data, device, cancellationToken);
                        sentCount++;
                        continue;
                    }

                    // Check if the device is connected
                    if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} not connected, attempting connection");

                        // Try to connect
                        webSocket = await ConnectToDeviceAsync(device, cancellationToken);

                        // Check again after connection attempt
                        if (webSocket == null || webSocket.State != WebSocketState.Open)
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not connect to {device.DeviceName}, skipping");
                            continue;
                        }
                    }

                    // Rest of the method for handling direct connections...
                    // (existing code)
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending clipboard data to {device.DeviceName}: {ex.Message}");
                }
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Clipboard data sent to {sentCount} devices");
        }


        /// <summary>
        /// Send clipboard data via relay server with chunking for large content
        /// </summary>
        private async Task SendClipboardDataViaRelayAsync(ClipboardData data, PairedDevice device, CancellationToken cancellationToken)
        {
            if (data == null || !device.IsRelayPaired || string.IsNullOrEmpty(device.RelayDeviceId))
            {
                System.Diagnostics.Debug.WriteLine("[NETWORK] Invalid relay device or data");
                return;
            }

            // Check relay connection
            if (!_isConnectedToRelayServer || _relayConnection == null)
            {
                // Try to connect to relay server
                bool connected = await ConnectToRelayServerAsync(cancellationToken);
                if (!connected)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Cannot send data to {device.DeviceName} - relay server not connected");
                    return;
                }
            }

            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending clipboard data via relay to {device.DeviceName}");

                // Check if we have a shared key
                if (string.IsNullOrEmpty(device.SharedKey))
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] No shared key for {device.DeviceName}, skipping");
                    return;
                }

                // Encrypt the data
                string encryptedData;
                bool isBinary = false;

                // Determine the proper content type for the relay server
                string contentType = "Text"; // Default to Text

                if (data.Format == "text/plain" && data.TextData != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Encrypting text for relay: {data.TextData.Length} chars");
                    encryptedData = _encryptionService.EncryptText(data.TextData, device.SharedKey);
                    contentType = "Text"; // Server expected value
                }
                else if (data.Format == "image/png" && data.BinaryData != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Encrypting binary for relay: {data.BinaryData.Length} bytes");
                    var encryptedBytes = _encryptionService.EncryptData(data.BinaryData, Convert.FromBase64String(device.SharedKey));
                    encryptedData = Convert.ToBase64String(encryptedBytes);
                    isBinary = true;
                    contentType = "Image"; // Server expected value
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Unsupported data format for relay: {data.Format}");
                    return;
                }

                // Create the message
                var message = new ClipboardUpdateMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    Format = data.Format,
                    Data = encryptedData,
                    IsBinary = isBinary,
                    Timestamp = data.Timestamp,
                    KeyId = _encryptionService.GetCurrentKeyId()
                };

                // Serialize message to JSON
                string messageJson = JsonSerializer.Serialize(message);
                byte[] messageBytes = Encoding.UTF8.GetBytes(messageJson);

                // IMPORTANT: Use Base64 encoding for the relay server
                string base64Message = Convert.ToBase64String(messageBytes);

                // Check size and handle chunking if needed
                int maxChunkSize = 50 * 1024; // 50KB max chunk size

                if (messageBytes.Length > maxChunkSize)
                {
                    // Need to chunk the data as it's too large
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Message size ({messageBytes.Length} bytes) exceeds max chunk size, splitting into chunks");
                    await SendChunkedClipboardDataAsync(device.RelayDeviceId, message, encryptedData, cancellationToken);
                }
                else
                {
                    // Message is small enough to send in one go
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending clipboard data as single message ({messageBytes.Length} bytes)");

                    // Send via relay server using the proper content type
                    await _relayConnection.SendEncryptedDataAsync(
                        device.RelayDeviceId,
                        base64Message,
                        contentType, // This should be either "Text" or "Image"
                        cancellationToken);
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Clipboard data sent via relay to {device.DeviceName}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending clipboard data via relay: {ex.Message}");
            }
        }

        /// <summary>
        /// Send large clipboard data in chunks via relay server
        /// </summary>
        private async Task SendChunkedClipboardDataAsync(string recipientId, ClipboardUpdateMessage message, string originalEncryptedData, CancellationToken cancellationToken)
        {
            try
            {
                // Constants for chunking
                const int maxChunkSize = 40 * 1024; // 40KB chunks to be safe
                string chunkId = Guid.NewGuid().ToString(); // Unique ID for this chunked message set

                // Split the encrypted data into chunks
                List<string> chunks = new List<string>();
                for (int i = 0; i < originalEncryptedData.Length; i += maxChunkSize)
                {
                    int length = Math.Min(maxChunkSize, originalEncryptedData.Length - i);
                    chunks.Add(originalEncryptedData.Substring(i, length));
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Splitting clipboard data into {chunks.Count} chunks");

                // Send each chunk with metadata
                for (int i = 0; i < chunks.Count; i++)
                {
                    // Create chunk message - using a simplified approach
                    var chunkMessage = new
                    {
                        type = "ClipboardChunk", // Keep message type
                        sender_id = _deviceManager.LocalDeviceId,
                        sender_name = _deviceManager.LocalDeviceName,
                        hardware_id = _deviceManager.LocalHardwareId,
                        format = message.Format,
                        is_binary = message.IsBinary,
                        key_id = message.KeyId,
                        chunk_id = chunkId, // ID to associate chunks together
                        chunk_index = i,
                        chunk_count = chunks.Count,
                        chunk_data = chunks[i],
                        timestamp = message.Timestamp
                    };

                    // Serialize and send
                    string chunkJson = JsonSerializer.Serialize(chunkMessage);
                    byte[] chunkBytes = Encoding.UTF8.GetBytes(chunkJson);
                    string base64Chunk = Convert.ToBase64String(chunkBytes);

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending chunk {i + 1}/{chunks.Count}, size: {chunks[i].Length} chars");

                    // Determine proper content type - always use Text for chunks
                    string contentType = "Text";

                    await _relayConnection.SendEncryptedDataAsync(
                        recipientId,
                        base64Chunk,
                        contentType,
                        cancellationToken);

                    // Brief delay between chunks to avoid overwhelming the server
                    if (i < chunks.Count - 1)
                    {
                        await Task.Delay(50, cancellationToken);
                    }
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] All {chunks.Count} chunks sent successfully");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending chunked clipboard data: {ex.Message}");
                throw;
            }
        }


        /// <summary>
        /// Process a received clipboard chunk
        /// </summary>
        private void ProcessClipboardChunk(JsonElement root, string senderId, string hardwareId)
        {
            try
            {
                // Extract chunk information
                string chunkId = root.GetProperty("chunk_id").GetString() ?? string.Empty;
                int chunkIndex = root.GetProperty("chunk_index").GetInt32();
                int chunkCount = root.GetProperty("chunk_count").GetInt32();
                string chunkData = root.GetProperty("chunk_data").GetString() ?? string.Empty;
                string format = root.GetProperty("format").GetString() ?? string.Empty;
                bool isBinary = root.GetProperty("is_binary").GetBoolean();
                uint keyId = root.GetProperty("key_id").GetUInt32();
                long timestamp = root.GetProperty("timestamp").GetInt64();
                string senderIdFromMessage = root.GetProperty("sender_id").GetString() ?? string.Empty;
                string senderName = root.GetProperty("sender_name").GetString() ?? string.Empty;

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received clipboard chunk {chunkIndex + 1}/{chunkCount} for ID {chunkId}");

                // Store the chunk
                if (!_clipboardChunks.ContainsKey(chunkId))
                {
                    _clipboardChunks[chunkId] = new Dictionary<int, string>();
                    _chunkMetadata[chunkId] = (chunkCount, format, isBinary, keyId, timestamp, senderIdFromMessage, senderName);
                }

                _clipboardChunks[chunkId][chunkIndex] = chunkData;

                // Check if we have all chunks
                if (_clipboardChunks[chunkId].Count == chunkCount)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] All {chunkCount} chunks received for {chunkId}, reassembling");

                    // Reassemble the complete data
                    StringBuilder dataBuilder = new StringBuilder();
                    for (int i = 0; i < chunkCount; i++)
                    {
                        if (_clipboardChunks[chunkId].TryGetValue(i, out string chunk))
                        {
                            dataBuilder.Append(chunk);
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Missing chunk {i} for {chunkId}, cannot reassemble");
                            return;
                        }
                    }

                    // Get metadata
                    var metadata = _chunkMetadata[chunkId];

                    // Create a complete clipboard update message
                    var clipboardMessage = new ClipboardUpdateMessage
                    {
                        DeviceId = metadata.senderId,
                        DeviceName = metadata.senderName,
                        Format = metadata.format,
                        Data = dataBuilder.ToString(),
                        IsBinary = metadata.isBinary,
                        Timestamp = metadata.timestamp,
                        KeyId = metadata.keyId,
                        HardwareId = hardwareId
                    };

                    // Find the device
                    var device = _deviceManager.GetDeviceById(metadata.senderId);
                    if (device == null && !string.IsNullOrEmpty(hardwareId))
                    {
                        device = _deviceManager.GetDeviceByHardwareId(hardwareId);
                    }

                    if (device != null)
                    {
                        // Process the reassembled clipboard data
                        ProcessReassembledClipboardData(clipboardMessage, device);
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Unknown device {metadata.senderId} for reassembled clipboard data");
                    }

                    // Clean up
                    _clipboardChunks.Remove(chunkId);
                    _chunkMetadata.Remove(chunkId);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing clipboard chunk: {ex.Message}");
            }
        }

        /// <summary>
        /// Process the reassembled clipboard data after all chunks are received
        /// </summary>
        private void ProcessReassembledClipboardData(ClipboardUpdateMessage message, PairedDevice device)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Processing reassembled clipboard data from {device.DeviceName}");

                // Check if hardware ID matches if provided
                if (!string.IsNullOrEmpty(message.HardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                    message.HardwareId != device.HardwareId)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch: {message.HardwareId} vs {device.HardwareId}");
                    return;
                }

                // Decrypt clipboard data
                if (!string.IsNullOrEmpty(message.Data) && !string.IsNullOrEmpty(device.SharedKey))
                {
                    try
                    {
                        ClipboardData clipboardData;

                        if (message.Format == "text/plain" && !message.IsBinary)
                        {
                            // Decrypt text
                            var decryptedText = _encryptionService.DecryptText(message.Data, device.SharedKey);
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Decrypted reassembled text length: {decryptedText.Length}");
                            clipboardData = ClipboardData.CreateText(decryptedText);
                        }
                        else if (message.Format == "image/png" && message.IsBinary)
                        {
                            // Decrypt binary data
                            var encryptedBytes = Convert.FromBase64String(message.Data);
                            var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(device.SharedKey));
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Decrypted reassembled binary length: {decryptedBytes.Length}");
                            clipboardData = ClipboardData.CreateImage(decryptedBytes);
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Unsupported clipboard format: {message.Format}");
                            return;
                        }

                        // Update device last seen
                        _deviceManager.UpdateDeviceLastSeen(device.DeviceId);

                        // Notify listeners
                        ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, device));
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Error decrypting reassembled clipboard data: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing reassembled clipboard data: {ex.Message}");
            }
        }

        /// <summary>
        /// Check if key rotation is needed and handle it
        /// </summary>
        public async Task CheckAndHandleKeyRotationAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                // Check if rotation is needed
                if (_encryptionService.ShouldRotateKey())
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Key rotation needed, creating new rotation key");

                    // Create new rotation key
                    uint newKeyId = _encryptionService.CreateRotationKey();
                    if (newKeyId == 0)
                    {
                        System.Diagnostics.Debug.WriteLine("[NETWORK] Failed to create rotation key");
                        return;
                    }

                    // Get paired devices
                    var devices = _deviceManager.GetPairedDevices();
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending key rotation update to {devices.Count} devices");

                    // Send key rotation update to all devices
                    foreach (var device in devices)
                    {
                        try
                        {
                            // Check if it's a relay device
                            if (device.IsRelayPaired)
                            {
                                await SendKeyRotationUpdateViaRelayAsync(device, cancellationToken);
                                continue;
                            }

                            // Try to connect to the device if not connected
                            if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                            {
                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} not connected, attempting connection");
                                webSocket = await ConnectToDeviceAsync(device, cancellationToken);

                                // Check if connected
                                if (webSocket == null || webSocket.State != WebSocketState.Open)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not connect to {device.DeviceName} for key rotation");
                                    continue;
                                }
                            }

                            // Send key update to this device
                            await SendKeyUpdateToDeviceAsync(device, webSocket, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending key rotation update to {device.DeviceName}: {ex.Message}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error checking key rotation: {ex.Message}");
            }
        }

        /// <summary>
        /// Send a key update to a specific device
        /// </summary>
        private async Task SendKeyUpdateToDeviceAsync(PairedDevice device, WebSocket webSocket, CancellationToken cancellationToken)
        {
            try
            {
                // Get key update package
                byte[] keyPackage = _encryptionService.GetKeyUpdatePackage(device.CurrentKeyId);

                // Check if we have a valid package
                if (keyPackage.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Failed to get key update package for device {device.DeviceName}");
                    return;
                }

                // Encrypt the key package with the device's shared key
                byte[] encryptedPackage = _encryptionService.EncryptData(keyPackage, Convert.FromBase64String(device.SharedKey));

                // Create key rotation update message
                var message = new KeyRotationUpdateMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    CurrentKeyId = _encryptionService.GetCurrentKeyId(),
                    KeyPackage = Convert.ToBase64String(encryptedPackage)
                };

                // Send the message
                await SendMessageAsync(webSocket, message, cancellationToken);
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation update sent to {device.DeviceName}");

                // Update device's key ID
                device.CurrentKeyId = _encryptionService.GetCurrentKeyId();
                _deviceManager.UpdateDevice(device);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending key update to device: {ex.Message}");
            }
        }



        /// <summary>
        /// Send key rotation update via relay server
        /// </summary>
        private async Task SendKeyRotationUpdateViaRelayAsync(PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                if (!device.IsRelayPaired || string.IsNullOrEmpty(device.RelayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Cannot send key update - not a relay paired device");
                    return;
                }

                // Check relay connection
                if (!_isConnectedToRelayServer || _relayConnection == null)
                {
                    // Try to connect to relay server
                    bool connected = await ConnectToRelayServerAsync(cancellationToken);
                    if (!connected)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Cannot send key update to {device.DeviceName} - relay server not connected");
                        return;
                    }
                }

                // Get key update package
                byte[] keyPackage = _encryptionService.GetKeyUpdatePackage(device.CurrentKeyId);

                // Check if we have a valid package
                if (keyPackage.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Failed to get key update package for device {device.DeviceName}");
                    return;
                }

                // Encrypt the key package with the device's shared key
                byte[] encryptedPackage = _encryptionService.EncryptData(keyPackage, Convert.FromBase64String(device.SharedKey));

                // Send key rotation update message via relay
                var message = new
                {
                    sender_id = _deviceManager.LocalDeviceId,
                    recipient_id = device.RelayDeviceId,
                    encrypted_key_package = Convert.ToBase64String(encryptedPackage),
                    key_id = _encryptionService.GetCurrentKeyId(),
                    hardware_id = _deviceManager.LocalHardwareId
                };

                await _relayConnection.SendMessageAsync(
                    device.RelayDeviceId,
                    "KeyRotationUpdate",
                    message,
                    cancellationToken);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation update sent via relay to {device.DeviceName}");

                // Update device's key ID
                device.CurrentKeyId = _encryptionService.GetCurrentKeyId();
                _deviceManager.UpdateDevice(device);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending key update via relay: {ex.Message}");
            }
        }

        /// <summary>
        /// Request a key update from a device
        /// </summary>
        private async Task RequestKeyUpdateAsync(PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Requesting key update from {device.DeviceName}");

                // Check if it's a relay device
                if (device.IsRelayPaired)
                {
                    await RequestKeyUpdateViaRelayAsync(device, cancellationToken);
                    return;
                }

                // Try to connect to the device if not connected
                if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} not connected, attempting connection");
                    webSocket = await ConnectToDeviceAsync(device, cancellationToken);

                    // Check if connected
                    if (webSocket == null || webSocket.State != WebSocketState.Open)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not connect to {device.DeviceName} for key update request");
                        return;
                    }
                }

                // Create key rotation request message
                var message = new KeyRotationRequestMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    HardwareId = _deviceManager.LocalHardwareId,
                    LastKnownKeyId = device.CurrentKeyId
                };

                // Send message
                await SendMessageAsync(webSocket, message, cancellationToken);
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key update request sent to {device.DeviceName}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error requesting key update: {ex.Message}");
            }
        }

        /// <summary>
        /// Request a key update via relay server
        /// </summary>
        private async Task RequestKeyUpdateViaRelayAsync(PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                if (!device.IsRelayPaired || string.IsNullOrEmpty(device.RelayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Cannot request key update - not a relay paired device");
                    return;
                }

                // Check relay connection
                if (!_isConnectedToRelayServer || _relayConnection == null)
                {
                    // Try to connect to relay server
                    bool connected = await ConnectToRelayServerAsync(cancellationToken);
                    if (!connected)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Cannot request key update from {device.DeviceName} - relay server not connected");
                        return;
                    }
                }

                // Send key rotation request via relay
                var message = new
                {
                    sender_id = _deviceManager.LocalDeviceId,
                    recipient_id = device.RelayDeviceId,
                    last_known_key_id = device.CurrentKeyId,
                    hardware_id = _deviceManager.LocalHardwareId
                };

                await _relayConnection.SendMessageAsync(
                    device.RelayDeviceId,
                    "KeyRotationRequest",
                    message,
                    cancellationToken);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key update request sent via relay to {device.DeviceName}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error requesting key update via relay: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle key rotation update message
        /// </summary>
        private async Task HandleKeyRotationUpdateAsync(JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                // Get key package and key ID
                var keyPackage = root.GetProperty("key_package").GetString() ?? string.Empty;
                var keyId = root.GetProperty("current_key_id").GetUInt32();

                // Get hardware ID from message (if provided)
                string? hardwareId = null;
                if (root.TryGetProperty("hardware_id", out var hwIdProperty))
                {
                    hardwareId = hwIdProperty.GetString();
                }

                // Verify hardware ID if provided 
                if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                    hardwareId != device.HardwareId)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch in key rotation update: {hardwareId} vs {device.HardwareId}");
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received key rotation update from {device.DeviceName}, key ID: {keyId}");

                if (string.IsNullOrEmpty(keyPackage))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Empty key package received");
                    return;
                }

                // Decrypt and process the key package
                try
                {
                    byte[] encryptedPackage = Convert.FromBase64String(keyPackage);
                    byte[] packageData = _encryptionService.DecryptData(encryptedPackage, Convert.FromBase64String(device.SharedKey));

                    // Import the key package (using existing method instead of ApplyKeyUpdatePackage)
                    uint importedKeyId = _encryptionService.ImportKeyUpdatePackage(packageData);

                    if (importedKeyId == 0)
                    {
                        System.Diagnostics.Debug.WriteLine("[NETWORK] Failed to import key package");
                        return;
                    }

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully imported key package, current key ID = {importedKeyId}");

                    // Update device's key ID
                    device.CurrentKeyId = keyId;
                    _deviceManager.UpdateDevice(device);

                    // Send acknowledgment if requested
                    if (root.TryGetProperty("requires_ack", out var reqAckProp) && reqAckProp.GetBoolean())
                    {
                        await SendKeyRotationAckAsync(device, keyId, true, cancellationToken);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error processing key package: {ex.Message}");

                    // Send negative acknowledgment if requested
                    if (root.TryGetProperty("requires_ack", out var reqAckProp) && reqAckProp.GetBoolean())
                    {
                        await SendKeyRotationAckAsync(device, keyId, false, cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling key rotation update: {ex.Message}");
            }
        }

        /// <summary>
        /// Send key rotation acknowledgment
        /// </summary>
        private async Task SendKeyRotationAckAsync(PairedDevice device, uint keyId, bool success, CancellationToken cancellationToken)
        {
            try
            {
                // Check if it's a relay device
                if (device.IsRelayPaired)
                {
                    await SendKeyRotationAckViaRelayAsync(device, keyId, success, cancellationToken);
                    return;
                }

                // Try to connect to the device if not connected
                if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} not connected, attempting connection");
                    webSocket = await ConnectToDeviceAsync(device, cancellationToken);

                    // Check if connected
                    if (webSocket == null || webSocket.State != WebSocketState.Open)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Could not connect to {device.DeviceName} for key rotation ACK");
                        return;
                    }
                }

                // Create key rotation ACK message
                var message = new
                {
                    type = "KeyRotationAck",
                    device_id = _deviceManager.LocalDeviceId,
                    device_name = _deviceManager.LocalDeviceName,
                    hardware_id = _deviceManager.LocalHardwareId,
                    key_id = keyId,
                    success = success
                };

                // Send message
                await SendMessageAsync(webSocket, message, cancellationToken);
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation ACK sent to {device.DeviceName}, success: {success}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending key rotation ACK: {ex.Message}");
            }
        }

        /// <summary>
        /// Send key rotation acknowledgment via relay
        /// </summary>
        private async Task SendKeyRotationAckViaRelayAsync(PairedDevice device, uint keyId, bool success, CancellationToken cancellationToken)
        {
            try
            {
                if (!device.IsRelayPaired || string.IsNullOrEmpty(device.RelayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Cannot send key rotation ACK - not a relay paired device");
                    return;
                }

                // Check relay connection
                if (!_isConnectedToRelayServer || _relayConnection == null)
                {
                    // Try to connect to relay server
                    bool connected = await ConnectToRelayServerAsync(cancellationToken);
                    if (!connected)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Cannot send key rotation ACK to {device.DeviceName} - relay server not connected");
                        return;
                    }
                }

                // Send key rotation ACK via relay
                var message = new
                {
                    sender_id = _deviceManager.LocalDeviceId,
                    recipient_id = device.RelayDeviceId,
                    key_id = keyId,
                    success = success,
                    hardware_id = _deviceManager.LocalHardwareId
                };

                await _relayConnection.SendMessageAsync(
                    device.RelayDeviceId,
                    "KeyRotationAck",
                    message,
                    cancellationToken);

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation ACK sent via relay to {device.DeviceName}, success: {success}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending key rotation ACK via relay: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle key rotation request
        /// </summary>
        private async Task HandleKeyRotationRequestAsync(WebSocket webSocket, JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                // Get last known key ID
                var lastKnownKeyId = root.GetProperty("last_known_key_id").GetUInt32();

                // Get hardware ID if provided
                string? hardwareId = null;
                if (root.TryGetProperty("hardware_id", out var hwIdProperty))
                {
                    hardwareId = hwIdProperty.GetString();
                }

                // Verify hardware ID if provided
                if (!string.IsNullOrEmpty(hardwareId) && !string.IsNullOrEmpty(device.HardwareId) &&
                    hardwareId != device.HardwareId)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Hardware ID mismatch in key rotation request: {hardwareId} vs {device.HardwareId}");
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received key rotation request from {device.DeviceName}, last known key ID: {lastKnownKeyId}");

                // Check if device needs an update (i.e., if our current key ID is different)
                uint currentKeyId = _encryptionService.GetCurrentKeyId();
                if (lastKnownKeyId != currentKeyId)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} needs key update: {lastKnownKeyId} -> {currentKeyId}");
                    await SendKeyUpdateToDeviceAsync(device, webSocket, cancellationToken);
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} already has current key ID: {currentKeyId}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling key rotation request: {ex.Message}");
            }
        }

        /// <summary>
        /// Dispose implementation
        /// </summary>
        public void Dispose()
        {
            // Stop the server if it's running
            StopAsync();

            // Disconnect from relay server
            DisconnectFromRelayServerAsync().Wait();

            // Cancel any pending operations
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();
        }
    }
}