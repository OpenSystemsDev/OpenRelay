using System;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using OpenRelay.Models;
using System.Text.Json.Nodes;

namespace OpenRelay.Services
{
    /// <summary>
    /// Event args for when relay messages are received
    /// </summary>
    public class RelayMessageEventArgs : EventArgs
    {
        /// <summary>
        /// The relay server ID of the sender
        /// </summary>
        public string SenderId { get; }

        /// <summary>
        /// The ID of the message
        /// </summary>
        public string MessageId { get; }

        /// <summary>
        /// The encrypted data
        /// </summary>
        public string EncryptedData { get; }

        /// <summary>
        /// The hardware ID of the sender
        /// </summary>
        public string HardwareId { get; }

        /// <summary>
        /// Create new relay message event args
        /// </summary>
        public RelayMessageEventArgs(string senderId, string messageId, string encryptedData, string hardwareId = "")
        {
            SenderId = senderId;
            MessageId = messageId;
            EncryptedData = encryptedData;
            HardwareId = hardwareId;
        }
    }

    /// <summary>
    /// Event args for authentication challenge
    /// </summary>
    public class AuthChallengeEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public string Challenge { get; set; } = string.Empty;
        public string PublicKey { get; set; } = string.Empty;
    }

    /// <summary>
    /// Event args for authentication response
    /// </summary>
    public class AuthResponseEventArgs : EventArgs
    {
        public string DeviceId { get; set; } = string.Empty;
        public string ChallengeResponse { get; set; } = string.Empty;
        public string Challenge { get; set; } = string.Empty;
        public bool IsValid { get; set; } = false;
    }

    /// <summary>
    /// Handles communication with the OpenRelay server
    /// </summary>
    public class RelayConnection : IDisposable
    {
        private readonly string _serverUri;
        private readonly string _localDeviceId;
        private readonly string _localDeviceName;
        private readonly string _hardwareId;

        private ClientWebSocket? _webSocket;
        private string _relayDeviceId = string.Empty;
        private bool _isConnected = false;
        private bool _isRegistered = false;
        private CancellationTokenSource? _cancellationTokenSource;

        // Event handlers
        public event EventHandler<string>? Connected;
        public event EventHandler? Disconnected;
        public event EventHandler<RelayMessageEventArgs>? MessageReceived;

        // Authentication events
        public event EventHandler<AuthChallengeEventArgs>? AuthChallengeReceived;
        public event EventHandler<AuthResponseEventArgs>? AuthResponseReceived;
        public event EventHandler<AuthVerifyEventArgs>? AuthVerifyReceived;
        public event EventHandler<AuthSuccessEventArgs>? AuthSuccessReceived;

        // Dictionary to track pending authentication requests
        private Dictionary<string, TaskCompletionSource<bool>> _pendingAuthRequests = new Dictionary<string, TaskCompletionSource<bool>>();

        // Connection state
        public bool IsConnected => _isConnected && _isRegistered && _webSocket?.State == WebSocketState.Open;
        public string RelayDeviceId => _relayDeviceId;

        /// <summary>
        /// Create a new relay connection
        /// </summary>
        public RelayConnection(string serverUri, string localDeviceId, string localDeviceName)
        {
            _serverUri = serverUri;
            _localDeviceId = localDeviceId;
            _localDeviceName = localDeviceName;

            // Generate hardware ID
            _hardwareId = HardwareIdProvider.GetHardwareId();
            System.Diagnostics.Debug.WriteLine($"[RELAY] Hardware ID: {_hardwareId}");
        }

        /// <summary>
        /// Connect to the relay server
        /// </summary>
        public async Task<bool> ConnectAsync(CancellationToken cancellationToken = default)
        {
            if (IsConnected)
                return true;

            try
            {
                // Create cancellation token source
                _cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

                // Create WebSocket client with proper settings
                _webSocket = new ClientWebSocket();

                // Set options for better compatibility
                _webSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);

                // Ensure server URI is correct
                string serverUri = _serverUri;

                // If the URI doesn't end with /relay, append it
                if (!serverUri.EndsWith("/relay", StringComparison.OrdinalIgnoreCase))
                {
                    serverUri = serverUri.TrimEnd('/') + "/relay";
                }

                System.Diagnostics.Debug.WriteLine($"[RELAY] Connecting to {serverUri}");

                // Set a reasonable timeout for connection
                using var timeoutTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                using var combinedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(
                    _cancellationTokenSource.Token, timeoutTokenSource.Token);

                // Connect to server
                await _webSocket.ConnectAsync(new Uri(serverUri), combinedTokenSource.Token);
                _isConnected = true;

                System.Diagnostics.Debug.WriteLine("[RELAY] Connected to server");
                System.Diagnostics.Debug.WriteLine($"[RELAY] WebSocket state: {_webSocket.State}");

                // Start message processing immediately to catch any immediate responses
                var processingTask = Task.Run(() => ProcessMessagesAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);

                // Register with server using hardware ID
                bool registered = await RegisterWithServerAsync(_cancellationTokenSource.Token);
                if (!registered)
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Failed to register with server");
                    await DisconnectAsync();
                    return false;
                }

                // Start ping timer
                _ = Task.Run(() => PingTimerAsync(_cancellationTokenSource.Token), _cancellationTokenSource.Token);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Connection error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Inner exception: {ex.InnerException.Message}");
                }
                System.Diagnostics.Debug.WriteLine($"[RELAY] Stack trace: {ex.StackTrace}");
                _isConnected = false;
                return false;
            }
        }

        /// <summary>
        /// Disconnect from the relay server
        /// </summary>
        public async Task DisconnectAsync()
        {
            if (!_isConnected || _webSocket == null)
                return;

            try
            {
                // Cancel all operations
                _cancellationTokenSource?.Cancel();

                // Close connection
                if (_webSocket.State == WebSocketState.Open)
                {
                    await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Disconnecting", CancellationToken.None);
                }

                _webSocket.Dispose();
                _webSocket = null;

                _isConnected = false;
                _isRegistered = false;

                Disconnected?.Invoke(this, EventArgs.Empty);

                System.Diagnostics.Debug.WriteLine("[RELAY] Disconnected from server");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error disconnecting: {ex.Message}");
            }
        }

        /// <summary>
        /// Register with the relay server using hardware ID
        /// </summary>
        private async Task<bool> RegisterWithServerAsync(CancellationToken cancellationToken)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
                return false;

            try
            {
                // Create register message with hardware ID
                var registerMessage = new
                {
                    type = "Register",
                    payload = new
                    {
                        hardware_id = _hardwareId
                    }
                };

                // Serialize and send
                string jsonMessage = JsonSerializer.Serialize(registerMessage);
                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending registration request: {jsonMessage}");

                byte[] messageBytes = Encoding.UTF8.GetBytes(jsonMessage);
                await _webSocket.SendAsync(
                    new ArraySegment<byte>(messageBytes),
                    WebSocketMessageType.Text,
                    true, // endOfMessage
                    cancellationToken);

                // Wait for response (handled in ProcessMessagesAsync)
                System.Diagnostics.Debug.WriteLine("[RELAY] Waiting for registration response...");
                int attempts = 0;
                while (!_isRegistered && attempts < 20 && !cancellationToken.IsCancellationRequested)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Waiting for registration response (attempt {attempts + 1}/20)");
                    await Task.Delay(500, cancellationToken);
                    attempts++;
                }

                if (_isRegistered)
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Registration successful");
                    return true;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Registration timed out - attempting to diagnose");

                    // Try to check WebSocket state
                    if (_webSocket.State != WebSocketState.Open)
                    {
                        System.Diagnostics.Debug.WriteLine($"[RELAY] WebSocket state is now: {_webSocket.State}");
                    }

                    // Try sending a ping to check connectivity
                    try
                    {
                        string pingMessage = "{\"type\":\"Ping\"}";
                        byte[] pingBytes = Encoding.UTF8.GetBytes(pingMessage);
                        System.Diagnostics.Debug.WriteLine("[RELAY] Sending ping to test connectivity...");
                        await _webSocket.SendAsync(
                            new ArraySegment<byte>(pingBytes),
                            WebSocketMessageType.Text,
                            true,
                            CancellationToken.None);
                        System.Diagnostics.Debug.WriteLine("[RELAY] Ping sent successfully");
                    }
                    catch (Exception pingEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Failed to send ping: {pingEx.Message}");
                    }

                    return false;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Registration error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Inner exception: {ex.InnerException.Message}");
                }
                System.Diagnostics.Debug.WriteLine($"[RELAY] Stack trace: {ex.StackTrace}");
                return false;
            }
        }

        /// <summary>
        /// Send a message to another device via the relay server
        /// </summary>
        public async Task<bool> SendMessageAsync(string recipientId, string messageType, object payload, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send message, not registered with server");
                    return false;
                }

                // Create relay message
                var relayMessage = new
                {
                    type = "Send",
                    payload = new
                    {
                        recipient_id = recipientId,
                        sender_id = _relayDeviceId,
                        message_id = Guid.NewGuid().ToString(),
                        encrypted_data = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
                        {
                            type = messageType,
                            sender_id = _localDeviceId,
                            sender_name = _localDeviceName,
                            hardware_id = _hardwareId,
                            payload
                        }))),
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        ttl = 300, // 5 minutes
                        hardware_id = _hardwareId,
                        content_type = "Text",
                        size_bytes = 0 // Will be updated below
                    }
                };

                // Calculate size
                var json = JsonSerializer.Serialize(relayMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                // Use JsonNode to modify the JSON
                var jsonNode = JsonNode.Parse(json);
                if (jsonNode != null && jsonNode["payload"] != null)
                {
                    jsonNode["payload"]["size_bytes"] = buffer.Length;

                    // Serialize again with correct size
                    json = jsonNode.ToJsonString();
                    buffer = Encoding.UTF8.GetBytes(json);
                }

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending message to {recipientId}, size: {buffer.Length} bytes");

                // Send message
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending message: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send encrypted data to another device via the relay server
        /// </summary>
        public async Task<bool> SendEncryptedDataAsync(string recipientId, string encryptedData, string contentType, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send data, not registered with server");
                    return false;
                }

                // Create relay message
                var relayMessage = new
                {
                    type = "Send",
                    payload = new
                    {
                        recipient_id = recipientId,
                        sender_id = _relayDeviceId,
                        message_id = Guid.NewGuid().ToString(),
                        encrypted_data = encryptedData,
                        timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        ttl = 300, // 5 minutes
                        hardware_id = _hardwareId,
                        content_type = contentType,
                        size_bytes = encryptedData.Length
                    }
                };

                // Serialize message
                var json = JsonSerializer.Serialize(relayMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending encrypted data to {recipientId}, size: {buffer.Length} bytes");

                // Send message
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending encrypted data: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Generate a cryptographic challenge for device authentication
        /// </summary>
        private string GenerateChallenge()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] challenge = new byte[32]; // 256 bits
                rng.GetBytes(challenge);
                return Convert.ToBase64String(challenge);
            }
        }

        /// <summary>
        /// Send authentication challenge to another device
        /// </summary>
        public async Task<bool> SendAuthChallengeAsync(string recipientId, string publicKey, string challenge, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send auth challenge, not registered with server");
                    return false;
                }

                // Create auth challenge message
                var authChallengeMessage = new
                {
                    type = "AuthRequest",
                    payload = new
                    {
                        device_id = _relayDeviceId,
                        public_key = publicKey,
                        challenge = challenge,
                        hardware_id = _hardwareId
                    }
                };

                // Serialize and send
                var json = JsonSerializer.Serialize(authChallengeMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending auth challenge to {recipientId}");
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending auth challenge: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send authentication response to a challenge
        /// </summary>
        public async Task<bool> SendAuthResponseAsync(string recipientId, string challengeResponse, string newChallenge, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send auth response, not registered with server");
                    return false;
                }

                // Create auth response message
                var authResponseMessage = new
                {
                    type = "AuthResponse",
                    payload = new
                    {
                        device_id = _relayDeviceId,
                        challenge_response = challengeResponse,
                        challenge = newChallenge,
                        hardware_id = _hardwareId
                    }
                };

                // Serialize and send
                var json = JsonSerializer.Serialize(authResponseMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending auth response to {recipientId}");
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending auth response: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send authentication verification
        /// </summary>
        public async Task<bool> SendAuthVerifyAsync(string recipientId, string challengeResponse, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send auth verify, not registered with server");
                    return false;
                }

                // Create auth verify message
                var authVerifyMessage = new
                {
                    type = "AuthVerify",
                    payload = new
                    {
                        device_id = _relayDeviceId,
                        challenge_response = challengeResponse,
                        hardware_id = _hardwareId
                    }
                };

                // Serialize and send
                var json = JsonSerializer.Serialize(authVerifyMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending auth verification to {recipientId}");
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending auth verification: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Send authentication success
        /// </summary>
        public async Task<bool> SendAuthSuccessAsync(string recipientId, bool trusted, CancellationToken cancellationToken = default)
        {
            if (!IsConnected || _webSocket == null)
                return false;

            try
            {
                // Check if we have a relay device ID
                if (string.IsNullOrEmpty(_relayDeviceId))
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Cannot send auth success, not registered with server");
                    return false;
                }

                // Create auth success message
                var authSuccessMessage = new
                {
                    type = "AuthSuccess",
                    payload = new
                    {
                        device_id = _relayDeviceId,
                        trusted = trusted,
                        hardware_id = _hardwareId
                    }
                };

                // Serialize and send
                var json = JsonSerializer.Serialize(authSuccessMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sending auth success to {recipientId}, trusted: {trusted}");
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending auth success: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Process messages from the relay server
        /// </summary>
        private async Task ProcessMessagesAsync(CancellationToken cancellationToken)
        {
            if (_webSocket == null)
                return;

            var buffer = new byte[16384]; // 16KB buffer
            var messageBuilder = new StringBuilder();

            try
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Starting message processing loop, WebSocket state: {_webSocket.State}");

                while (_webSocket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        // Receive a message
                        System.Diagnostics.Debug.WriteLine("[RELAY] Waiting for WebSocket message...");
                        var result = await _webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);

                        System.Diagnostics.Debug.WriteLine($"[RELAY] Received WebSocket frame: Type={result.MessageType}, EndOfMessage={result.EndOfMessage}, Count={result.Count}");

                        // Check if connection is closed
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            System.Diagnostics.Debug.WriteLine($"[RELAY] Server sent WebSocket close message with status: {result.CloseStatus}, description: {result.CloseStatusDescription}");
                            await _webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", CancellationToken.None);
                            break;
                        }

                        // Process binary messages
                        if (result.MessageType == WebSocketMessageType.Binary)
                        {
                            System.Diagnostics.Debug.WriteLine($"[RELAY] Received binary message of {result.Count} bytes");
                            // Most likely not expected, but we'll log it
                            continue;
                        }

                        // Process text messages
                        if (result.MessageType == WebSocketMessageType.Text)
                        {
                            // Add this frame to the message
                            var messageText = Encoding.UTF8.GetString(buffer, 0, result.Count);
                            System.Diagnostics.Debug.WriteLine($"[RELAY] Received text frame: {messageText}");
                            messageBuilder.Append(messageText);

                            // Process complete message
                            if (result.EndOfMessage)
                            {
                                var message = messageBuilder.ToString();
                                messageBuilder.Clear();

                                System.Diagnostics.Debug.WriteLine($"[RELAY] Processing complete message: {message}");

                                try
                                {
                                    // Parse message
                                    var jsonDoc = JsonDocument.Parse(message);
                                    var root = jsonDoc.RootElement;

                                    // Get message type
                                    if (root.TryGetProperty("type", out var typeProperty))
                                    {
                                        var type = typeProperty.GetString() ?? string.Empty;

                                        switch (type)
                                        {
                                            case "RegisterResponse":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received RegisterResponse");
                                                HandleRegisterResponse(root);
                                                break;

                                            case "Receive":
                                                HandleReceiveMessage(root);
                                                break;

                                            case "Ack":
                                                HandleAcknowledgment(root);
                                                break;

                                            case "Pong":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received pong from server");
                                                break;

                                            case "Error":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received error message from server");
                                                HandleErrorMessage(root);
                                                break;

                                            case "AuthRequest":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received AuthRequest");
                                                HandleAuthRequest(root);
                                                break;

                                            case "AuthResponse":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received AuthResponse");
                                                HandleAuthResponse(root);
                                                break;

                                            case "AuthVerify":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received AuthVerify");
                                                HandleAuthVerify(root);
                                                break;

                                            case "AuthSuccess":
                                                System.Diagnostics.Debug.WriteLine("[RELAY] Received AuthSuccess");
                                                HandleAuthSuccess(root);
                                                break;

                                            default:
                                                System.Diagnostics.Debug.WriteLine($"[RELAY] Received unknown message type: {type}");
                                                System.Diagnostics.Debug.WriteLine($"[RELAY] Full message: {message}");
                                                break;
                                        }
                                    }
                                    else
                                    {
                                        System.Diagnostics.Debug.WriteLine($"[RELAY] Received message without 'type' property: {message}");
                                    }
                                }
                                catch (JsonException jsonEx)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[RELAY] JSON parsing error: {jsonEx.Message}");
                                    System.Diagnostics.Debug.WriteLine($"[RELAY] Failed message content: {message}");
                                }
                                catch (Exception ex)
                                {
                                    System.Diagnostics.Debug.WriteLine($"[RELAY] Error processing message: {ex.Message}");
                                    System.Diagnostics.Debug.WriteLine($"[RELAY] Failed message content: {message}");
                                    if (ex.InnerException != null)
                                    {
                                        System.Diagnostics.Debug.WriteLine($"[RELAY] Inner exception: {ex.InnerException.Message}");
                                    }
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        System.Diagnostics.Debug.WriteLine("[RELAY] WebSocket receive operation was canceled");
                        break;
                    }
                    catch (WebSocketException wsEx)
                    {
                        System.Diagnostics.Debug.WriteLine($"[RELAY] WebSocket error: {wsEx.Message}, WebSocketErrorCode: {wsEx.WebSocketErrorCode}");
                        if (wsEx.WebSocketErrorCode == WebSocketError.ConnectionClosedPrematurely)
                        {
                            System.Diagnostics.Debug.WriteLine("[RELAY] Connection closed prematurely");
                            break;
                        }
                        // Continue for other errors
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Error receiving message: {ex.Message}");
                        // Try to continue
                    }
                }
                System.Diagnostics.Debug.WriteLine("[RELAY] Exited message processing loop");
            }
            catch (OperationCanceledException)
            {
                // Operation was canceled, this is expected
                System.Diagnostics.Debug.WriteLine("[RELAY] Message processing canceled");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error in message processing loop: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Inner exception: {ex.InnerException.Message}");
                }
            }
            finally
            {
                _isConnected = false;
                Disconnected?.Invoke(this, EventArgs.Empty);
            }
        }

        /// <summary>
        /// Handle authentication request
        /// </summary>
        private void HandleAuthRequest(JsonElement root)
        {
            try
            {
                if (root.TryGetProperty("payload", out var payload))
                {
                    string deviceId = payload.GetProperty("device_id").GetString() ?? string.Empty;
                    string challenge = payload.GetProperty("challenge").GetString() ?? string.Empty;
                    string publicKey = payload.GetProperty("public_key").GetString() ?? string.Empty;
                    string hardwareId = payload.TryGetProperty("hardware_id", out var hwIdProp) ?
                        hwIdProp.GetString() ?? string.Empty : string.Empty;

                    System.Diagnostics.Debug.WriteLine($"[RELAY] Received auth challenge from {deviceId}");

                    // Notify event subscribers
                    AuthChallengeReceived?.Invoke(this, new AuthChallengeEventArgs
                    {
                        DeviceId = deviceId,
                        Challenge = challenge,
                        PublicKey = publicKey
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling auth request: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle authentication response
        /// </summary>
        private void HandleAuthResponse(JsonElement root)
        {
            try
            {
                if (root.TryGetProperty("payload", out var payload))
                {
                    string deviceId = payload.GetProperty("device_id").GetString() ?? string.Empty;
                    string challengeResponse = payload.GetProperty("challenge_response").GetString() ?? string.Empty;
                    string challenge = payload.GetProperty("challenge").GetString() ?? string.Empty;
                    string hardwareId = payload.TryGetProperty("hardware_id", out var hwIdProp) ?
                        hwIdProp.GetString() ?? string.Empty : string.Empty;

                    System.Diagnostics.Debug.WriteLine($"[RELAY] Received auth response from {deviceId}");

                    // Notify event subscribers
                    AuthResponseReceived?.Invoke(this, new AuthResponseEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        Challenge = challenge,
                        IsValid = true // Validation is done by the DeviceManager
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling auth response: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle authentication verification
        /// </summary>
        private void HandleAuthVerify(JsonElement root)
        {
            try
            {
                if (root.TryGetProperty("payload", out var payload))
                {
                    string deviceId = payload.GetProperty("device_id").GetString() ?? string.Empty;
                    string challengeResponse = payload.GetProperty("challenge_response").GetString() ?? string.Empty;
                    string hardwareId = payload.TryGetProperty("hardware_id", out var hwIdProp) ?
                        hwIdProp.GetString() ?? string.Empty : string.Empty;

                    System.Diagnostics.Debug.WriteLine($"[RELAY] Received auth verification from {deviceId}");

                    // Notify event subscribers
                    AuthVerifyReceived?.Invoke(this, new AuthVerifyEventArgs
                    {
                        DeviceId = deviceId,
                        ChallengeResponse = challengeResponse,
                        IsValid = true // Validation is done by the DeviceManager
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling auth verify: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle authentication success
        /// </summary>
        private void HandleAuthSuccess(JsonElement root)
        {
            try
            {
                if (root.TryGetProperty("payload", out var payload))
                {
                    string deviceId = payload.GetProperty("device_id").GetString() ?? string.Empty;
                    bool trusted = payload.GetProperty("trusted").GetBoolean();
                    string hardwareId = payload.TryGetProperty("hardware_id", out var hwIdProp) ?
                        hwIdProp.GetString() ?? string.Empty : string.Empty;

                    System.Diagnostics.Debug.WriteLine($"[RELAY] Received auth success from {deviceId}, trusted: {trusted}");

                    // Notify event subscribers
                    AuthSuccessReceived?.Invoke(this, new AuthSuccessEventArgs
                    {
                        DeviceId = deviceId,
                        Trusted = trusted
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling auth success: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle registration response
        /// </summary>
        private void HandleRegisterResponse(JsonElement root)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Processing registration response: {JsonSerializer.Serialize(root)}");

                // According to RESPONSES.md, the format should be:
                // {
                //   "type": "RegisterResponse",
                //   "payload": {
                //     "device_id": "d8f8a9b0-f6e1-4a2b-8d7c-1e9f0a1b2c3d"
                //   }
                // }

                // Get payload
                if (root.TryGetProperty("payload", out var payloadProperty))
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Registration response payload: {JsonSerializer.Serialize(payloadProperty)}");

                    if (payloadProperty.ValueKind == JsonValueKind.Object)
                    {
                        // Get device ID
                        if (payloadProperty.TryGetProperty("device_id", out var deviceIdProperty))
                        {
                            _relayDeviceId = deviceIdProperty.GetString() ?? string.Empty;
                            _isRegistered = true;

                            System.Diagnostics.Debug.WriteLine($"[RELAY] Registered with server, device ID: {_relayDeviceId}");

                            Connected?.Invoke(this, _relayDeviceId);
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine("[RELAY] Registration response payload doesn't contain 'device_id' field");
                            System.Diagnostics.Debug.WriteLine($"[RELAY] Available fields: {string.Join(", ", payloadProperty.EnumerateObject().Select(p => p.Name))}");
                        }
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Payload is not an object. ValueKind: {payloadProperty.ValueKind}");
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("[RELAY] Registration response doesn't contain 'payload' field");
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Available fields: {string.Join(", ", root.EnumerateObject().Select(p => p.Name))}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling register response: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Inner exception: {ex.InnerException.Message}");
                }
                System.Diagnostics.Debug.WriteLine($"[RELAY] Stack trace: {ex.StackTrace}");
            }
        }

        /// <summary>
        /// Handle received message
        /// </summary>
        private void HandleReceiveMessage(JsonElement root)
        {
            try
            {
                // Get payload
                if (root.TryGetProperty("payload", out var payloadProperty))
                {
                    // Get sender ID
                    string senderId = string.Empty;
                    if (payloadProperty.TryGetProperty("sender_id", out var senderIdProperty))
                    {
                        senderId = senderIdProperty.GetString() ?? string.Empty;
                    }

                    // Get message ID
                    string messageId = string.Empty;
                    if (payloadProperty.TryGetProperty("message_id", out var messageIdProperty))
                    {
                        messageId = messageIdProperty.GetString() ?? string.Empty;
                    }

                    // Get encrypted data
                    string encryptedData = string.Empty;
                    if (payloadProperty.TryGetProperty("encrypted_data", out var encryptedDataProperty))
                    {
                        encryptedData = encryptedDataProperty.GetString() ?? string.Empty;
                    }

                    // Get hardware ID
                    string hardwareId = string.Empty;
                    if (payloadProperty.TryGetProperty("hardware_id", out var hardwareIdProperty))
                    {
                        hardwareId = hardwareIdProperty.GetString() ?? string.Empty;
                    }

                    System.Diagnostics.Debug.WriteLine($"[RELAY] Received message from {senderId} (HW: {hardwareId}), message ID: {messageId}");

                    // Notify about received message
                    MessageReceived?.Invoke(this, new RelayMessageEventArgs(senderId, messageId, encryptedData, hardwareId));

                    // Send acknowledgment
                    _ = SendAcknowledgmentAsync(messageId);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling received message: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle acknowledgment
        /// </summary>
        private void HandleAcknowledgment(JsonElement root)
        {
            try
            {
                // Get payload
                if (root.TryGetProperty("payload", out var payloadProperty))
                {
                    // Get message ID
                    if (payloadProperty.TryGetProperty("message_id", out var messageIdProperty))
                    {
                        string messageId = messageIdProperty.GetString() ?? string.Empty;
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Received acknowledgment for message: {messageId}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling acknowledgment: {ex.Message}");
            }
        }

        /// <summary>
        /// Handle error message
        /// </summary>
        private void HandleErrorMessage(JsonElement root)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Full error message structure: {JsonSerializer.Serialize(root)}");

                // Get payload
                if (root.TryGetProperty("payload", out var payloadProperty))
                {
                    // Get error message
                    if (payloadProperty.TryGetProperty("message", out var messageProperty))
                    {
                        string errorMessage = messageProperty.GetString() ?? string.Empty;
                        int errorCode = 0;

                        // Get error code if available
                        if (payloadProperty.TryGetProperty("code", out var codeProperty))
                        {
                            errorCode = codeProperty.GetInt32();
                        }

                        System.Diagnostics.Debug.WriteLine($"[RELAY] Received error from server: {errorMessage} (code: {errorCode})");

                        // Handle specific errors
                        if (errorCode == 429)
                        {
                            System.Diagnostics.Debug.WriteLine("[RELAY] Rate limit exceeded - will need to wait before retrying");
                        }
                        else if (errorCode >= 500)
                        {
                            System.Diagnostics.Debug.WriteLine("[RELAY] Server-side error occurred");
                        }
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("[RELAY] Error payload doesn't contain 'message' field");
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Payload content: {JsonSerializer.Serialize(payloadProperty)}");
                    }
                }
                else
                {
                    // Try direct message property
                    if (root.TryGetProperty("message", out var messageProperty))
                    {
                        string errorMessage = messageProperty.GetString() ?? string.Empty;
                        System.Diagnostics.Debug.WriteLine($"[RELAY] Direct error message: {errorMessage}");
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("[RELAY] Error message doesn't contain 'payload' or 'message' field");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error handling error message: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error message structure: {JsonSerializer.Serialize(root)}");
            }
        }

        /// <summary>
        /// Send acknowledgment for a message
        /// </summary>
        private async Task SendAcknowledgmentAsync(string messageId)
        {
            if (_webSocket == null || _webSocket.State != WebSocketState.Open)
                return;

            try
            {
                // Create acknowledgment message
                var ackMessage = new
                {
                    type = "Ack",
                    payload = new
                    {
                        message_id = messageId
                    }
                };

                // Serialize message
                var json = JsonSerializer.Serialize(ackMessage);
                var buffer = Encoding.UTF8.GetBytes(json);

                // Send message
                await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None);

                System.Diagnostics.Debug.WriteLine($"[RELAY] Sent acknowledgment for message: {messageId}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending acknowledgment: {ex.Message}");
            }
        }

        /// <summary>
        /// Send ping to keep connection alive
        /// </summary>
        private async Task PingTimerAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(30000, cancellationToken); // 30 seconds

                if (_webSocket == null || _webSocket.State != WebSocketState.Open)
                    continue;

                try
                {
                    // Create ping message
                    var pingMessage = new
                    {
                        type = "Ping"
                    };

                    // Serialize message
                    var json = JsonSerializer.Serialize(pingMessage);
                    var buffer = Encoding.UTF8.GetBytes(json);

                    // Send message
                    await _webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);

                    System.Diagnostics.Debug.WriteLine("[RELAY] Sent ping to server");
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[RELAY] Error sending ping: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Dispose of resources
        /// </summary>
        public void Dispose()
        {
            // Cancel all operations
            _cancellationTokenSource?.Cancel();
            _cancellationTokenSource?.Dispose();

            // Dispose of WebSocket
            _webSocket?.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}