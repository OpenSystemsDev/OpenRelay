using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
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

        // Dependencies
        private readonly DeviceManager _deviceManager;
        private readonly EncryptionService _encryptionService;

        // WebSocket server
        private HttpListener? _httpListener;
        private bool _isListening;
        private CancellationTokenSource? _cancellationTokenSource;

        // Connected clients
        private readonly Dictionary<string, WebSocket> _connectedClients = new Dictionary<string, WebSocket>();

        // Pending pairing requests
        private readonly Dictionary<string, TaskCompletionSource<bool>> _pairingRequests = new Dictionary<string, TaskCompletionSource<bool>>();

        /// <summary>
        /// Initialize the network service
        /// </summary>
        public NetworkService(DeviceManager deviceManager, EncryptionService encryptionService)
        {
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
        }

        /// <summary>
        /// Start the WebSocket server with TLS enabled
        /// </summary>
        public async Task StartAsync()
        {
            if (_isListening)
                return;

            try
            {
                // Create cancellation token source
                _cancellationTokenSource = new CancellationTokenSource();

                // Create certificate manager
                var certificateManager = new CertificateManager();
                var certificate = await certificateManager.GetOrCreateCertificateAsync();

                // Set up the certificate
                if (!TlsBindingManager.SetupCertificate(DEFAULT_PORT, certificate))
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Warning: Could not set up TLS certificate binding");
                }

                // Create HTTP listener with HTTPS binding
                _httpListener = new HttpListener();
                
                // Add the HTTPS prefix
                _httpListener.Prefixes.Add($"https://+:{DEFAULT_PORT}/");
                _httpListener.Start();

                _isListening = true;

                // Log server start
                System.Diagnostics.Debug.WriteLine($"[NETWORK] TLS WebSocket server started on port {DEFAULT_PORT}");

                // Start listening for connections
                await AcceptConnectionsAsync(_cancellationTokenSource.Token);
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
                    // Ignore errors when closing connections
                }
            }

            _connectedClients.Clear();

            // Stop HTTP listener
            _httpListener?.Stop();
            _httpListener = null;

            _isListening = false;

            System.Diagnostics.Debug.WriteLine("[NETWORK] WebSocket server stopped");
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
                        // Process the WebSocket request
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

                // Get the client's IP address
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
                        // Ignore errors when closing
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

                            // Log a snippet of the message (avoid logging huge messages)
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

                                        // Handle different message types
                                        switch (messageType)
                                        {
                                            case MessageType.PairingRequest:
                                                await HandlePairingRequestAsync(webSocket, root, ipAddress, cancellationToken);
                                                break;

                                            case MessageType.PairingResponse:
                                                await HandlePairingResponseAsync(root, cancellationToken);
                                                break;

                                            case MessageType.Auth:
                                                // Try to authenticate the device
                                                deviceId = await HandleAuthAsync(webSocket, root, ipAddress, cancellationToken);

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

                                            case MessageType.ClipboardUpdate:
                                                // Only process clipboard updates from authenticated devices
                                                if (device != null)
                                                {
                                                    await HandleClipboardUpdateAsync(root, device, cancellationToken);
                                                }
                                                break;
                                                
                                            case MessageType.KeyRotationUpdate:
                                                if (device != null)
                                                {
                                                    await HandleKeyRotationUpdateAsync(root, device, cancellationToken);
                                                }
                                                break;
                                                
                                            case MessageType.KeyRotationRequest:
                                                if (device != null)
                                                {
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

                                // Send error response
                                var errorMessage = new ErrorMessage
                                {
                                    DeviceId = _deviceManager.LocalDeviceId,
                                    DeviceName = _deviceManager.LocalDeviceName,
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
                        // Ignore errors when closing
                    }
                }
            }
        }

        /// <summary>
        /// Handle a pairing request
        /// </summary>
        private async Task HandlePairingRequestAsync(WebSocket webSocket, JsonElement root, string ipAddress, CancellationToken cancellationToken)
        {
            // Extract request information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var deviceName = root.GetProperty("device_name").GetString() ?? string.Empty;
            var requestId = root.GetProperty("request_id").GetString() ?? string.Empty;

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing request from {deviceName} ({deviceId})");

            // Handle the pairing request
            var accepted = _deviceManager.HandlePairingRequest(deviceId, deviceName, ipAddress, DEFAULT_PORT);

            // Send response
            var response = new PairingResponseMessage
            {
                DeviceId = _deviceManager.LocalDeviceId,
                DeviceName = _deviceManager.LocalDeviceName,
                RequestId = requestId,
                Accepted = accepted
            };

            // If accepted, include the shared key
            if (accepted)
            {
                var device = _deviceManager.GetDeviceById(deviceId);
                if (device != null)
                {
                    response.EncryptedSharedKey = device.SharedKey;
                    
                    // Set the device's current key ID
                    device.CurrentKeyId = _encryptionService.GetCurrentKeyId();
                    _deviceManager.UpdateDevice(device);
                }
            }

            await SendMessageAsync(webSocket, response, cancellationToken);
        }

        /// <summary>
        /// Handle a pairing response
        /// </summary>
        private async Task HandlePairingResponseAsync(JsonElement root, CancellationToken cancellationToken)
        {
            // Extract response information
            var requestId = root.GetProperty("request_id").GetString() ?? string.Empty;
            var accepted = root.GetProperty("accepted").GetBoolean();

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received pairing response for request {requestId}: {accepted}");

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
                        LastSeen = DateTime.Now
                    };

                    _deviceManager.AddOrUpdateDevice(device);
                }

                // Complete the task
                tcs.TrySetResult(accepted);
                _pairingRequests.Remove(requestId);
            }
        }

        /// <summary>
        /// Handle an authentication request
        /// </summary>
        private async Task<string?> HandleAuthAsync(WebSocket webSocket, JsonElement root, string ipAddress, CancellationToken cancellationToken)
        {
            // Extract auth information
            var deviceId = root.GetProperty("device_id").GetString() ?? string.Empty;
            var deviceName = root.GetProperty("device_name").GetString() ?? string.Empty;
            
            // Get key ID if available
            uint keyId = 0;
            if (root.TryGetProperty("key_id", out var keyIdElement))
            {
                keyId = keyIdElement.GetUInt32();
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Received auth request from {deviceName} ({deviceId}) with key ID {keyId}");

            // Check if the device is paired
            var device = _deviceManager.GetDeviceById(deviceId);
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
                _deviceManager.UpdateDeviceLastSeen(deviceId);

                // Send success response
                var response = new AuthSuccessMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    KeyId = _encryptionService.GetCurrentKeyId()
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
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Connecting to {device.DeviceName} at {device.IpAddress}:{device.Port}");

                var uri = new Uri($"wss://{device.IpAddress}:{device.Port}/");
                var client = new ClientWebSocket();

                // Enhanced certificate validation with certificate pinning
                client.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => {
                    string thumbprint = certificate?.GetCertHashString() ?? string.Empty;

                    // First connection to this device, store the certificate
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

                // Create auth message with current key ID
                var authMessage = new AuthMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    KeyId = _encryptionService.GetCurrentKeyId()
                };

                // Send auth message
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
            var buffer = new byte[16384]; // 16KB buffer
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

                            // Parse and handle the message
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
                                                break;

                                            case MessageType.AuthFailed:
                                                System.Diagnostics.Debug.WriteLine($"[NETWORK] Authentication failed with {device.DeviceName}");
                                                await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Authentication failed", CancellationToken.None);
                                                _connectedClients.Remove(device.DeviceId);
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

                System.Diagnostics.Debug.WriteLine($"[NETWORK] Clipboard format: {format}, IsBinary: {isBinary}, Data length: {data.Length}, Key ID: {keyId}");

                // If key ID doesn't match, request key update
                if (keyId != _encryptionService.GetCurrentKeyId())
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Key ID mismatch: device={keyId}, local={_encryptionService.GetCurrentKeyId()}");
                    
                    // Request key update
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
        public async Task<bool> SendPairingRequestAsync(string ipAddress, int port = DEFAULT_PORT, CancellationToken cancellationToken = default)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending pairing request to {ipAddress}:{port}");

                // Create a new WebSocket connection with WSS (secure WebSocket)
                var uri = new Uri($"wss://{ipAddress}:{port}/");
                using var client = new ClientWebSocket();

                // Configure TLS - accept self-signed certificates
                client.Options.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;

                // Set a connection timeout
                var timeoutToken = new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token;
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutToken);

                // Connect to the device
                await client.ConnectAsync(uri, linkedCts.Token);

                // Create a pairing request message
                var request = new PairingRequestMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName
                };

                // Create a task completion source for the response
                var tcs = new TaskCompletionSource<bool>();
                _pairingRequests[request.RequestId] = tcs;

                // Send the request
                await SendMessageAsync(client, request, linkedCts.Token);

                // Start listening for the response
                _ = Task.Run(async () =>
                {
                    var buffer = new byte[16384]; // 16KB buffer

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
                                            await HandlePairingResponseAsync(root, cancellationToken);

                                            // Close the connection
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
                if (buffer.Length > 8192) // A 8KB chunk
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

                    // Check if we have a shared key
                    if (string.IsNullOrEmpty(device.SharedKey))
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] No shared key for {device.DeviceName}, skipping");
                        continue;
                    }

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Encrypting data for {device.DeviceName}");

                    // Encrypt the data
                    string encryptedData;
                    bool isBinary = false;

                    if (data.Format == "text/plain" && data.TextData != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Encrypting text: {data.TextData.Length} chars");
                        encryptedData = _encryptionService.EncryptText(data.TextData, device.SharedKey);
                    }
                    else if (data.Format == "image/png" && data.BinaryData != null)
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Encrypting binary: {data.BinaryData.Length} bytes");
                        var encryptedBytes = _encryptionService.EncryptData(data.BinaryData, Convert.FromBase64String(device.SharedKey));
                        encryptedData = Convert.ToBase64String(encryptedBytes);
                        isBinary = true;
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine($"[NETWORK] Unsupported data format: {data.Format}");
                        continue;
                    }

                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Creating clipboard update message");

                    // Create the message
                    var message = new ClipboardUpdateMessage
                    {
                        DeviceId = _deviceManager.LocalDeviceId,
                        DeviceName = _deviceManager.LocalDeviceName,
                        Format = data.Format,
                        Data = encryptedData,
                        IsBinary = isBinary,
                        Timestamp = data.Timestamp,
                        KeyId = _encryptionService.GetCurrentKeyId() // Add key ID
                    };

                    // Send the message
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Sending message to {device.DeviceName}");
                    await SendMessageAsync(webSocket, message, cancellationToken);
                    sentCount++;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Error sending clipboard data to {device.DeviceName}: {ex.Message}");
                }
            }

            System.Diagnostics.Debug.WriteLine($"[NETWORK] Clipboard data sent to {sentCount} devices");
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
        /// Request a key update from a device
        /// </summary>
        private async Task RequestKeyUpdateAsync(PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                // Check if the device is connected
                if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                {
                    System.Diagnostics.Debug.WriteLine($"[NETWORK] Device {device.DeviceName} not connected, can't request key update");
                    return;
                }
                
                // Create key rotation request message
                var message = new KeyRotationRequestMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    LastKnownKeyId = device.CurrentKeyId
                };
                
                // Send the message
                await SendMessageAsync(webSocket, message, cancellationToken);
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation request sent to {device.DeviceName}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error requesting key update: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Handle a key rotation update message
        /// </summary>
        private async Task HandleKeyRotationUpdateAsync(JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received key rotation update from {device.DeviceName}");
                
                // Extract key information
                var currentKeyId = root.GetProperty("current_key_id").GetUInt32();
                var keyPackage = root.GetProperty("key_package").GetString() ?? string.Empty;
                
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation update: current key ID = {currentKeyId}");
                
                // Decrypt the key package
                byte[] encryptedPackage = Convert.FromBase64String(keyPackage);
                byte[] packageData = _encryptionService.DecryptData(encryptedPackage, Convert.FromBase64String(device.SharedKey));
                
                // Import the key package
                uint importedKeyId = _encryptionService.ImportKeyUpdatePackage(packageData);
                
                if (importedKeyId == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] Failed to import key package");
                    return;
                }
                
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Successfully imported key package, current key ID = {importedKeyId}");
                
                // Update device's key ID
                device.CurrentKeyId = currentKeyId;
                _deviceManager.UpdateDevice(device);
                
                // Update device last seen
                _deviceManager.UpdateDeviceLastSeen(device.DeviceId);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling key rotation update: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Handle a key rotation request message
        /// </summary>
        private async Task HandleKeyRotationRequestAsync(WebSocket webSocket, JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Received key rotation request from {device.DeviceName}");
                
                // Extract last known key ID
                var lastKnownKeyId = root.GetProperty("last_known_key_id").GetUInt32();
                
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation request: last known key ID = {lastKnownKeyId}");
                
                // Get key update package
                byte[] keyPackage = _encryptionService.GetKeyUpdatePackage(lastKnownKeyId);
                
                // Check if we have a valid package
                if (keyPackage.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[NETWORK] No valid key update package available, re-auth required");
                    
                    // Send auth failed message to trigger re-authentication
                    var authFailedMessage = new AuthFailedMessage
                    {
                        DeviceId = _deviceManager.LocalDeviceId,
                        DeviceName = _deviceManager.LocalDeviceName,
                        Reason = "Key rotation required, please re-authenticate"
                    };
                    
                    await SendMessageAsync(webSocket, authFailedMessage, cancellationToken);
                    return;
                }
                
                // Encrypt the key package with the device's shared key
                byte[] encryptedPackage = _encryptionService.EncryptData(keyPackage, Convert.FromBase64String(device.SharedKey));
                
                // Create key rotation update message
                var message = new KeyRotationUpdateMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName,
                    CurrentKeyId = _encryptionService.GetCurrentKeyId(),
                    KeyPackage = Convert.ToBase64String(encryptedPackage)
                };
                
                // Send the message
                await SendMessageAsync(webSocket, message, cancellationToken);
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Key rotation update sent to {device.DeviceName}");
                
                // Update device last seen
                _deviceManager.UpdateDeviceLastSeen(device.DeviceId);
                
                // Update device's key ID
                device.CurrentKeyId = _encryptionService.GetCurrentKeyId();
                _deviceManager.UpdateDevice(device);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[NETWORK] Error handling key rotation request: {ex.Message}");
            }
        }

        /// <summary>
        /// Dispose of the network service
        /// </summary>
        public void Dispose()
        {
            StopAsync();
            _cancellationTokenSource?.Dispose();
        }
    }
}