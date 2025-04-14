using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
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
        /// Start the WebSocket server
        /// </summary>
        public async Task StartAsync()
        {
            if (_isListening)
                return;

            try
            {
                // Create cancellation token source
                _cancellationTokenSource = new CancellationTokenSource();

                // Create HTTP listener
                _httpListener = new HttpListener();
                _httpListener.Prefixes.Add($"http://+:{DEFAULT_PORT}/");
                _httpListener.Start();

                _isListening = true;

                // Log server start
                System.Diagnostics.Debug.WriteLine($"WebSocket server started on port {DEFAULT_PORT}");

                // Start listening for connections
                await AcceptConnectionsAsync(_cancellationTokenSource.Token);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error starting network service: {ex.Message}");
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

            System.Diagnostics.Debug.WriteLine("WebSocket server stopped");
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
                System.Diagnostics.Debug.WriteLine("WebSocket server canceled");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error accepting connections: {ex.Message}");
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
                System.Diagnostics.Debug.WriteLine($"WebSocket connection from {ipAddress}");

                // Process messages
                await ProcessMessagesAsync(webSocket, ipAddress, cancellationToken);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error processing WebSocket request: {ex.Message}");

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
                    System.Diagnostics.Debug.WriteLine($"Client {deviceId} disconnected");
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

                                if (Enum.TryParse<MessageType>(type, true, out var messageType))
                                {
                                    System.Diagnostics.Debug.WriteLine($"Received message of type {messageType}");

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

                                        default:
                                            System.Diagnostics.Debug.WriteLine($"Unhandled message type: {messageType}");
                                            break;
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine($"Error processing message: {ex.Message}");

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
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException || cancellationToken.IsCancellationRequested)
            {
                // Canceled, just return
                System.Diagnostics.Debug.WriteLine("WebSocket processing canceled");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error processing messages: {ex.Message}");

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

            System.Diagnostics.Debug.WriteLine($"Received pairing request from {deviceName} ({deviceId})");

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
                    response.SharedKey = device.SharedKey;
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

            System.Diagnostics.Debug.WriteLine($"Received pairing response for request {requestId}: {accepted}");

            // If we have a pending request for this ID, complete it
            if (_pairingRequests.TryGetValue(requestId, out var tcs))
            {
                // If accepted, get the device info and shared key
                if (accepted &&
                    root.TryGetProperty("device_id", out var deviceIdElement) &&
                    root.TryGetProperty("device_name", out var deviceNameElement) &&
                    root.TryGetProperty("shared_key", out var sharedKeyElement))
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

            System.Diagnostics.Debug.WriteLine($"Received auth request from {deviceName} ({deviceId})");

            // Check if the device is paired
            var device = _deviceManager.GetDeviceById(deviceId);
            if (device != null)
            {
                // Update device info
                device.DeviceName = deviceName;
                device.IpAddress = ipAddress;
                _deviceManager.UpdateDeviceLastSeen(deviceId);

                // Send success response
                var response = new AuthSuccessMessage
                {
                    DeviceId = _deviceManager.LocalDeviceId,
                    DeviceName = _deviceManager.LocalDeviceName
                };

                await SendMessageAsync(webSocket, response, cancellationToken);

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
        /// Handle a clipboard update
        /// </summary>
        private async Task HandleClipboardUpdateAsync(JsonElement root, PairedDevice device, CancellationToken cancellationToken)
        {
            try
            {
                // Extract clipboard data
                var format = root.GetProperty("format").GetString() ?? string.Empty;
                var data = root.GetProperty("data").GetString() ?? string.Empty;
                var isBinary = root.TryGetProperty("is_binary", out var isBinaryElement) && isBinaryElement.GetBoolean();

                System.Diagnostics.Debug.WriteLine($"Received clipboard update of format {format} from {device.DeviceName}");

                // Decrypt the data
                if (!string.IsNullOrEmpty(data) && !string.IsNullOrEmpty(device.SharedKey))
                {
                    try
                    {
                        // Create clipboard data
                        ClipboardData clipboardData;

                        if (format == "text/plain" && !isBinary)
                        {
                            // Decrypt text
                            var decryptedText = _encryptionService.DecryptText(data, device.SharedKey);
                            clipboardData = ClipboardData.CreateText(decryptedText);
                        }
                        else if (format == "image/png" && isBinary)
                        {
                            // Decrypt binary data
                            var encryptedBytes = Convert.FromBase64String(data);
                            var decryptedBytes = _encryptionService.DecryptData(encryptedBytes, Convert.FromBase64String(device.SharedKey));
                            clipboardData = ClipboardData.CreateImage(decryptedBytes);
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine($"Unsupported clipboard format: {format}");
                            return;
                        }

                        // Notify listeners
                        ClipboardDataReceived?.Invoke(this, new ClipboardDataReceivedEventArgs(clipboardData, device));
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error decrypting clipboard data: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error handling clipboard update: {ex.Message}");
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

                // Send the message
                await webSocket.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, cancellationToken);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error sending message: {ex.Message}");
            }
        }

        /// <summary>
        /// Send clipboard data to all connected devices
        /// </summary>
        public async Task SendClipboardDataAsync(ClipboardData data, CancellationToken cancellationToken = default)
        {
            if (data == null)
                return;

            // Get all paired devices
            var devices = _deviceManager.GetPairedDevices();

            foreach (var device in devices)
            {
                try
                {
                    // Check if the device is connected
                    if (!_connectedClients.TryGetValue(device.DeviceId, out var webSocket) || webSocket.State != WebSocketState.Open)
                    {
                        continue;
                    }

                    // Encrypt the data
                    string encryptedData;

                    if (data.Format == "text/plain" && data.TextData != null)
                    {
                        encryptedData = _encryptionService.EncryptText(data.TextData, device.SharedKey);
                    }
                    else if (data.Format == "image/png" && data.BinaryData != null)
                    {
                        var encryptedBytes = _encryptionService.EncryptData(data.BinaryData, Convert.FromBase64String(device.SharedKey));
                        encryptedData = Convert.ToBase64String(encryptedBytes);
                    }
                    else
                    {
                        continue;
                    }

                    // Create the message
                    var message = new ClipboardUpdateMessage
                    {
                        DeviceId = _deviceManager.LocalDeviceId,
                        DeviceName = _deviceManager.LocalDeviceName,
                        Format = data.Format,
                        Data = encryptedData,
                        IsBinary = data.Format == "image/png",
                        Timestamp = data.Timestamp
                    };

                    // Send the message
                    await SendMessageAsync(webSocket, message, cancellationToken);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Error sending clipboard data to {device.DeviceName}: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Send a pairing request to a device
        /// </summary>
        public async Task<bool> SendPairingRequestAsync(string ipAddress, int port = DEFAULT_PORT, CancellationToken cancellationToken = default)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"Sending pairing request to {ipAddress}:{port}");

                // Create a new WebSocket connection
                var uri = new Uri($"ws://{ipAddress}:{port}");
                using var client = new ClientWebSocket();

                // Connect to the device
                await client.ConnectAsync(uri, cancellationToken);

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
                await SendMessageAsync(client, request, cancellationToken);

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
                                    System.Diagnostics.Debug.WriteLine($"Error processing pairing response: {ex.Message}");
                                    tcs.TrySetResult(false);
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"Error receiving pairing response: {ex.Message}");
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
                    System.Diagnostics.Debug.WriteLine("Pairing request timed out");
                    _pairingRequests.Remove(request.RequestId);
                    return false;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error sending pairing request: {ex.Message}");
                return false;
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