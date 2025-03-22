using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using WebSocketSharp;
using WebSocketSharp.Server;
using Newtonsoft.Json;
using Zeroconf;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class SimpleNetworkService : IDisposable
    {
        // WebSocket server for accepting connections
        private WebSocketServer? _server;
        
        // WebSocket clients for sending data to other devices
        private Dictionary<string, WebSocket> _clients = new Dictionary<string, WebSocket>();
        
        // Device manager for tracking paired devices
        private DeviceManager _deviceManager;
        
        // Service name for mDNS/Bonjour discovery
        private const string SERVICE_NAME = "_openrelay._tcp.local.";
        
        // Port for WebSocket server
        private int _port = 9876;
        
        // Local device information
        private string _deviceId;
        private string _deviceName;
        
        // Callback for when clipboard data is received
        private Action<ClipboardData>? _onClipboardDataReceived;
        
        // Task completion sources for pairing requests
        private Dictionary<string, TaskCompletionSource<bool>> _pairingResponses = 
            new Dictionary<string, TaskCompletionSource<bool>>();
        
        public SimpleNetworkService(DeviceManager deviceManager)
        {
            _deviceManager = deviceManager;
            _deviceId = deviceManager.LocalDeviceId;
            _deviceName = deviceManager.LocalDeviceName;
        }
        
        public async Task StartAsync()
        {
            try
            {
                // Start WebSocket server
                StartServer();
                
                // Register service for discovery
                await RegisterServiceAsync();
                
                // Start discovery of other devices
                await DiscoverDevicesAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting network service: {ex.Message}");
                throw;
            }
        }
        
        public void SetOnClipboardDataReceivedCallback(Action<ClipboardData> callback)
        {
            _onClipboardDataReceived = callback;
        }
        
        private void StartServer()
        {
            try
            {
                _server = new WebSocketServer(IPAddress.Any, _port);
                _server.AddWebSocketService<ClipboardSyncService>("/clipboard", (service) => {
                    service.NetworkService = this;
                });
                _server.Start();
                
                Console.WriteLine($"WebSocket server started on port {_port}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting WebSocket server: {ex.Message}");
                throw;
            }
        }
        
        private async Task RegisterServiceAsync()
        {
            try
            {
                // This would require a different library for Windows
                // In production, you'd want to use a native Windows API for this
                // For demo purposes, we'll rely on discovery only
                Console.WriteLine("Service registration not implemented for Windows");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registering service: {ex.Message}");
            }
        }
        
        private async Task DiscoverDevicesAsync()
        {
            try
            {
                // Discover other OpenRelay instances on the network
                var results = await ZeroconfResolver.ResolveAsync(SERVICE_NAME);
                
                foreach (var result in results)
                {
                    // Zeroconf results don't include port directly, we'll use our default port
                    Console.WriteLine($"Found service: {result.DisplayName} at {result.IPAddress}");
                    
                    // Check if this is a known device
                    var deviceInfo = _deviceManager.GetDeviceByIp(result.IPAddress);
                    if (deviceInfo != null)
                    {
                        // Connect to this device
                        ConnectToDevice(deviceInfo);
                    }
                }
                
                var subscription = ZeroconfResolver.ResolveContinuous(
                    SERVICE_NAME,
                    TimeSpan.FromSeconds(5),  // Timeout
                    2,               // Scan time
                    100
                );
                
                // Subscribe to the results
                subscription.Subscribe(result => 
                {
                    Console.WriteLine($"Found service: {result.DisplayName} at {result.IPAddress}");
                    
                    // Check if this is a known device
                    var deviceInfo = _deviceManager.GetDeviceByIp(result.IPAddress);
                    if (deviceInfo != null)
                    {
                        // Connect to this device
                        ConnectToDevice(deviceInfo);
                    }
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error discovering devices: {ex.Message}");
            }
        }
        
        public async Task<bool> SendPairingRequestAsync(string ipAddress, int port = 9876)
        {
            try
            {
                Console.WriteLine($"Sending pairing request to {ipAddress}:{port}");
                
                // Create a websocket connection to the device
                var url = $"ws://{ipAddress}:{port}/clipboard";
                var ws = new WebSocket(url);
                
                var taskCompletionSource = new TaskCompletionSource<bool>();
                
                ws.OnOpen += (sender, e) => {
                    Console.WriteLine($"Connected to {ipAddress}, sending pairing request");
                    
                    // Store the TCS for the response
                    string requestId = Guid.NewGuid().ToString();
                    _pairingResponses[requestId] = taskCompletionSource;
                    
                    // Send pairing request
                    var pairingRequest = new Dictionary<string, string> {
                        { "type", "pairing_request" },
                        { "request_id", requestId },
                        { "device_id", _deviceId },
                        { "device_name", _deviceName }
                    };
                    
                    ws.Send(JsonConvert.SerializeObject(pairingRequest));
                };
                
                ws.OnMessage += (sender, e) => {
                    try
                    {
                        var response = JsonConvert.DeserializeObject<Dictionary<string, string>>(e.Data);
                        if (response != null && 
                            response.TryGetValue("type", out var type) && 
                            type == "pairing_response" &&
                            response.TryGetValue("request_id", out var requestId) &&
                            _pairingResponses.TryGetValue(requestId, out var tcs))
                        {
                            if (response.TryGetValue("status", out var status) && status == "accepted")
                            {
                                Console.WriteLine("Pairing request accepted");
                                
                                // Get remote device info
                                if (response.TryGetValue("device_id", out var remoteDeviceId) &&
                                    response.TryGetValue("device_name", out var remoteDeviceName))
                                {
                                    // Add the device to paired devices
                                    var device = new PairedDevice
                                    {
                                        DeviceId = remoteDeviceId,
                                        DeviceName = remoteDeviceName,
                                        IpAddress = ipAddress,
                                        Port = port,
                                        Platform = "Unknown", // Could be added to protocol
                                        SharedKey = "none" // No encryption
                                    };
                                    
                                    _deviceManager.AddOrUpdateDevice(device);
                                    
                                    // Success
                                    tcs.SetResult(true);
                                }
                                else
                                {
                                    Console.WriteLine("Missing device info in pairing response");
                                    tcs.SetResult(false);
                                }
                            }
                            else
                            {
                                Console.WriteLine("Pairing request declined");
                                tcs.SetResult(false);
                            }
                            
                            // Remove the TCS
                            _pairingResponses.Remove(requestId);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error handling pairing response: {ex.Message}");
                        taskCompletionSource.SetException(ex);
                    }
                };
                
                ws.OnError += (sender, e) => {
                    Console.WriteLine($"Pairing error: {e.Message}");
                    taskCompletionSource.SetException(new Exception(e.Message));
                };
                
                ws.OnClose += (sender, e) => {
                    if (!taskCompletionSource.Task.IsCompleted)
                    {
                        Console.WriteLine($"Connection closed during pairing: {e.Reason}");
                        taskCompletionSource.SetResult(false);
                    }
                };
                
                ws.Connect();
                
                // Wait for pairing result with timeout
                var timeoutTask = Task.Delay(30000); // 30 second timeout
                var completedTask = await Task.WhenAny(taskCompletionSource.Task, timeoutTask);
                
                if (completedTask == timeoutTask)
                {
                    Console.WriteLine("Pairing timed out");
                    ws.Close();
                    return false;
                }
                
                return await taskCompletionSource.Task;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending pairing request: {ex.Message}");
                return false;
            }
        }
        
        private void ConnectToDevice(PairedDevice device)
        {
            try
            {
                if (_clients.ContainsKey(device.DeviceId))
                {
                    // Already connected
                    return;
                }
                
                var url = $"ws://{device.IpAddress}:{device.Port}/clipboard";
                var ws = new WebSocket(url);
                
                ws.OnOpen += (sender, e) => {
                    Console.WriteLine($"Connected to {device.DeviceName}");
                    
                    // Send authentication message
                    var authMessage = new Dictionary<string, string> {
                        { "type", "auth" },
                        { "device_id", _deviceId },
                        { "device_name", _deviceName }
                    };
                    
                    ws.Send(JsonConvert.SerializeObject(authMessage));
                };
                
                ws.OnMessage += (sender, e) => {
                    HandleMessage(e.Data, device);
                };
                
                ws.OnClose += (sender, e) => {
                    Console.WriteLine($"Disconnected from {device.DeviceName}: {e.Reason}");
                    _clients.Remove(device.DeviceId);
                };
                
                ws.OnError += (sender, e) => {
                    Console.WriteLine($"Error with connection to {device.DeviceName}: {e.Message}");
                };
                
                ws.Connect();
                _clients[device.DeviceId] = ws;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to device {device.DeviceName}: {ex.Message}");
            }
        }
        
        public void SendClipboardData(ClipboardData data)
        {
            var pairedDevices = _deviceManager.GetPairedDevices();
            
            foreach (var device in pairedDevices)
            {
                try
                {
                    if (!_clients.TryGetValue(device.DeviceId, out var ws) || !ws.IsAlive)
                    {
                        // Try to connect
                        ConnectToDevice(device);
                        if (!_clients.TryGetValue(device.DeviceId, out ws) || !ws.IsAlive)
                        {
                            continue; // Unable to connect
                        }
                    }
                    
                    // Create message - no encryption
                    var message = new Dictionary<string, object> {
                        { "type", "clipboard_update" },
                        { "device_id", _deviceId },
                        { "device_name", _deviceName },
                        { "timestamp", data.Timestamp },
                        { "format", data.Format }
                    };
                    
                    // Add the actual data
                    if (data.Format == "text/plain" && data.TextData != null)
                    {
                        message["data"] = data.TextData;
                    }
                    else if (data.BinaryData != null)
                    {
                        // Convert binary to Base64 for JSON
                        message["data"] = Convert.ToBase64String(data.BinaryData);
                        message["is_binary"] = true;
                    }
                    else
                    {
                        continue; // Skip unsupported format
                    }
                    
                    // Send message
                    ws.Send(JsonConvert.SerializeObject(message));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending to {device.DeviceName}: {ex.Message}");
                }
            }
        }
        
        private void HandleMessage(string message, PairedDevice device)
        {
            try
            {
                var dict = JsonConvert.DeserializeObject<Dictionary<string, object>>(message);
                
                if (dict != null && dict.TryGetValue("type", out var typeObj) && typeObj.ToString() == "clipboard_update")
                {
                    // Create clipboard data
                    var clipboardData = new ClipboardData();
                    
                    // Get format
                    if (dict.TryGetValue("format", out var formatObj))
                    {
                        clipboardData.Format = formatObj.ToString();
                    }
                    
                    // Get timestamp
                    if (dict.TryGetValue("timestamp", out var timestampObj))
                    {
                        clipboardData.Timestamp = Convert.ToInt64(timestampObj);
                    }
                    
                    // Get data - no decryption needed
                    if (dict.TryGetValue("data", out var dataObj))
                    {
                        bool isBinary = false;
                        if (dict.TryGetValue("is_binary", out var isBinaryObj))
                        {
                            isBinary = Convert.ToBoolean(isBinaryObj);
                        }
                        
                        if (clipboardData.Format == "text/plain" && !isBinary)
                        {
                            clipboardData.TextData = dataObj.ToString();
                        }
                        else if (isBinary)
                        {
                            clipboardData.BinaryData = Convert.FromBase64String(dataObj.ToString());
                        }
                        else
                        {
                            Console.WriteLine($"Unsupported format: {clipboardData.Format}");
                            return;
                        }
                        
                        // Update clipboard
                        _onClipboardDataReceived?.Invoke(clipboardData);
                    }
                }
                else if (dict != null && dict.TryGetValue("type", out var typeStr))
                {
                    switch (typeStr.ToString())
                    {
                        case "auth":
                            HandleAuthMessage(dict, device);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling message: {ex.Message}");
            }
        }
        
        private void HandleAuthMessage(Dictionary<string, object> message, PairedDevice device)
        {
            try
            {
                if (message.TryGetValue("device_id", out var deviceIdObj) &&
                    message.TryGetValue("device_name", out var deviceNameObj))
                {
                    string deviceId = deviceIdObj.ToString();
                    string deviceName = deviceNameObj.ToString();
                    
                    // Verify device
                    if (deviceId != device.DeviceId)
                    {
                        Console.WriteLine($"Device ID mismatch: expected {device.DeviceId}, got {deviceId}");
                        return;
                    }
                    
                    // Update device info
                    device.DeviceName = deviceName;
                    _deviceManager.UpdateDeviceLastSeen(deviceId);
                    
                    Console.WriteLine($"Authentication successful for {deviceName}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling auth message: {ex.Message}");
            }
        }
        
        // Internal WebSocket service for handling connections
        internal class ClipboardSyncService : WebSocketBehavior
        {
            public SimpleNetworkService? NetworkService { get; set; }
            
            private PairedDevice? _connectedDevice;
            
            protected override void OnOpen()
            {
                Console.WriteLine($"New connection from {Context.UserEndPoint}");
            }
            
            protected override void OnMessage(MessageEventArgs e)
            {
                if (NetworkService == null) return;
                
                try
                {
                    // Parse as a dictionary
                    var message = JsonConvert.DeserializeObject<Dictionary<string, object>>(e.Data);
                    
                    if (message != null && message.TryGetValue("type", out var typeObj))
                    {
                        string type = typeObj.ToString();
                        
                        switch (type)
                        {
                            case "auth":
                                HandleAuthMessage(message);
                                break;
                                
                            case "pairing_request":
                                HandlePairingRequest(message);
                                break;
                                
                            default:
                                // If the device is connected, pass the message to the network service
                                if (_connectedDevice != null)
                                {
                                    NetworkService.HandleMessage(e.Data, _connectedDevice);
                                }
                                else
                                {
                                    // Not authenticated
                                    Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                                        { "type", "error" },
                                        { "error", "not_authenticated" }
                                    }));
                                }
                                break;
                        }
                    }
                    else
                    {
                        // If the device is connected, pass the message to the network service
                        if (_connectedDevice != null)
                        {
                            NetworkService.HandleMessage(e.Data, _connectedDevice);
                        }
                        else
                        {
                            // Not authenticated
                            Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                                { "type", "error" },
                                { "error", "not_authenticated" }
                            }));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling WebSocket message: {ex.Message}");
                }
            }
            
            private void HandleAuthMessage(Dictionary<string, object> message)
            {
                try
                {
                    if (message.TryGetValue("device_id", out var deviceIdObj) &&
                        message.TryGetValue("device_name", out var deviceNameObj))
                    {
                        string deviceId = deviceIdObj.ToString();
                        string deviceName = deviceNameObj.ToString();
                        
                        // Check if this is a known device
                        var device = NetworkService._deviceManager.GetDeviceById(deviceId);
                        if (device != null)
                        {
                            // Store the device for this connection
                            _connectedDevice = device;
                            
                            // Update device info
                            device.DeviceName = deviceName;
                            
                            // Update IP address if it changed
                            if (Context.UserEndPoint != null && Context.UserEndPoint is IPEndPoint ipEndPoint)
                            {
                                device.IpAddress = ipEndPoint.Address.ToString();
                            }
                            
                            NetworkService._deviceManager.UpdateDeviceLastSeen(deviceId);
                            
                            // Send authentication success
                            Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                                { "type", "auth_success" },
                                { "device_id", NetworkService._deviceId },
                                { "device_name", NetworkService._deviceName }
                            }));
                            
                            Console.WriteLine($"Authentication successful for {deviceName}");
                            return;
                        }
                    }
                    
                    // Authentication failed
                    Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                        { "type", "auth_failed" },
                        { "reason", "device_not_paired" }
                    }));
                    
                    Console.WriteLine("Authentication failed: device not paired");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling auth message: {ex.Message}");
                    
                    // Authentication failed
                    Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                        { "type", "auth_failed" },
                        { "reason", "internal_error" }
                    }));
                }
            }
            
            private void HandlePairingRequest(Dictionary<string, object> message)
            {
                try
                {
                    if (message.TryGetValue("device_id", out var deviceIdObj) &&
                        message.TryGetValue("device_name", out var deviceNameObj) &&
                        message.TryGetValue("request_id", out var requestIdObj))
                    {
                        string deviceId = deviceIdObj.ToString();
                        string deviceName = deviceNameObj.ToString();
                        string requestId = requestIdObj.ToString();
                        
                        Console.WriteLine($"Received pairing request from {deviceName} ({deviceId})");
                        
                        // Get IP address
                        string ipAddress = "unknown";
                        if (Context.UserEndPoint != null && Context.UserEndPoint is IPEndPoint ipEndPoint)
                        {
                            ipAddress = ipEndPoint.Address.ToString();
                        }
                        
                        // Handle the pairing request
                        bool accepted = NetworkService._deviceManager.HandlePairingRequest(
                            deviceId, deviceName, ipAddress, NetworkService._port);
                        
                        // Send the response
                        var response = new Dictionary<string, string> {
                            { "type", "pairing_response" },
                            { "request_id", requestId },
                            { "status", accepted ? "accepted" : "declined" },
                            { "device_id", NetworkService._deviceId },
                            { "device_name", NetworkService._deviceName }
                        };
                        
                        Send(JsonConvert.SerializeObject(response));
                        
                        Console.WriteLine($"Pairing request {(accepted ? "accepted" : "declined")}");
                    }
                    else
                    {
                        // Invalid request
                        Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                            { "type", "pairing_response" },
                            { "request_id", message.TryGetValue("request_id", out var reqId) ? reqId.ToString() : "unknown" },
                            { "status", "declined" },
                            { "reason", "invalid_request" }
                        }));
                        
                        Console.WriteLine("Invalid pairing request");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling pairing request: {ex.Message}");
                    
                    // Pairing failed
                    Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                        { "type", "pairing_response" },
                        { "request_id", message.TryGetValue("request_id", out var reqId) ? reqId.ToString() : "unknown" },
                        { "status", "declined" },
                        { "reason", "internal_error" }
                    }));
                }
            }
            
            protected override void OnClose(CloseEventArgs e)
            {
                Console.WriteLine($"Connection closed: {e.Reason}");
            }
        }
        
        public void Dispose()
        {
            // Close client connections
            foreach (var client in _clients.Values)
            {
                client.Close();
            }
            
            // Stop server
            _server?.Stop();
        }
    }
}