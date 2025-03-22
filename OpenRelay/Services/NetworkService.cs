using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using WebSocketSharp;
using WebSocketSharp.Server;
using Newtonsoft.Json;
using Zeroconf;
using OpenRelay.Models;

namespace OpenRelay.Services
{
    public class NetworkService : IDisposable
    {
        // WebSocket server for accepting connections
        private WebSocketServer? _server;
        
        // WebSocket clients for sending data to other devices
        private Dictionary<string, WebSocket> _clients = new Dictionary<string, WebSocket>();
        
        // Device manager for tracking paired devices
        private DeviceManager _deviceManager;
        
        // Encryption service for secure communication
        private EncryptionService _encryptionService;
        
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
        
        public NetworkService(DeviceManager deviceManager, EncryptionService encryptionService)
        {
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
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
                
                // Continue listening for new services
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
                                
                                // Create a shared key
                                string sharedKey = _encryptionService.GenerateSharedKey();
                                Console.WriteLine($"Generated shared key for pairing. Length: {sharedKey.Length}");

                                try {
                                    byte[] keyBytes = Convert.FromBase64String(sharedKey);
                                    Console.WriteLine($"Decoded key length: {keyBytes.Length} bytes");
                                    
                                    // Ensure key meets AES requirements (16, 24, or 32 bytes)
                                    if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                                    {
                                        Console.WriteLine($"WARNING: Invalid key size: {keyBytes.Length} bytes. Generating new key.");
                                        
                                        // Generate a fixed-size 32-byte key instead
                                        keyBytes = new byte[32]; // 256 bits
                                        using (var rng = RandomNumberGenerator.Create())
                                        {
                                            rng.GetBytes(keyBytes);
                                        }
                                        sharedKey = Convert.ToBase64String(keyBytes);
                                        Console.WriteLine($"New key generated with length: {keyBytes.Length} bytes");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Error validating key: {ex.Message}. Generating new fixed key.");
                                    
                                    // Generate a fixed-size 32-byte key instead
                                    byte[] keyBytes = new byte[32]; // 256 bits
                                    using (var rng = RandomNumberGenerator.Create())
                                    {
                                        rng.GetBytes(keyBytes);
                                    }
                                    sharedKey = Convert.ToBase64String(keyBytes);
                                }
                                
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
                                        SharedKey = sharedKey
                                    };
                                    
                                    _deviceManager.AddOrUpdateDevice(device);
                                    
                                    // Send the shared key
                                    var keyMessage = new Dictionary<string, string> {
                                        { "type", "shared_key" },
                                        { "request_id", requestId },
                                        { "shared_key", sharedKey }
                                    };
                                    
                                    ws.Send(JsonConvert.SerializeObject(keyMessage));
                                    
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
                    
                    // Verify shared key is valid
                    try {
                        byte[] keyBytes = Convert.FromBase64String(device.SharedKey);
                        Console.WriteLine($"Using shared key length: {keyBytes.Length} bytes for device {device.DeviceName}");
                        
                        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                        {
                            Console.WriteLine($"WARNING: Invalid key size for device {device.DeviceName}: {keyBytes.Length} bytes. Skipping.");
                            continue;
                        }
                    }
                    catch (Exception ex) {
                        Console.WriteLine($"Error with shared key for device {device.DeviceName}: {ex.Message}. Skipping.");
                        continue;
                    }
                    
                    // Encrypt the data with the shared key
                    string encryptedData;
                    if (data.Format == "text/plain" && data.TextData != null)
                    {
                        encryptedData = _encryptionService.EncryptData(data.TextData, device.SharedKey);
                    }
                    else if (data.BinaryData != null)
                    {
                        encryptedData = _encryptionService.EncryptBinaryData(data.BinaryData, device.SharedKey);
                    }
                    else
                    {
                        continue; // Skip unsupported format
                    }
                    
                    // Create message
                    var message = new ClipboardMessage
                    {
                        Type = "clipboard_update",
                        DeviceId = _deviceId,
                        DeviceName = _deviceName,
                        Timestamp = data.Timestamp,
                        Format = data.Format,
                        Data = encryptedData
                    };
                    
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
                // First try to parse as a clipboard message
                try
                {
                    var msg = JsonConvert.DeserializeObject<ClipboardMessage>(message);
                    
                    if (msg != null && msg.Type == "clipboard_update")
                    {
                        // Verify shared key is valid
                        try {
                            byte[] keyBytes = Convert.FromBase64String(device.SharedKey);
                            Console.WriteLine($"Using shared key length: {keyBytes.Length} bytes for device {device.DeviceName}");
                            
                            if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                            {
                                Console.WriteLine($"WARNING: Invalid key size for device {device.DeviceName}: {keyBytes.Length} bytes. Skipping message.");
                                return;
                            }
                        }
                        catch (Exception ex) {
                            Console.WriteLine($"Error with shared key for device {device.DeviceName}: {ex.Message}. Skipping message.");
                            return;
                        }
                        
                        // Create clipboard data
                        var clipboardData = new ClipboardData
                        {
                            Format = msg.Format,
                            Timestamp = msg.Timestamp
                        };
                        
                        // Decrypt data with the shared key
                        if (msg.Format == "text/plain")
                        {
                            clipboardData.TextData = _encryptionService.DecryptData(msg.Data, device.SharedKey);
                        }
                        else if (msg.Format == "image/png")
                        {
                            clipboardData.BinaryData = _encryptionService.DecryptBinaryData(msg.Data, device.SharedKey);
                        }
                        else
                        {
                            Console.WriteLine($"Unsupported format: {msg.Format}");
                            return;
                        }
                        
                        // Update clipboard
                        _onClipboardDataReceived?.Invoke(clipboardData);
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling clipboard message: {ex.Message}");
                }
                
                // If not a clipboard message, try as a dictionary
                var dict = JsonConvert.DeserializeObject<Dictionary<string, string>>(message);
                
                if (dict != null && dict.TryGetValue("type", out var type))
                {
                    switch (type)
                    {
                        case "auth":
                            HandleAuthMessage(dict, device);
                            break;
                            
                        case "shared_key":
                            HandleSharedKeyMessage(dict, device);
                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling message: {ex.Message}");
            }
        }
        
        private void HandleAuthMessage(Dictionary<string, string> message, PairedDevice device)
        {
            try
            {
                if (message.TryGetValue("device_id", out var deviceId) &&
                    message.TryGetValue("device_name", out var deviceName))
                {
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
        
        private void HandleSharedKeyMessage(Dictionary<string, string> message, PairedDevice device)
        {
            try
            {
                if (message.TryGetValue("shared_key", out var sharedKey) &&
                    message.TryGetValue("request_id", out var requestId))
                {
                    Console.WriteLine($"Received shared key from {device.DeviceName}. Key length: {sharedKey.Length}");
                    
                    // Check key validity
                    try
                    {
                        byte[] keyBytes = Convert.FromBase64String(sharedKey);
                        Console.WriteLine($"Decoded key length: {keyBytes.Length} bytes");
                        
                        // AES requires key size of 16, 24, or 32 bytes (128, 192, or 256 bits)
                        if (keyBytes.Length != 16 && keyBytes.Length != 24 && keyBytes.Length != 32)
                        {
                            Console.WriteLine($"Invalid key size: {keyBytes.Length} bytes. Must be 16, 24, or 32 bytes.");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error validating key: {ex.Message}");
                        return;
                    }
                    
                    // Update the shared key
                    device.SharedKey = sharedKey;
                    _deviceManager.AddOrUpdateDevice(device);
                    
                    Console.WriteLine($"Saved shared key for {device.DeviceName}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling shared key message: {ex.Message}");
            }
        }
        
        // Internal WebSocket service for handling connections
        internal class ClipboardSyncService : WebSocketBehavior
        {
            public NetworkService? NetworkService { get; set; }
            
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
                    // First try to parse as a dictionary for control messages
                    var message = JsonConvert.DeserializeObject<Dictionary<string, string>>(e.Data);
                    
                    if (message != null && message.TryGetValue("type", out var type))
                    {
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
            
            private void HandleAuthMessage(Dictionary<string, string> message)
            {
                try
                {
                    if (message.TryGetValue("device_id", out var deviceId) &&
                        message.TryGetValue("device_name", out var deviceName))
                    {
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
            
            private void HandlePairingRequest(Dictionary<string, string> message)
            {
                try
                {
                    if (message.TryGetValue("device_id", out var deviceId) &&
                        message.TryGetValue("device_name", out var deviceName) &&
                        message.TryGetValue("request_id", out var requestId))
                    {
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
                            { "request_id", message.TryGetValue("request_id", out var reqId) ? reqId : "unknown" },
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
                        { "request_id", message.TryGetValue("request_id", out var reqId) ? reqId : "unknown" },
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