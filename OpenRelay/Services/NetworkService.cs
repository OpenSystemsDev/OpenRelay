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
        
        // Device ID of this device
        private string _deviceId;
        
        // Callback for when clipboard data is received
        private Action<ClipboardData>? _onClipboardDataReceived;
        
        public NetworkService(DeviceManager deviceManager, EncryptionService encryptionService)
        {
            _deviceManager = deviceManager;
            _encryptionService = encryptionService;
            _deviceId = deviceManager.LocalDeviceId;
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
        
        private Task RegisterServiceAsync()
        {
            try
            {
                // This would require a different library for Windows
                // In production, you'd want to use a native Windows API for this
                // For demo purposes, we'll rely on discovery only
                Console.WriteLine("Service registration not implemented for Windows");
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registering service: {ex.Message}");
                return Task.FromException(ex);
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
                    1,                         // Retries
                    1                          // Max services per endpoint
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
                        { "deviceId", _deviceId },
                        { "signature", _encryptionService.SignData(_deviceId) }
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
                    
                    // Encrypt the data for this device
                    string encryptedData;
                    if (data.Format == "text/plain" && data.TextData != null)
                    {
                        encryptedData = _encryptionService.EncryptData(data.TextData, device.PublicKey);
                    }
                    else if (data.BinaryData != null)
                    {
                        encryptedData = _encryptionService.EncryptBinaryData(data.BinaryData, device.PublicKey);
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
                        Timestamp = data.Timestamp,
                        Format = data.Format,
                        Data = encryptedData,
                        Signature = _encryptionService.SignData(encryptedData)
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
                var msg = JsonConvert.DeserializeObject<ClipboardMessage>(message);
                
                if (msg == null)
                {
                    return;
                }
                
                if (msg.Type == "clipboard_update")
                {
                    // Verify signature
                    if (!_encryptionService.VerifySignature(msg.Data, msg.Signature, device.PublicKey))
                    {
                        Console.WriteLine("Invalid signature, rejecting message");
                        return;
                    }
                    
                    // Create clipboard data
                    var clipboardData = new ClipboardData
                    {
                        Format = msg.Format,
                        Timestamp = msg.Timestamp
                    };
                    
                    // Decrypt data
                    if (msg.Format == "text/plain")
                    {
                        clipboardData.TextData = _encryptionService.DecryptData(msg.Data);
                    }
                    else if (msg.Format == "image/png")
                    {
                        clipboardData.BinaryData = _encryptionService.DecryptBinaryData(msg.Data);
                    }
                    else
                    {
                        Console.WriteLine($"Unsupported format: {msg.Format}");
                        return;
                    }
                    
                    // Update clipboard
                    _onClipboardDataReceived?.Invoke(clipboardData);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error handling message: {ex.Message}");
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
                    var message = JsonConvert.DeserializeObject<Dictionary<string, string>>(e.Data);
                    
                    if (message == null)
                    {
                        return;
                    }
                    
                    if (message.TryGetValue("type", out var type) && type == "auth")
                    {
                        // Handle authentication
                        if (message.TryGetValue("deviceId", out var deviceId) && 
                            message.TryGetValue("signature", out var signature))
                        {
                            // Verify device
                            var device = NetworkService._deviceManager.GetDeviceById(deviceId);
                            if (device != null && 
                                NetworkService._encryptionService.VerifySignature(deviceId, signature, device.PublicKey))
                            {
                                _connectedDevice = device;
                                
                                // Send acknowledgment
                                Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                                    { "type", "auth_success" },
                                    { "deviceId", NetworkService._deviceId }
                                }));
                                
                                return;
                            }
                        }
                        
                        // Authentication failed
                        Send(JsonConvert.SerializeObject(new Dictionary<string, string> {
                            { "type", "auth_failed" },
                            { "reason", "Invalid credentials" }
                        }));
                        
                        // Close connection
                        Context.WebSocket.Close(CloseStatusCode.PolicyViolation, "Authentication failed");
                    }
                    else if (_connectedDevice != null)
                    {
                        // Handle other messages
                        NetworkService.HandleMessage(e.Data, _connectedDevice);
                    }
                    else
                    {
                        // Not authenticated
                        Context.WebSocket.Close(CloseStatusCode.PolicyViolation, "Not authenticated");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error handling WebSocket message: {ex.Message}");
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