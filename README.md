# OpenRelay: Cross-Platform Clipboard Sync

OpenRelay is a secure clipboard synchronization tool that allows you to seamlessly share clipboard contents between your devices. Currently supporting Windows-to-Windows clipboard synchronization with planned support for Android.

## Architecture

OpenRelay uses a hybrid architecture:
- **Core functionality**: Implemented in Rust for performance, security, and cross-platform capabilities
- **User interface**: Windows Forms (.NET) for the desktop interface

## Features

- Real-time clipboard synchronization (text, images)
- End-to-end encryption with secure key exchange during pairing
- Simple device pairing over the local network
- System tray integration
- Automatic discovery of devices on local network
- Lightweight memory footprint

## Requirements

- .NET 9.0 or later
- Windows 10/11 (as of now)
- The Rust-based [`openrelay_core.dll`](https://github.com/Awe03/OpenRelay-core)

## Building from Source
1. Clone this repository
2. Ensure you have the Rust toolchain installed for building the core library
3. Build the Rust core library (see the Rust project in `rust/` directory)
4. Build the C# solution using Visual Studio 2022 or later

## Connectivity

OpenRelay uses a sophisticated connectivity approach with multiple fallback options:

1. **Same Network**: When devices are on the same network, OpenRelay transfers data directly through the local network for maximum speed and privacy
   
2. **Different Networks**: When devices can't connect directly, OpenRelay securely routes clipboard data through an encrypted relay server

3. **Offline Mode**: When no internet connection is available:
   - Bluetooth Low Energy (BLE) is used for device discovery
   - Wi-Fi Direct establishes a high-speed direct connection for data transfer
   - As a final fallback, BLE itself can be used to transfer smaller clipboard content

This multi-tiered approach ensures your clipboard remains synchronized regardless of network conditions.

## Security

OpenRelay ensures your clipboard data remains private:

- AES-256-GCM for clipboard content encryption
- Secure key exchange during device pairing
- All communication encrypted end-to-end

## Planned Features

- Android support
- Mac/iOS support
- File transfer for larger content
- QR code scanning for easier pairing

## Technical Details

- The Rust core handles encryption, networking, and clipboard monitoring
- WebSocket-based communication between devices
- mDNS for local device discovery
- Windows Forms UI for system tray integration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-3.0 License - see the LICENSE file for details.
