# OpenRelay: Cross-Platform Clipboard Sync

OpenRelay is a secure clipboard synchronization tool that allows you to seamlessly share clipboard contents between your devices. Currently supporting Windows-to-Windows clipboard synchronization with planned support for Android.

## Features

- Real-time clipboard synchronization (text, images)
- End-to-end encryption
- Simple device pairing
- System tray integration
- Automatic discovery of devices on local network

## Requirements

- .NET 9.0 or later
- Windows 10/11

## Installation

1. Clone this repository
2. Build the solution using Visual Studio or JetBrains Rider
3. Run the application

## Usage

1. Launch the application on two Windows computers
2. Right-click the system tray icon and select "Add Device"
3. On each device, copy the Device ID and Public Key from the "This Device" section
4. On the other device, enter this information in the "Add Remote Device" section
5. After pairing, any content copied on one device will be synced to the other

## Security

OpenRelay uses industry-standard encryption:
- AES-256 for clipboard content encryption
- RSA-2048 for key exchange and signatures
- Device verification prevents unauthorized access

## Planned Features

- Android support
- Mac/iOS support
- File transfer for larger content
- Cloud relay for cross-network sync
- QR code scanning for easier pairing

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.