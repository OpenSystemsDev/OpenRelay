# OpenRelay -  Cross platform clipboard sync

Openrelay is a clipboard synchronization service that securely relays your clipboard data between your devices.
As of now, this is Microsoft Windows only, with planned support for Android, Linux and MacOS

## Architecture

OpenRelay follows a hybrid architecture:
- Core functionality in Rust for performance across all ecosystems, memory safety, security and cross platform code reusability.
- User interface in Windows Forms (.NET) managing the UI, pairing with devices and networking.

## Features

- Cross-Platform and Cross-Ecosystem sync
Effortlessly sync text and images between your devices across Windows, with planned support for Android, macOS, and Linux. No more walled gardens or platform-exclusive features.

- Privacy
Your data is yours alone. Your clipboard content is, and will never be accessed, read, or collected by anyone, including the developers of OpenRelay. End-to-end encryption isemployed to ensure that your paired devices are the only ones that can decrypt your data.
- Low compute usage
The use of a Rust backend for critical functions, and optimization of the codebase (to the extent that I could) ensures that the application is light on memory, compute and power.
- No ads, tracking or analytics
OpenRelay was built to be lightweight and private. This means that we do not, and will never serve ads, collect analytics or data about your usage of our application(s), or sell any of your information.

## Security Standards
OpenRelay implements a comprehensive security framework based on industry standards.

- Military-Grade End-to-End Encryption:
All clipboard data is encrypted with AES-256-GCM (NIST SP 800-38D) and only accessible by your paired devices
- Zero knowledge architecture
All services used simply facilitate the connection, with no knowledge of any of your data.
- Advanced Key Management
Keys automatically rotate every 7 days (following NIST SP 800-57 guidelines with 7-day cycles) and secure key recovery mechanisms ensure your keys are always protected and manageable.
- FIPS 140-3 Alignment
The use of NIST-approved algorithms is in line with the requirements for FIPS 140-3 compliance in cryptographic modules.
- Secure Key Storage
Sensitive data, such as the encryption keys, are stored securely, encrypted on each device.


## Requirements

- .NET 9.0 or later
- Windows 10/11 (as of now)
- The Rust-based `openrelay_core.dll` (see [OpenRelay-core](https://github.com/Awe03/OpenRelay-core))

## Building from Source
1. Clone this repository
2. Ensure that you have the Rust toolchain installed to build
3. Build the openrelay_core library, and copy openrelay_core.dll to the solution directory
4. Build OpenRelay using Visual Studio 2022 or later, or a C# IDE of your choice

## Planned Features

- Android, MacOS and Linux support
- Implementation of Elliptic Curve Diffie-Hellman (ECDH) for device pairing
- When devices can't connect directly, OpenRelay securely routes clipboard data through an encrypted relay server, if you opt in to do so
- Wifi direct for high speed data transfer when devices are offline, with BLE as a fallback method to transfer smaller amounts of data

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-3.0 License - see the LICENSE file for details.