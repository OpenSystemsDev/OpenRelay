# Development Log - OpenRelay

This log tracks the development progress, major changes, decisions, and bug fixes for the OpenRelay server project.

**Maintainer:** Awe03  
**Repository:** https://github.com/OpenSystemsDev/OpenRelay-Server  
Note: Older updates are not included in this log, as they were not documented. This log starts from 2025-04-29.

---

## 2025-04-29

Today marks the completion of the cross-network functionality for OpenRelay.

### Goal  
Implement cross‑network clipboard sync so that a client can transfer data to paired devices even if its not on the same network.

*   **Added:**  Functionality to sync clipboard data across networks using OpenRelay-Server, or a selfhosted server.
Instead of using a local wss connection, the client now has one connection to the server, and the server will relay messages to all connected clients.  
The server follows a zero-knowledge architecture, implements rate limiting to prevent abuse, supports transfer of rotated keys and pairing of devices.
*   **Added:**  Random generation of of a password to encrypt the certificate, instead of a hardcoded string.
*   **Issue:**  The server is consistently returning a 400 when trying to authenticate. Somethings wrong with the client or the nginx configuration on the server
*   **Resolved:**  The nginx server was not forwarding the upgrade headers. See OpenRelay-Server for more details.  
Removed `_webSocket.Options.SetRequestHeader()` This was overriding the clients built in headers, confusing Nginx. Now, the proper Sec‑WebSocket‑Version is being emitted (along with other headers)

### Next Steps  
- Add a dynamic connection feature, where the device will use the relay server if not on the same network, but switch back to local if its on the same network, and vis a versa. This way, a device does not need to be paired twice to ensure it can communicate at all times.

### Lessons Learned  
- If the code works, do NOT touch it, even for optimization.
---

## 2025-05-02 to 2025-05-16

## Goal
Remove debugging logic from the server, and unify the Relay and Local pairing logic
As of now, Local pairing and Relay pairing have separate logics (relay uses the challenge based authentication, and local just sends a pairing request), and they are handled by deparate functions, complicating the codebase.

*   **Added:**  Unified pairing logic for both Local and Relay connections, and processes are managed by the same functions, with switch / if for connection type specific handling.
*   **Issue:**  There is a lot of code simplified for debugging purposes on the client. One instance is that since previously we were experiencing issues with the client saving the wrong device IDs thus rejecting messages from legitimate users, and so temporarily, instead of rejecting the message, we updated the Device ID to match the sender. This is a severe vunerability since now anyone claiming to be a device can send messages to the client, and the client will accept and also update ownership.