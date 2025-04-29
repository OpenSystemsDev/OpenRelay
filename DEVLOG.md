# Development Log - OpenRelay

This log tracks the development progress, major changes, decisions, and bug fixes for the OpenRelay server project.

**Maintainer:** Awe03  
**Repository:** https://github.com/OpenSystemsDev/OpenRelay-Server  
Note: Older updates are not included in this log, as they were not documented. This log starts from 2025-04-29.

---

## 2025-04-29

**Time:** 16:27:05 UTC | **Author:** Awe03
Today marks the completion of the cross-network functionality for OpenRelay.

### Goal  
Implement cross‑network clipboard sync so that a client can transfer data to paired devices even if its not on the same network.

*   **Added:**  Functionality to sync clipboard data across networks using OpenRelay-Server, or a selfhosted server.
Instead of using a local wss connection, the client now has one connection to the server, and the server will relay messages to all connected clients.  
The server follows a zero-knowledge architecture, implements rate limiting to prevent abuse, supports transfer of rotated keys and pairing of devices.
*   **Issue:**  The server is consistently returning a 400 when trying to authenticate. Somethings wrong with the client or the nginx configuration on the server
*   **Resolved:**  The nginx server was not forwarding the upgrade headers. See OpenRelay-Server for more details.  
Removed `_webSocket.Options.SetRequestHeader()` This was overriding the clients built in headers, confusing Nginx. Now, the proper Sec‑WebSocket‑Version is being emitted (along with other headers)

### Next Steps  
- Add a dynamic connection feature, where the device will use the relay server if not on the same network, but switch back to local if its on the same network, and vis a versa. This way, a device does not need to be paired twice to ensure it can communicate at all times.

### Lessons Learned  
- If the code works, do NOT touch it, even for optimization.
---