# Harmless Native Messaging Lab

This lab exists only to verify the trust-path model on your own Windows machine.

1. Load `extension/` as an unpacked Chrome/Edge extension.
2. Copy the generated extension ID.
3. Prepare a Windows launcher (`.bat` or `.exe`) that runs `native_host/native_host.py` with Python.
4. Copy `host_manifest.template.json`, replace the extension ID and launcher path, and save it as a real host manifest.
5. Register `com.nativebridgeguard.lab` under the browser's NativeMessagingHosts registry key.
6. Click the extension action and confirm the `pong` response in the extension service-worker console.
7. Run NativeBridgeGuard and confirm it reconstructs the lab trust path.

The host only echoes a framed JSON `pong` response. It does not execute commands, access credentials, or contact remote systems.
