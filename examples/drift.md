# NativeBridgeGuard Trust Drift Report

## [HIGH] effective_registration_changed

- Trust path: `edge:com.example.bridge`
- Summary: Effective host registration changed.
- before: `{'registry_key': 'HKLM\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.example.bridge', 'manifest_path': 'C:\\Program Files\\Example\\host.json'}`
- after: `{'registry_key': 'HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.example.bridge', 'manifest_path': 'C:\\Users\\Alice\\AppData\\Local\\Example\\host.json'}`

## [MEDIUM] trust_surface_expanded

- Trust path: `edge:com.example.bridge`
- Summary: Native host authorization expanded to additional extension IDs.
- added_extension_ids: `['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']`

## [HIGH] binary_path_changed

- Trust path: `edge:com.example.bridge`
- Summary: Native host executable path changed.
- before: `C:\Program Files\Example\bridge.exe`
- after: `C:\Users\Alice\AppData\Local\Example\bridge.exe`

## [MEDIUM] binary_identity_changed

- Trust path: `edge:com.example.bridge`
- Summary: Native host binary hash changed.
- before: `AAA`
- after: `BBB`

## [HIGH] binary_signature_changed

- Trust path: `edge:com.example.bridge`
- Summary: Native host signing evidence changed.
- before: `{'status': 'Valid', 'signer': 'CN=Example Corp'}`
- after: `{'status': 'NotSigned', 'signer': None}`
