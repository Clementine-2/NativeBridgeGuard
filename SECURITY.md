# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v0.1.5 | Yes (current release) |
| earlier / unreleased branches | No |

Security fixes land on the main branch and appear in the next tagged release.
There are no long-term maintenance branches for v0.1.x.

## Reporting a Vulnerability

There is no dedicated security mailbox at this time.

> Please open a **GitHub Security Advisory** after the repository is published.
> Until the repository is public and has Security Advisories enabled, open a
> regular issue containing only a description — no exploit steps against a real
> endpoint, and no raw scan output.

## Do NOT include these in a public issue

NativeBridgeGuard reports on the configuration of your own machine, so its
output is endpoint-sensitive.

- **Secrets**: API keys, tokens, passwords, private keys, bearer/authorization
  headers.
- **Personal information**: Windows account names, host names, domain names,
  SIDs, real profile paths (`C:\Users\<real user>\...`), emails, IP or MAC
  addresses.
- **Raw endpoint evidence**: `scan` snapshots, `events.ndjson`, `alert.md`,
  full `diff` output, or any dump produced against a real machine.

To reproduce safely, use the sanitized fixtures in `examples/`, or attach a
redacted excerpt with host-specific fields replaced by placeholders such as
`<USER_PROFILE>`.

## Scope and security boundary

NativeBridgeGuard is a **read-only audit and drift-monitoring tool**. To state
the boundary plainly:

- It **reads** browser/extension state, registry registrations, host manifests,
  and binary metadata. It does not install services, does not patch binaries,
  and does not modify trust configuration.
- The bundled validation lab is intentionally harmless: a test extension sends
  a JSON `ping` and a local host replies `pong`. There is no command
  execution, credential access, persistence, or remote contact.
- `HKLM`-scope lab steps require elevation, and the scripts never request
  elevation silently.

The following are **known limitations, not vulnerabilities** — please read the
README before reporting them:

- The `current_user_writable_hint` is a **DACL heuristic**, not a Windows
  Effective Access / AuthZ computation. It may disagree with your
  authorization tooling.
- The monitor is **schedule-driven**, so trust changes made and reverted inside
  a single interval can be missed.
- Browser preference/extension discovery depends on undocumented on-disk
  Chromium layout and may break on a future browser release.
- A finding is **not** a malware verdict or proof of exploitation.

Weaknesses in the tool's own code or packaging are in scope and welcome.
