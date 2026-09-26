# Security

## Credentials

- SNMP, SSH and Telnet secrets are sealed with **AES-256-GCM**. The 32-byte master key comes
  from `NEXUS_MASTER_KEY` or `NEXUS_MASTER_KEY_FILE` and is never stored in the database or
  the source tree.
- Each ciphertext is bound to its row id and kind (AEAD associated data), so ciphertexts
  cannot be swapped between rows.
- The API never returns secrets: credential listings expose only non-secret summaries
  (version, username, protocols, port). Decryption happens only inside the discovery,
  polling and CLI services.
- Losing the master key makes stored credentials unreadable (they must be re-entered);
  rotating it requires re-entering credentials.

## Users and sessions

- Passwords are hashed with bcrypt; login attempts are rate limited per client (10 per 5
  minutes) with constant-time failure handling.
- Sessions are random 256-bit tokens; only their SHA-256 hash is stored. Cookies are
  `HttpOnly`, `SameSite=Strict` and `Secure` when `NEXUS_COOKIE_SECURE=true`.
- Changing a password or disabling a user revokes their sessions. The last active admin
  cannot be demoted, disabled or deleted.

| Role | Can |
|---|---|
| viewer | read everything except credentials |
| operator | + add devices / run discovery, edit context and locations, manual links, acknowledge alerts, open CLI sessions |
| admin | + manage credentials, users, settings, delete devices, reset SSH host keys, enable Telnet, read audit log and CLI transcripts |

## Web protections

- State-changing requests require the `X-Requested-With: nexus` header (not sendable
  cross-origin without a CORS preflight, which is never granted) in addition to
  `SameSite=Strict` cookies.
- WebSocket upgrades check that `Origin` matches the host.
- Strict Content-Security-Policy (`script-src 'self'`), `X-Frame-Options: DENY`,
  `nosniff`, `Referrer-Policy: same-origin`, request body limits.
- CSV exports neutralize spreadsheet formula injection.

## CLI access

- The browser connects only to Nexus over a WebSocket; Nexus connects to the device.
  Credentials never reach the browser.
- SSH host keys are pinned on first use; a changed key is refused until an admin resets it.
- Idle timeout (default 15 min) and maximum duration (default 4 h); admins can terminate
  live sessions.
- Every session is recorded in `cli_sessions` (user, device, addresses, timings, bytes,
  up to 1 MiB of output transcript) and in the audit log.
- **Telnet** is disabled by default. It requires the global Settings switch *and* a
  per-device flag set by an admin; the UI shows a clear-text warning.

## Discovery safety

- Recursion only follows LLDP/CDP neighbors whose management address is inside the
  **allowed networks** (default: the seed's /16), up to the configured hop count and
  device budget, with loop detection and bounded concurrency.
- Endpoint probing is **passive by default** (reverse DNS). Active identification
  (NetBIOS, TCP connect to a short list of service ports, HTTP GET `/`, SMB negotiate and the
  first leg of an anonymous NTLM exchange, SNMP `public`) must be enabled explicitly, stays
  inside the allowed networks and is rate limited. No exploit, brute force or credential
  guessing is ever performed; SMB stops after the server's challenge without authenticating.
- Only use discovery on networks you are authorized to manage.

## Audit

`audit_log` records logins (including failures), user and credential changes, settings
changes, discovery starts/cancellations, context edits, deletions, CLI session opens,
transcript views and terminations.

## LLM usage (optional)

When `ANTHROPIC_API_KEY` is set, only the user's question and the lists of known
vendor/device/location/OS names are sent to the model to obtain a JSON filter. Query
results and device details are never sent. Without the key, everything stays local.

## Reporting vulnerabilities

Please report security issues privately to the maintainers rather than opening a public
issue.
