# ADR 0003 — Local IPC over named pipes / Unix sockets with a mutual HMAC handshake

- Status: accepted
- Date: 2026-11-24

## Context

The hook process, the CLI and the desktop app need to talk to the daemon: submit hook events, query the audit log, change mode, subscribe to live events. Requirements: local only; fast enough for the hook's hot path; no browser-reachable surface; a process that merely *occupies the endpoint name* must not be able to impersonate the daemon; no admin rights; works identically on Windows and Linux.

Alternatives considered:
- **HTTP on 127.0.0.1** (used by some competitors): reachable from any local process *and from web pages* (DNS rebinding / CSRF unless carefully defended), port conflicts, firewall prompts on Windows.
- **OS peer-credential checks only** (SO_PEERCRED / `GetNamedPipeClientProcessId` + token inspection): strong on Unix, but on Windows requires Win32 security APIs (`unsafe`) and does not help the *client* verify the *server*.
- **TLS / Noise** over the pipe: confidentiality that local pipes do not need, at the cost of key management and dependencies.

## Decision

- **Transport**: Windows named pipe `\\.\pipe\agentshield-<id>` created with `first_pipe_instance(true)` and `reject_remote_clients(true)`; Unix domain socket `<data>/run/daemon.sock` (0600) in a 0700 directory. `<id>` = first 8 bytes of SHA-256 of the data directory, so isolated installs get isolated daemons. **No TCP listener exists.**
- **Framing**: newline-delimited JSON, max 4 MiB per frame, protocol version in the hello.
- **Authentication**: mutual challenge/response. The daemon writes a fresh 32-byte random token to `daemon.token` at every start. Client sends a nonce; server answers with its nonce and `HMAC-SHA256(token, "server"|cn|sn)`; the client verifies **first**, then sends `HMAC-SHA256(token, "client"|cn|sn)`; the server verifies in constant time. The token never crosses the wire; role labels prevent reflection.
- **Semantics**: the handshake proves exactly one thing — *the peer can read this user's token file*. Everything a client says about itself (client label, agent, session, `actor`) is telemetry.
- **Limits**: 5 s handshake timeout, 600 s idle timeout, 400 requests/s per connection, 64 concurrent handler calls, bounded broadcast channel for subscribers.

## Consequences

Positive
- Pipe/socket squatting is detected on both sides: the daemon refuses to start if the name is taken; clients refuse a server without the token and fall back to local evaluation.
- No port, no firewall prompt, no browser-reachable surface, no certificates.
- Measured daemon-side handling p50 0.63 ms / p95 0.85 ms.
- Implemented without `unsafe` code.

Negative / residual
- **No protection against same-user processes**: they can read the token and are then fully authorised (including `SetMode`, `DeleteAll`, `Shutdown`). There is one trust level; no separation between "submit events" and "administer".
- On **Windows** the token file is protected only by the profile directory's ACL, and the pipe uses the default security descriptor; no explicit DACL is applied.
- A squatter can still deny daemon service (the daemon cannot bind); evaluation continues in the hook's degraded local path.
- No encryption on the channel; confidentiality relies on OS pipe/socket isolation.
- A custom protocol must be maintained and versioned (currently `PROTOCOL_VERSION = 1`).
