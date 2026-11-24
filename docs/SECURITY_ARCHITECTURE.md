# AgentShield — Security Architecture

Version 0.1.0, 2026-11-24. Describes the implementation in this repository. Companion documents: [THREAT_MODEL.md](THREAT_MODEL.md) (threats and residual risk), [AGENT_CAPABILITY_MATRIX.md](AGENT_CAPABILITY_MATRIX.md), ADRs in [adr/](adr/).

## 1. Design principles

1. **Local only.** No TCP listener, no outbound connections, no account, no telemetry, no update check. IPC is a Windows named pipe or a Unix domain socket.
2. **Can only restrict.** AgentShield never returns `allow` or `updatedInput` to Claude Code. Combined with Claude Code's documented precedence (`deny > defer > ask > allow`, native deny/ask rules always evaluated), AgentShield cannot weaken the agent's native permission system.
3. **Honest coverage.** Every event carries a `coverage` value (enforceable / partial / observed / degraded) and every capability a status with a reason. Scores are policy classifications, not attack probabilities; confidence is stored separately.
4. **Static analysis only.** Commands are parsed, never executed, expanded or resolved against the filesystem.
5. **Redact before store.** Nothing is persisted, pushed to the GUI or exported before redaction.
6. **Per-user, unprivileged.** No admin/root, no service, no driver. Consequence: no protection against same-user code (THREAT_MODEL "[SAME-USER]").

## 2. Components

| Component | Crate / path | Role | Trust notes |
|---|---|---|---|
| Event model | `crates/event-model` | `NormalizedEvent`, `ActionKind`, `Finding`, `RiskAssessment`, `AuditRecord`, `Mode`, decisions. | Pure data. |
| Claude Code adapter | `crates/adapters/claude-code` | Normalises hook payloads; renders decisions; installs/uninstalls hooks in `settings.json` (preview, backup, atomic write, verify); detects agents; reads MCP config read-only. | Only component that knows Claude Code's formats. |
| Command parser | `crates/command-parser` | Quote-aware tokenizer for Bash/sh/zsh, PowerShell, CMD; pipelines, redirections, wrappers, nested interpreters (depth ≤ 4). | Never executes. |
| Secret detector | `crates/secret-detector` | Redactor (provider regexes, key/value heuristics, entropy; keyed fingerprints); sensitive-path classification. | Holds the per-install fingerprint key in memory. |
| Supply chain | `crates/supply-chain` | Offline analysis of package-manager and container commands. | No lookups. |
| Risk engine | `crates/risk-engine` | Deterministic findings (fixed scores) + URL assessment + prompt-injection indicators. | Pure. |
| Policy engine | `crates/policy-engine` | TOML policies in layers (preset → user → project), precedence, thresholds, **mode decision** (`mode.rs`). | The single place where blocking is decided. |
| Core | `crates/core` | Pipeline, correlation, config, paths, redaction of the record. | Shared by daemon and hook fallback → identical decisions. |
| Audit log | `crates/audit-log` | SQLite (WAL), hash chain, queries, stats, retention, backup, verify. | Tamper-evident only. |
| IPC | `crates/ipc` | Framing, mutual HMAC handshake, client, async server with limits. | Authenticates "can read the token file". |
| Daemon | `crates/daemon` | Owns the DB writer, evaluates hook events, streams to subscribers, mode changes, retention, incidents. | Independent of the GUI. |
| Reporting | `crates/reporting` | JSON, CSV, SARIF 2.1.0, static HTML exports and reports. | Formats already-redacted data. |
| CLI | `apps/cli` | `agentshield` binary: `hook`, `daemon`, `status`, `doctor`, `agent install`, `policy`, `events`, `export`, `selftest`, … | One binary for hook, daemon and CLI. |
| Desktop | `apps/desktop` (React/Vite) + `apps/desktop/src-tauri` (Tauri 2, separate Cargo workspace) | Dashboard; talks to the daemon through the same IPC client; bundles the CLI as sidecar. | WebView has no direct OS access beyond the command list. |

## 3. Pipeline

```
Claude Code ──(hook JSON on stdin)──► agentshield hook
   1. read stdin (≤ 4 MiB), parse JSON                              [apps/cli/src/hook.rs]
   2. IPC call Method::Hook to daemon (deadline 3 s)                [crates/ipc]
        └─ unreachable/auth failure → local evaluation, record marked degraded,
           daemon autostart attempted (≤ once / 30 s)
   daemon / local:
   3. normalize(payload) → NormalizedEvent {phase, action, ctx, enforceable}   [adapter]
   4. risk = assess(event)   — parser, shell rules, paths, secrets, supply chain, URLs   [risk-engine]
   5. correlate(event, risk, recent session events within window) → extra findings       [core]
   6. policy = PolicySet(preset+user+project).evaluate(event, risk)  → simulated decision [policy-engine]
   7. mode_outcome = apply_mode(mode, policy, event, risk)           → actual decision    [policy-engine/mode.rs]
   8. build AuditRecord: redact + truncate every free-text field                          [core]
   9. insert (IMMEDIATE txn, hash chain) → broadcast to subscribers                       [audit-log, daemon]
  10. render(hook_event, mode_outcome) → at most one JSON object on stdout, exit code 0   [adapter]
```

Two decisions are always recorded: the **simulated decision** (what the policy says: allow / warn / ask / require_sandbox / deny) and the **actual decision** (what was told to the agent: no_opinion / ask / deny / not_applicable). Pre-execution intent and post-execution result are separate rows linked by `correlation_id` (`tool_use_id`); the "observed outcome" in listings comes from the post row.

Risk score = `max(finding scores) + 5 per additional distinct category with a finding ≥ 40 (max +15)`, plus correlation findings. Policy precedence: `deny > require_sandbox > ask > warn > allow`; an explicit `allow` rule suppresses score thresholds but never a stricter rule; `hard = true` deny rules cannot be overridden.

## 4. Mode semantics and invariants

Source of truth: `crates/policy-engine/src/mode.rs` (`apply_mode`). Only **pre-execution, enforceable** events can receive a decision; everything else is `NotApplicable`.

| Mode | Policy `allow`/`warn` | Policy `ask` | Policy `require_sandbox` | Policy `deny` | Hard deny rule |
|---|---|---|---|---|---|
| **Monitor** | no opinion | no opinion | no opinion | no opinion | no opinion |
| **Shadow** | no opinion | no opinion | no opinion | no opinion | no opinion (recorded as "would block") |
| **Interactive** | no opinion | **ask** | **ask** | **ask** | **deny** |
| **Enforce** | no opinion | **ask** | **deny** (no verifiable sandbox exists) | **deny** | **deny** |
| **Lockdown** | deny if mutating, network, or risk ≥ 40; else no opinion | **deny** | **deny** | **deny** | **deny** |

"No opinion" = no output; Claude Code's own permission flow continues unchanged. "Paused" forces Monitor semantics.

Monitor and Shadow evaluate identically; the difference is presentation (Shadow reports "would ask / would block" for policy tuning and replay).

**Invariants** (tests: `invariant_monitor_and_shadow_never_block`, `invariant_post_and_lifecycle_never_decide`, `layering_and_project_restrictions` in `crates/policy-engine/src/tests.rs`; I2 additionally holds by construction — `ActualDecision` is only ever rendered as deny/ask or as no output):

- I1. Monitor and Shadow never return Ask or Deny.
- I2. No mode ever returns an explicit allow.
- I3. Post-execution and lifecycle events are always NotApplicable.
- I4. A project-layer policy cannot loosen the result (allow rules dropped, thresholds only lowered).
- I5. Daemon path and fallback path use the same `Engine` → same decision for the same input, config and history. (History can differ if the DB is unavailable in fallback; the record is then marked degraded.)

## 5. Failure behaviour (fail-open / fail-closed)

"Fail-open" = the tool call continues through Claude Code's normal permission flow (which may itself prompt or deny). It never means AgentShield approves.

| Failure | Monitor / Shadow / Interactive | Enforce / Lockdown |
|---|---|---|
| Daemon unreachable, IPC auth failure, daemon timeout (3 s) | Local evaluation with the same engine; record `degraded`; normal mode semantics still apply (Interactive still asks/denies). | Same: local evaluation, **decisions are still enforced**. |
| AgentShield **panic** during evaluation, or stdin read failure | Fail-open (no output). | **Deny** for PreToolUse with reason "AgentShield internal error … fail-closed" (`fail_closed_reply`). Other events: no output. |
| Payload is not JSON | Exit 0, no output, nothing recorded. | Same (fail-open; "never block on garbage"). |
| Payload JSON but not a recognised event | No decision. | No decision. |
| Config unreadable in the fallback/panic path | Defaults (Monitor) — fail-open. | **Becomes Monitor**: `configured_mode` falls back to Monitor when `config.toml` cannot be loaded. This is a fail-open edge case in a nominally fail-closed mode. |
| Policy file invalid | Built-in preset is used; record `degraded` with the policy error. | Same (never "no policy"). |
| Audit insert fails | Decision still returned; `dropped_events` counter incremented. | Same. |
| Hook process **cannot start, crashes hard, or exceeds Claude Code's timeout** (10 s configured) — e.g. binary deleted, AV delay | Fail-open: Claude Code treats it as a non-blocking error. **AgentShield cannot influence this from inside.** | Fail-open **unless** hooks were installed with `agentshield agent install --fail-closed`, which sets `"onFailure": "block"` on the PreToolUse handler (Claude Code ≥ 2.1.295). |

Guidance: Enforce/Lockdown without `--fail-closed` is fail-closed against AgentShield's *own* logic errors only. With `--fail-closed`, a missing or broken binary blocks every tool call until repaired (`agentshield agent repair` / `uninstall`) — a deliberate trade-off the installer shows in its preview.

Non-PreToolUse events are never blocking: AgentShield returns no decision on PermissionRequest, UserPromptSubmit, Stop, etc.

## 6. Redaction before storage

- Performed in `core::Engine::build_record` on: the action (command, path, URL, query, pattern), the stored input, finding evidence and explanations, the decision reason.
- Replacement format: `[REDACTED:<kind>:<fingerprint>]`; fingerprint = keyed SHA-256, 16 hex chars, key = 32 random bytes in `fingerprint.key` (Unix 0600). Same secret → same fingerprint within one install, enabling correlation without storage.
- Truncation: commands 4096 bytes, paths 1024, URLs 2048, patterns/queries 512, evidence 300, summary 240.
- **Not stored at all**: file contents (length only), prompts (length only), tool responses (scanned in memory up to 256 KiB for secrets/injection indicators, then dropped).
- MCP configuration: env variable **names** only; command lines redacted; URLs reduced to host.
- The IPC live stream, exports and reports only ever see redacted records.
- Limits: detection is pattern/heuristic based; an unknown secret format is stored as typed. The database is not encrypted at rest.

## 7. Authenticated vs. telemetry

| Item | Status |
|---|---|
| "The peer can read `daemon.token` in this user's data directory" (both directions) | **Authenticated** by mutual HMAC-SHA256 challenge/response; server proves first; constant-time verify; token never transmitted; fresh token per daemon start. |
| Peer is local | Enforced: pipe rejects remote clients; UDS is local by nature; no TCP. |
| Peer is *which program* (hook vs CLI vs GUI vs something else) | **Not authenticated.** `ClientHello.client` is a label. |
| `agent`, `session_id`, `cwd`/workspace, `tool_name`, `permission_mode`, `mcp_server` in a hook payload | **Telemetry** as reported by the caller. Any token holder can submit arbitrary events. |
| `actor` on SetMode / SetPreset / SetPaused / Shutdown | **Telemetry** (self-reported string, recorded in the audit log). |
| Audit rows | Integrity-*evident* via unkeyed hash chain; not authenticated. |
| Claude Code settings content | Read and verified structurally (our handlers present, binary path exists); not signed. |

There is no privilege separation between "may submit events" and "may change mode / delete data": one token, one trust level (the user).

## 8. IPC hardening summary

- Endpoint name derived from the data directory (`SHA-256(data_dir)[..8]`) → isolated installs (`AGENTSHIELD_HOME`) get isolated daemons.
- Windows: `\\.\pipe\agentshield-<id>`, `first_pipe_instance(true)`, `reject_remote_clients(true)`. Default pipe security descriptor (no custom DACL).
- Unix: socket in `<data>/run` (dir 0700), socket 0600, stale socket removed on bind.
- Framing: newline-delimited JSON, ≤ 4 MiB per frame, oversize → connection error.
- Limits: handshake 5 s, idle 600 s, 400 requests/s per connection, 64 concurrent handler calls (2 s acquire timeout), bounded broadcast (4096) for subscribers.
- Protocol version checked in the handshake.

## 9. `unsafe` code register

Workspace lint: `unsafe_code = "deny"` (`Cargo.toml`), also set in the desktop shell's `Cargo.toml`. Exceptions in first-party code:

| # | Location | What | Why | Safety argument |
|---|---|---|---|---|
| 1 | `apps/cli/src/daemon_ctl.rs`, `std_handles_not_inheritable()` (`#[cfg(windows)]`, `#[allow(unsafe_code)]`) | `GetStdHandle` + `SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0)` for stdin/stdout/stderr via `windows-sys`. | **Bug fix**: the daemon auto-started from a hook inherited Claude Code's stdout pipe; Claude Code then waited for EOF until the hook timeout. Rust's `std::process` offers no way to clear the inherit flag on the parent's own std handles. | `GetStdHandle` has no preconditions; null and `INVALID_HANDLE_VALUE` are skipped; `SetHandleInformation` only clears a flag on a handle owned by this process — it neither closes nor transfers it; no pointers are dereferenced, no memory is touched. |

No other `unsafe` exists in first-party code (verified by search on 2026-11-24). Third-party crates (tokio, rusqlite/bundled SQLite in C, windows-sys, Tauri/WebView bindings) contain unsafe code; that is not audited by this project.

## 10. Shell-parser limitations

The parser is a tokenizer for classification, not a shell. Each limitation is surfaced as an *uncertainty* on the event (coverage `partial`, lower confidence) where it can be detected.

| Limitation | Effect |
|---|---|
| Variables, parameter expansion, globbing, brace expansion | Not expanded; `rm -rf $DIR` is assessed without knowing `$DIR`. |
| Command substitution `$(…)`, backticks, `bash -c`, `sh -c`, `pwsh -Command`, `powershell -EncodedCommand` (base64/UTF-16), `cmd /c` | Parsed recursively to depth **4**; deeper nesting is flagged, not analysed. |
| `eval`, `Invoke-Expression`, `source` of computed strings | Flagged (`shell.dynamic_eval`), content unknown. |
| Inline interpreter code (`python -c`, `node -e`, `perl -e`) | Keyword-level capability detection only (`shell.inline_code_capabilities`); no language parsing. |
| Here-documents | Body is not analysed as code. |
| Aliases, shell functions, earlier `cd`/`export` in the session | Unknown; each command is analysed in isolation (only `cwd` from the payload is known). |
| Scripts on disk (`./deploy.sh`, `npm run x`, `make`) | The invocation is seen, the content is not. Writes of the script by the agent are seen separately. |
| Filesystem state: symlinks, junctions, reparse points, PATH resolution, case sensitivity | Never resolved (lexical normalisation only). |
| Input > 64 KiB | Truncated for analysis and flagged. |
| Shell dialect guess | `guess_shell` uses the tool name and syntax hints; a wrong guess (e.g. PowerShell text sent to the Bash tool) changes quoting rules. |
| Obfuscation | Common forms are detected (encoded commands, decode-pipe-exec, download-pipe-exec); novel encodings and string-building tricks are not. |

Bottom line: the parser reliably classifies what a cooperative or naively-injected agent writes on a command line. It is **not** resistant to an adversary deliberately hiding intent — that requires OS-level enforcement.

## 11. Desktop (Tauri) security notes

Configuration: `apps/desktop/src-tauri/tauri.conf.json`, `capabilities/default.json`.

**CSP as configured:**

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src ipc: http://ipc.localhost;
object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

- `script-src 'self'` — no inline scripts, no `eval`, no remote code. `withGlobalTauri: false`, `freezePrototype: true`.
- **`style-src 'unsafe-inline'` is required** because ECharts builds tooltips with inline `style` attributes and CodeMirror 6 injects style elements at runtime (`style-mod`). Risk accepted: inline *styles* allow CSS-based UI spoofing or data exfiltration via `url()` only if an attacker can inject markup; `img-src 'self' data:`, `font-src 'self'` and `connect-src` restricted to Tauri IPC leave no remote destination, and markup injection is prevented by escaping.
- **Everything is escaped**: React escapes by default; tooltip HTML is the only hand-built markup and goes through `escapeHtml` / `safeHtml` / `tooltipHtml` (`src/lib/escape.ts`); colours in tooltips must come from the theme, never from event data. Policy text is shown in CodeMirror as text.
- Fonts (Geist, JetBrains Mono) are bundled via `@fontsource-variable/*` — no font CDN.
- Capabilities: the main window gets `core:event:allow-listen` / `allow-unlisten` only, plus the app's own commands (a fixed list in `commands.rs`: status, events, stats, sessions, mode/preset/pause, policy validate/save, simulate/replay, agent install/uninstall preview, MCP inventory, verify, export, report, config, delete, backup, self-test, open path). No shell, fs, http or dialog plugin is enabled.
- Commands are thin wrappers over daemon IPC (30 s timeout); destructive ones (delete all, mode Lockdown, install) are confirmed in the UI. The GUI holds no state the daemon depends on: closing or crashing it changes nothing.
- Demo Mode uses an in-memory fictional dataset and never calls the real API (`src/lib/backend.ts`).
- `connect-src` contains `http://ipc.localhost` because Tauri's IPC uses that origin on Windows (WebView2); it is not a network endpoint.
- Not done: no auto-updater (by design), bundles are unsigned, the WebView runtime (WebView2 / WebKitGTK) is the system's and is patched by the OS.

## 12. Files on disk

| File | Location (Windows / Linux) | Content | Protection |
|---|---|---|---|
| `config.toml`, `policies/user.toml` | `%APPDATA%\AgentShield` / `$XDG_CONFIG_HOME/agentshield` | Mode, preset, preferences; user policy | Dir 0700 (Unix); profile ACL (Windows); atomic writes |
| `audit.db` (+ WAL) | `%LOCALAPPDATA%\AgentShield` / `$XDG_DATA_HOME/agentshield` | Redacted events, incidents, chain breaks | as above |
| `daemon.token` | data dir | Per-start IPC token | 0600 (Unix); removed on clean shutdown |
| `fingerprint.key` | data dir | Redaction fingerprint key | 0600 (Unix) |
| `run/daemon.sock`, `daemon.pid`, `run/autostart.attempt` | data dir | Runtime | 0600 socket in 0700 dir |
| `backups/`, `exports/`, `logs/daemon.log` | data dir | Settings backups, DB backups, exports, daemon log | as above |
| `~/.claude/settings.json` | Claude Code | Hook entries added by AgentShield | Backed up before each change |

`AGENTSHIELD_HOME` relocates config and data (used by tests and development so the real profile is untouched).

## 13. Known gaps (cross-reference)

Unsigned binaries; no CI/supply-chain gates; no explicit Windows ACLs on token/pipe; unkeyed hash chain; no silence watchdog; `ConfigChange` and `mcp_server.source` unused; `disableAllHooks` not checked; lexical path handling; fail-open edge case when config is unreadable in Enforce. See THREAT_MODEL §6 and §8.
