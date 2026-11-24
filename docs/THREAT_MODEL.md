# AgentShield — Threat Model

Version: 0.1.0 (2026-11-24). Describes the code as it exists in this repository. Method: assets → actors → trust boundaries → STRIDE → specific threats with mitigation and **residual risk**. Statements marked "not implemented" are gaps, not plans disguised as features.

## 1. What AgentShield is — and is not

AgentShield is a **same-user, hook-based observer and policy gate** for Claude Code tool calls. It is a guardrail and an audit tool. It is **not** a sandbox, not an EDR, not a security boundary against code running as the same OS user. The single most important limitation, stated once and referenced below as **[SAME-USER]**:

> Everything AgentShield owns (binary, config, policies, token, fingerprint key, SQLite database, the hook entries in `~/.claude/settings.json`) is readable and writable by the user account that also runs the agent. Any process running as that user — including a command the agent was allowed to run — can read, alter or disable all of it. AgentShield can *detect and deny declared attempts* that pass through a hook; it cannot *prevent* undeclared ones.

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | The user's files, credentials, repositories, infrastructure | What the agent could damage or leak; the reason AgentShield exists. |
| A2 | Decision integrity (the deny/ask AgentShield returns) | A forged or suppressed decision defeats enforcement. |
| A3 | Monitoring continuity (hooks installed, daemon/hook functional) | Silent loss of monitoring is worse than a visible failure. |
| A4 | Audit log (`audit.db`) integrity and confidentiality | Evidence; contains redacted command lines, paths, hostnames. |
| A5 | Secrets passing through hook payloads | Must not be persisted or displayed. |
| A6 | Policy and mode configuration (`config.toml`, `policies/user.toml`) | Defines what is enforced. |
| A7 | IPC token (`daemon.token`) and fingerprint key (`fingerprint.key`) | Authenticate local peers; correlate redacted secrets. |
| A8 | Claude Code settings (`~/.claude/settings.json`) | AgentShield edits it; corruption breaks the user's agent. |
| A9 | The AgentShield binaries and installer | Run on every tool call with user rights. |

## 3. Actors

| Actor | Capability | Trust |
|---|---|---|
| User | Owns the machine account; changes mode/policy via CLI/GUI. | Trusted. |
| AI agent (Claude Code + model) | Issues tool calls; can be steered by untrusted content. Runs as the user. | **Untrusted for intent**, even though it has the user's rights. |
| Remote content author | Controls web pages, repository files, issue text, MCP tool descriptions/results the agent reads (indirect prompt injection). | Untrusted. |
| Malicious repository | Ships `.agentshield/policy.toml`, `.claude/settings.json`, `.mcp.json`, crafted file names. | Untrusted. |
| MCP server (local or remote) | Supplies tool names, descriptions, results. | Untrusted. |
| Other local process, same user | Full access to AgentShield's files and endpoints. | **Out of scope to defend against** [SAME-USER]; partially detectable. |
| Other local user (multi-user host) | Can try to reach the pipe/socket, pre-create (squat) the endpoint name. | Untrusted; defended. |
| Supply-chain attacker | Compromises a crate/npm dependency, the build, or the download. | Untrusted. |
| Network attacker | — | No network surface exists (no listener, no outbound traffic). |

## 4. Trust boundaries and data flow

```
 untrusted content ─► Claude Code (agent) ──stdin JSON──► agentshield hook (short-lived process)
                            ▲   │                              │  B1: hook payload = untrusted input
                            │   │ stdout: deny/ask JSON        │
                            │   ◄──────────────────────────────┤
                            │                                  │  B2: IPC (named pipe / UDS, mutual HMAC)
 MCP servers ◄─────────────┘                                   ▼
 (never contacted by AgentShield)                        agentshield daemon ──► core pipeline
                                                               │                (normalize → correlate → risk
 project files (.agentshield/policy.toml) ──B3: untrusted──►   │                 → policy → mode → redact)
 ~/.claude.json, .mcp.json (read-only) ─────B3──────────────►  │
                                                               ▼  B4: redaction happens before this line
                                                         SQLite audit.db (WAL, hash chain)
                                                               ▲
                              B2: IPC (same handshake)         │
 Tauri WebView (GUI) ◄─B5: Tauri command bridge─► desktop Rust shell ──► daemon
 CLI ───────────────────────B2─────────────────────────────────┘
```

| Boundary | Crossing data | Treated as |
|---|---|---|
| B1 agent → hook | Hook JSON (`tool_input`, `tool_response`, `prompt`, `cwd`, `session_id`, …) | Untrusted: size-capped, parsed defensively, never executed. |
| B2 hook/CLI/GUI ↔ daemon | Newline-delimited JSON frames | Peer authenticated as "can read the user's token file"; **all self-descriptions (agent name, session, paths, `actor`) are telemetry, not identity**. |
| B3 project/agent config → engine | `.agentshield/policy.toml`, `.mcp.json`, `~/.claude.json` | Untrusted: size cap, strict schema, project layer can only restrict; MCP config is read as metadata only. |
| B4 engine → storage | `AuditRecord` | Redacted and truncated before insert. |
| B5 WebView ↔ Rust | Tauri commands (fixed list), events | WebView content is local bundle only; data rendered in it is untrusted (derived from B1). |

## 5. STRIDE overview

| Component | S — Spoofing | T — Tampering | R — Repudiation | I — Information disclosure | D — Denial of service | E — Elevation of privilege |
|---|---|---|---|---|---|---|
| Hook process | Fake hook payloads from any same-user process (accepted; telemetry only) | Hook entry removed from settings.json | Events dropped on DB failure (counted, `dropped_events`) | Secrets in payload → redacted before storage | Oversized stdin (4 MiB cap), slow hook (3 s daemon deadline, 10 s Claude timeout) | None: same rights as caller; never executes input |
| IPC | Pipe/socket squatting → mutual HMAC, first-instance pipe | Frame injection → JSON framing, authenticated channel only for token holders | — | Token never on the wire; pipe rejects remote clients; socket 0600 in 0700 dir | 4 MiB frames, 5 s handshake timeout, 400 req/s per connection, 64 in-flight, 600 s idle | None: daemon runs as the same user |
| Daemon / core | — | Policy/config edits [SAME-USER] | Mode changes are recorded as events (`agentshield.mode_change`) | Logs: `daemon.log` (no payloads by design) | Regex/parse cost bounded by input caps (64 KiB command, depth 4, 256 KiB response scan) | — |
| Audit DB | — | Row edits → hash chain (evident, not proof) | Deletions recorded in `chain_breaks` | File readable by same user; content redacted | Unbounded growth → retention (default 90 days) | — |
| GUI (Tauri) | — | XSS via event data → CSP + escaping | — | Displays redacted data only | Large lists → virtualised tables | Tauri capability file grants only event listen/unlisten + own commands |
| Installer / binary | Trojaned download | Dependency compromise | — | — | AV delays (measured) | Runs with user rights on every tool call |

## 6. Specific threats

Format: **Threat → Mitigation (implemented) → Residual risk.**

### T1. Malformed or hostile hook input
- **Threat**: the agent (or injected content shaping `tool_input`) sends oversized, deeply nested, non-JSON, non-UTF-8 or adversarial payloads to crash the hook, exhaust memory, or make it mis-parse a command.
- **Mitigation**: stdin capped at 4 MiB (`MAX_STDIN`); non-JSON → exit 0 silently ("never block on garbage"); non-object / missing `hook_event_name` → adapter error → no decision; command analysis capped at 64 KiB and recursion depth 4; tool responses scanned up to 256 KiB; every stored string truncated (4096 / 1024 / 512 bytes); `catch_unwind` around evaluation; the parser never executes or expands anything. Secret detector and parser have property tests (proptest).
- **Residual risk**: a payload that cannot be parsed is *not evaluated* → in all modes the tool call proceeds through Claude Code's own permission flow (deliberate fail-open on garbage; an attacker who can make the payload unparseable also has to make Claude Code accept it as a valid tool call, which limits this). Regex worst-case behaviour is bounded by the `regex` crate's linear-time guarantee, but not benchmarked adversarially. Truncated commands (> 64 KiB) are flagged, not fully analysed.

### T2. IPC spoofing — pipe/socket squatting, rogue client, rogue server
- **Threat**: (a) another process creates `\\.\pipe\agentshield-<id>` (or the socket) first and impersonates the daemon, returning "no decision" for everything; (b) a rogue client sends fake events or `SetMode`/`Shutdown`; (c) a remote machine connects to the pipe.
- **Mitigation**: (a) Windows pipe is created with `first_pipe_instance(true)` — if the name is already taken the daemon fails loudly instead of sharing it; clients verify the **server's** HMAC proof first (`HMAC-SHA256(token, "server"|client_nonce|server_nonce)`) and abort if it is wrong, so a squatter that cannot read the token file cannot complete the handshake; the hook then falls back to local evaluation (marked degraded). (b) Clients must return the "client" proof; constant-time verification; the token is 32 random bytes, regenerated on every daemon start, stored in the per-user data dir (Unix `0600` in a `0700` dir), removed on shutdown, and never sent over the wire. (c) `reject_remote_clients(true)`; no TCP listener exists anywhere. Role strings prevent reflection of one proof as the other.
- **Residual risk**: [SAME-USER] any same-user process can read the token and act as a fully authenticated client (change mode, delete data, shut the daemon down) or as a server after killing the real one. On **Windows the token file's protection is the profile directory ACL only** — `restrict_file` is a no-op on non-Unix; no explicit DACL is set on the file or on the pipe (default pipe DACL applies). A squatter can still cause *denial of daemon service* (daemon cannot bind); the hook then runs the degraded local path, which still evaluates and logs. No channel encryption (local IPC; confidentiality relies on OS pipe/socket semantics).

### T3. Log injection
- **Threat**: attacker-controlled strings (commands, paths, file names, tool output) forge log lines, break the CSV/HTML/SARIF exports, inject spreadsheet formulas, or inject markup/script into the GUI or HTML reports.
- **Mitigation**: events are stored as structured JSON in SQLite via parameterised statements (no string-built SQL for values); HTML exports/reports are static, script-free, and escape every value (`reporting::esc`); CSV fields starting with `= + - @ \t \r` are prefixed with `'` and quoted (formula-injection defence); the GUI renders through React (escaped by default) and all ECharts tooltip HTML goes through `escapeHtml`/`tooltipHtml` (`apps/desktop/src/lib/escape.ts`); CSP forbids inline and remote script.
- **Residual risk**: event summaries replace CR/LF (so one event stays one line), but other control characters / ANSI escape sequences are not stripped for terminal display (`agentshield watch`, `events list`); a crafted file name could visually spoof a terminal line. SARIF/JSON consumers must do their own escaping.

### T4. Path traversal
- **Threat**: (a) the agent uses `..`, mixed separators, case or quoting tricks to make a sensitive path look harmless to policy globs; (b) attacker-influenced names make AgentShield itself write outside its directories (exports, backups, reports).
- **Mitigation**: (a) paths are normalised for matching (lower-case, forward slashes, collapsed `//`, quotes stripped, `~` expansion) before classification and glob matching; any `..` raises `path.traversal`; writes resolving outside the workspace raise `path.write_outside_workspace`. Claude Code documents that `tool_input.file_path` for Read/Write/Edit "is always absolute". (b) Export/report/backup file names are generated by the daemon inside `exports/` / `backups/`; IPC methods take a *format/kind*, not a path.
- **Residual risk**: normalisation is **lexical only** — see T5. Paths inside shell command lines are best-effort (arguments, redirections); a path assembled at runtime (`$HOME/.s""sh`, variables, globs) is recorded as an uncertainty and lowers confidence, it is not resolved.

### T5. Races, symlinks, junctions, reparse points (TOCTOU)
- **Threat**: the agent creates `./notes -> ~/.ssh` (symlink, or NTFS junction / other reparse point on Windows, no admin needed for junctions) and then reads `./notes/id_ed25519`; or swaps a path between AgentShield's check and the tool's use; or a hard link aliases a sensitive file.
- **Mitigation**: creation of links via shell is visible as a command; path classification applies to the *declared* path; `core` adds the uncertainty "Runtime values (variables, globs, symlinks, PATH lookups, aliases) cannot be resolved statically." AgentShield's own writes (`config.toml`, token, key, settings.json) use create-new temp file + `sync_all` + atomic rename in the same directory.
- **Residual risk**: **not mitigated by design.** AgentShield never touches the filesystem to resolve a declared path (no `canonicalize`), because resolving is itself racy and would add I/O to the hot path; even a resolved answer could change before the tool runs. A link-based indirection defeats path rules. Only an OS-level mechanism (Landlock, AppContainer, sandbox-runtime) closes this. AgentShield's own atomic writes do not use `O_NOFOLLOW`/reparse checks: a same-user attacker could pre-place a link in AgentShield's directories [SAME-USER].

### T6. Policy tampering
- **Threat**: (a) a repository ships `.agentshield/policy.toml` that allows everything or raises thresholds; (b) the agent edits that file mid-session; (c) the agent edits the user policy or `config.toml`, or runs `agentshield mode monitor` / `policy use observe-everything`.
- **Mitigation**: (a)(b) the project layer **can only restrict**: `allow` rules from a project layer are dropped with a warning, thresholds can only be lowered; file size capped at 256 KiB; `deny_unknown_fields` schema; a broken policy falls back to the built-in preset, never to "no policy". (c) writes to agent/AgentShield configuration paths (`path.agent_configuration.write`, `path.agentshield_configuration.write`, also via MCP) and the commands `tamper.agentshield_weaken` (mode monitor/shadow, agent uninstall, policy use/import/set, daemon stop, …), `tamper.claude_config`, `tamper.kill_agentshield` match the **hard** rule `agentshield-self-protection` in the built-in presets → denied in Interactive, Enforce and Lockdown; hard rules cannot be overridden by allow rules. Mode changes are written to the audit log with the claimed actor.
- **Residual risk**: in Monitor/Shadow nothing is blocked (by definition) — tampering is only recorded. A project policy *can* make things stricter to the point of nuisance (deny everything) — availability, not integrity. Detection is pattern-based: an indirect edit (`python -c "open(…).write(…)"`, `sed -i` through a variable, a script file) is not recognised [SAME-USER]. The `actor` in a mode-change record is self-reported. The `observe-everything` preset intentionally has no self-protection semantics beyond what it lists.

### T7. Audit database tampering
- **Threat**: an attacker (or the agent) edits, deletes or inserts rows in `audit.db` to hide activity.
- **Mitigation**: `hash = SHA-256(prev_hash ‖ "\n" ‖ record_json)` per row; inserts run in `IMMEDIATE` transactions so daemon and fallback writers keep one linear chain; deletions by retention or privacy request are recorded in `chain_breaks` with bridge hashes; `agentshield security check` / GUI "verify" recompute the chain, report the first bad id, and run SQLite's integrity check. Online backup via SQLite backup API.
- **Residual risk**: **tamper-evident, NOT tamper-proof.** There is no secret in the chain and no external anchor: anyone with write access can delete the tail or recompute the entire chain, and can also forge `chain_breaks` rows to "explain" a deletion. The chain detects naive edits and corruption only. Truncation of the newest rows is undetectable without an external copy of the last hash. Mitigation for users who need evidence: export/backup regularly to a location the agent cannot write. Not implemented: HMAC-keyed chain, external anchoring, append-only storage.

### T8. Approval replay
- **Threat**: in systems with their own approval tokens, a captured "approved" can be replayed for a different action.
- **Status**: **not applicable.** AgentShield issues no approvals and holds no approval state. In Interactive/Enforce it returns `permissionDecision: "ask"`; the prompt, the user's answer and its binding to the specific `tool_use_id` are entirely Claude Code's ([ADR 0005](adr/0005-delegate-approvals-to-native-prompt.md)). AgentShield never returns `allow`, so there is no AgentShield artefact whose replay would grant anything.
- **Residual risk**: approval fatigue (users clicking through prompts) and Claude Code's "don't ask again" persistence are outside AgentShield's control; an `ask` is not shown in non-interactive (`-p`) sessions the same way — behaviour there is Claude Code's.

### T9. Untrusted MCP metadata
- **Threat**: server names, tool names, descriptions and results are attacker-controlled: names crafted to look trusted or to break parsing/rendering (`mcp__github__…` from a non-GitHub server), poisoned descriptions, rug pulls, injected instructions in results.
- **Mitigation**: MCP config is read **read-only** and never executed or connected to; only metadata is kept (env variable *names*, never values; redacted command lines; URL host); names are length-capped and escaped on display; the adapter prefers `mcp_server.name` from the payload over the name parsed from the tool prefix; configuration fingerprints flag changes since last seen; tool results are scanned for injection indicators and secrets; MCP calls are enforceable pre-call like any tool.
- **Residual risk**: tool **descriptions are never seen** (no proxy) → tool poisoning and description-level rug pulls are undetectable by AgentShield. Capability heuristics are name-based and trivially evaded by an innocently named tool. `mcp_server.source` (the field Claude Code recommends for trust decisions) is not yet used. Injection indicators are regex heuristics with false negatives and positives.

### T10. Dependency or installer compromise
- **Threat**: a malicious crate/npm package, a compromised build machine, or a trojaned download gives an attacker code execution on every tool call.
- **Mitigation**: `Cargo.lock` and `package-lock.json` committed; small, mainstream dependency set (core workspace: 158 third-party packages in `cargo metadata` across all targets; GUI production: 35 npm packages); bundled SQLite (no system library lookup); `unsafe_code = "deny"` workspace-wide with one documented exception; the hook path has no network code at all; desktop shell is a separate workspace so WebView dependencies stay out of the hook/daemon binary; Tauri capability file limited to event listen/unlisten.
- **Residual risk**: **no** `cargo audit`/`cargo deny`/`npm audit` gate, no CI, no reproducible builds, no SBOM, no release signatures or checksums exist yet (`.github/workflows/`, `packaging/` are empty). Binaries are **unsigned** → no authenticity check for users, plus the measured AV penalty. Build-time dependencies (proc-macros, build scripts, Vite/Tailwind toolchain: 326 npm packages incl. dev) run with developer rights. This is the weakest area of the project today.

### T11. Denial of service / resource exhaustion
- **Threat**: flooding the daemon, huge frames, slow-loris handshakes, event storms from a looping agent, disk exhaustion; or simply making the hook slow enough that Claude Code times it out (→ fail-open).
- **Mitigation**: frame limit 4 MiB both directions; handshake timeout 5 s; idle timeout 600 s; per-connection rate limit 400 requests/s (`rate_limited` error); at most 64 concurrent blocking handler calls with a 2 s acquire timeout; live subscribers use a bounded broadcast channel (4096) — slow GUIs lag/drop, they do not block evaluation; latency sample buffers bounded (5000); policy cache bounded (32 entries); daemon autostart from the hook at most once per 30 s; hook asks the daemon with a 3 s deadline, then evaluates locally; retention (default 90 days, 1–3650) bounds the database; failed inserts are counted (`dropped_events`) and surfaced in status.
- **Residual risk**: no global connection cap and no per-session event quota; a same-user process can still saturate the daemon [SAME-USER]. No disk-space guard. **A hook that exceeds Claude Code's timeout fails open** in every mode unless installed with `--fail-closed` — demonstrated in practice by the antivirus delay (26 s) found during development ([ADR 0006](adr/0006-hook-args-avoid-av-heuristics.md)).

### T12. The agent tries to disable monitoring
- **Threat**: the agent (possibly prompt-injected) removes the hooks from `settings.json`, sets `disableAllHooks`, kills or stops the daemon, switches mode, replaces the binary, deletes the database, or starts a nested `claude --bare`.
- **Mitigation**: detections `tamper.claude_config`, `tamper.agentshield_weaken`, `tamper.kill_agentshield`, `path.agent_configuration.write`, `path.agentshield_configuration.write` (score up to 97, category AgentConfigurationTampering) and the hard deny rule `agentshield-self-protection` (effective in Interactive/Enforce/Lockdown); the hook does not depend on the daemon (local fallback + autostart), so killing the daemon degrades but does not blind; `agentshield doctor`/`status` and the GUI Agents page verify the installed hook entries (`verified`, `missing_events`, binary path) and show `degraded`; uninstall touches only AgentShield's own handlers and every settings change is backed up.
- **Residual risk**: [SAME-USER] — this is detection and a speed bump, not prevention. Any indirect modification that does not match a pattern succeeds, after which no further events arrive; AgentShield has **no heartbeat/watchdog that alerts when an active session goes silent**, does not register Claude Code's `ConfigChange` hook (which could block in-session settings changes), and does not check `disableAllHooks`. Tamper-resistant placement (managed policy settings, a service under a different account) is not implemented. In Monitor/Shadow tampering is only logged.

### T13. Antivirus / endpoint software interference (environmental)
- **Threat**: security software delays or blocks the unsigned hook binary, turning enforcement into silent fail-open or (with `--fail-closed`) into a blocked agent.
- **Mitigation**: hook arguments reduced to `hook` (avoids the observed heuristic); exec form (no shell); `doctor`/`selftest` exercise the real hook binary end-to-end.
- **Residual risk**: observed on one machine with one product; other products may behave differently. Code signing is the real fix and is not done.

### T14. Secrets leaking through AgentShield itself
- **Threat**: AgentShield becomes the place where secrets accumulate (command lines, prompts, tool output).
- **Mitigation**: redaction in the core pipeline before any persistence, IPC push or display; file contents and prompts are not stored (length/metadata only); findings carry `[kind:fingerprint]`, not values; fingerprints are keyed with a per-install random key; fixtures use synthetic credentials.
- **Residual risk**: redaction is pattern/heuristic based — an unrecognised secret format in a command line is stored in clear (truncated to 4096 bytes). The fingerprint key is a same-user-readable file; with it, guesses of a low-entropy secret can be confirmed offline. The database is not encrypted at rest.

## 7. Out of scope

- Kernel/admin-level attackers; physical access; a compromised Claude Code binary; the model provider.
- Network-level controls, sandboxing, process telemetry (see RESEARCH §6).
- Agents other than Claude Code: **not monitored at all**.
- Correctness of Claude Code's implementation of its documented hook contract.

## 8. Top residual risks (ranked)

1. [SAME-USER] — monitoring and evidence can be disabled or forged by same-user code.
2. Fail-open on hook timeout/crash in Claude Code (default install), including environmental causes.
3. No supply-chain assurance for AgentShield itself (unsigned, no CI gates).
4. Lexical path matching: symlink/junction indirection and runtime-computed commands bypass rules.
5. No visibility into MCP tool descriptions.
