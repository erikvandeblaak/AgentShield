# AgentShield — Research Notes

Status: research snapshot of **2026-11-24**. All URLs were accessed on that date unless stated otherwise (full list in [SOURCES.md](SOURCES.md)).

Evidence labels used throughout the documentation:

| Label | Meaning |
|---|---|
| **[P] proven** | Verified in this project: read in primary documentation *and/or* exercised by code and tests in this repository. |
| **[E] experimental** | Plausible and partly verified, but depends on undocumented behaviour, a single machine, or a third-party feature that is itself beta/preview. |
| **[M] marketing claim** | Stated by a vendor/project about itself; not independently verified here. |
| **[S] secondary** | Taken from a secondary source (blog, search summary); the primary source was not read. |

Scope decision by the owner: **only Claude Code is integrated**. Everything about other agents below is background, not a description of AgentShield functionality.

---

## 1. Claude Code hooks

Source: <https://code.claude.com/docs/en/hooks> (hooks reference; local Claude Code version during development: **2.1.331**).

### 1.1 Facts the adapter relies on

| # | Fact | Label |
|---|---|---|
| 1 | The reference lists **33 hook events**: SessionStart, Setup, UserPromptSubmit, UserPromptExpansion, PreToolUse, PermissionRequest, PermissionDenied, PostToolUse, PostToolUseFailure, PostToolBatch, Notification, MessageDisplay, SubagentStart, SubagentStop, TaskCreated, TaskCompleted, Stop, StopFailure, TeammateIdle, InstructionsLoaded, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreCompact, PostCompact, PreModelSwitch, PostModelSwitch, Elicitation, ElicitationResult, SessionEnd. | [P] |
| 2 | Hook locations: `~/.claude/settings.json`, `.claude/settings.json`, `.claude/settings.local.json`, managed policy settings; additionally plugin `hooks/hooks.json` and skill/subagent frontmatter. | [P] |
| 3 | "When an event fires, its matching hooks run in parallel." Identical handlers defined in several settings files run once. | [P] |
| 4 | Command handler fields: `command`, `args` (exec form: "spawned directly with `args` as the argument vector, with no shell involved"), `timeout` (default 600 s for command hooks; 30 s on UserPromptSubmit/PreModelSwitch/PostModelSwitch, 10 s on MessageDisplay), `async`, `asyncRewake`, `shell` (`bash`\|`powershell`, ignored with `args`), `onFailure` (`continue`\|`block`, "Requires Claude Code v2.1.295 or later"). | [P] |
| 5 | PreToolUse JSON output: `hookSpecificOutput.permissionDecision` = `allow` \| `deny` \| `ask` \| `defer`, with `permissionDecisionReason`. For `deny` the reason is shown to Claude, for `ask` in the permission prompt. | [P] |
| 6 | "When multiple PreToolUse hooks return different decisions, precedence is `deny` > `defer` > `ask` > `allow`." | [P] |
| 7 | "Deny and ask rules are still evaluated regardless of what the hook returns." A hook `allow` therefore cannot override a native deny rule. | [P] |
| 8 | Exit code 2 blocks on PreToolUse. Other non-zero exit codes are non-blocking errors. A timed-out hook "doesn't block the tool call … don't count on a stalled hook to act as a gate" unless `onFailure: "block"`. | [P] |
| 9 | Exit 0 with no output = no decision; "staying silent doesn't approve it" — the call continues through the normal permission flow. | [P] |
| 10 | Windows: shell form uses Git Bash, or PowerShell when Git Bash is missing; in that case "only exit code 0 or 2 counts as this hook's verdict" for PreToolUse/PermissionRequest and other codes may block. Exec form needs a real executable (`.exe`), not a `.cmd`/`.bat` shim. | [P] |
| 11 | Payload fields: `session_id`, `cwd`, `permission_mode`, `hook_event_name`, `transcript_path`; tool events add `tool_name`, `tool_input`, `tool_use_id`; PostToolUse adds `tool_response` (+ optional `duration_ms`); PostToolUseFailure adds `error`, optional `is_interrupt`; UserPromptSubmit adds `prompt`. | [P] |
| 12 | MCP tools are named `mcp__<server>__<tool>` (plugins: `mcp__plugin_<plugin>_<server>__<tool>`). Since v2.1.274 MCP payloads carry `mcp_server` = `{name, source}`; the docs advise: "Base trust decisions on `source` rather than on `name` or the `mcp__<server>__` tool-name prefix." | [P] |
| 13 | PostToolUseFailure "doesn't fire for calls rejected before execution" (permission denials, schema failures). | [P] |

### 1.2 How AgentShield uses them (as implemented)

- Registers **11 of the 33 events** in the user settings file (`~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR/settings.json`): PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest (matcher `*`), UserPromptSubmit, SessionStart, SessionEnd, Notification, Stop, SubagentStop, ConfigChange (`crates/adapters/claude-code/src/install.rs`). [P]
- Exec form: `command` = absolute path of the `agentshield` binary, `args` = `["hook"]`, `timeout` 10 s (5 s for SessionEnd). No shell, hence no Git Bash dependency (fact 10). [P]
- Output: only `deny` or `ask` on PreToolUse, always with exit code 0; otherwise no output (fact 9). AgentShield never emits `allow`, `defer`, or `updatedInput`, and returns no decision on PermissionRequest. Consequence of facts 6–7: AgentShield can only *add* restrictions. [P]
- Optional `--fail-closed` sets `onFailure: "block"` on the PreToolUse handler (fact 4/8). [P] (installation path tested; behaviour inside Claude Code is documented, not independently fuzzed → the *effect* is [E]).
- The adapter reads `mcp_server.name` to correct the server name parsed from the tool-name prefix (fact 12). It does **not** yet use `mcp_server.source` for trust decisions — open improvement.

### 1.3 Additional findings from this review (not yet used)

| Finding | Relevance | Label |
|---|---|---|
| **`ConfigChange` event** fires when `user_settings`/`project_settings`/`local_settings`/`policy_settings`/`skills` files change and "can block configuration changes from taking effect" for the running session (not for `policy_settings`). | A native in-session tripwire for hook removal. AgentShield currently detects tampering only through tool calls (`tamper.*`, `path.agent_configuration.write`). Registering ConfigChange would close part of the "agent edits settings.json through a path we do not see" gap. Not implemented. | [P] doc / not implemented |
| **Workspace trust**: in interactive sessions Claude Code "holds back hooks from every settings file, including your own `~/.claude/settings.json`, until you accept the workspace trust dialog". | Before trust is accepted there is no monitoring. Acceptable (nothing else runs either), but must be stated. | [P] |
| **`disableAllHooks`**, `--bare` and `--settings '{"disableAllHooks": true}'` switch all hooks off. | A user (or a wrapper script) can start an unmonitored session. AgentShield cannot see such a session at all; `agentshield doctor`/`state()` do not check `disableAllHooks` today. | [P] doc / gap |
| Hooks defined in **managed policy settings** cannot be removed by the user or the agent. | The only tamper-resistant placement on a same-user machine; relevant for a future "managed install". | [P] doc / not implemented |
| Docs disclaimer: "Command hooks execute shell commands with your full user permissions." | AgentShield's hook process is as privileged as the agent it watches (same user) — see THREAT_MODEL. | [P] |
| `PermissionRequest` hooks can return `decision.behavior = allow|deny`; "The hook can't approve what a deny rule refuses". | AgentShield observes PermissionRequest only. | [P] |
| `if` filters on hooks are "best-effort"; docs: "use the permission system rather than a hook to enforce a hard allow or deny." | Anthropic positions hooks as a guardrail, not a security boundary. AgentShield documentation must not claim more. | [P] |

### 1.4 Measured behaviour (this project, Windows 11, release build)

| Measurement | Value | Label |
|---|---|---|
| Hook end-to-end incl. process start (after AV warm-up) | p50 14 ms / p95 16.5 ms | [P] single machine |
| Daemon-side handling | p50 0.63 ms / p95 0.85 ms | [P] single machine |
| Policy evaluation (debug build) | p95 0.59 ms | [P] |
| Fallback path (daemon down, local evaluation) | 37 ms | [P] |
| SQLite: 100k inserts / filtered page | ~1 s / 0.7 ms | [P] |

Environmental finding [E] (one machine, Norton Antivirus, Defender disabled): process creation of an **unsigned** binary whose command line is exactly `hook claude-code` was delayed by ~26 s — longer than the 10 s hook timeout, i.e. a silent fail-open. Changing the arguments to `hook` removed the delay; Norton still adds ~0.55 s to the first launches of an unsigned binary. See [ADR 0006](adr/0006-hook-args-avoid-av-heuristics.md).

---

## 2. Other agents (not integrated — owner scope)

These agents are detected on `PATH` and shown as **Unsupported / not monitored** (`detect.rs`). No adapter exists. The notes below explain what an adapter *could* build on; none of it is implemented.

| Agent | Hook surface (per vendor docs) | Notes | Label |
|---|---|---|---|
| OpenAI Codex CLI | `hooks.json` in `$CODEX_HOME`, `.codex/` (trusted projects), system dir (`%ProgramData%\OpenAI\Codex\hooks.json` on Windows), inline in `config.toml`. Events incl. SessionStart, PreToolUse, PermissionRequest, PostToolUse, UserPromptSubmit, Stop. PreToolUse can deny (`permissionDecision: "deny"`, legacy `decision: "block"`, or exit 2). | Docs: "Treat tool hooks as a useful guardrail, not a complete enforcement boundary." and "A `PreToolUse` error, timeout, or malformed response can let the tool run." Hosted tools (WebSearch) are not intercepted. New/changed hooks are skipped until trusted via `/hooks`. | [P] doc read; not tested |
| Cursor | `.cursor/hooks.json` (project), `~/.cursor/hooks.json` (user), enterprise/team. Events incl. `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `afterFileEdit`, `preToolUse`. `permission`: allow/deny/ask. | Fails open by default; `failClosed: true` per hook. `ask` "is not enforced for `preToolUse` today." | [P] doc read; not tested |
| OpenCode, GitHub Copilot CLI | Not researched in depth. | Listed as unsupported only. | — |

Why not integrated: explicit scope decision ([ADR 0002](adr/0002-claude-code-only.md)). Each adapter is its own compatibility and test burden (payload schema, fail-open semantics, Windows behaviour), and a half-verified adapter would force the capability matrix to say "enforced" where we cannot prove it.

---

## 3. MCP security

### 3.1 Threat classes

| Threat | Description | Source | What AgentShield does today | What it does not do |
|---|---|---|---|---|
| **Tool poisoning** | Malicious instructions "embedded within MCP tool descriptions that are invisible to users but visible to AI models". | Invariant Labs, 2025-04-01 | Nothing at description level. Observes the *resulting* tool calls (PreToolUse) and applies name-based heuristics (`mcp.exec_capability`, `mcp.egress_capability`, `mcp.write_capability`, `mcp.destructive_capability`). | **No inspection of tool descriptions** — AgentShield is not an MCP proxy and never connects to servers (`mcp.rs`: "Nothing is started or connected to"). |
| **Rug pull** | "a malicious server can change the tool description after the client has already approved it." | Invariant Labs; ATLAS AML.T0109 | Fingerprints the *configuration* of each server (command, args, URL host, env key names) and flags `changed_since_last_seen`. Flags `mcp.unpinned_package` (`npx -y pkg` without version). | Cannot see a description change when the configuration is unchanged (remote server, or same package version serving different metadata). |
| **Shadowing / cross-server** | A tool description of server A alters how the agent uses server B. | Invariant Labs | Session correlation only (`correlation.secret_then_egress`). | No data-flow tracking between servers. |
| **Indirect prompt injection** | Instructions arrive via tool output, fetched pages, files. OWASP LLM01:2025; ATLAS AML.T0051. | OWASP, MITRE | PostToolUse responses (first 256 KiB) are scanned with regex indicators → `injection.indicator`; a later risky action in the same session raises `correlation.injection_then_risky_action` (confidence Low, "correlation only"). | Detection is heuristic and after the content already reached the model. It is an *indicator*, not prevention. [E] |
| **Local MCP server compromise** | Malicious startup command or payload in a locally launched server. | MCP spec "Security Best Practices" | Config scan: `mcp.privileged_container`, `mcp.plaintext_remote`, `mcp.literal_secret_in_config`, `mcp.unpinned_package`. | No sandboxing of servers; no package reputation lookup. |
| **Secret leakage to servers** | Credentials passed as tool arguments. | — | `mcp.secret_in_arguments` (redactor scan of arguments), enforceable pre-call. | — |
| Confused deputy, token passthrough, SSRF, session hijacking | OAuth/proxy-level attacks on MCP servers and clients. | MCP spec (page references spec revision 2025-11-25) | Out of scope: these are properties of servers/clients, not of a hook-based observer. | — |

### 3.2 Why no MCP proxy

A proxy (as used by Oktsec, HOL Guard "managed MCP proxies") is the only way to see `tools/list` responses and therefore the only real defence against poisoning/rug pulls at description level. It is deferred because (a) it rewrites the user's MCP configuration and becomes a single point of failure for every MCP call, (b) it would hold the credentials of every proxied server, enlarging AgentShield's own attack surface considerably, (c) remote/OAuth servers need a full client implementation. The capability matrix therefore states "tool descriptions are not inspected (no proxy)".

---

## 4. Secret exfiltration

Pattern of concern (OWASP LLM02:2025 Sensitive Information Disclosure; ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation): agent reads a credential (file, env, secret store) and a later action sends data out (HTTP upload, DNS/paste/webhook channel, `git push` to a new remote, MCP egress tool).

Implemented [P] (unit-tested with synthetic credentials):

- **Access side**: sensitive-path classification (`classify_path`: SSH keys, cloud credentials, `.env`, browser stores, …), credential commands (`cred.*`: `gh auth token`, `aws configure export`, `gcloud auth print-access-token`, `kubectl get secret`, `reg save` hives, shell history, environment dumps).
- **Egress side**: `network.*` (data upload, file upload, exfil channels such as webhook/paste/OAST/tunnel hosts, raw IP, unusual port, TLS disabled, reverse shell, cloud metadata endpoint), `shell.sensitive_read_and_network` (both in one command line).
- **Correlation**: `correlation.secret_then_egress` within a configurable window (default 15 min). Explicitly "not proof that data was sent".
- **Redaction before storage**: provider patterns + key/value heuristics + entropy; stored as `[REDACTED:<kind>:<fingerprint>]` with a keyed SHA-256 fingerprint.

Limits: only *intent visible in tool input* is assessed. A script that the agent writes and then runs can read and send anything; AgentShield sees `python x.py`, flags the write if content matches, and nothing else. There is no network telemetry (section 6).

---

## 5. Supply chain

References: OWASP LLM03:2025 Supply Chain; ASI04:2026 Agentic Supply Chain Vulnerabilities; ATT&CK T1195; ATLAS AML.T0010.

Implemented [P] (`crates/supply-chain`, static and offline): detection of package-manager commands (npm, pnpm, Yarn, Bun, pip, uv, Poetry, Composer, Cargo, dotnet, apt, winget, Chocolatey, Docker) and of: non-registry sources (URL/git), registry overrides (dependency-confusion indicator), typosquatting against a built-in list of popular names, remote execution of unpinned packages (`npx -y`, `uvx`, `pnpm dlx`), global installs, install scripts, unpinned container images, container-escape flags.

Not implemented: vulnerability lookup (OSV), package reputation/malware feeds, lockfile diffing, SBOM generation. Reason: offline-first; any lookup would send package names to a third party and must be opt-in. Installs triggered indirectly (a `make` target, a post-install script) are invisible → capability "Package detection: partial".

### 5.1 SBOM / CycloneDX

CycloneDX: current spec **1.7** (released 2025-10-21); standardised as **ECMA-424** (page lists publication 2025-12-10). AgentShield does **not** produce or consume SBOMs today. Two realistic uses, both deferred: (1) ship a CycloneDX SBOM of AgentShield's own Rust/npm dependencies with each release (`cargo cyclonedx`, `@cyclonedx/cyclonedx-npm` — build-time only, no runtime code); (2) export "packages the agent installed in this session" as a CycloneDX document. (1) is a release-engineering task (Phase 8), (2) has low confidence data (command lines, not resolved versions) and would be misleading as an SBOM.

---

## 6. OS mechanisms — what each could add, and why it is deferred

AgentShield today sees **only what the agent declares in a tool call**. OS mechanisms could provide ground truth (what processes actually did) or real containment. None is implemented; "Process monitoring" and "Sandbox integration" are `unsupported` in the capability matrix.

### Windows

| Mechanism | Could add | Why deferred |
|---|---|---|
| **ETW** (Microsoft-Windows-Kernel-Process / -File / -Network, Threat-Intelligence) | Ground-truth process tree, file and network activity of the agent's children; detection of actions that never appeared in a tool call. | Kernel providers need an **elevated** real-time session (admin or Performance Log Users); the Threat-Intelligence provider needs a PPL/ELAM-signed consumer. Contradicts "per-user, no admin". Requires `unsafe` FFI or a large dependency; high event volume; attribution of processes to an agent session is non-trivial. Observation only — cannot block. |
| **Job Objects** | Group the agent's process tree; limits (process count, memory, UI restrictions), kill-on-close; reliable attribution of descendants. | Only works if AgentShield *launches* the agent (wrapper model). AgentShield is hook-based and does not own the process. No file/network policy. |
| **AppContainer / LPAC, restricted tokens** | Real file/registry/network isolation for a launched process. | Requires launching the agent in the container; developer toolchains (git, node, cargo, MSVC) break without extensive capability/ACL work. Anthropic's own sandbox-runtime reports Windows as alpha with a dedicated local account + WFP fence + elevated install — evidence of the cost. |
| **Windows Filtering Platform** | Per-process/SID egress control. | Admin install, driver-adjacent API; explicitly out of scope ("no firewall integration by design"). |
| **Code signing (Authenticode)** | Not a monitoring mechanism, but removes the AV start-up penalty measured in §1.4 and SmartScreen warnings. | Certificate cost/identity validation; recommended before any public release. |

### Linux

| Mechanism | Could add | Why deferred |
|---|---|---|
| **eBPF** (tracepoints, kprobes, LSM hooks) | Ground-truth exec/open/connect telemetry with cgroup-based attribution; with BPF-LSM even enforcement. | Needs CAP_BPF/CAP_PERFMON or root, kernel ≥ 5.8 for the useful parts, BTF; a privileged helper daemon and a C/`aya` toolchain. Contradicts unprivileged per-user design. |
| **Landlock** | Unprivileged, kernel-enforced filesystem (and since ABI v4 TCP bind/connect) restrictions that are inherited by children. | Applies to the *calling* process and its descendants → requires a launcher/wrapper. Kernel ≥ 5.13 (network: ≥ 6.7). Cannot be applied to an already running agent. Most promising candidate for a future opt-in "launch sandboxed" mode. |
| **seccomp-bpf** | Syscall filtering (e.g. block `socket(AF_UNIX)`, `ptrace`). | Same wrapper requirement; filters cannot dereference path arguments, so not a path policy tool on its own. |
| **Namespaces / bubblewrap** | Mount/net/pid isolation without root (user namespaces). | Wrapper requirement; Ubuntu 24.04+ restricts unprivileged user namespaces via AppArmor by default (also noted in sandbox-runtime's README), so it fails out of the box on a primary target platform. |
| **fanotify** | File access notification, and with permission events (`FAN_OPEN_PERM`) blocking. | Permission events need CAP_SYS_ADMIN; system-wide marks are heavy. |

Conclusion: every containment mechanism requires owning the agent's process launch, and every telemetry mechanism requires privileges. Both are deliberate non-goals for v0.1. Users who need containment should enable Claude Code's own sandboxing (built on `anthropic-experimental/sandbox-runtime`); AgentShield states that "Claude Code's own sandbox settings remain authoritative".

---

## 7. OpenTelemetry

The GenAI semantic conventions (spans, metrics, events for GenAI clients and MCP) have moved out of the main semantic-conventions repository into `open-telemetry/semantic-conventions-genai`; the old page states it "is no longer maintained in this repository". The new repository's README shows no released version and a "TODO" schema URL on the access date → treat the conventions as **unstable** [E].

AgentShield does not emit OTLP. Reasons: (1) "no network listener, no outbound connections" is a core property; an OTLP exporter is an outbound channel that must be opt-in and redaction-reviewed; (2) the conventions are not stable; (3) Claude Code has its own OpenTelemetry export for usage telemetry, which overlaps. A future opt-in exporter would map `AuditRecord` → span/log with `gen_ai.*`/MCP attributes and send only redacted fields.

## 8. SARIF 2.1.0

SARIF v2.1.0 is an OASIS Standard; current text "Plus Errata 01", 2023-08-28. Implemented [P]: `agentshield export --format sarif` (`crates/reporting`, `to_sarif`): one `result` per finding of events with score ≥ 20, `$schema` `https://json.schemastore.org/sarif-2.1.0.json`, tool information URI `https://www.vandeblaak.com`; shape covered by a unit test. Caveat: SARIF is designed for static-analysis results tied to source locations; AgentShield findings are runtime events without a meaningful `physicalLocation`. Validation against the official JSON schema and ingestion into GitHub code scanning have **not** been tested [E].

---

## 9. OWASP mapping

**OWASP Top 10 for LLM Applications 2025** (genai.owasp.org) and **OWASP Top 10 for Agentic Applications 2026** (released 2025-12-09; ASI names taken from a secondary source [S], the official page only offers a download).

| OWASP item | AgentShield coverage | Finding prefixes |
|---|---|---|
| LLM01:2025 Prompt Injection / ASI01 Agent Goal Hijack | Indicators only, post-hoc; correlation with later risky actions. | `injection.*`, `correlation.injection_then_risky_action` |
| LLM02:2025 Sensitive Information Disclosure | Secret access, secrets in commands/prompts/outputs/URLs; redaction of the audit log. | `secret.*`, `cred.*`, `path.<sensitive kind>.*`, `network.secret_in_url` |
| LLM03:2025 Supply Chain / ASI04 Agentic Supply Chain Vulnerabilities | Package-manager command analysis; MCP config hygiene. | `supply.*`, `mcp.unpinned_package`, `mcp.privileged_container` |
| LLM05:2025 Improper Output Handling / ASI05 Unexpected Code Execution | Shell analysis of what the agent wants to execute. | `shell.*`, `lolbin.*` |
| LLM06:2025 Excessive Agency / ASI02 Tool Misuse & Exploitation | Core use case: policy on destructive, infra, database, git operations; modes Interactive/Enforce/Lockdown. | `shell.*`, `git.*`, `db.*`, `infra.*`, `mcp.*` |
| ASI03 Identity & Privilege Abuse | Privilege elevation, account/IAM changes, credential stores. | `shell.privilege_elevation`, `sec.account_change`, `infra.cloud_iam`, `cred.*` |
| ASI06 Memory & Context Poisoning | Not covered (no visibility into model context/memory). | — |
| ASI07 Insecure Inter-Agent Communication | Not covered. Subagent stops are recorded (`agent.subagent`) only. | — |
| ASI08 Cascading Failures | Partially: `correlation.repeated_denied_attempts`; Lockdown mode as a manual circuit breaker. | `correlation.*` |
| ASI09 Human-Agent Trust Exploitation | Partially: `ask` prompts carry AgentShield's reason and risk; approval fatigue is not measured. | — |
| ASI10 Rogue Agents | Self-protection detections and hard deny. | `tamper.*`, `path.agent_configuration.write` |
| LLM04, LLM07, LLM08, LLM09, LLM10 | Out of scope (model/data-level risks). | — |

---

## 10. MITRE ATLAS / ATT&CK mapping of AgentShield detections

**This is the author's indicative mapping, not validated by MITRE.** A finding is a *policy classification of a declared action*, not evidence that an adversary technique occurred. ATLAS IDs/names were checked against ATLAS data **2026.07** (`ATLAS-2026.07.yaml`); ATT&CK IDs are Enterprise technique IDs cited from memory of the public matrix and should be re-verified against the current ATT&CK release before external publication.

| Finding id prefix | Examples | ATT&CK (Enterprise) | ATLAS (2026.07) |
|---|---|---|---|
| `shell.download_pipe_exec`, `shell.ps_download_exec`, `net.webclient` | `curl … \| sh`, `iex (iwr …)` | T1105 Ingress Tool Transfer; T1059.004 / T1059.001 | AML.T0050 Command and Scripting Interpreter; AML.T0102 Generate Malicious Commands |
| `shell.encoded_command`, `shell.decode_pipe_exec`, `shell.dynamic_eval`, `shell.inline_code_capabilities` | `powershell -enc`, `base64 -d \| sh`, `eval` | T1027 Obfuscated Files or Information; T1140 Deobfuscate/Decode | AML.T0050 |
| `shell.rm_*`, `shell.find_delete`, `shell.shred`, `shell.dd_device`, `shell.disk_format`, `shell.docker_prune_all`, `shell.docker_volume_rm` | `rm -rf /`, `mkfs`, `dd of=/dev/sda` | T1485 Data Destruction; T1561 Disk Wipe | AML.T0101 Data Destruction via AI Agent Tool Invocation |
| `shell.fork_bomb` | `:(){ :\|:& };:` | T1499 Endpoint Denial of Service | — |
| `shell.privilege_elevation`, `shell.setuid`, `sec.sudoers` | `sudo`, `chmod u+s`, sudoers edits | T1548 Abuse Elevation Control Mechanism (.001, .003) | — |
| `shell.chmod_world_writable`, `shell.chown_root_recursive`, `shell.icacls_grant`, `sec.chattr` | `chmod -R 777` | T1222 File and Directory Permissions Modification | — |
| `shell.dev_tcp`, `network.reverse_shell`, `network.raw_socket`, `network.listener` | `/dev/tcp/…`, `nc -e` | T1059; T1095 Non-Application Layer Protocol; T1571 | AML.T0050 |
| `cred.dumping_tool`, `cred.reg_save_hive` | mimikatz, `reg save HKLM\SAM` | T1003 OS Credential Dumping (.002) | AML.T0090 OS Credential Dumping |
| `cred.secret_store`, `cred.cmdkey_list`, `git.credential_access`, `git.config_credential` | keychain/credential manager | T1555 Credentials from Password Stores | AML.T0055 Unsecured Credentials |
| `cred.aws_credentials`, `cred.gh_token`, `cred.gcloud_token`, `cred.az_token`, `cred.k8s_secrets` | `gh auth token` | T1528 Steal Application Access Token; T1552.001 | AML.T0055; AML.T0098 AI Agent Tool Credential Harvesting |
| `cred.shell_history`, `cred.dump_environment`, `cred.print_secret_var`, `path.<credential kind>.read`, `secret.credential_hunting` | `cat ~/.bash_history`, `env`, read `.env` / `id_rsa` | T1552 Unsecured Credentials (.001 files, .003 shell history, .004 private keys) | AML.T0055; AML.T0083 Credentials from AI Agent Configuration (when the file is agent/MCP config) |
| `secret.in_command`, `secret.written_to_file`, `secret.in_prompt`, `secret.in_tool_output`, `network.secret_in_url`, `network.secret_in_search`, `mcp.secret_in_arguments`, `mcp.literal_secret_in_config` | token on a command line | T1552 (exposure rather than theft) | AML.T0055 |
| `network.cloud_metadata` | `169.254.169.254` | T1552.005 Cloud Instance Metadata API | — |
| `network.data_upload`, `network.file_upload`, `network.exfil_channel`, `network.send_mail`, `network.remote_copy`, `shell.sensitive_read_and_network`, `correlation.secret_then_egress`, `mcp.egress_capability` | `curl -d @file`, webhook/paste hosts, `scp` | T1041; T1567 Exfiltration Over Web Service; T1048 Exfiltration Over Alternative Protocol | AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0025 Exfiltration via Cyber Means |
| `network.ssh_tunnel`, `network.ssh` | `ssh -R`, tunnels | T1572 Protocol Tunneling; T1021.004 | — |
| `network.plaintext*`, `network.tls_disabled`, `network.raw_ip`, `network.unusual_port`, `mcp.plaintext_remote` | `curl -k`, `http://1.2.3.4:8443` | T1071 Application Layer Protocol; T1571 Non-Standard Port (weak) | — |
| `persist.crontab`, `persist.at`, `persist.schtasks` | cron, `schtasks /create` | T1053 Scheduled Task/Job (.003, .002, .005) | — |
| `persist.systemd_enable`, `persist.service`, `persist.launchd` | `systemctl enable`, `sc create` | T1543 Create or Modify System Process | — |
| `persist.registry_run`, `persist.wmi` | Run keys, WMI subscriptions | T1547.001; T1546.003 | — |
| `sec.defender_change`, `sec.security_service_stop`, `sec.firewall_change`, `sec.selinux_off`, `sec.apparmor_off`, `sec.execution_policy`, `sec.audit_change` | `Set-MpPreference -Disable…`, `setenforce 0` | T1562 Impair Defenses (.001, .004, .002) | — |
| `sec.clear_logs`, `sec.clear_history` | `wevtutil cl`, `history -c` | T1070 Indicator Removal (.001/.002/.003) | — |
| `sec.bcdedit` | boot configuration | T1490 Inhibit System Recovery | — |
| `sec.account_change`, `infra.cloud_iam` | `net user /add`, IAM policy changes | T1136 Create Account; T1098 Account Manipulation | — |
| `lolbin.certutil`, `lolbin.bitsadmin`, `lolbin.proxy_exec` | `certutil -urlcache`, `mshta`, `regsvr32` | T1218 System Binary Proxy Execution; T1197 BITS Jobs; T1105 | — |
| `supply.non_registry_source`, `supply.registry_override`, `supply.dependency_confusion`, `supply.typosquat`, `supply.remote_execute_unpinned`, `supply.install_scripts`, `supply.global_install`, `supply.system_package`, `mcp.unpinned_package` | `npm i https://…`, `npx -y pkg` | T1195 Supply Chain Compromise (.001/.002) | AML.T0010 AI Supply Chain Compromise (.005 AI Agent Tool); AML.T0011.002 Poisoned AI Agent Tool |
| `supply.container_escape_flags`, `supply.container_unpinned`, `mcp.privileged_container` | `docker run --privileged -v /:/host` | T1611 Escape to Host; T1610 Deploy Container | — |
| `git.force_push`, `git.history_rewrite`, `git.reset_hard`, `git.clean_force`, `git.push_delete`, `git.branch_force_delete`, `git.reflog_expire`, `git.gc_prune_now`, `git.stash_drop`, `git.discard_changes`, `shell.rm_git_dir` | `git push --force` | T1485 Data Destruction; T1565.001 Stored Data Manipulation | AML.T0101 |
| `git.config_exec` (`core.hooksPath`, `core.sshCommand`, `core.fsmonitor`), `git.remote_change` | execution via git config | T1546 Event Triggered Execution; T1574 Hijack Execution Flow (weak) | — |
| `db.*` | `DROP DATABASE`, `migrate:fresh --force`, `FLUSHALL` | T1485; T1565.001 | AML.T0101 |
| `infra.destroy`, `infra.cloud_delete`, `infra.k8s_delete`, `infra.helm_uninstall`, `infra.state_change` | `terraform destroy` | T1485; T1578 Modify Cloud Compute Infrastructure | AML.T0101 |
| `infra.apply`, `infra.deploy`, `infra.k8s_change`, `infra.helm_change`, `infra.k8s_exec` | `kubectl apply`, `kubectl exec` | T1578; T1609 Container Administration Command | AML.T0053 AI Agent Tool Invocation |
| `mcp.exec_capability`, `mcp.write_capability`, `mcp.destructive_capability`, `mcp.call` | MCP tool calls | — | AML.T0053; (context) AML.T0110 AI Agent Tool Poisoning, AML.T0109 AI Supply Chain Rug Pull — *AgentShield does not detect poisoning itself* |
| `injection.indicator`, `correlation.injection_then_risky_action` | "ignore previous instructions" in tool output | — | AML.T0051 LLM Prompt Injection (indirect; sub-technique id per secondary source [S]); AML.T0080 AI Agent Context Poisoning (weak) |
| `tamper.claude_config`, `tamper.agentshield_weaken`, `tamper.kill_agentshield`, `path.agent_configuration.write`, `path.agentshield_configuration.write`, `mcp.path.*configuration.write` | edit `~/.claude/settings.json`, `agentshield mode monitor`, `taskkill agentshield` | T1562.001 Impair Defenses: Disable or Modify Tools | AML.T0081 Modify AI Agent Configuration |
| `path.traversal`, `path.write_outside_workspace` | `../../` | — (policy hygiene, no direct technique) | — |
| `correlation.repeated_denied_attempts` | ≥ 3 deny-rated actions in window | — | — |
| Informational ids `shell.exec`, `file.read`, `file.write`, `file.edit`, `file.search`, `network.fetch`, `network.search`, `http.request`, `git.push`, `supply.package_action`, `session.start`, `agent.subagent`, `agentshield.mode_change`, `tool.other` | action/summary types | — | — |

Note: path findings are generated as `path.<kind>.<read|write>` from `SensitiveKind` (`crates/secret-detector/src/paths.rs`); only the two configuration kinds are named explicitly in the built-in presets.
