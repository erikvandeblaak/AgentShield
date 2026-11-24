# Competitor & Related-Tool Analysis

Snapshot: **2026-11-24**. Repository metadata (license, stars, last push, archived flag) comes from the public GitHub REST API (`api.github.com/repos/<owner>/<repo>`); descriptions come from each project's README or website on that date. Stars and activity change daily. Evidence labels as in [RESEARCH.md](RESEARCH.md): **[P]** read in primary source, **[M]** the project's own claim, not verified by us.

**Reuse policy: AgentShield reuses no competitor code.** It is an independent implementation. Nothing below was copied, vendored, translated or used as a rule source; rule sets, regexes and typosquat lists in this repository were written for this project. Where a license would permit reuse (Apache-2.0, MIT) that is noted as a fact about the other project, not as something we did. None of the tools were installed or executed for this analysis — statements about their behaviour are documentation-based.

## 1. Summary table

| Project | Category | License (GitHub API) | Language | Stars | Last push | Archived |
|---|---|---|---|---|---|---|
| hashgraph-online/hol-guard | Agent runtime guard (hooks + MCP proxies) | Apache-2.0 | Rust (+ Python CLI) | 1,121 | 2026-11-24 | no |
| solongate/agent-security | Agent runtime gateway (hooks) | Apache-2.0 | Go | 696 | 2026-11-24 | no |
| oktsec/oktsec | Agent/MCP security proxy + hooks | Apache-2.0 | Go | 19 | 2026-11-14 | no |
| anthropic-experimental/sandbox-runtime | OS sandbox | Apache-2.0 | TypeScript | 7,249 | 2026-11-13 | no |
| cisco-ai-defense/mcp-scanner | MCP server scanner | Apache-2.0 | Python | 1,126 | 2026-11-23 | no |
| semgrep/semgrep | SAST | LGPL-2.1 | (API reports C; OCaml/Python project) | 17,920 | 2026-11-24 | no |
| gitleaks/gitleaks | Secret scanner | MIT | Go | 31,302 | 2026-10-28 | no |
| aquasecurity/trivy | Vulnerability/misconfig/SBOM scanner | Apache-2.0 | Go | 39,682 | 2026-11-24 | no |
| google/osv-scanner | Vulnerability scanner (OSV) | Apache-2.0 | Go | 11,611 | 2026-11-23 | no |
| ossf/scorecard | Repo security health metrics | Apache-2.0 | Go | 5,865 | 2026-11-23 | no |

All ten repositories were reachable on the access date.

## 2. Direct competitors (agent runtime security)

### 2.1 HOL Guard — hol.org/guard, github.com/hashgraph-online/hol-guard

- **What it is** [P/M]: "Open-source antivirus and firewall for AI agents"; reviews shell commands, file access, package installs and MCP tool calls before they run. The README itself qualifies the "antivirus" framing: it only sees actions an agent sends through its hooks.
- **Integration** [P]: "Guard connects through native agent hooks, managed MCP proxies, and launch integrations." For Codex, `hol-guard run codex` is a managed launch that refuses to start when hooks are missing.
- **Agents** [M]: Codex, Claude Code, GitHub Copilot CLI, Cursor, Cline, Gemini CLI, OpenCode, OpenClaw, Antigravity and more; per-agent depth is in a separate support matrix (not reviewed). README FAQ: "some events fail open or are only observed."
- **Architecture** [P]: Rust native runtime + Python CLI (`pipx install hol-guard`, Python 3.10+), local dashboard, "receipts" (decision history), supply-chain intelligence sync, plugin scanner with SARIF output.
- **Commercial** [P, from hol.org/guard]: Guard Local is free (Apache-2.0); optional **Guard Cloud** with listed tiers Free / Solo $4.99 / Pro $15 / Team $30 / Enterprise; cloud is "for visibility and coordination, not for enforcement".
- **Status**: very active (pushed on the access date; created 2026-03-28; 78 open issues).
- **Claims to treat with care** [M]: website states "6.7K+ GitHub stars", "2.8M+ PyPI downloads", "37M+ network transactions". The GitHub API reports **1,121** stars for `hashgraph-online/hol-guard` on the same day; the website figure may aggregate several repositories — we could not reconcile it. "Reviewed by Enclave" badge: no audit scope/report was seen.
- **Reusable**: license permits it; **nothing reused**.
- **How AgentShield differs**: one agent, verified end-to-end, instead of many agents at varying depth; no cloud tier, no account, no advisory/intelligence sync (fully offline); native desktop GUI (Tauri) + single Rust binary with no Python runtime; explicit Monitor/Shadow modes that record "would block" without interfering; never returns `allow`; tamper-evident hash-chained audit log. **HOL Guard is ahead on**: breadth of agents, MCP proxying (can see tool metadata — AgentShield cannot), supply-chain intelligence feeds, maturity and community size.

### 2.2 SolonGate Agent Security — github.com/solongate/agent-security

- **What it is** [P/M]: "open source, local first security gateway for AI coding agents"; policy check of tool calls, DLP ("70+ built in secret patterns", modes off/detect/redact/block), rate limits, local audit trail, TUI + CLI.
- **Integration** [P]: hook-based ("Hooks load when a session starts…"); for Claude Code additionally "A shim masks the outbound request body" (i.e. it also touches the request to the model API, which hooks cannot reach). Includes a sandbox command that gives the agent a minimal filesystem.
- **Agents** [M]: Claude Code, Codex CLI, Antigravity CLI, OpenCode; more planned.
- **Privacy** [M]: "the guard makes no network calls. No account, no telemetry." (the updater necessarily does).
- **Status**: very active, young (created 2026-09-27; 137 open issues). Go 1.26+, installed via clone + `scripts/install.sh`. Platform support not enumerated in the README.
- **Claims not verified** [M]: "a policy in a repository cannot switch it off", OS-enforced protected paths, "the guard's own state is unreachable from a tool call".
- **Reusable**: license permits it; **nothing reused**.
- **How AgentShield differs**: GUI dashboard with charts/sessions/reports rather than a TUI; risk scoring with per-finding explanations and confidence rather than allow/deny rules only; shadow-mode replay of policies against recorded history; does **not** intercept or modify the model API request (smaller trust footprint, but also no DLP on prompts leaving the machine — SolonGate is ahead there); no sandbox.

### 2.3 Oktsec — github.com/oktsec/oktsec

- **What it is** [P/M]: "Runtime security for AI agents" — a local layer between agents and tools/MCP servers/agent-to-agent messages. Deterministic 10-stage pipeline (rate limit, Ed25519 identity, policy/ACL, content scanning, hash-chained audit, …); "No LLM on the hot path."
- **Integration** [P]: stdio wrapping of MCP servers, a Streamable-HTTP MCP gateway, Claude Code hooks posting to a local HTTP endpoint (`POST /hooks/event`), SDKs (Go, Python). Auto-discovers MCP config of 17 clients.
- **UI** [P]: local web dashboard on `127.0.0.1:8080` protected by an access code; SQLite under `~/.oktsec/`; observe (default) and enforce modes; SARIF export; Prometheus and OpenTelemetry.
- **Telemetry** [P]: "Anonymous install telemetry can be disabled" → on by default.
- **Status**: active but small (19 stars; pushed 2026-11-14). 268 detection rules, mostly from the author's "Aguara" engine [M].
- **Reusable**: license permits it; **nothing reused**. The similarity "observe/enforce + hash-chained SQLite audit" is convergent design, implemented independently here.
- **How AgentShield differs**: no TCP listener at all (named pipe / Unix socket with mutual HMAC, versus an HTTP dashboard and hook endpoint on localhost — a browser-reachable surface); no telemetry of any kind; no MCP proxy (Oktsec is ahead: it sees and can block at MCP protocol level, and covers agent-to-agent messaging); native GUI.

## 3. Adjacent: sandboxing

### 3.1 anthropic-experimental/sandbox-runtime (`srt`)

- **What it is** [P]: "A lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container." "research preview developed for Claude Code"; "APIs and configuration formats may evolve."
- **Mechanisms** [P]: macOS `sandbox-exec` (Seatbelt profiles); Linux `bubblewrap` + network namespace removal + host-side HTTP/SOCKS5 proxies + seccomp (blocks Unix sockets, x64/arm64); **Windows: alpha** — dedicated `srt-sandbox` local account, Windows Filtering Platform egress fence keyed on its SID, write-restricted token, ACEs on the working tree, one-time **elevated** install; Schannel/WinHTTP clients cannot complete HTTPS inside the sandbox.
- **Known limits** [P]: Ubuntu 24.04+ user-namespace restriction needs a sysctl/AppArmor change; narrower glob support on Linux; nested user namespaces off by default.
- **Status**: active (pushed 2026-11-13; 344 open issues), Apache-2.0 per the GitHub API (the README excerpt we read did not name the license).
- **Relationship, not competition**: a sandbox *contains*; AgentShield *observes, explains and gates declared tool calls*. They are complementary. AgentShield does not embed or wrap `srt` (it is a Node/TypeScript package; AgentShield has no Node runtime dependency) and reports "Sandbox integration: unsupported — Claude Code's own sandbox settings remain authoritative". When a policy returns `require_sandbox`, Enforce mode denies, because AgentShield cannot verify that a sandbox is active.
- **Reusable**: license permits it; **nothing reused**. Its Windows design is cited in RESEARCH §6 as evidence for the cost of OS-level containment.

## 4. Adjacent: MCP scanning

### 4.1 cisco-ai-defense/mcp-scanner

- **What it is** [P]: Python tool that "combines Cisco AI Defense inspect API, YARA rules and LLM-based analysis to detect malicious MCP tools." Scans tools, prompts, resources and server instructions of **live** servers (stdio/HTTP/SSE), server source code (behavioural mismatch), PyPI/npm packages (Docker sandbox), dependencies (pip-audit), binaries (VirusTotal hash lookup). Static mode for pre-generated JSON.
- **Keys/cloud** [P]: YARA-only, readiness and vulnerable-package scans need no keys; LLM analyzer needs an LLM key (local Ollama possible); API analyzer needs a Cisco AI Defense subscription; malware scan needs a VirusTotal key.
- **Status**: active (pushed 2026-11-23), Apache-2.0.
- **How AgentShield differs**: mcp-scanner is a point-in-time **scanner of server metadata** — exactly the layer AgentShield does *not* inspect. AgentShield observes **runtime calls** and configuration drift, offline, with no LLM. The two are complementary: run mcp-scanner before trusting a server; AgentShield watches what the agent then does with it. A user who needs tool-poisoning detection should use a scanner or proxy; AgentShield's `RiskCategory::McpToolPoisoning` is only assigned by heuristics on calls/config, never by description analysis.
- **Reusable**: license permits it; **nothing reused** (no YARA rules imported).

## 5. Established scanners (different problem, overlapping detections)

These are not agent-runtime tools. They are listed because AgentShield contains small, purpose-built detectors in the same domains, and users will ask why the established tool is not embedded.

| Tool | What it does | Overlap with AgentShield | Why not embedded / reused | License note |
|---|---|---|---|---|
| **Semgrep** (semgrep/semgrep) | Pattern-based static analysis of source code. | None at runtime. Conceptually similar "pattern → finding" model. | Analyses repositories, not live commands; large runtime. | Engine **LGPL-2.1** (copyleft); Semgrep's rule registry has separate license terms. Not linked, not vendored, no rules copied → no obligation arises. |
| **Gitleaks** (gitleaks/gitleaks) | Regex + entropy secret scanning of git history/files. | AgentShield's `secret-detector` uses the same general technique (provider-specific regexes, key/value heuristics, entropy). | AgentShield needs in-process, sub-millisecond redaction of arbitrary strings *before storage*, with keyed fingerprints; shelling out per event is not viable. | MIT. **Patterns were written independently** from public token-format documentation; `gitleaks.toml` was not copied. |
| **Trivy** (aquasecurity/trivy) | Vulnerabilities, misconfigurations, secrets, SBOM for images/filesystems/repos. | None at runtime; could complement the Supply Chain page (scan after install). | Requires vulnerability DB downloads (network) — conflicts with offline-first default. | Apache-2.0. Not integrated. |
| **OSV-Scanner** (google/osv-scanner) | Matches dependencies against osv.dev. | Would answer "is the package the agent is installing known-vulnerable?". | Sends package names/versions to a Google-hosted API (or needs an offline DB download); must be an explicit opt-in. Listed as planned opt-in module in technical debt. | Apache-2.0. Not integrated. |
| **OpenSSF Scorecard** (ossf/scorecard) | Security-health heuristics for a repository. | Could inform package/MCP-server reputation. | Needs GitHub API access and tokens; out of scope. Also relevant *for* AgentShield as a project hygiene check once the repo is public. | Apache-2.0. Not integrated. |

## 6. Positioning — honest version

What AgentShield offers that the reviewed alternatives do not combine in one tool **[P where implemented, see IMPLEMENTATION_PLAN]**:

1. Local-only by construction: no TCP listener, no account, no telemetry, no update or intelligence fetches.
2. One integration (Claude Code) with a capability matrix that states per capability whether it is enforced, observed, partial, degraded or unsupported, and why.
3. Five modes with tested invariants (Monitor/Shadow never interfere; no mode ever returns `allow`).
4. Explainable, deterministic scoring with separate confidence; shadow replay of presets against recorded history.
5. Redaction before storage and a tamper-evident audit log with explicit deletion records.
6. Native desktop GUI plus CLI from a single Rust workspace; Windows is a first-class target.

Where AgentShield is **behind**:

- Single agent; no MCP proxy → no visibility into tool descriptions (HOL Guard, Oktsec, mcp-scanner have it).
- No sandbox/containment (sandbox-runtime, SolonGate have it).
- No vulnerability or reputation data (HOL Guard, Trivy, OSV-Scanner).
- No DLP on the model API request (SolonGate).
- v0.1.0, one author, no external audit, unsigned binaries, no installers published yet.
- The name "AgentShield" is used by several other projects in the same space (see [LICENSING.md](LICENSING.md) §5).
