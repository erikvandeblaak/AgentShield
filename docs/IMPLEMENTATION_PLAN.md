# Implementation Plan and Status

Status date: **2026-11-24**, version 0.1.0. Status is derived from the code and directory contents in this repository on that date, not from intentions.

> **Caveat on phase definitions.** The owner's specification document is not part of the repository. The phase titles and contents below (0–9) are a reconstruction from the workspace structure and the task description; if the spec numbers phases differently, the *status facts* per deliverable remain valid but need re-mapping.

Legend: **done** = implemented and covered by tests or verified end-to-end · **partial** = implemented in part, or implemented but unverified/unpackaged · **not started** = no code or configuration present.

Test evidence reported by the owner for this state: 139 Rust tests passing on Windows 11 and on WSL Ubuntu 24.04; 38/38 end-to-end checks with the real binary; 102 Vitest tests for the frontend. (This document's author did not re-run the suites — builds were not to be run concurrently. Source inspection finds 136 `#[test]` attributes plus 3 `proptest!` blocks in the core workspace, consistent with that figure.)

## Overview

| Phase | Title | Status |
|---|---|---|
| 0 | Research, threat model, architecture decisions | **done** (this document set) |
| 1 | Workspace, event model, audit log | **done** |
| 2 | Claude Code adapter (hooks, install, fixtures) | **done** |
| 3 | Analysis engines: command parser, secrets, supply chain, risk | **done** (known limits documented) |
| 4 | Policy engine, presets, modes | **done** |
| 5 | IPC, daemon, CLI | **done** |
| 6 | Desktop GUI (Tauri + React) | **partial** (functional; unpackaged, unsigned, Linux GUI unverified) |
| 7 | Reporting, exports, MCP inventory | **partial** (formats exist; external validation missing) |
| 8 | Packaging, signing, CI, release engineering | **not started** (bundle configuration only) |
| 9 | Hardening and OS-level extensions | **not started** (researched, deferred) |

## Phase 0 — Research, threat model, architecture decisions — done

| Deliverable | Status | Evidence |
|---|---|---|
| Research (hooks, MCP, OS mechanisms, standards, mappings) | done | `docs/RESEARCH.md`, `docs/SOURCES.md` |
| Competitor analysis | done | `docs/COMPETITOR_ANALYSIS.md` |
| Threat model | done | `docs/THREAT_MODEL.md` |
| Security architecture | done | `docs/SECURITY_ARCHITECTURE.md` |
| Capability matrix | done | `docs/AGENT_CAPABILITY_MATRIX.md` (mirrors `detect.rs`) |
| Licensing and name review | done; **action required** | `docs/LICENSING.md` — name conflict, missing `LICENSE` file |
| ADRs 0001–0006 | done | `docs/adr/` |
| `docs/ROADMAP.md` | **missing** | Referenced by `detect.rs` ("ETW / eBPF planned, see docs/ROADMAP.md") but does not exist. Either create it or change the reason string. |

## Phase 1 — Workspace, event model, audit log — done

| Deliverable | Status | Evidence |
|---|---|---|
| Cargo workspace (13 members, edition 2024, MSRV 1.89, `unsafe_code = "deny"`, clippy warn, thin-LTO release) | done | `Cargo.toml` |
| Normalised event model (actions, phases, findings, 18 risk categories, decisions, coverage, modes) | done | `crates/event-model` |
| SQLite audit log: WAL, forward-only migrations, indexes, queries/filters, stats, sessions, incidents | done | `crates/audit-log` (+ tests) |
| Hash chain, verification, explicit `chain_breaks` for deletions, retention, per-session delete, backup | done | `crates/audit-log` |
| Per-user paths, `AGENTSHIELD_HOME` isolation, atomic writes, Unix permissions | done | `crates/core/src/paths.rs` |
| Explicit Windows ACLs on token/key files | not started | `restrict_file` is a no-op on Windows (relies on profile ACL) |

## Phase 2 — Claude Code adapter — done

| Deliverable | Status | Evidence |
|---|---|---|
| Payload normalisation for Bash, PowerShell, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch, Agent, MCP tools, prompts, lifecycle events | done | `crates/adapters/claude-code/src/lib.rs`, fixtures in `fixtures/claude-code/` (9 payloads) |
| Decision rendering (deny/ask only, exit 0) | done | `render` |
| Idempotent, reversible install into `settings.json` (preview/dry-run, backup, atomic write, verify, repair, uninstall of own handlers only, legacy-form detection) | done | `install.rs` |
| `--fail-closed` (`onFailure: "block"`) | done (install side); effect inside Claude Code documented, not fuzzed | `install.rs` |
| Agent detection and capability matrix | done | `detect.rs` |
| Hook entry point with daemon call, local fallback, autostart, panic handling | done | `apps/cli/src/hook.rs` |
| Windows handle-inheritance fix | done | `apps/cli/src/daemon_ctl.rs` (single documented `unsafe`) |
| AV-heuristic mitigation (hook args `["hook"]`) | done | `install.rs` `HOOK_ARGS`; ADR 0006 |
| Use of `mcp_server.source`, `ConfigChange` hook, `disableAllHooks` check | not started | identified in RESEARCH §1.3 |
| Compatibility tests against multiple Claude Code versions | not started | only 2.1.331 exercised |

## Phase 3 — Analysis engines — done

| Deliverable | Status | Evidence |
|---|---|---|
| Shell parser for Bash/sh/zsh, PowerShell, CMD; nested interpreters; uncertainties | done | `crates/command-parser` (1,114 lines incl. tests) |
| Secret detection + redaction with keyed fingerprints; sensitive-path classification | done | `crates/secret-detector` (proptest regressions present) |
| Supply-chain command analysis (14 ecosystems/tools) | done | `crates/supply-chain` |
| Risk engine: shell rules (destructive, credentials, persistence, defence evasion, LOLBins, git, DB, infra, network), URL assessment, prompt-injection indicators | done | `crates/risk-engine` (`shell.rs` 2,252 lines) |
| Session correlation (secret→egress, injection→risky action, repeated denials) | done | `crates/core/src/correlation.rs` |
| Detection-quality measurement (labelled corpus, false-positive/negative rates) | **not started** | No benchmark corpus exists; all scores are expert-assigned constants |
| OSV / vulnerability lookup (opt-in) | not started | deliberately deferred (offline-first) |

## Phase 4 — Policy engine, presets, modes — done

| Deliverable | Status | Evidence |
|---|---|---|
| TOML policy schema v1 (strict, `deny_unknown_fields`), matchers, thresholds, hard rules, validation with warnings | done | `crates/policy-engine/src/lib.rs` |
| Layering preset → user → project; project layer can only restrict | done + tested | `layering_and_project_restrictions` |
| 9 built-in presets | done | `policies/*.toml` (developer-balanced, strict-security, read-only, observe-everything, production-server, database-safety, laravel-, python-, rust-developer) |
| Five modes with invariants | done + tested | `mode.rs`, `invariant_*` tests |
| Simulation and replay of a preset against recorded history | done | IPC `Simulate`, `Replay`; CLI `policy simulate` |
| Multiple user policy files | partial | Module docs mention `<config>/policies/*.toml`; the engine loads `policies/user.toml` only |
| Workspace-level integration tests in `tests/` | **missing** | `mode.rs` references `tests/mode_invariants`; the top-level `tests/` directory is empty |

## Phase 5 — IPC, daemon, CLI — done

| Deliverable | Status | Evidence |
|---|---|---|
| Named pipe / Unix socket transport, framing, mutual HMAC handshake, limits | done + tested | `crates/ipc` |
| Daemon: single writer, evaluation, live subscription, mode/preset/pause with audit records, retention, incidents, latency summaries | done | `crates/daemon` |
| CLI: status, doctor, detect, watch, dashboard, mode, pause/resume, agent (list/install/repair/uninstall), policy, command analyze, events, sessions, security check, report, export, selftest, daemon, hook | done | `apps/cli/src/main.rs` |
| Performance targets | met on one machine | hook p95 16.5 ms end-to-end; daemon p95 0.85 ms (see `docs/PERFORMANCE.md`) |
| Daemon autostart at login / service registration | not started | daemon is started on demand by the hook or the GUI |
| Silence watchdog (active session stops reporting) | not started | THREAT_MODEL T12 |

## Phase 6 — Desktop GUI — partial

| Deliverable | Status | Evidence |
|---|---|---|
| React 19 + Vite 8 + Tailwind 4 frontend, 16 pages (Overview, Live, Threats, Sessions, Agents, Approvals, Policy, Simulator, Secrets, MCP, Supply Chain, Network, Reports, Settings, About, Onboarding) | done | `apps/desktop/src/pages`, 53 screenshots in `docs/screenshots` |
| Dark/light themes, English + Dutch | done | `src/theme`, `src/i18n/{en,nl}` |
| Demo Mode isolated from the real API | done | `src/lib/backend.ts`, `src/demo` |
| Escaping discipline for chart tooltips | done + tested | `src/lib/escape.ts`, `lib.test.ts` |
| Tauri 2 shell: command bridge, live event stream with reconnect, tray, restrictive CSP and capability file | done (code present) | `apps/desktop/src-tauri` (804 lines Rust), `tauri.conf.json` |
| Frontend tests | done | 102 Vitest tests (owner-reported) |
| Rust tests for the Tauri shell | not started | no test modules in `src-tauri/src` |
| Verified build and run on Linux (WebKitGTK) | **unverified** | Rust tests ran on WSL; no evidence of a GUI run on Linux |
| "Approvals" page | by design informational | approvals are delegated to Claude Code's prompt (ADR 0005); the page shows asked/blocked history, not an approval queue |
| Accessibility audit, keyboard-only pass | not started | — |

## Phase 7 — Reporting, exports, MCP inventory — partial

| Deliverable | Status | Evidence |
|---|---|---|
| Exports: JSON, CSV (formula-injection safe), HTML (static, escaped), SARIF 2.1.0 | done | `crates/reporting` |
| HTML reports: daily, weekly, project, agent comparison, shadow, incident, coverage | done | `report_html`, CLI `report generate` |
| MCP server inventory from `~/.claude.json` and `.mcp.json`; config findings; change tracking; observed calls | done | `adapters/claude-code/src/mcp.rs`, daemon `McpServers` |
| SARIF validated against the official schema / ingested by a consumer (e.g. GitHub code scanning) | **not done** | only a shape unit test |
| CycloneDX SBOM (own dependencies or session packages) | not started | RESEARCH §5.1 |
| OpenTelemetry export | not started | RESEARCH §7 (deferred, opt-in only) |
| MCP tool-description inspection (proxy) | not started | deliberately out of scope |

## Phase 8 — Packaging, signing, CI, release — not started

| Deliverable | Status | Evidence |
|---|---|---|
| Bundle configuration (NSIS per-user, MSI, deb, AppImage; CLI as sidecar) | configured only | `tauri.conf.json`; a Windows sidecar binary is present in `src-tauri/binaries/` |
| Installer scripts / packaging assets | not started | `packaging/windows`, `packaging/linux` are empty |
| CI (build, test on Windows + Linux, clippy, fmt) | not started | `.github/workflows/` is empty |
| Supply-chain gates (`cargo audit`, `cargo deny`, `npm audit`), SBOM, checksums, provenance | not started | — |
| **Code signing** (Authenticode; Linux package signatures) | not started | recommended; removes the measured AV start-up penalty |
| `LICENSE`, `NOTICE`, third-party notices | not started | LICENSING §5 |
| README, user documentation | owner in progress | not in repository on the status date |
| Helper scripts | not started | `scripts/` is empty |
| **Name decision** | open, blocking for release | LICENSING §6 |

## Phase 9 — Hardening and OS-level extensions — not started

Researched and deliberately deferred (RESEARCH §6, THREAT_MODEL §8). Candidate order by value/cost:

| Item | Status | Note |
|---|---|---|
| Register `ConfigChange` hook; check `disableAllHooks`; use `mcp_server.source` | not started | cheap, hook-level, no new privileges |
| Silence watchdog / heartbeat per active session | not started | addresses the "monitoring silently lost" class |
| Explicit Windows DACLs for token, key, pipe | not started | needs Win32 security APIs (more `unsafe` or a helper crate) |
| Keyed (HMAC) hash chain + external anchor/export of the head hash | not started | moves audit log from tamper-evident toward tamper-resistant against non-key-holders |
| Managed-settings install option (tamper-resistant hooks) | not started | requires admin; changes the "no admin" principle for that option only |
| Opt-in OSV lookup; opt-in OTLP export | not started | each breaks "no outbound traffic" → explicit consent, redaction review |
| Linux Landlock launcher ("run agent sandboxed") | not started | requires wrapper model |
| Windows ETW / Linux eBPF process telemetry | not started | requires elevation / privileged helper |
| External security review / audit | not started | none has taken place |
| Additional agents | **out of scope** | owner decision (ADR 0002) |

## Open inconsistencies found while documenting

1. `detect.rs` points to `docs/ROADMAP.md`, which does not exist.
2. `mode.rs` cites `tests/mode_invariants`; top-level `tests/` is empty (the invariant tests live in `crates/policy-engine/src/tests.rs`).
3. `install.rs` module docs still describe the handler as "invoked with `hook claude-code`"; the current form is `hook` (legacy form is still recognised for uninstall/repair).
4. Policy-engine docs mention user policies `policies/*.toml`; only `policies/user.toml` is loaded.
5. In the hook's fallback/panic path an unreadable `config.toml` yields Monitor semantics even if the user had selected Enforce/Lockdown (SECURITY_ARCHITECTURE §5).
