# ADR 0001 — Rust workspace with a Tauri desktop shell

- Status: accepted
- Date: 2026-11-24

## Context

AgentShield runs a process on **every** Claude Code tool call. That process must start in milliseconds, must not hang, must run on Windows and Linux without a runtime to install, and handles untrusted input (hook payloads). A background daemon owns the audit database, and a desktop dashboard presents it. The same evaluation logic has to be available to the hook (fallback when the daemon is down), the daemon, the CLI and the GUI.

Alternatives considered: Go (single binary, GC, good Windows support; GUI would still need a web stack or a second toolkit); Node/TypeScript (start-up cost per hook in the tens to hundreds of ms, requires Node on the machine); Python (same, plus packaging); Electron for the GUI (bundles Chromium, ~100 MB+, larger attack surface).

## Decision

- One **Cargo workspace** (edition 2024, MSRV 1.88) of small crates with one-directional dependencies: `event-model` → `command-parser` / `secret-detector` / `supply-chain` → `risk-engine` → `policy-engine` → `core` → `audit-log` / `ipc` → `daemon`, plus `adapters/claude-code`, `reporting`, and the `apps/cli` binary (`agentshield`), which is hook, daemon and CLI in one executable.
- `unsafe_code = "deny"` workspace-wide; exceptions must be registered in SECURITY_ARCHITECTURE §9.
- SQLite via `rusqlite` with the **bundled** amalgamation (no system library dependency).
- Desktop app: **Tauri 2** with a React/Vite frontend, in a **separate Cargo workspace** (`apps/desktop/src-tauri`, excluded from the root workspace) so WebView/GTK dependencies never enter the hook/daemon build. The GUI talks to the daemon through the same IPC client as the CLI and ships the CLI as a sidecar.

## Consequences

Positive
- Hook latency p50 14 ms / p95 16.5 ms end-to-end on Windows 11 (release build, measured), no runtime prerequisite.
- Memory safety for the code that parses untrusted input; one evaluation engine shared by all entry points, so daemon and fallback decisions are identical.
- Small GUI bundle using the OS WebView (WebView2 / WebKitGTK); restrictive CSP and capability file are first-class in Tauri 2.
- Core workspace stays at 158 third-party packages; the heavy graph (452) is confined to the desktop shell.

Negative
- Two lockfiles and two dependency graphs to keep consistent and to audit.
- The GUI depends on the system WebView: behaviour differs between WebView2 and WebKitGTK; the Linux GUI is not yet verified; AppImage bundling raises LGPL redistribution questions (LICENSING §3.1).
- Tauri brings MPL-2.0 transitive crates (file-level copyleft, acceptable unmodified).
- Rust + TypeScript raises the contribution bar compared with a single-language project.
- Unsigned Rust binaries attract antivirus heuristics (ADR 0006).
