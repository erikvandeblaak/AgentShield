# Changelog

## 0.1.0 — 2026-11-24 (first working vertical slice, unreleased)

- Claude Code adapter: normalization of hook payloads, deny/ask output on PreToolUse (never allow),
  safe idempotent installer (dry-run, backup, atomic write, verify, rollback, exact uninstall),
  detection, capability matrix, MCP server discovery.
- Five modes (Monitor, Shadow, Interactive, Enforce, Lockdown) with tested invariants.
- Static shell analysis for Bash/PowerShell/CMD incl. nested interpreters and `-EncodedCommand`.
- Explainable risk engine (destructive, secrets, exfiltration, persistence, security config,
  agent-config tampering, infrastructure, database, supply chain, obfuscation, prompt injection, MCP).
- Policy engine with 9 presets, user + project layers (project can only restrict), validation and conflicts.
- Secret detection/redaction with keyed fingerprints; prompts and file contents never stored.
- Daemon with authenticated named-pipe / Unix-socket IPC, live streaming, correlation incidents.
- SQLite audit log with hash chain, recorded deletions, retention, backup, integrity check.
- CLI, reports (7 kinds) and exports (JSON, CSV, SARIF 2.1.0, HTML).
- Tauri 2 desktop dashboard (15 pages, onboarding, Demo Mode, EN/NL, dark/light, tray).
- VS Code workspace (tasks, launch configs, quality gate), Windows + WSL Linux validation.
