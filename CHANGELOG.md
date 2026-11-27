# Changelog

## Unreleased

- Claude Code `PreSkillShellCommand` (2.1.332+): shell commands that a skill or command injects while it
  loads are now analysed and, in the enforcing modes, denied before they run; PreToolUse never sees
  them. Registered only when the `claude` on PATH is 2.1.332 or later (older versions warn about an
  unknown hook event at every start); `agent install --skill-shell-hook auto|on|off`. Claude Code
  treats *ask* as *deny* there, so AgentShield records and sends *deny* with that explanation.
  `doctor`, `security check` and the capability matrix report the gap when Claude Code supports the
  event but it is not registered, and the warning case the other way round.
- `selftest` now fails (exit 4) when the hook takes 5 s or longer, half of the 10 s hook timeout:
  Claude Code runs the action without AgentShield's decision when the hook times out. Previously it
  reported success at 26–54 s (SF-003).
- Release pipeline for code signing via SignPath (free OSS signing, SignPath Foundation):
  `.github/workflows/release.yml` + `scripts/release-windows.ps1` sign the binaries first and build the
  installers from exactly those files (the desktop binary is pre-patched per installer type, because the
  Tauri bundler would otherwise patch, and so invalidate, a signed binary). Without SignPath configuration
  the workflow produces unsigned release files. See `CODE_SIGNING_POLICY.md`.
- `agentshield.exe` now carries Windows version information (product name, version, company), required
  for signing and matching the desktop app.

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
