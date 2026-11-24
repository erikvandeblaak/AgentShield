# Progress

Status per 2026-11-24. "Verified" means: covered by automated tests and/or the end-to-end check with the
real binaries in an isolated profile — not by mock responses.

## MVP criteria (spec §39)

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Claude Code reliably detected | ✅ | `detect` finds 2.1.331 + executable; Agents page |
| 2 | Hooks installed & removed safely | ✅ | dry-run, backup, atomic write, verify, rollback, exact uninstall; preserves other tools' hooks, permissions and key order (adapter tests + e2e) |
| 3 | Real tool calls visible in the dashboard | ✅ | Live Claude Code session blocked a sentinel command in Enforce mode (isolated profile); since 2026-11-24 the real installation records this developer's own Claude Code sessions |
| 4 | Secrets redacted | ✅ | proptests; e2e greps the raw DB + WAL files for a fictional token and prompt text — absent |
| 5 | Monitor Mode never blocks | ✅ | invariant tests over all presets × corpus; e2e |
| 6 | Shadow Mode correct simulations | ✅ | would-deny recorded, no output; replay against other presets |
| 7 | Daemon runs independently | ✅ | detached start, auto-start by hook after outage, survives GUI close (tray) |
| 8 | SQLite audit logging reliable | ✅ | hash chain verify, concurrent writers, 100k events, recorded deletions |
| 9 | GUI shows real realtime activity | ✅ | live subscription (push), screenshots with real events |
| 10 | Windows 11 + Linux Mint within tested configs | ✅ Windows 11 / ✅ WSL Ubuntu 24.04 (Mint 22 base) | 144 Rust tests on both; e2e 38/38 on both; .deb + AppImage built; Linux GUI starts under WSLg (not visually verified on a Mint desktop) |
| 11 | Integration coverage visible | ✅ | capability matrix (CLI, GUI, coverage report) |
| 12 | Works without account / internet | ✅ | no network calls at runtime; offline-first |

## Test inventory

- Rust: 144 tests (incl. 5 property-test suites, 100k-event performance test, IPC fuzz-style frames,
  mode invariants) — green on Windows 11 and WSL Ubuntu 24.04.
- End-to-end: 38/38 checks with the release binary on Windows 11 and on Linux (WSL Ubuntu 24.04) (install → modes → fallback → integrity → uninstall).
- Frontend: 102 vitest tests, typecheck, ESLint, production build.
- Desktop: release app driven over CDP against a real daemon with seeded hook events — 0 console errors.
- Packaging: NSIS (per-user) + MSI built by `scripts/package-windows.ps1` with SHA-256 sums.

## Phases

| Phase | Status |
|---|---|
| 0 Research | ✅ docs/RESEARCH.md, COMPETITOR_ANALYSIS.md, THREAT_MODEL.md, SOURCES.md, ADRs |
| 1 Security core | ✅ |
| 2 Claude Code monitor | ✅ (live session pending consent) |
| 3 Local runtime | ✅ |
| 4 Desktop app | ✅ Windows; Linux bundle pending |
| 5 Enforcement | ✅ Interactive (native prompt), Enforce, Lockdown on PreToolUse |
| 6 Codex | ⛔ out of scope (owner decision: Claude Code only) |
| 7 Broadening | 🟡 MCP Center + MCP proxy (tool-definition pinning, poisoning detection, enforcement; stdio), supply chain (static + offline OSV: 286k advisories, malware hard-deny) |
| 8 OS security | ⏳ not started (TD-006/007) |
| 9 Hardening & release | 🟡 CI, cargo-deny, SBOM job, installers; signing pending |
