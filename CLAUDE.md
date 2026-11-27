# Erik's AgentShield — instructies voor Claude Code

Erik's AgentShield (kort: AgentShield) is een lokaal security- en observability-platform voor AI-codingagents (Erik van de Blaak Edition).
Scope: **alleen Claude Code** wordt geïntegreerd. Windows 11 en Linux Mint.
Lees bij twijfel eerst `docs/SECURITY_ARCHITECTURE.md`, `docs/THREAT_MODEL.md` en `docs/PROGRESS.md`.

## Commando's

```
cargo build --workspace                               # core + CLI (binary `agentshield`)
cargo test --workspace --no-fail-fast                 # alle Rust-tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cd apps/desktop/src-tauri && cargo clippy --all-targets -- -D warnings   # desktop-backend (eigen workspace)
cd apps/desktop && npm run typecheck && npm run lint && npm test -- --run && npm run build
cd apps/desktop && npx tauri build --no-bundle        # desktop-app (release, frontend ingebed)
pwsh scripts/linux-check.ps1                          # Linux: fmt + clippy + tests in WSL Ubuntu 24.04
pwsh scripts/package-windows.ps1                      # dist\: NSIS + MSI + CLI + SHA256SUMS (lokaal, unsigned)
pwsh scripts/release-windows.ps1 -Step Prepare|Bundle|Finalize   # release in stappen rond SignPath-ondertekening (CI: release.yml)
bash scripts/package-linux.sh                         # dist/: CLI + .deb + AppImage (op Linux)
```

Kwaliteitspoort vóór "klaar" (VS Code-task **Kwaliteitspoort**): fmt-check, clippy zonder warnings
(core én desktop), alle Rust-tests, frontend typecheck/lint/tests; Linux-validatie bij wijzigingen in
`#[cfg(unix)]`-code, IPC of paden.

## Regels

- **Nooit je echte profiel gebruiken bij testen.** Zet altijd `AGENTSHIELD_HOME=<scratchpad>` en
  `CLAUDE_CONFIG_DIR=<scratchpad>`; de VS Code-tasks/launch-configs doen dat al (`target/dev`).
  Installeer nooit hooks in de echte `~/.claude/settings.json` zonder expliciete toestemming.
- **Geen nepfunctionaliteit / nepcijfers.** Alle getallen komen uit echte events. Demo Mode is alleen
  in de UI, duidelijk gemarkeerd, en raakt nooit de daemon.
- **Nooit `allow` of `updatedInput` teruggeven** aan Claude Code. Alleen `deny`/`ask` op `PreToolUse`.
  De invariant-tests in `crates/policy-engine/src/tests.rs` en `crates/adapters/claude-code/src/tests.rs` bewaken dit.
- **Monitor/Shadow blokkeren nooit.** Enforce/Lockdown zijn fail-closed bij interne fouten (alleen PreToolUse).
- **Redactie vóór opslag.** Niets ongeredigeerd naar DB, GUI, rapporten of logs. Bestandsinhoud en prompts
  worden nooit opgeslagen (alleen lengte/hash). Tests gebruiken uitsluitend fictieve credentials.
- **Beslissing hangt nooit af van opslag**: renderen gebeurt vóór de DB-insert.
- **Hook-argumenten**: Claude Code roept `agentshield hook` aan (geen `hook claude-code`: Norton vertraagt die
  exacte commandline ~26 s, zie `docs/SECURITY_FINDINGS.md` SF-003).
- **Geen `unsafe`** (workspace-lint `deny`). Eén gedocumenteerde uitzondering: `std_handles_not_inheritable`
  in `apps/cli/src/daemon_ctl.rs` (Windows handle-overerving, SF-004).
- **Projectpolicies (`.agentshield/policy.toml`) mogen alleen strenger maken**; allow-regels daaruit worden genegeerd.
- Nieuwe detector = vaste score + categorie + uitleg + mitigatie + test (positief én een false-positive-check).
- Platformcode achter `#[cfg]`; Windows named pipe / Unix socket alleen in `crates/ipc`.
- Linux testen: WSL Ubuntu 24.04 met rustup per gebruiker; kopie in `~` (niet via /mnt/c bouwen).
  Claim geen validatie op een echte Mint-desktop zonder die test.
- GUI testen: `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9333` + Playwright `connect_over_cdp`,
  met geïsoleerd profiel. Claude Code zet `NO_COLOR`; haal die weg voor kleur-tests van de CLI.

## Structuur

- `crates/event-model` — genormaliseerd eventmodel, modi, beslissingen, risicotypes
- `crates/command-parser` — statische shell-analyse (Bash/PowerShell/CMD), geneste interpreters, `-EncodedCommand`
- `crates/secret-detector` — secretpatronen + entropie, redactie, keyed fingerprints, gevoelige paden
- `crates/supply-chain` — pakketbeheerders, typosquatting, registry-overrides, install scripts
- `crates/risk-engine` — deterministische, uitlegbare scores (shell/pad/url/mcp/prompt-injectie)
- `crates/policy-engine` — TOML-policies, lagen (preset → user → project), precedentie, modusbeslissing, presets uit `policies/`
- `crates/audit-log` — SQLite (WAL), hash-chain, queries, stats, sessies, incidenten, retentie, backup
- `crates/ipc` — named pipe / Unix socket, HMAC-handshake, framing, server + client
- `crates/core` — pipeline (correlatie → risico → policy → modus → redactie → record), config, paden
- `crates/reporting` — JSON/CSV/SARIF/HTML-export en 7 rapportsoorten
- `crates/daemon` — IPC-handler, opslag, live-stream, incidenten, retentie
- `crates/adapters/claude-code` — normalisatie hookpayloads, output, veilige installer, detectie, MCP-discovery
- `apps/cli` — `agentshield` (CLI, hook-entrypoint, daemon)
- `apps/desktop` — Tauri 2 + React/TS dashboard (`src-tauri` is een aparte Cargo-workspace)
- `policies/` — ingebouwde presets · `fixtures/claude-code/` — hookpayloads in het gedocumenteerde formaat
