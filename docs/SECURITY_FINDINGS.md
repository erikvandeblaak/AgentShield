# Security findings & open questions

Findings discovered while building and testing AgentShield. Status: **fixed**, **mitigated**, **open**, **accepted**.

## SF-001 — Secret prefixed by a word character was not redacted (fixed)
A property test found that `aghp_…` (a token directly after a letter) bypassed the `\b` word boundary
in provider patterns. Fixed by removing the leading boundary for distinctive prefixes (`ghp_`, `glpat-`,
`xox?-`, `AIza`, `hf_`, `npm_`, `AKIA…`, `sk_live_`). `sk-` keeps its boundary to avoid false positives
such as `desk-…`. Regression: proptest `redacted_output_never_contains_github_token`.

## SF-002 — Transposition typosquats not detected (fixed)
`lodahs` vs `lodash` has Levenshtein distance 2. Switched to Damerau-Levenshtein (OSA).

## SF-003 — Antivirus delays `agentshield hook claude-code` by ~26 s (mitigated)
On the development machine (Windows 11, Norton Antivirus active, Defender disabled) process creation
of an **unsigned** binary with exactly the command line `hook claude-code` was delayed ~26 s before
`main()` ran — regardless of the executable name; a signed `cmd.exe /c rem hook claude-code` was not
delayed, and other argument forms were not delayed. Claude Code's hook timeout is 10 s and timeouts are
fail-open, so this would have **silently disabled monitoring**. Mitigation: hooks are registered as
`agentshield hook` (agent defaults to `claude-code`); the installer flags the old form as outdated
("run repair"). Norton also adds ~0.5 s to the first launches of a new unsigned binary.
**Recommendation:** code-sign releases; users of strict AV products can exclude the install directory.
`agentshield selftest` measures the real hook latency on the user's machine.

## SF-004 — Daemon spawned from the hook inherited Claude Code's stdout pipe (fixed)
On Windows every inheritable handle is inherited by child processes. When the hook auto-started the
daemon, the long-lived daemon kept Claude Code's stdout pipe open, so Claude Code would wait for EOF
until its hook timeout. Fix: `std_handles_not_inheritable()` clears `HANDLE_FLAG_INHERIT` on the standard
handles before spawning (`apps/cli/src/daemon_ctl.rs`, the project's only `unsafe` block). Verified by
the end-to-end test (auto-start after an outage, no hang).

## SF-005 — Tauri `freezePrototype` incompatible with ECharts (accepted)
`freezePrototype: true` makes ECharts/zrender throw ("Cannot assign to read only property
'constructor'"). Disabled. XSS protection relies on a strict CSP (`script-src 'self'`, no eval, no remote
origins), rendering all event-derived strings as text, escaping ECharts tooltip HTML (`lib/escape.ts`),
and an ESLint ban on React raw-HTML props and `innerHTML`. `style-src 'unsafe-inline'` is required by
ECharts tooltips and CodeMirror.

## SF-006 — Repeated-pattern incidents flooded the Threat Center (fixed)
Each new risky action in a session with ≥3 denied attempts created a new incident. Incidents with the
same session and rule within the correlation window are now merged (evidence ids appended, score = max).

## SF-007 — Same-user limitation (accepted, documented)
The agent runs as the same OS user. It can in principle edit `~/.claude/settings.json`, AgentShield's
config or database, set `disableAllHooks`, or kill the daemon. Mitigations: such actions are detected
(`tamper.*`, `path.agent_configuration.write`, `path.agentshield_configuration.write`) and hard-denied by
all enforcing presets; `ConfigChange` events are recorded; `doctor`/status report `disableAllHooks`;
the hash chain makes naive log edits detectable; mode changes are logged. Real isolation needs a
separate OS account or OS-level enforcement (TD-007).

## SF-008 — Malformed / oversized hook input (verified)
Non-JSON, empty or >4 MiB stdin never blocks and never crashes (exit 0, no output). In Enforce/Lockdown
an internal panic denies PreToolUse (fail-closed). Covered by the end-to-end test.

## SF-009 — Unreadable config in the hook fallback means Monitor semantics (accepted)
If the daemon is down **and** `config.toml` is unreadable/invalid, the hook cannot know that Enforce was
selected and evaluates with defaults (Monitor), marked degraded. The daemon never overwrites an invalid
config and reports it as degraded. Residual risk: an agent corrupting `config.toml` while killing the
daemon — both actions are themselves detected and hard-denied in Enforce mode.

## SF-010 — Windows token/key file permissions (accepted)
On Windows `restrict_file` relies on the per-user profile ACL of `%LOCALAPPDATA%`; the named pipe uses
the default DACL. Authentication does not depend on the pipe ACL (mutual HMAC handshake; the token
never crosses the wire). An explicit DACL is a planned hardening step.

## SF-011 — Terminal control characters in CLI output (fixed)
Event summaries are agent-controlled; the CLI now strips control characters before printing so ANSI
escape sequences in commands cannot manipulate the terminal.

## SF-012 — Literal passwords in command lines were stored unredacted (fixed; residue needs user action)
Found in **real use** on the developer's own installation: commands such as
`echo '<password>' | sudo -S …` (run by the agent while installing packages) were stored in the audit log
with the password in clear text — none of the provider/assignment patterns matched. Added detectors for
passwords piped into `sudo -S`/`passwd`/`chpasswd`/`su`/`docker login --password-stdin`,
`--password[=]`, `sshpass -p`, `mysql -p…`, `curl -u user:pass` and `PGPASSWORD=`-style variables, with
false-positive tests (`$VAR` references, `mysql -p` prompt, `git log -p`). Added privacy deletion of
specific events (`agentshield events delete <ids>`), recorded as a chain break, with `secure_delete`, WAL
checkpoint and `VACUUM` so the content is physically removed. Deleting audit events is deliberately an
action the **user** performs; an agent attempting it is blocked by Claude Code's own safety classifier
(observed) and flagged by AgentShield's tamper detections.

## SF-013 — Here-document bodies were parsed as commands (fixed)
Found in real use: `python - <<'X' … X` scripts mentioning `chpasswd` were scored as an account change
(75 → ask) and paths in Python strings as writes outside the workspace. The lexer now captures
here-document bodies (`<<`, `<<-`, quoted/unquoted delimiters, several per line) and hands them to the
receiving command: shells → parsed as commands, interpreters → inline code, SQL clients → argument for
the database detectors (so `psql <<SQL … DROP TABLE …` is now *detected*), anything else → data.

## SF-014 — Outage handled as designed (observed in real use)
The real daemon was stopped unexpectedly during development; hooks fell back to local evaluation (3 events,
coverage `degraded`, 0 dropped), the hash chain stayed intact, and the daemon was restarted.

## Open questions
- Q-001: Own approval UI with scoped, expiring tokens in Interactive Mode? Currently delegated to the
  native prompt (ADR-0005) because it is the only surface that reliably pauses the agent.
- Q-002: Use `PermissionRequest` hooks for enforcement? Currently observation only (avoids double prompts).
- Q-003: Product name: "AgentShield" is used by several projects in the same niche (see LICENSING.md §6).
