# Agent Capability Matrix

Version 0.1.0, 2026-11-24. This document mirrors `crates/adapters/claude-code/src/detect.rs` (`claude_capabilities`, `detect_all`). The code is authoritative; the same matrix is shown live by `agentshield detect` and on the GUI's Agents page, computed from the actual integration state on the machine.

## 1. Status vocabulary

| Status | Meaning |
|---|---|
| **enforced** | A documented pre-execution deny path exists, AgentShield uses it, and the hooks are installed **and verified**. Effective only in Interactive / Enforce / Lockdown mode. |
| **observed** | Events are recorded; no blocking for this capability. |
| **partial** | Only part of the activity is visible or controllable; the reason says which part. |
| **degraded** | Hooks are installed but something required is missing or unverified. |
| **unsupported** | Not available. |
| **unverified** | Reserved in the type; not currently emitted for any capability. |

Rule from the source: *"A capability is only 'enforced' when there is a documented pre-execution deny path that AgentShield uses and the hooks are installed & verified."*

## 2. Claude Code (tested against 2.1.332)

Integration: hooks in `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`), exec form, for PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest, UserPromptSubmit, SessionStart, SessionEnd, Notification, Stop, SubagentStop, ConfigChange (tamper tripwire, observation only), and PreSkillShellCommand (matcher `Bash|PowerShell`) when the `claude` on PATH is 2.1.332 or later: older versions show a warning for an unknown hook event at every start, so it is not registered there (`agent install --skill-shell-hook on|off` overrides). `disableAllHooks: true` in the settings file is reported as an integration problem.

State inputs: `installed`, `verified`, and whether `PreToolUse`, `PostToolUse`, `SessionStart` are registered.

### 2.1 Matrix when hooks are installed and verified

| Capability | Status | Reason (verbatim from code) |
|---|---|---|
| Shell monitoring | observed | Bash/PowerShell tool calls via PreToolUse + PostToolUse |
| Shell blocking | enforced | PreToolUse hook can return deny/ask before the tool runs (Enforce/Interactive/Lockdown modes) |
| Skill shell commands | enforced | Commands a skill or command injects while loading, via PreSkillShellCommand (Claude Code 2.1.332+); ask counts as deny there |
| File read monitoring | observed | Read/Glob/Grep tool calls (not reads done inside shell commands' child processes beyond what the command line shows) |
| File write monitoring | observed | Write/Edit/MultiEdit/NotebookEdit tool calls |
| File blocking | enforced | PreToolUse hook can return deny/ask before the tool runs (Enforce/Interactive/Lockdown modes) |
| Package detection | partial | Package manager commands are detected from the command line; installs triggered indirectly by scripts are not visible |
| MCP observation | observed | mcp__<server>__<tool> calls via PreToolUse/PostToolUse; tool descriptions are not inspected (no proxy) |
| MCP enforcement | enforced | PreToolUse hook can return deny/ask before the tool runs (Enforce/Interactive/Lockdown modes) |
| Session correlation | observed | session_id on every hook payload |
| Network metadata | partial | Only intended destinations visible in WebFetch URLs and command lines; no connection-level telemetry |
| Network enforcement | partial | Only tool calls whose destination is visible can be denied; connections made by child processes are not controlled (no firewall integration by design) |
| Process monitoring | unsupported | No OS-level process telemetry yet (ETW / eBPF planned, see docs/ROADMAP.md) |
| Sandbox integration | unsupported | AgentShield does not provide a sandbox; Claude Code's own sandbox settings remain authoritative |
| Execution outcome | observed | PostToolUse / PostToolUseFailure confirm whether a tool actually ran |

### 2.2 How the status changes with integration state

| Capability | Not installed | Installed, but not verified or required event missing |
|---|---|---|
| Shell / File / MCP **blocking / enforcement** | unsupported — "AgentShield hooks are not installed in Claude Code" | degraded — "Hooks installed but not verified (see integration problems)" (when not verified or PreToolUse missing) |
| Shell monitoring, File read/write monitoring, MCP observation | unsupported — same reason | degraded — "Required hook event is not registered" (when PreToolUse missing) |
| Session correlation | unsupported | degraded — "Required hook event is not registered" (when SessionStart missing) |
| Skill shell commands | unsupported | unsupported — "PreSkillShellCommand not registered (needs Claude Code 2.1.332+ and a repair): PreToolUse does not fire for commands a skill injects while loading" |
| Package detection, Network metadata | unsupported | partial (unchanged while installed) |
| Network enforcement | unsupported (reason text unchanged) | partial |
| Process monitoring, Sandbox integration | unsupported | unsupported |
| Execution outcome | unsupported | degraded — "PostToolUse not registered" (when PostToolUse missing) |

### 2.3 Notes attached to the agent entry

- "Monitoring covers Claude Code CLI and IDE sessions that load ~/.claude/settings.json hooks."
- "Hooks run with your user rights; an agent that can edit settings files could remove them. AgentShield flags such edits as agent configuration tampering."
- When installed with `--fail-closed`: "Fail-closed is on: if the AgentShield binary is missing or crashes, Claude Code blocks tool calls."

### 2.4 Caveats the matrix does not express

- "enforced" is conditional on the **mode**: in Monitor and Shadow nothing is blocked.
- "enforced" means *declared tool calls can be denied*. It does not mean the underlying effect is impossible by another route (a script, a child process, an MCP tool).
- Enforcement depends on Claude Code honouring its documented hook contract; if the hook process times out or cannot start, Claude Code continues unless `onFailure: "block"` is set (see SECURITY_ARCHITECTURE §5).
- Sessions started with hooks disabled (`disableAllHooks`, `--bare`) or before workspace trust is accepted produce no events; the matrix is computed from `settings.json` and cannot see this.
- `Execution outcome`: PostToolUseFailure does not fire for calls rejected before execution (per Claude Code docs); a denied call therefore has no post event — its outcome is the recorded `Blocked`/`AskedUser`.
- The reason for "Process monitoring" references `docs/ROADMAP.md`, which does not exist in the repository on 2026-11-24 (the deferred mechanisms are discussed in RESEARCH §6).
- Detection (`detected`) is true when a `claude` executable is on `PATH` (or in `~/.local/bin`, `~/.claude/local`) **or** the settings directory exists; the version comes from `claude --version` with a 5 s timeout.

## 3. Other agents — Unsupported

Scope decision: only Claude Code is integrated ([ADR 0002](adr/0002-claude-code-only.md)). The following agents are looked up on `PATH` only so the UI can say honestly that they are present and **not monitored**.

| Agent | Looked-up executable | supported | Capabilities reported |
|---|---|---|---|
| OpenAI Codex CLI | `codex` | false | all unsupported |
| Cursor | `cursor` | false | all unsupported |
| OpenCode | `opencode` | false | all unsupported |
| GitHub Copilot CLI | `copilot` | false | all unsupported |

For each of them the six capabilities *Shell monitoring, Shell blocking, File read monitoring, File write monitoring, MCP observation, Session correlation* are reported as **unsupported** with the reason:

> "No AgentShield adapter for this agent (scope: Claude Code only). Activity of this agent is NOT monitored."

and the note "Not monitored by AgentShield." No version is queried and no configuration of these agents is read or modified.

Agents not in this list (Gemini CLI, Cline, Windsurf, Aider, …) are not detected at all; absence from the list does not imply anything about them other than "not monitored".

Also **not covered** even for Claude Code: Claude Desktop, claude.ai in the browser, and API/SDK applications that do not load the user's `settings.json` hooks.
