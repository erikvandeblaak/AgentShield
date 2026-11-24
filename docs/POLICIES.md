# Policy reference

Policies are TOML (`schema_version = 1`). Layers, in order:

1. **Preset** (selected with `agentshield policy use <id>`): `policies/*.toml`, embedded in the binary.
2. **User**: `<config>/policies/user.toml` (`%APPDATA%\AgentShield\policies\user.toml` or
   `~/.config/agentshield/policies/user.toml`). Editable in Policy Studio.
3. **Project**: `<workspace>/.agentshield/policy.toml`. Untrusted (the agent can edit it): `allow`
   rules are ignored, thresholds can only be lowered, existing rule ids cannot be replaced.

## File structure

```toml
schema_version = 1
name = "my-policy"            # optional
description = "…"             # optional

[thresholds]                  # default decisions from the risk score (when no rule decides)
warn_at = 40
ask_at  = 70
deny_at = 90

[[rules]]
id = "protect-prod-env"       # unique; a later layer with the same id overrides (not project)
name = "Production env file"
enabled = true                # default true
hard = false                  # hard deny: also denies in Interactive mode; beats explicit allow
[rules.match]                 # all given fields must match (AND); list entries are OR
event_types = ["file.read", "shell.exec"]
path_globs  = ["**/.env.production"]
[rules.unless]                # optional: rule does not apply when this matcher matches
path_globs  = ["**/fixtures/**"]
[rules.effect]
action = "deny"               # allow | warn | ask | require_sandbox | deny
severity = "critical"
reason = "Production credentials"
suggestion = "Use .env.example for non-secret values."
```

### Match fields

| Field | Matches |
|---|---|
| `event_types` | `shell.exec`, `file.read`, `file.write`, `file.edit`, `file.search`, `network.fetch`, `network.search`, `mcp.call`, `agent.subagent`, `agent.prompt`, `session.start`, `session.end`, `agent.notification`, `agent.stop`, `agent.permission_request`, `agent.permission_denied`, `agentshield.mode_change`, `tool.other` (also `shell.*`) |
| `tools` | glob on Claude Code tool name (`Bash`, `mcp__github__*`) |
| `agents` | glob on agent id (`claude-code`) |
| `path_globs` | glob (case-insensitive, `/` separators) on target paths and path-like shell arguments/redirections |
| `programs` | any program in the command (normalized: lowercase, no `.exe`) |
| `programs_all_in` | every program in the command is in the list |
| `command_contains` | case-insensitive substring of the full command line |
| `all_segments_match` | every simple command (`program args…`) matches one of these regexes (case-insensitive) |
| `categories` | any risk category of the assessment |
| `finding_ids` | glob on finding ids (`shell.rm_*`, `tamper.*`) — see `agentshield command analyze` output |
| `min_score` / `max_score` | risk score bounds |
| `mcp_servers` | glob on MCP server name |
| `url_hosts` | glob on hosts of fetched URLs and URLs in commands |
| `workspaces` | glob on the workspace path |

### Precedence

`deny > require_sandbox > ask > warn > allow`. Hard rules win over everything. An explicit `allow`
suppresses the score thresholds but never a stricter rule. `require_sandbox` denies in Enforce Mode
(AgentShield provides no enforceable sandbox) and asks in Interactive Mode.

### Mode effect

| Policy says | Monitor | Shadow | Interactive | Enforce | Lockdown |
|---|---|---|---|---|---|
| allow / warn | – | – | – | – | deny if mutating / network / score ≥ 40 |
| ask | – | would ask | ask (native prompt) | ask | deny |
| deny | – | would deny | ask (hard: deny) | deny | deny |

Validate with `agentshield policy validate <file>`; simulate with `agentshield policy simulate "<cmd>" --preset <id>`.
