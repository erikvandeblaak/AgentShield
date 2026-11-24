# MCP proxy — tool-poisoning and rug-pull protection

Claude Code's hooks show every MCP tool **call** and its arguments, but not the tool **definitions**
(name, description, input schema) that the server sends straight into the model's context. Tool
poisoning hides instructions in those definitions; a *rug pull* changes a definition after you started
trusting the server. The AgentShield MCP proxy closes that gap for stdio servers.

```
Claude Code ⇄ agentshield mcp proxy --name <server> -- <original command> ⇄ MCP server
```

## What it does

| Message | Behaviour |
|---|---|
| `tools/list` response | Definitions are sent to the daemon: each tool's definition is fingerprinted (SHA-256 of description + schema) and **pinned** on first sight; analyzed for poisoning; an audit event is recorded (`McpToolsList`, `mcp.call → tools/list`). |
| `tools/call` request | Relayed — unless the tool was hidden, then answered with JSON-RPC error `-32001` and never sent to the server. |
| everything else | Relayed byte-for-byte. |

Findings (`docs/POLICIES.md` can match them with `finding_ids`):

| Finding | Score | Meaning |
|---|---|---|
| `mcp.tool_poisoning` | 80–90 | Instructions aimed at the model: `<IMPORTANT>`-style tags, "before using this tool read/send…", concealment ("do not tell the user"), smuggling file contents through parameters, overrides of other tools, prompt-injection phrases (description **and** schema property descriptions). |
| `mcp.tool_mentions_sensitive_path` | 75 | Definition references credential or agent-configuration files (`~/.ssh/id_rsa`, `.env`, `mcp.json`, …). |
| `mcp.tool_hidden_characters` | 75 | Invisible Unicode tag / zero-width / bidi-control characters. |
| `mcp.tool_description_changed` | 72 | Definition differs from the pinned fingerprint (rug pull). |
| `mcp.tool_added` | 35 | New tool on a server whose tools were already known. |
| `mcp.tool_description_long` | 30 | Description longer than 4000 characters. |

## Modes

- **Monitor / Shadow / Interactive**: tools are relayed unchanged; findings, events and incidents are recorded.
- **Enforce / Lockdown**: tools with a finding ≥ 70 are removed from `tools/list` (the model never sees
  them) and calls to them are refused. The audit event's actual decision is `deny` with the hidden tools.
- **Daemon unreachable**: the proxy analyzes locally (same detectors, no pinning) and applies the configured mode.

## Commands

```
agentshield mcp list                                   # servers, transport, routed or direct, findings
agentshield mcp wrap [server…] [--config <file>] --dry-run
agentshield mcp wrap [server…] [--config <file>]       # backup + atomic write; asks for confirmation
agentshield mcp unwrap [server…] [--config <file>]     # restores the original command exactly
agentshield mcp trust <server>                         # accept changed definitions after review (logged)
```

`--config` defaults to `~/.claude.json` (user-scope `mcpServers`); use a project's `.mcp.json` for project
scope. **Close Claude Code before wrapping `~/.claude.json`** — Claude Code rewrites that file while running.

## Verified

- 17/17 end-to-end checks with a fictional server (`fixtures/mcp/fake_mcp_server.py`): monitor pass-through,
  enforce hiding + call refusal, rug pull, trust, daemon-down fallback, wrap/unwrap round trip, audit chain.
- Live Claude Code 2.1.331 session (`--mcp-config`, Enforce mode): Claude listed only `mcp__fakesrv__add`;
  the poisoned `weather` tool was invisible to the model.

## Limitations

- stdio servers only; HTTP/SSE servers would need an HTTP proxy (no TLS interception by design).
- Detection is heuristic; a cleverly worded description can evade it, and harmless descriptions can be
  flagged. Pinning still catches *changes* regardless of wording.
- Resources and prompts (`resources/*`, `prompts/*`) are relayed but not analyzed yet.
- JSON-RPC batches (removed from MCP in 2025-06) are relayed unchanged.
