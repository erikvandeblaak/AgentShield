# ADR 0002 — Integrate Claude Code only

- Status: accepted (owner scope decision)
- Date: 2026-11-24

## Context

Several coding agents expose hook mechanisms (Claude Code, OpenAI Codex CLI, Cursor, and others). Their payload schemas, decision formats, trust models and failure semantics differ and change frequently. Competing tools advertise a dozen or more supported agents while conceding in their own documentation that depth "varies by agent and event type" and that "some events fail open or are only observed".

AgentShield's central promise is an honest capability matrix: a capability is "enforced" only if a documented pre-execution deny path exists, is used, and was verified end-to-end. That standard has been met for exactly one agent: Claude Code 2.1.331, whose hooks reference was read in full and whose behaviour was exercised with the real binary (38/38 end-to-end checks).

## Decision

- AgentShield ships **one adapter**: `crates/adapters/claude-code`.
- Other agents (Codex CLI, Cursor, OpenCode, GitHub Copilot CLI) are only looked up on `PATH` and reported as **`supported: false`** with every capability **unsupported** and the reason "No AgentShield adapter for this agent (scope: Claude Code only). Activity of this agent is NOT monitored."
- The architecture stays adapter-shaped (`NormalizedEvent`, `agent` field on records and IPC, `Method::Hook { agent, … }`), but no second adapter is planned in the current scope. The hook entry point ignores unknown agent ids ("never interfere").

## Consequences

Positive
- Every claim in the capability matrix is backed by documentation and tests for the one supported agent.
- One compatibility surface to track; smaller code and test matrix; clear user expectations.

Negative
- Users running several agents get **partial visibility with no warning beyond the Agents page**: activity of other agents is invisible, and the dashboard cannot say how much activity that is.
- Narrower market than multi-agent competitors.
- Dependence on one vendor's hook contract: a breaking change in Claude Code's hooks breaks AgentShield entirely. Only version 2.1.331 has been exercised; the adapter relies on features introduced in 2.1.274 (`mcp_server`) and 2.1.295 (`onFailure`) and degrades without them (no fail-closed, MCP server name from the tool prefix).
- Claude surfaces that do not load `~/.claude/settings.json` hooks (Claude Desktop, web, API/SDK apps) are not covered either.

## Revisit when

The owner widens the scope, or a second agent's hook contract is stable and documented well enough to meet the same "enforced" standard. Research notes for Codex and Cursor are kept in RESEARCH §2.
