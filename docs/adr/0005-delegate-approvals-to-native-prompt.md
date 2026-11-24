# ADR 0005 — Delegate approvals to Claude Code's native permission prompt

- Status: accepted
- Date: 2026-11-24

## Context

When a policy says "ask the user", something has to ask. Two designs:

1. **Own approval flow**: the hook blocks while the daemon shows a dialog in the AgentShield GUI (or tray), waits for the user, then returns `allow` or `deny` to Claude Code.
2. **Delegate**: the hook returns `permissionDecision: "ask"` with a reason and lets Claude Code show its own permission prompt.

Relevant facts from the Claude Code hooks reference: `ask` "prompts the user to confirm" and the reason is shown in the prompt; a hook `allow` "skips the permission prompt"; multiple hooks combine as `deny > defer > ask > allow`; native deny/ask rules are evaluated regardless; hook timeouts fail open by default.

Design 1 requires AgentShield to return **`allow`** after approval — otherwise the user is asked twice. Returning `allow` would suppress Claude Code's own prompt for that call, i.e. AgentShield would be *weakening* the native permission flow. It would also need: approval state bound to a specific `tool_use_id` (replay protection), timeouts and expiry, a GUI that must be running and focused, behaviour for headless/SSH sessions, and protection of the approval channel against the very same-user processes that can already reach the daemon. A hook blocked on a human also collides with hook timeouts.

## Decision

- AgentShield **never returns `allow`** (nor `defer`, nor `updatedInput`). `ActualDecision` has only `NoOpinion`, `Ask`, `Deny`, `NotApplicable`.
- "Ask" is rendered as `hookSpecificOutput.permissionDecision = "ask"` with `permissionDecisionReason` containing AgentShield's reason, risk score/level, the first finding's explanation and, where available, a safer alternative. Claude Code shows the prompt and owns the answer.
- AgentShield returns no decision on `PermissionRequest`; it only records that a prompt occurred.
- The GUI's "Approvals" page is a **history** of asked/blocked actions and their observed outcomes, not a queue of pending approvals.
- In Interactive mode, policy `deny` is downgraded to `ask` (the user decides) except for `hard` rules, which deny.

## Consequences

Positive
- AgentShield can only add restrictions; it cannot become the component that auto-approves something Claude Code would have questioned (invariant I2).
- No approval state exists inside AgentShield → **approval replay is not applicable**; nothing to steal, forge or expire.
- The hook never waits for a human, so it stays within its latency budget and cannot time out on a prompt.
- Works without the GUI running, over SSH, and in any terminal Claude Code supports; one familiar prompt instead of two.

Negative
- AgentShield does not learn the user's answer directly. It infers the outcome from the presence or absence of a matching `PostToolUse`/`PostToolUseFailure` event (same `tool_use_id`); a denied prompt simply has no post event.
- No richer approval UX (diff previews, "approve for this session" under AgentShield's own rules, approval by a second person).
- "Don't ask again" choices persist in Claude Code's permission settings, outside AgentShield's control; approval fatigue is not addressed.
- Behaviour of `ask` in non-interactive (`-p`) sessions is defined by Claude Code, not by AgentShield.
- Because AgentShield never says `allow`, it cannot reduce prompts for actions it considers safe; it only ever adds prompts or denials.
