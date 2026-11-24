# ADR 0006 — Hook command line is `agentshield hook` (avoid antivirus start-up heuristics)

- Status: accepted
- Date: 2026-11-24
- Evidence level: **experimental** — one machine, one antivirus product.

## Context

The hook handler was originally installed as exec form `command: <path>\agentshield.exe`, `args: ["hook", "claude-code"]`.

During end-to-end testing on Windows 11 with **Norton Antivirus** active (Microsoft Defender disabled on that machine), process creation of the **unsigned** `agentshield.exe` with the command line exactly `hook claude-code` was delayed by about **26 seconds**. The same binary with other arguments started normally. The delay happens before `main` runs, so nothing inside AgentShield can shorten or even observe it.

Why this is a security problem and not just a performance problem: AgentShield installs its handlers with a 10 s timeout, and Claude Code treats a timed-out hook as a non-blocking error — the tool call proceeds. A 26 s delay therefore means **monitoring and enforcement are silently lost** (fail-open), in every mode, while the user sees only a slow agent. With `--fail-closed` (`onFailure: "block"`) the same delay would instead block every tool call.

Separately, Norton adds roughly **0.55 s** to the first launches of an unsigned binary (reputation check); after warm-up the hook measures p50 14 ms / p95 16.5 ms end-to-end.

The cause inside the antivirus product is not known. The observation is consistent with a behavioural/command-line heuristic applied to low-reputation executables; no vendor documentation was found, and the behaviour was not reproduced on other products or machines.

## Decision

- The installed handler uses **`args: ["hook"]`** (`install.rs`, `HOOK_ARGS`). The adapter defaults to Claude Code, which is the only supported agent (ADR 0002); an explicit `hook --agent claude-code` form remains accepted.
- The installer recognises all three forms as its own (`["hook"]`, legacy `["hook", "claude-code"]`, `["hook", "--agent", "claude-code"]`) and flags the legacy form so `agentshield agent repair` rewrites it.
- `agentshield selftest` runs the real hook binary end-to-end so that start-up delays on a given machine become visible; `AGENTSHIELD_HOOK_DEBUG` prints the in-process decision time (which explicitly excludes process start).
- **Code signing is recommended** before any public release; it is the actual fix. This ADR is a workaround.

## Consequences

Positive
- The 26 s delay disappeared on the affected machine; hooks complete well inside the timeout.
- No shell is involved (exec form), so there is no additional interpreter start for security software to inspect.

Negative / residual
- The fix is empirical. Another product, a signature update, or a different heuristic can reintroduce a delay at any time; AgentShield has **no runtime detection** of "the hook was started late or not at all" (no heartbeat/watchdog — THREAT_MODEL T12/T13).
- Choosing arguments to avoid a heuristic is fragile and could be misread as evasion. It is documented here openly; the binary's behaviour is unchanged and the proper remedy (signing, vendor allow-listing/false-positive submission) is still required.
- The first launches of every new unsigned build still pay the ~0.55 s reputation check on that product.
- If a future second adapter is added, the agent can no longer be implied by a bare `hook`; the explicit `--agent` form would have to be re-tested against antivirus products.
- Users on fail-closed installs are exposed to the opposite failure: an AV-induced delay blocks the agent until the hook is repaired or uninstalled.
