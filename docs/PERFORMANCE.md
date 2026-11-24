# Performance

Measured 2026-11-24 on the development machine (Windows 11 x64, Norton Antivirus active). Targets from
the specification are goals, not guarantees; numbers below are real measurements of this build.

| Metric | Target | Measured | How |
|---|---|---|---|
| Policy + risk evaluation | p95 ≤ 20 ms | p50 0.40 ms · p95 0.59 ms · p99 0.79 ms (debug build) | `core::tests::eval_latency_budget`, 700 mixed commands |
| Hook overhead, daemon side | p95 ≤ 50 ms | p50 0.63 ms · p95 0.85 ms · p99 2.8 ms (release) | daemon latency histogram (`agentshield status`) |
| Hook end-to-end incl. process start | – | p50 14.4 ms · p95 16.5 ms · p99 16.6 ms | 60 real hook invocations, warm AV cache |
| Hook with daemon down (local fallback) | – | 37 ms | e2e test |
| Store 100 000 events | ≥ 100k supported | ~1.0 s (batches of 1000) | `audit_log::tests::hundred_thousand_events_perf` (release) |
| Filtered page (min_score, 200 rows) on 100k | – | 0.7 ms | same test |
| Dashboard stats over 100k | – | 311 ms | same test |

## Antivirus impact (important)

Norton delayed the *first* starts of a freshly built unsigned binary by ~0.5 s and delayed the exact
command line `hook claude-code` by ~26 s (SF-003). With the current `agentshield hook` form and a warm
cache, process start is ~14 ms. Code signing is the structural fix.

## Design choices

- The hook is a short-lived process that asks the daemon over a local pipe (3 s deadline) and falls back
  to in-process evaluation; no busy polling anywhere (subscriptions are push-based with 15 s heartbeats).
- Bounded everything: 4 MiB IPC frames and hook stdin, 64 in-flight handler calls, 400 req/s per
  connection, broadcast queue 4096 with explicit `lagged` notifications, dropped events counted and shown.
- SQLite WAL, `busy_timeout` 5 s, immediate transactions for the hash chain, indexes on time, session,
  score, action, correlation id and decisions.
