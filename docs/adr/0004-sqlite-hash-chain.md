# ADR 0004 — SQLite audit log with a tamper-evident hash chain

- Status: accepted
- Date: 2026-11-24

## Context

AgentShield needs a local, queryable, durable record of every evaluated event: filterable lists, statistics, sessions, replay of policies against history, exports. Two writers can exist at the same time (the daemon, and a hook in fallback mode when the daemon is unreachable). Users must be able to delete data (retention, privacy) and must be able to tell whether the log was altered. Everything is stored in a file owned by the same user who runs the agent.

Alternatives considered: append-only JSONL files (simple, but no indexes, hard to query and paginate, concurrent appends from two processes are fragile on Windows); an embedded key-value store (no SQL, custom query layer); an external log service or a signed/remote ledger (violates local-only, no account).

## Decision

- **SQLite in WAL mode**, bundled (`rusqlite` feature `bundled`), forward-only migrations keyed on `PRAGMA user_version`, 5 s busy timeout.
- **Append-oriented schema**: events are inserted, never updated. Pre-execution intent and post-execution result are separate rows linked by `correlation_id`. Indexed columns duplicate the fields needed for filtering; the full redacted record is stored as `record_json`.
- **Hash chain**: `hash = SHA-256(prev_hash ‖ "\n" ‖ record_json)`, genesis = 64 zeros. Inserts run in `BEGIN IMMEDIATE` transactions so concurrent writers keep one linear chain.
- **Deletions are explicit**: retention, per-session deletion and "delete all" write a `chain_breaks` row (reason, id range, count, bridge hashes); verification bridges recorded breaks and reports unrecorded gaps as failures.
- **Verification** (`agentshield security check`, GUI): recompute the chain, report the first bad id, and run SQLite's integrity check.
- Records are **redacted before insertion**; the database is not encrypted.

## Consequences

Positive
- Fast enough: ~1 s for 100,000 inserts, 0.7 ms for a filtered page (measured).
- Naive edits, accidental corruption and silent row deletion in the middle of the log are detected; legitimate deletions remain visible as such.
- Single file, online backup through SQLite's backup API, standard tooling can read it.

Negative / residual — **tamper-evident, not tamper-proof**
- The chain contains no secret and has no external anchor. Anyone with write access to the file (the user, the agent's child processes, malware running as the user) can recompute the whole chain, truncate the newest rows undetectably, or forge a `chain_breaks` row to legitimise a deletion.
- It therefore provides no evidence against a deliberate same-user attacker; it is an integrity *check*, not a proof. Users who need evidential value must export/back up to a location the agent cannot write.
- `record_json` is hashed as serialised: the serialisation of `AuditRecord` is part of the format (`preserve_order` is enabled for `serde_json`); schema changes need a migration strategy that keeps old rows verifiable.
- Stored data is readable by any same-user process; redaction is the only confidentiality control.

## Possible follow-ups (not implemented)

HMAC-keyed chain with the key outside the agent's reach; periodic export of the head hash to an external location; append-only file attributes / a separate service account.
