//! Schema migrations (PRAGMA user_version based, forward-only).

use rusqlite::Connection;

const MIGRATIONS: &[&str] = &[
    // v1
    r#"
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
        id                 INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid               TEXT NOT NULL UNIQUE,
        ts_utc             TEXT NOT NULL,
        agent              TEXT NOT NULL,
        session_id         TEXT,
        workspace          TEXT,
        hook_event         TEXT NOT NULL,
        phase              TEXT NOT NULL,
        action_type        TEXT NOT NULL,
        tool               TEXT,
        summary            TEXT NOT NULL,
        risk_score         INTEGER NOT NULL,
        risk_level         TEXT NOT NULL,
        confidence         TEXT NOT NULL,
        categories         TEXT NOT NULL,
        mode               TEXT NOT NULL,
        simulated_decision TEXT NOT NULL,
        actual_decision    TEXT NOT NULL,
        outcome            TEXT NOT NULL,
        coverage           TEXT NOT NULL,
        policy_version     TEXT NOT NULL,
        correlation_id     TEXT,
        latency_us         INTEGER NOT NULL,
        via_daemon         INTEGER NOT NULL,
        record_json        TEXT NOT NULL,
        prev_hash          TEXT NOT NULL,
        hash               TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, id);
    CREATE INDEX IF NOT EXISTS idx_events_score ON events(risk_score);
    CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_type);
    CREATE INDEX IF NOT EXISTS idx_events_corr ON events(correlation_id, phase);
    CREATE INDEX IF NOT EXISTS idx_events_sim ON events(simulated_decision);
    CREATE INDEX IF NOT EXISTS idx_events_act ON events(actual_decision);
    CREATE TABLE IF NOT EXISTS incidents (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc      TEXT NOT NULL,
        session_id  TEXT,
        rule_id     TEXT NOT NULL,
        title       TEXT NOT NULL,
        severity    TEXT NOT NULL,
        score       INTEGER NOT NULL,
        confidence  TEXT NOT NULL,
        explanation TEXT NOT NULL,
        event_ids   TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);
    CREATE TABLE IF NOT EXISTS chain_breaks (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_utc           TEXT NOT NULL,
        reason           TEXT NOT NULL,
        from_id          INTEGER NOT NULL,
        to_id            INTEGER NOT NULL,
        deleted          INTEGER NOT NULL,
        bridge_prev_hash TEXT NOT NULL,
        bridge_last_hash TEXT NOT NULL
    );
    "#,
];

pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let v = i as i64 + 1;
        if v > current {
            conn.execute_batch(&format!("BEGIN; {sql}; PRAGMA user_version = {v}; COMMIT;"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub const LATEST: i64 = MIGRATIONS.len() as i64;
