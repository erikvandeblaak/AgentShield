//! Local audit database (SQLite, WAL).
//!
//! * **Append-oriented**: events are inserted, never updated. Pre-execution intent and the
//!   post-execution result are separate rows linked by `correlation_id`.
//! * **Tamper-evident hash chain**: `hash = SHA-256(prev_hash || record_json)`. Inserts take
//!   an immediate write lock so concurrent writers (daemon + hook fallback) keep the chain
//!   linear. Deletions (retention, user privacy requests) are recorded in `chain_breaks`
//!   so verification can bridge them *explicitly* instead of hiding them.
//! * Local logs are **not tamper-proof**: a user (or malware) with write access to the file
//!   can rebuild the whole chain. The chain detects naive edits and accidental corruption.

mod schema;

use agentshield_event_model::{AuditRecord, Outcome, RiskCategory};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params, params_from_iter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Filters for listing events.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct EventQuery {
    /// Only rows with id > after_id (live streaming).
    pub after_id: Option<i64>,
    /// Only rows with id < before_id (pagination backwards).
    pub before_id: Option<i64>,
    pub limit: Option<u32>,
    pub agent: Option<String>,
    pub session_id: Option<String>,
    pub workspace: Option<String>,
    pub action_type: Option<String>,
    pub phase: Option<String>,
    pub min_score: Option<u8>,
    pub category: Option<String>,
    pub simulated_decision: Option<String>,
    pub actual_decision: Option<String>,
    /// Case-insensitive search in summary, tool and workspace.
    pub search: Option<String>,
    /// RFC3339 lower bound.
    pub since: Option<String>,
    pub correlation_id: Option<String>,
    /// Only events with at least one secret-related finding.
    pub secrets_only: bool,
    /// Only package-manager related events.
    pub packages_only: bool,
    /// Only network-related events.
    pub network_only: bool,
    /// Only MCP events.
    pub mcp_only: bool,
}

/// One listed event plus the outcome observed later (post event with same correlation id).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventRow {
    pub record: AuditRecord,
    pub observed_outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Bucket {
    pub key: String,
    pub count: u64,
    pub max_score: u8,
    pub risky: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CountItem {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Stats {
    pub total_events: u64,
    pub events_in_window: u64,
    pub window_hours: u32,
    pub risky_events: u64,
    pub would_block: u64,
    pub would_ask: u64,
    pub actually_blocked: u64,
    pub actually_asked: u64,
    pub degraded_events: u64,
    pub dropped_events: u64,
    pub by_level: Vec<CountItem>,
    pub by_category: Vec<CountItem>,
    pub by_agent: Vec<CountItem>,
    pub by_action: Vec<CountItem>,
    pub top_workspaces: Vec<CountItem>,
    pub per_minute: Vec<Bucket>,
    pub per_hour: Vec<Bucket>,
    /// day-of-week (0=Sun) x hour heatmap: key "d:h".
    pub heatmap: Vec<Bucket>,
    pub active_sessions: u64,
    pub first_event: Option<String>,
    pub last_event: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionSummary {
    pub session_id: String,
    pub agent: String,
    pub workspace: Option<String>,
    pub first_ts: String,
    pub last_ts: String,
    pub events: u64,
    pub max_score: u8,
    pub would_block: u64,
    pub blocked: u64,
    pub ended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Incident {
    pub id: i64,
    pub ts_utc: String,
    pub session_id: Option<String>,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub score: u8,
    pub confidence: String,
    pub explanation: String,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityReport {
    pub checked: u64,
    pub ok: bool,
    pub bridged_breaks: u64,
    pub first_bad_id: Option<i64>,
    pub problem: Option<String>,
    pub sqlite_integrity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainBreak {
    pub ts_utc: String,
    pub reason: String,
    pub from_id: i64,
    pub to_id: i64,
    pub deleted: u64,
}

/// Handle to the audit database.
pub struct AuditLog {
    conn: Connection,
}

fn hash_of(prev: &str, json: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(json.as_bytes());
    hex::encode(h.finalize())
}

fn cats(c: &[RiskCategory]) -> String {
    if c.is_empty() {
        return String::new();
    }
    format!(
        ",{},",
        c.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(",")
    )
}

impl AuditLog {
    /// Open (and migrate) the database read-write.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuditError::Other(format!("create {}: {e}", parent.display())))?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Deleted rows are overwritten, so privacy deletions do not leave readable residue.
        conn.pragma_update(None, "secure_delete", "ON")?;
        schema::migrate(&conn)?;
        Ok(AuditLog { conn })
    }

    /// Open read-only (GUI/CLI queries). Fails if the database does not exist.
    pub fn open_readonly(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(Duration::from_secs(5))?;
        Ok(AuditLog { conn })
    }

    /// In-memory database (tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::migrate(&conn)?;
        Ok(AuditLog { conn })
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Append records atomically; fills `id`, `prev_hash` and `hash`.
    pub fn insert_batch(&mut self, records: &mut [AuditRecord]) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut prev: String = tx
            .query_row(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| GENESIS.to_string());
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO events (uuid, ts_utc, agent, session_id, workspace, hook_event, phase, action_type, tool, summary,
                  risk_score, risk_level, confidence, categories, mode, simulated_decision, actual_decision, outcome, coverage,
                  policy_version, correlation_id, latency_us, via_daemon, record_json, prev_hash, hash)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)",
            )?;
            for rec in records.iter_mut() {
                rec.id = 0;
                rec.prev_hash = String::new();
                rec.hash = String::new();
                let json = serde_json::to_string(&*rec)?;
                let hash = hash_of(&prev, &json);
                stmt.execute(params![
                    rec.uuid,
                    rec.ts_utc,
                    rec.agent,
                    rec.session_id,
                    rec.workspace,
                    rec.hook_event,
                    rec.phase.as_str(),
                    rec.action_type,
                    rec.tool,
                    rec.summary,
                    rec.risk.score,
                    rec.risk.level.as_str(),
                    rec.risk.confidence.as_str(),
                    cats(&rec.risk.categories),
                    rec.mode.as_str(),
                    rec.simulated_decision.as_str(),
                    rec.actual_decision.as_str(),
                    rec.outcome.as_str(),
                    rec.coverage.as_str(),
                    rec.policy_version,
                    rec.correlation_id,
                    rec.latency_us as i64,
                    rec.via_daemon,
                    json,
                    prev,
                    hash,
                ])?;
                rec.id = tx.last_insert_rowid();
                rec.prev_hash = prev.clone();
                rec.hash = hash.clone();
                prev = hash;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert(&mut self, rec: &mut AuditRecord) -> Result<i64> {
        self.insert_batch(std::slice::from_mut(rec))?;
        Ok(rec.id)
    }

    fn row_to_record(json: &str, id: i64, prev: String, hash: String) -> Result<AuditRecord> {
        let mut r: AuditRecord = serde_json::from_str(json)?;
        r.id = id;
        r.prev_hash = prev;
        r.hash = hash;
        Ok(r)
    }

    pub fn get(&self, id: i64) -> Result<Option<EventRow>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, record_json, prev_hash, hash FROM events WHERE id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, json, p, h)) => {
                let record = Self::row_to_record(&json, id, p, h)?;
                let observed = self.outcomes_for(&[&record])?.into_iter().next().flatten();
                Ok(Some(EventRow {
                    record,
                    observed_outcome: observed,
                }))
            }
        }
    }

    fn outcomes_for(&self, recs: &[&AuditRecord]) -> Result<Vec<Option<Outcome>>> {
        let mut out = Vec::with_capacity(recs.len());
        let mut stmt = self.conn.prepare_cached("SELECT record_json FROM events WHERE correlation_id = ?1 AND phase = 'post' ORDER BY id DESC LIMIT 1")?;
        for r in recs {
            if r.phase != agentshield_event_model::Phase::Pre {
                out.push(None);
                continue;
            }
            let Some(cid) = &r.correlation_id else {
                out.push(None);
                continue;
            };
            let j: Option<String> = stmt.query_row([cid], |row| row.get(0)).optional()?;
            out.push(match j {
                Some(j) => serde_json::from_str::<AuditRecord>(&j)
                    .ok()
                    .map(|p| p.outcome),
                None => None,
            });
        }
        Ok(out)
    }

    /// List events, newest first (or oldest first when `after_id` is set for streaming).
    /// WHERE clause (starting with " WHERE 1=1") and arguments for an [`EventQuery`].
    fn where_clause(q: &EventQuery) -> (String, Vec<rusqlite::types::Value>) {
        let mut sql = String::from(" WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        let mut push = |cond: &str, v: rusqlite::types::Value, sql: &mut String| {
            sql.push_str(" AND ");
            sql.push_str(cond);
            args.push(v);
        };
        use rusqlite::types::Value as V;
        if let Some(a) = q.after_id {
            push("id > ?", V::Integer(a), &mut sql);
        }
        if let Some(b) = q.before_id {
            push("id < ?", V::Integer(b), &mut sql);
        }
        if let Some(v) = &q.agent {
            push("agent = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.session_id {
            push("session_id = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.workspace {
            push("workspace = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.action_type {
            push("action_type = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.phase {
            push("phase = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = q.min_score {
            push("risk_score >= ?", V::Integer(i64::from(v)), &mut sql);
        }
        if let Some(v) = &q.category {
            push(
                "categories LIKE ?",
                V::Text(format!("%,{},%", like_escape(v))),
                &mut sql,
            );
            sql.push_str(" ESCAPE '\\'");
        }
        if let Some(v) = &q.simulated_decision {
            push("simulated_decision = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.actual_decision {
            push("actual_decision = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.since {
            push("ts_utc >= ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(v) = &q.correlation_id {
            push("correlation_id = ?", V::Text(v.clone()), &mut sql);
        }
        if let Some(s) = q.search.as_ref().filter(|s| !s.trim().is_empty()) {
            let pat = format!("%{}%", like_escape(&s.to_lowercase()));
            sql.push_str(" AND (lower(summary) LIKE ? ESCAPE '\\' OR lower(coalesce(tool,'')) LIKE ? ESCAPE '\\' OR lower(coalesce(workspace,'')) LIKE ? ESCAPE '\\' OR lower(action_type) LIKE ? ESCAPE '\\')");
            for _ in 0..4 {
                args.push(V::Text(pat.clone()));
            }
        }
        if q.secrets_only {
            sql.push_str(" AND (categories LIKE '%,secret_access,%' OR categories LIKE '%,credential_exposure,%')");
        }
        if q.packages_only {
            sql.push_str(" AND (categories LIKE '%,suspicious_package_installation,%' OR categories LIKE '%,supply_chain_compromise,%')");
        }
        if q.network_only {
            sql.push_str(" AND (action_type IN ('network.fetch','network.search') OR categories LIKE '%,unsafe_network_access,%' OR categories LIKE '%,data_exfiltration,%')");
        }
        if q.mcp_only {
            sql.push_str(" AND action_type = 'mcp.call'");
        }
        (sql, args)
    }

    /// Number of events matching `q` (ignores limit / pagination ordering).
    pub fn count_matching(&self, q: &EventQuery) -> Result<u64> {
        let (w, args) = Self::where_clause(q);
        let n: i64 = self.conn.query_row(
            &format!("SELECT count(*) FROM events{w}"),
            params_from_iter(args.iter()),
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn list(&self, q: &EventQuery) -> Result<Vec<EventRow>> {
        let (w, args) = Self::where_clause(q);
        let mut sql = format!("SELECT id, record_json, prev_hash, hash FROM events{w}");
        let ascending = q.after_id.is_some();
        sql.push_str(if ascending {
            " ORDER BY id ASC"
        } else {
            " ORDER BY id DESC"
        });
        let limit = q.limit.unwrap_or(200).clamp(1, 5000);
        sql.push_str(&format!(" LIMIT {limit}"));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut recs = Vec::new();
        for row in rows {
            let (id, json, p, h) = row?;
            recs.push(Self::row_to_record(&json, id, p, h)?);
        }
        let refs: Vec<&AuditRecord> = recs.iter().collect();
        let outcomes = self.outcomes_for(&refs)?;
        Ok(recs
            .into_iter()
            .zip(outcomes)
            .map(|(record, observed_outcome)| EventRow {
                record,
                observed_outcome,
            })
            .collect())
    }

    pub fn max_id(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT coalesce(max(id),0) FROM events", [], |r| r.get(0))?)
    }

    pub fn count(&self) -> Result<u64> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM events", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    /// Aggregate statistics for the dashboard.
    pub fn stats(&self, window_hours: u32) -> Result<Stats> {
        let window_hours = window_hours.clamp(1, 24 * 90);
        let since = (chrono::Utc::now() - chrono::Duration::hours(i64::from(window_hours)))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let minute_since = (chrono::Utc::now() - chrono::Duration::minutes(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let c = &self.conn;
        let q1 = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Result<u64> {
            Ok(c.query_row(sql, p, |r| r.get::<_, i64>(0))? as u64)
        };
        let mut s = Stats {
            window_hours,
            ..Default::default()
        };
        s.total_events = q1("SELECT count(*) FROM events", &[])?;
        s.events_in_window = q1("SELECT count(*) FROM events WHERE ts_utc >= ?1", &[&since])?;
        s.risky_events = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND risk_score >= 40",
            &[&since],
        )?;
        s.would_block = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND phase='pre' AND simulated_decision IN ('deny','require_sandbox')",
            &[&since],
        )?;
        s.would_ask = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND phase='pre' AND simulated_decision = 'ask'",
            &[&since],
        )?;
        s.actually_blocked = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND actual_decision = 'deny'",
            &[&since],
        )?;
        s.actually_asked = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND actual_decision = 'ask'",
            &[&since],
        )?;
        s.degraded_events = q1(
            "SELECT count(*) FROM events WHERE ts_utc >= ?1 AND coverage = 'degraded'",
            &[&since],
        )?;
        s.dropped_events = self
            .meta_get("dropped_events")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        s.active_sessions = q1(
            "SELECT count(DISTINCT session_id) FROM events WHERE session_id IS NOT NULL AND ts_utc >= ?1 AND session_id NOT IN (SELECT session_id FROM events WHERE action_type='session.end' AND session_id IS NOT NULL)",
            &[&(chrono::Utc::now() - chrono::Duration::hours(2))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)],
        )?;
        let group = |sql: &str, arg: &str| -> Result<Vec<CountItem>> {
            let mut st = c.prepare(sql)?;
            let rows = st.query_map([arg], |r| {
                Ok(CountItem {
                    key: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    count: r.get::<_, i64>(1)? as u64,
                })
            })?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        };
        s.by_level = group(
            "SELECT risk_level, count(*) FROM events WHERE ts_utc >= ?1 GROUP BY risk_level",
            &since,
        )?;
        s.by_agent = group(
            "SELECT agent, count(*) FROM events WHERE ts_utc >= ?1 GROUP BY agent ORDER BY 2 DESC LIMIT 20",
            &since,
        )?;
        s.by_action = group(
            "SELECT action_type, count(*) FROM events WHERE ts_utc >= ?1 GROUP BY action_type ORDER BY 2 DESC LIMIT 30",
            &since,
        )?;
        s.top_workspaces = group(
            "SELECT workspace, count(*) FROM events WHERE ts_utc >= ?1 AND workspace IS NOT NULL GROUP BY workspace ORDER BY 2 DESC LIMIT 10",
            &since,
        )?;
        // Categories are stored as ",a,b," — count in Rust.
        {
            let mut st =
                c.prepare("SELECT categories FROM events WHERE ts_utc >= ?1 AND categories != ''")?;
            let mut map: std::collections::BTreeMap<String, u64> = Default::default();
            for row in st.query_map([&since], |r| r.get::<_, String>(0))? {
                for cat in row?.split(',').filter(|x| !x.is_empty()) {
                    *map.entry(cat.to_string()).or_default() += 1;
                }
            }
            let mut v: Vec<CountItem> = map
                .into_iter()
                .map(|(key, count)| CountItem { key, count })
                .collect();
            v.sort_by_key(|c| std::cmp::Reverse(c.count));
            s.by_category = v;
        }
        let buckets = |sql: &str, arg: &str| -> Result<Vec<Bucket>> {
            let mut st = c.prepare(sql)?;
            let rows = st.query_map([arg], |r| {
                Ok(Bucket {
                    key: r.get(0)?,
                    count: r.get::<_, i64>(1)? as u64,
                    max_score: r.get::<_, i64>(2)? as u8,
                    risky: r.get::<_, i64>(3)? as u64,
                })
            })?;
            Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
        };
        s.per_minute = buckets(
            "SELECT substr(ts_utc,1,16), count(*), max(risk_score), sum(risk_score >= 40) FROM events WHERE ts_utc >= ?1 GROUP BY 1 ORDER BY 1",
            &minute_since,
        )?;
        s.per_hour = buckets(
            "SELECT substr(ts_utc,1,13), count(*), max(risk_score), sum(risk_score >= 40) FROM events WHERE ts_utc >= ?1 GROUP BY 1 ORDER BY 1",
            &since,
        )?;
        s.heatmap = buckets(
            "SELECT strftime('%w', ts_utc) || ':' || cast(strftime('%H', ts_utc) as integer), count(*), max(risk_score), sum(risk_score >= 40) FROM events WHERE ts_utc >= ?1 GROUP BY 1",
            &(chrono::Utc::now() - chrono::Duration::days(28))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )?;
        s.first_event = c
            .query_row("SELECT min(ts_utc) FROM events", [], |r| r.get(0))
            .optional()?
            .flatten();
        s.last_event = c
            .query_row("SELECT max(ts_utc) FROM events", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(s)
    }

    /// One session by id (any age).
    pub fn session(&self, session_id: &str) -> Result<Option<SessionSummary>> {
        Ok(self
            .session_rows("WHERE session_id = ?1", rusqlite::params![session_id], 1)?
            .into_iter()
            .next())
    }

    pub fn sessions(&self, limit: u32) -> Result<Vec<SessionSummary>> {
        self.session_rows("WHERE session_id IS NOT NULL", rusqlite::params![], limit)
    }

    fn session_rows(
        &self,
        filter: &str,
        p: &[&dyn rusqlite::ToSql],
        limit: u32,
    ) -> Result<Vec<SessionSummary>> {
        let sql = format!(
            "SELECT session_id, max(agent), max(workspace), min(ts_utc), max(ts_utc), count(*), max(risk_score),
                    sum(phase='pre' AND simulated_decision IN ('deny','require_sandbox')), sum(actual_decision='deny'), sum(action_type='session.end')
             FROM events {filter} GROUP BY session_id ORDER BY max(ts_utc) DESC LIMIT {}",
            limit.clamp(1, 1000)
        );
        let mut st = self.conn.prepare(&sql)?;
        let rows = st.query_map(p, |r| {
            Ok(SessionSummary {
                session_id: r.get(0)?,
                agent: r.get(1)?,
                workspace: r.get(2)?,
                first_ts: r.get(3)?,
                last_ts: r.get(4)?,
                events: r.get::<_, i64>(5)? as u64,
                max_score: r.get::<_, i64>(6)? as u8,
                would_block: r.get::<_, i64>(7)? as u64,
                blocked: r.get::<_, i64>(8)? as u64,
                ended: r.get::<_, i64>(9)? > 0,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Recent risky events of a session (for correlation).
    pub fn recent_session_events(
        &self,
        session_id: &str,
        since: &str,
        limit: u32,
    ) -> Result<Vec<AuditRecord>> {
        let mut st = self.conn.prepare_cached("SELECT id, record_json, prev_hash, hash FROM events WHERE session_id = ?1 AND ts_utc >= ?2 ORDER BY id DESC LIMIT ?3")?;
        let rows = st.query_map(params![session_id, since, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, j, p, h) = row?;
            out.push(Self::row_to_record(&j, id, p, h)?);
        }
        Ok(out)
    }

    /// Insert an incident unless an identical one (session + rule + same evidence) exists.
    /// Insert an incident. When `group_since` is given and an incident with the same session
    /// and rule exists at or after that time, the new evidence is merged into it instead of
    /// creating a new incident (keeps repeated patterns from flooding the Threat Center).
    /// Returns the incident id, or `None` for an exact duplicate.
    pub fn insert_incident(
        &mut self,
        inc: &Incident,
        group_since: Option<&str>,
    ) -> Result<Option<i64>> {
        if let Some(since) = group_since {
            let existing: Option<(i64, String, i64)> = self
                .conn
                .query_row(
                    "SELECT id, event_ids, score FROM incidents WHERE coalesce(session_id,'') = coalesce(?1,'') AND rule_id = ?2 AND ts_utc >= ?3 ORDER BY id DESC LIMIT 1",
                    params![inc.session_id, inc.rule_id, since],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((id, ids_json, score)) = existing {
                let mut ids: Vec<i64> = serde_json::from_str(&ids_json).unwrap_or_default();
                let before = ids.len();
                for e in &inc.event_ids {
                    if !ids.contains(e) && ids.len() < 200 {
                        ids.push(*e);
                    }
                }
                if ids.len() == before {
                    return Ok(None);
                }
                ids.sort_unstable();
                let new_score = score.max(i64::from(inc.score));
                let severity = if new_score >= 80 {
                    "critical"
                } else if new_score >= 60 {
                    "high"
                } else {
                    "medium"
                };
                self.conn.execute(
                    "UPDATE incidents SET event_ids = ?1, score = ?2, severity = ?3, explanation = ?4 WHERE id = ?5",
                    params![serde_json::to_string(&ids)?, new_score, severity, inc.explanation, id],
                )?;
                return Ok(Some(id));
            }
        }
        let ids = serde_json::to_string(&inc.event_ids)?;
        let exists: Option<i64> = self
            .conn
            .query_row("SELECT id FROM incidents WHERE coalesce(session_id,'') = coalesce(?1,'') AND rule_id = ?2 AND event_ids = ?3", params![inc.session_id, inc.rule_id, ids], |r| r.get(0))
            .optional()?;
        if exists.is_some() {
            return Ok(None);
        }
        self.conn.execute(
            "INSERT INTO incidents (ts_utc, session_id, rule_id, title, severity, score, confidence, explanation, event_ids) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![inc.ts_utc, inc.session_id, inc.rule_id, inc.title, inc.severity, inc.score, inc.confidence, inc.explanation, ids],
        )?;
        Ok(Some(self.conn.last_insert_rowid()))
    }

    pub fn incidents(&self, limit: u32) -> Result<Vec<Incident>> {
        let mut st = self.conn.prepare("SELECT id, ts_utc, session_id, rule_id, title, severity, score, confidence, explanation, event_ids FROM incidents ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map([limit.clamp(1, 1000)], |r| {
            let ids: String = r.get(9)?;
            Ok(Incident {
                id: r.get(0)?,
                ts_utc: r.get(1)?,
                session_id: r.get(2)?,
                rule_id: r.get(3)?,
                title: r.get(4)?,
                severity: r.get(5)?,
                score: r.get::<_, i64>(6)? as u8,
                confidence: r.get(7)?,
                explanation: r.get(8)?,
                event_ids: serde_json::from_str(&ids).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }

    /// Record events that could not be stored (never hidden).
    pub fn add_dropped(&self, n: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES('dropped_events', ?1) ON CONFLICT(key) DO UPDATE SET value = cast(value as integer) + ?1",
            [n as i64],
        )?;
        Ok(())
    }

    fn delete_where(
        &mut self,
        cond: &str,
        args: &[&dyn rusqlite::ToSql],
        reason: &str,
    ) -> Result<u64> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let ids: Vec<i64> = {
            let mut st = tx.prepare(&format!("SELECT id FROM events WHERE {cond} ORDER BY id"))?;
            st.query_map(args, |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        if ids.is_empty() {
            return Ok(0);
        }
        // Record contiguous runs as chain breaks.
        let mut runs: Vec<(i64, i64)> = Vec::new();
        let all: Vec<i64> = {
            let mut st = tx.prepare("SELECT id FROM events ORDER BY id")?;
            st.query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?
        };
        let set: std::collections::HashSet<i64> = ids.iter().copied().collect();
        let mut start: Option<i64> = None;
        let mut last = 0;
        for id in &all {
            if set.contains(id) {
                if start.is_none() {
                    start = Some(*id);
                }
                last = *id;
            } else if let Some(s) = start.take() {
                runs.push((s, last));
            }
        }
        if let Some(s) = start {
            runs.push((s, last));
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        for (from, to) in &runs {
            let (bridge_prev, bridge_last): (String, String) = tx.query_row(
                "SELECT (SELECT prev_hash FROM events WHERE id = ?1), (SELECT hash FROM events WHERE id = ?2)",
                params![from, to],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM events WHERE id BETWEEN ?1 AND ?2",
                params![from, to],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO chain_breaks (ts_utc, reason, from_id, to_id, deleted, bridge_prev_hash, bridge_last_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![now, reason, from, to, count, bridge_prev, bridge_last],
            )?;
        }
        let n = tx.execute(&format!("DELETE FROM events WHERE {cond}"), args)? as u64;
        tx.commit()?;
        Ok(n)
    }

    /// Delete events older than `days` (retention). Returns deleted count.
    pub fn apply_retention(&mut self, days: u32) -> Result<u64> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(i64::from(days.max(1))))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let n = self.delete_where(
            "ts_utc < ?1",
            &[&cutoff],
            &format!("retention ({days} days)"),
        )?;
        if n > 0 {
            self.conn
                .execute("DELETE FROM incidents WHERE ts_utc < ?1", [&cutoff])?;
        }
        Ok(n)
    }

    /// Privacy deletion of one session.
    pub fn delete_session(&mut self, session_id: &str) -> Result<u64> {
        let n = self.delete_where("session_id = ?1", &[&session_id], "user deleted session")?;
        self.conn
            .execute("DELETE FROM incidents WHERE session_id = ?1", [session_id])?;
        self.purge_residue()?;
        Ok(n)
    }

    /// Privacy deletion of specific events (e.g. a secret that slipped past redaction).
    /// The deletion is recorded as a chain break; the WAL is checkpointed and truncated so
    /// the removed content does not linger on disk.
    pub fn delete_events(&mut self, ids: &[i64]) -> Result<u64> {
        if ids.is_empty() {
            return Ok(0);
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let n = self.delete_where(&format!("id IN ({list})"), &[], "user deleted events")?;
        self.purge_residue()?;
        Ok(n)
    }

    /// Checkpoint + truncate the WAL and reclaim free pages so deleted data is gone from disk.
    pub fn purge_residue(&self) -> Result<()> {
        let _: (i64, i64, i64) =
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        self.conn.execute_batch("VACUUM")?;
        let _: (i64, i64, i64) =
            self.conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
        Ok(())
    }

    /// Privacy deletion of everything.
    pub fn delete_all(&mut self) -> Result<u64> {
        let n = self.delete_where("1=1", &[], "user deleted all data")?;
        self.conn.execute("DELETE FROM incidents", [])?;
        self.purge_residue()?;
        Ok(n)
    }

    pub fn chain_breaks(&self) -> Result<Vec<ChainBreak>> {
        let mut st = self.conn.prepare(
            "SELECT ts_utc, reason, from_id, to_id, deleted FROM chain_breaks ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ChainBreak {
                ts_utc: r.get(0)?,
                reason: r.get(1)?,
                from_id: r.get(2)?,
                to_id: r.get(3)?,
                deleted: r.get::<_, i64>(4)? as u64,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Verify the hash chain and SQLite's own integrity.
    pub fn verify(&self) -> Result<IntegrityReport> {
        let sqlite_integrity: String = self
            .conn
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        let bridges: std::collections::HashMap<String, String> = {
            let mut st = self
                .conn
                .prepare("SELECT bridge_last_hash, bridge_prev_hash FROM chain_breaks")?;
            st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<std::result::Result<_, _>>()?
        };
        let mut st = self.conn.prepare("SELECT id, record_json, prev_hash, hash, risk_score, simulated_decision, actual_decision FROM events ORDER BY id")?;
        let mut rows = st.query([])?;
        let mut expected_prev = GENESIS.to_string();
        let mut checked = 0u64;
        let mut bridged = 0u64;
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let json: String = r.get(1)?;
            let prev: String = r.get(2)?;
            let hash: String = r.get(3)?;
            checked += 1;
            if prev != expected_prev {
                // Allowed only if a recorded deletion bridges exactly this gap.
                let mut cur = prev.clone();
                let mut ok = false;
                for _ in 0..10_000 {
                    match bridges.get(&cur) {
                        Some(before) => {
                            bridged += 1;
                            if *before == expected_prev {
                                ok = true;
                                break;
                            }
                            cur = before.clone();
                        }
                        None => break,
                    }
                }
                if !ok {
                    return Ok(IntegrityReport { checked, ok: false, bridged_breaks: bridged, first_bad_id: Some(id), problem: Some("prev_hash does not link to the previous event (unrecorded deletion or insertion)".into()), sqlite_integrity });
                }
            }
            if hash_of(&prev, &json) != hash {
                return Ok(IntegrityReport {
                    checked,
                    ok: false,
                    bridged_breaks: bridged,
                    first_bad_id: Some(id),
                    problem: Some("record content does not match its hash (modified)".into()),
                    sqlite_integrity,
                });
            }
            // Denormalized columns must agree with the hashed JSON.
            let rec: AuditRecord = serde_json::from_str(&json)?;
            let score: i64 = r.get(4)?;
            let sim: String = r.get(5)?;
            let act: String = r.get(6)?;
            if score != i64::from(rec.risk.score)
                || sim != rec.simulated_decision.as_str()
                || act != rec.actual_decision.as_str()
            {
                return Ok(IntegrityReport {
                    checked,
                    ok: false,
                    bridged_breaks: bridged,
                    first_bad_id: Some(id),
                    problem: Some("index columns differ from the hashed record (modified)".into()),
                    sqlite_integrity,
                });
            }
            expected_prev = hash;
        }
        let ok = sqlite_integrity == "ok";
        Ok(IntegrityReport {
            checked,
            ok,
            bridged_breaks: bridged,
            first_bad_id: None,
            problem: (!ok).then(|| format!("sqlite: {sqlite_integrity}")),
            sqlite_integrity,
        })
    }

    /// Consistent online backup (`VACUUM INTO`).
    pub fn backup(&self, dest: &Path) -> Result<()> {
        if dest.exists() {
            return Err(AuditError::Other(format!(
                "{} already exists",
                dest.display()
            )));
        }
        self.conn
            .execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])?;
        Ok(())
    }

    /// Raw connection for advanced queries in the same process (read-only use).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests;
