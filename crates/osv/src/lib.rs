//! Offline OSV database (https://osv.dev) for known vulnerabilities and known malicious
//! packages (OSV `MAL-*` advisories).
//!
//! * Downloading is an explicit user action (`agentshield osv update`); AgentShield never
//!   fetches it on its own. The request is a plain GET of the public per-ecosystem bulk file
//!   (`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`); no user data
//!   is sent.
//! * Lookups are local SQLite queries. Results state how old the data is.
//! * Version matching implements OSV's event semantics (introduced / fixed / last_affected)
//!   with a generic version comparator. It is exact for SemVer-like versions and a close
//!   approximation for other schemes (documented limitation).

use agentshield_event_model::{Confidence, Finding, RiskCategory};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// OSV ecosystem names AgentShield maps package managers to.
pub const ECOSYSTEMS: &[&str] = &[
    "npm",
    "PyPI",
    "crates.io",
    "Packagist",
    "NuGet",
    "RubyGems",
    "Go",
];
/// Data older than this is reported as stale.
pub const STALE_DAYS: i64 = 7;

#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("download: {0}")]
    Download(String),
    #[error("archive: {0}")]
    Zip(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Map AgentShield's supply-chain ecosystem names to OSV names.
pub fn osv_ecosystem(supply_chain_ecosystem: &str) -> Option<&'static str> {
    Some(match supply_chain_ecosystem {
        "npm" => "npm",
        "pypi" => "PyPI",
        "crates.io" => "crates.io",
        "packagist" => "Packagist",
        "nuget" => "NuGet",
        "rubygems" => "RubyGems",
        "go" => "Go",
        _ => return None,
    })
}

/// Normalize a package name for lookup (PyPI: PEP 503; others: lowercase).
pub fn normalize_name(ecosystem: &str, name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    match ecosystem {
        "PyPI" => {
            let mut out = String::with_capacity(n.len());
            let mut last_dash = false;
            for c in n.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !last_dash {
                        out.push('-');
                    }
                    last_dash = true;
                } else {
                    out.push(c);
                    last_dash = false;
                }
            }
            out
        }
        "Go" => name.trim().to_string(),
        _ => n,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(u64),
    Alpha(String),
}

fn tokens(v: &str) -> Vec<Tok> {
    let v = v.trim().trim_start_matches(['v', 'V', '=']);
    let v = v.split('+').next().unwrap_or(v); // build metadata is ignored
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut num = None::<bool>;
    let flush = |cur: &mut String, num: Option<bool>, out: &mut Vec<Tok>| {
        if cur.is_empty() {
            return;
        }
        if num == Some(true) {
            out.push(Tok::Num(cur.parse().unwrap_or(u64::MAX)));
        } else {
            out.push(Tok::Alpha(cur.to_ascii_lowercase()));
        }
        cur.clear();
    };
    for c in v.chars() {
        if matches!(c, '.' | '-' | '_' | '~') {
            flush(&mut cur, num, &mut out);
            num = None;
            continue;
        }
        let is_num = c.is_ascii_digit();
        if num.is_some_and(|n| n != is_num) {
            flush(&mut cur, num, &mut out);
        }
        num = Some(is_num);
        cur.push(c);
    }
    flush(&mut cur, num, &mut out);
    out
}

/// Generic version comparison: numeric components numerically, a pre-release tag sorts
/// before the release (`1.0.0-rc1 < 1.0.0`), trailing zeros are insignificant (`1.0 == 1.0.0`).
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (tokens(a), tokens(b));
    let n = ta.len().max(tb.len());
    for i in 0..n {
        match (ta.get(i), tb.get(i)) {
            (Some(Tok::Num(x)), Some(Tok::Num(y))) => match x.cmp(y) {
                Ordering::Equal => {}
                o => return o,
            },
            (Some(Tok::Alpha(x)), Some(Tok::Alpha(y))) => match x.cmp(y) {
                Ordering::Equal => {}
                o => return o,
            },
            // number vs pre-release tag: the release (number) is greater
            (Some(Tok::Num(_)), Some(Tok::Alpha(_))) => return Ordering::Greater,
            (Some(Tok::Alpha(_)), Some(Tok::Num(_))) => return Ordering::Less,
            (Some(Tok::Num(x)), None) => {
                if *x != 0 {
                    return Ordering::Greater;
                }
            }
            (None, Some(Tok::Num(y))) => {
                if *y != 0 {
                    return Ordering::Less;
                }
            }
            // extra alpha token = pre-release of the shorter version
            (Some(Tok::Alpha(_)), None) => return Ordering::Less,
            (None, Some(Tok::Alpha(_))) => return Ordering::Greater,
            (None, None) => {}
        }
    }
    Ordering::Equal
}

/// Is `v` an exact version (not a range / constraint / tag)?
pub fn is_exact_version(v: &str) -> bool {
    let t = v.trim().trim_start_matches(['v', '=']);
    !t.is_empty()
        && t.starts_with(|c: char| c.is_ascii_digit())
        && !t.contains(['^', '~', '*', '>', '<', ',', ' ', '|', 'x'])
        && t != "latest"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Range {
    #[serde(rename = "type")]
    kind: String,
    events: Vec<serde_json::Value>,
}

/// OSV event semantics for one range.
fn in_range(version: &str, r: &Range) -> bool {
    if r.kind.eq_ignore_ascii_case("GIT") {
        return false;
    }
    let mut affected = false;
    for e in &r.events {
        if let Some(i) = e.get("introduced").and_then(|x| x.as_str()) {
            if i == "0" || compare_versions(version, i) != Ordering::Less {
                affected = true;
            }
        } else if let Some(f) = e.get("fixed").and_then(|x| x.as_str()) {
            if compare_versions(version, f) != Ordering::Less {
                affected = false;
            }
        } else if let Some(l) = e.get("last_affected").and_then(|x| x.as_str())
            && compare_versions(version, l) == Ordering::Greater
        {
            affected = false;
        }
    }
    affected
}

fn range_has_fix(r: &Range) -> bool {
    r.events
        .iter()
        .any(|e| e.get("fixed").is_some() || e.get("last_affected").is_some())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: String,
    pub malicious: bool,
    pub aliases: Vec<String>,
    pub fixed_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EcosystemStatus {
    pub ecosystem: String,
    pub advisories: u64,
    pub updated: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsvStatus {
    pub enabled: bool,
    pub path: String,
    pub ecosystems: Vec<EcosystemStatus>,
    pub stale: bool,
}

pub struct OsvDb {
    conn: Connection,
}

const SCHEMA_VERSION: i64 = 2;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS adv (
    id TEXT NOT NULL, ecosystem TEXT NOT NULL, summary TEXT NOT NULL, severity TEXT NOT NULL,
    malicious INTEGER NOT NULL, aliases TEXT NOT NULL, modified TEXT,
    PRIMARY KEY (id, ecosystem)
);
CREATE TABLE IF NOT EXISTS aff (
    adv_id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
    ranges TEXT NOT NULL, versions TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aff ON aff(ecosystem, name);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

fn severity_of(v: &serde_json::Value) -> String {
    let s = v
        .pointer("/database_specific/severity")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => "critical",
        "HIGH" => "high",
        "MODERATE" | "MEDIUM" => "moderate",
        "LOW" => "low",
        _ => "unknown",
    }
    .to_string()
}

impl OsvDb {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("osv.db")
    }

    pub fn open(path: &Path) -> Result<OsvDb, OsvError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // Schema v2 keys advisories by (id, ecosystem): the same advisory can affect several
        // ecosystems. Older databases are rebuilt (the data is re-downloadable).
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v < SCHEMA_VERSION {
            conn.execute_batch(
                "DROP TABLE IF EXISTS aff; DROP TABLE IF EXISTS adv; DROP TABLE IF EXISTS meta;",
            )?;
        }
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(OsvDb { conn })
    }

    /// Read-only (used by the engine). `None` if no database was downloaded.
    pub fn open_readonly(path: &Path) -> Option<OsvDb> {
        if !path.is_file() {
            return None;
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
        Some(OsvDb { conn })
    }

    /// Replace one ecosystem's data with the advisories in an OSV `all.zip`.
    pub fn import_zip(&mut self, ecosystem: &str, zip_path: &Path) -> Result<u64, OsvError> {
        let f = std::fs::File::open(zip_path)?;
        let mut archive = zip::ZipArchive::new(f).map_err(|e| OsvError::Zip(e.to_string()))?;
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM aff WHERE ecosystem = ?1", [ecosystem])?;
        tx.execute("DELETE FROM adv WHERE ecosystem = ?1", [ecosystem])?;
        let mut n = 0u64;
        {
            let mut ins_adv = tx.prepare("INSERT OR REPLACE INTO adv (id, ecosystem, summary, severity, malicious, aliases, modified) VALUES (?1,?2,?3,?4,?5,?6,?7)")?;
            let mut ins_aff = tx.prepare("INSERT INTO aff (adv_id, ecosystem, name, ranges, versions) VALUES (?1,?2,?3,?4,?5)")?;
            let mut buf = String::new();
            for i in 0..archive.len() {
                let mut entry = archive
                    .by_index(i)
                    .map_err(|e| OsvError::Zip(e.to_string()))?;
                if !entry.name().ends_with(".json") || entry.size() > 32 * 1024 * 1024 {
                    continue;
                }
                buf.clear();
                if entry.read_to_string(&mut buf).is_err() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&buf) else {
                    continue;
                };
                let id = v
                    .get("id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if id.is_empty() || v.get("withdrawn").is_some() {
                    continue;
                }
                let summary: String = v
                    .get("summary")
                    .or_else(|| v.get("details"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(300)
                    .collect();
                let malicious = id.starts_with("MAL-");
                let aliases = v
                    .get("aliases")
                    .cloned()
                    .unwrap_or(serde_json::json!([]))
                    .to_string();
                ins_adv.execute(params![
                    id,
                    ecosystem,
                    summary,
                    severity_of(&v),
                    malicious,
                    aliases,
                    v.get("modified").and_then(|x| x.as_str())
                ])?;
                for a in v
                    .get("affected")
                    .and_then(|x| x.as_array())
                    .into_iter()
                    .flatten()
                {
                    let eco = a
                        .pointer("/package/ecosystem")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    // Ecosystem may carry a suffix (e.g. "Debian:12"); only the base matters here.
                    if !eco
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(ecosystem)
                    {
                        continue;
                    }
                    let name = a
                        .pointer("/package/name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    let ranges = a
                        .get("ranges")
                        .cloned()
                        .unwrap_or(serde_json::json!([]))
                        .to_string();
                    let versions = a
                        .get("versions")
                        .cloned()
                        .unwrap_or(serde_json::json!([]))
                        .to_string();
                    ins_aff.execute(params![
                        id,
                        ecosystem,
                        normalize_name(ecosystem, name),
                        ranges,
                        versions
                    ])?;
                }
                n += 1;
            }
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![format!("updated:{ecosystem}"), chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// Import advisories that are already parsed (tests, or a user-provided OSV JSON file).
    pub fn import_advisories(
        &mut self,
        ecosystem: &str,
        advisories: &[serde_json::Value],
    ) -> Result<u64, OsvError> {
        // Unique per call: concurrent imports in one process must not share a directory.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "agentshield-osv-import-{}-{seq}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)?;
        let zip_path = dir.join("all.zip");
        {
            use std::io::Write as _;
            let f = std::fs::File::create(&zip_path)?;
            let mut z = zip::ZipWriter::new(f);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (i, a) in advisories.iter().enumerate() {
                z.start_file(format!("{i}.json"), opts)
                    .map_err(|e| OsvError::Zip(e.to_string()))?;
                z.write_all(a.to_string().as_bytes())?;
            }
            z.finish().map_err(|e| OsvError::Zip(e.to_string()))?;
        }
        let r = self.import_zip(ecosystem, &zip_path);
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    /// Advisories affecting `name` (and `version`, if given and exact).
    /// Without an exact version only malicious-package and unfixed advisories are returned.
    pub fn lookup(
        &self,
        ecosystem: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<Vec<Advisory>, OsvError> {
        let norm = normalize_name(ecosystem, name);
        let mut st = self.conn.prepare_cached(
            "SELECT a.id, a.summary, a.severity, a.malicious, a.aliases, f.ranges, f.versions FROM aff f JOIN adv a ON a.id = f.adv_id AND a.ecosystem = f.ecosystem WHERE f.ecosystem = ?1 AND f.name = ?2",
        )?;
        let rows = st.query_map(params![ecosystem, norm], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        let exact = version
            .filter(|v| is_exact_version(v))
            .map(|v| v.trim().trim_start_matches(['v', '=']).to_string());
        let mut out: Vec<Advisory> = Vec::new();
        for row in rows {
            let (id, summary, severity, malicious, aliases, ranges, versions) = row?;
            let ranges: Vec<Range> = serde_json::from_str(&ranges).unwrap_or_default();
            let versions: Vec<String> = serde_json::from_str(&versions).unwrap_or_default();
            let fixed_in: Vec<String> = ranges
                .iter()
                .flat_map(|r| {
                    r.events.iter().filter_map(|e| {
                        e.get("fixed")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    })
                })
                .collect();
            let hit = match &exact {
                Some(v) => {
                    malicious && ranges.is_empty() && versions.is_empty()
                        || versions
                            .iter()
                            .any(|x| compare_versions(x, v) == Ordering::Equal)
                        || ranges.iter().any(|r| in_range(v, r))
                }
                // Unknown version: report only what is bad regardless of version.
                None => {
                    malicious
                        || (!ranges.is_empty()
                            && ranges.iter().all(|r| !range_has_fix(r))
                            && versions.is_empty())
                }
            };
            if hit {
                let aliases: Vec<String> = serde_json::from_str(&aliases).unwrap_or_default();
                // The same vulnerability is often published by several databases (GHSA, PYSEC,
                // RUSTSEC, …) and linked through aliases: report it once.
                let dup = out.iter_mut().find(|a| {
                    a.id == id
                        || a.aliases.contains(&id)
                        || aliases.contains(&a.id)
                        || a.aliases.iter().any(|x| aliases.contains(x))
                });
                match dup {
                    Some(existing) => {
                        if existing.severity == "unknown" && severity != "unknown" {
                            existing.severity = severity;
                        }
                        for f in fixed_in {
                            if !existing.fixed_in.contains(&f) {
                                existing.fixed_in.push(f);
                            }
                        }
                    }
                    None => out.push(Advisory {
                        id,
                        summary,
                        severity,
                        malicious,
                        aliases,
                        fixed_in,
                    }),
                }
            }
        }
        out.sort_by(|a, b| b.malicious.cmp(&a.malicious).then(a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn status(&self, path: &Path) -> Result<OsvStatus, OsvError> {
        let mut ecos = Vec::new();
        let mut stale = false;
        for e in ECOSYSTEMS {
            let n: i64 =
                self.conn
                    .query_row("SELECT count(*) FROM adv WHERE ecosystem = ?1", [e], |r| {
                        r.get(0)
                    })?;
            let updated: Option<String> = self
                .conn
                .query_row(
                    "SELECT value FROM meta WHERE key = ?1",
                    [format!("updated:{e}")],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(u) = &updated
                && let Ok(t) = chrono::DateTime::parse_from_rfc3339(u)
                && chrono::Utc::now().signed_duration_since(t) > chrono::Duration::days(STALE_DAYS)
            {
                stale = true;
            }
            ecos.push(EcosystemStatus {
                ecosystem: e.to_string(),
                advisories: n as u64,
                updated,
            });
        }
        let enabled = ecos.iter().any(|e| e.updated.is_some());
        Ok(OsvStatus {
            enabled,
            path: path.display().to_string(),
            ecosystems: ecos,
            stale,
        })
    }

    pub fn updated(&self, ecosystem: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [format!("updated:{ecosystem}")],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }
}

/// Result of a download: bytes written and advisories that are listed but not publicly
/// readable (HTTP 403/404), which are skipped and reported — never silently.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DownloadReport {
    pub bytes: u64,
    pub skipped: Vec<String>,
}

/// Download one ecosystem's bulk file to `dest` (streamed to disk). Explicit opt-in only.
pub fn download(
    ecosystem: &str,
    dest: &Path,
    progress: &mut dyn FnMut(u64),
) -> Result<DownloadReport, OsvError> {
    if !ECOSYSTEMS.contains(&ecosystem) {
        return Err(OsvError::Download(format!(
            "unsupported ecosystem '{ecosystem}'"
        )));
    }
    let url = format!("{BASE_URL}/{ecosystem}/all.zip");
    // Use the operating system's trust store (corporate proxies and AV products that inspect
    // TLS install their root there); certificate validation stays fully enabled.
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(std::time::Duration::from_secs(900)))
        .user_agent("agentshield-osv-sync")
        .build()
        .new_agent();
    let mut resp = match agent.get(&url).call() {
        Ok(r) => r,
        // Some ecosystems (observed: Packagist, 2026-11) have no public all.zip; fall back to
        // the individual advisory objects of the same public bucket.
        Err(ureq::Error::StatusCode(403 | 404)) => {
            return download_via_listing(&agent, ecosystem, dest, progress);
        }
        Err(e) => return Err(OsvError::Download(format!("{url}: {e}"))),
    };
    let mut reader = resp
        .body_mut()
        .with_config()
        .limit(2 * 1024 * 1024 * 1024)
        .reader();
    let mut file = std::fs::File::create(dest)?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| OsvError::Download(e.to_string()))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        total += n as u64;
        progress(total);
    }
    file.sync_all()?;
    Ok(DownloadReport {
        bytes: total,
        skipped: Vec::new(),
    })
}

/// Fallback: list `<ecosystem>/*.json` through the public GCS JSON API and fetch each
/// advisory (parallel, verified TLS), writing them into a local zip at `dest`.
fn download_via_listing(
    agent: &ureq::Agent,
    ecosystem: &str,
    dest: &Path,
    progress: &mut dyn FnMut(u64),
) -> Result<DownloadReport, OsvError> {
    let mut names: Vec<String> = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut url = format!(
            "https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o?prefix={ecosystem}/&maxResults=1000&fields=items(name),nextPageToken"
        );
        if let Some(t) = &token {
            url.push_str(&format!("&pageToken={t}"));
        }
        let mut resp = agent
            .get(&url)
            .call()
            .map_err(|e| OsvError::Download(format!("listing {ecosystem}: {e}")))?;
        let page: serde_json::Value = serde_json::from_reader(resp.body_mut().as_reader())
            .map_err(|e| OsvError::Download(format!("listing: {e}")))?;
        for it in page
            .get("items")
            .and_then(|i| i.as_array())
            .into_iter()
            .flatten()
        {
            if let Some(n) = it
                .get("name")
                .and_then(|n| n.as_str())
                .filter(|n| n.ends_with(".json"))
            {
                names.push(n.to_string());
            }
        }
        token = page
            .get("nextPageToken")
            .and_then(|t| t.as_str())
            .map(|t| t.to_string());
        if token.is_none() || names.len() > 200_000 {
            break;
        }
    }
    if names.is_empty() {
        return Err(OsvError::Download(format!(
            "no advisories found for {ecosystem}"
        )));
    }
    let queue = std::sync::Arc::new(std::sync::Mutex::new(names));
    let (tx, rx) = std::sync::mpsc::channel::<Result<(String, Vec<u8>), String>>();
    let workers = 12;
    for _ in 0..workers {
        let (queue, tx, agent) = (queue.clone(), tx.clone(), agent.clone());
        std::thread::spawn(move || {
            loop {
                let next = queue.lock().ok().and_then(|mut q| q.pop());
                let Some(name) = next else { break };
                let url = format!("{BASE_URL}/{name}");
                let mut r = Err(String::new());
                for attempt in 0..4u64 {
                    if attempt > 0 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            250 * attempt * attempt,
                        ));
                    }
                    r = agent
                        .get(&url)
                        .call()
                        .map_err(|e| format!("{url}: {e}"))
                        .and_then(|mut resp| {
                            resp.body_mut()
                                .with_config()
                                .limit(32 * 1024 * 1024)
                                .read_to_vec()
                                .map_err(|e| e.to_string())
                        });
                    if r.is_ok() {
                        break;
                    }
                }
                if tx.send(r.map(|b| (name, b))).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);
    let f = std::fs::File::create(dest)?;
    let mut z = zip::ZipWriter::new(f);
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut total = 0u64;
    let mut failed = 0u32;
    let mut first_error = String::new();
    let mut skipped: Vec<String> = Vec::new();
    for r in rx {
        match r {
            Ok((name, bytes)) => {
                total += bytes.len() as u64;
                z.start_file(name.replace('/', "_"), opts)
                    .map_err(|e| OsvError::Zip(e.to_string()))?;
                z.write_all(&bytes)?;
                progress(total);
            }
            Err(e) if e.contains("http status: 403") || e.contains("http status: 404") => {
                skipped.push(
                    e.split(": http status")
                        .next()
                        .unwrap_or(&e)
                        .rsplit('/')
                        .next()
                        .unwrap_or("")
                        .to_string(),
                );
            }
            Err(e) => {
                failed += 1;
                if first_error.is_empty() {
                    first_error = e;
                }
            }
        }
    }
    z.finish().map_err(|e| OsvError::Zip(e.to_string()))?;
    if failed > 0 {
        return Err(OsvError::Download(format!(
            "{failed} advisories of {ecosystem} could not be downloaded (first: {first_error}); nothing imported for this ecosystem"
        )));
    }
    Ok(DownloadReport {
        bytes: total,
        skipped,
    })
}

fn sev_score(s: &str) -> u8 {
    match s {
        "critical" => 88,
        "high" => 75,
        "moderate" => 55,
        "low" => 35,
        _ => 50,
    }
}

/// Turn advisories into risk findings.
pub fn findings(
    ecosystem: &str,
    name: &str,
    version: Option<&str>,
    advisories: &[Advisory],
    data_updated: Option<&str>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let age = data_updated
        .map(|u| format!(" (OSV data from {u})"))
        .unwrap_or_default();
    let mal: Vec<&Advisory> = advisories.iter().filter(|a| a.malicious).collect();
    if !mal.is_empty() {
        out.push(Finding {
            id: "supply.known_malicious_package".into(),
            category: RiskCategory::SupplyChainCompromise,
            score: 97,
            confidence: Confidence::High,
            explanation: format!(
                "'{name}' ({ecosystem}) is listed as a known MALICIOUS package: {}{age}",
                mal.iter()
                    .map(|a| a.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence: Some(name.to_string()),
            mitigation: Some(
                "Do not install this package. Check for typos in the package name.".into(),
            ),
        });
    }
    let vulns: Vec<&Advisory> = advisories.iter().filter(|a| !a.malicious).collect();
    if !vulns.is_empty() {
        let worst = vulns
            .iter()
            .map(|a| sev_score(&a.severity))
            .max()
            .unwrap_or(50);
        let ids: Vec<String> = vulns
            .iter()
            .take(6)
            .map(|a| {
                let cve = a
                    .aliases
                    .iter()
                    .find(|x| x.starts_with("CVE-"))
                    .map(|c| format!(" / {c}"))
                    .unwrap_or_default();
                format!("{}{cve} ({})", a.id, a.severity)
            })
            .collect();
        let fixes: Vec<String> = {
            let mut f: Vec<String> = vulns.iter().flat_map(|a| a.fixed_in.clone()).collect();
            f.sort_by(|a, b| compare_versions(a, b));
            f.dedup();
            f
        };
        let what = match version {
            Some(v) if is_exact_version(v) => format!("version {v} of '{name}'"),
            _ => format!("'{name}' (all versions, no fix published)"),
        };
        out.push(Finding {
            id: "supply.known_vulnerability".into(),
            category: RiskCategory::SupplyChainCompromise,
            score: worst,
            confidence: Confidence::High,
            explanation: format!(
                "{} known vulnerabilit{} affect {what}: {}{}{age}",
                vulns.len(),
                if vulns.len() == 1 { "y" } else { "ies" },
                ids.join(", "),
                if vulns.len() > 6 { ", …" } else { "" }
            ),
            evidence: Some(name.to_string()),
            mitigation: fixes
                .last()
                .map(|f| format!("Install a fixed version (≥ {f})")),
        });
    }
    out
}

#[cfg(test)]
mod tests;
