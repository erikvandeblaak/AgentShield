//! Secret detection and redaction.
//!
//! * [`Redactor`] finds credentials in free text and JSON using provider-specific patterns,
//!   key/value heuristics and an entropy check, and replaces them with
//!   `[REDACTED:<kind>:<fingerprint>]`. The fingerprint is a keyed SHA-256 (per-install key) so
//!   the same secret can be correlated across events without storing it.
//! * [`classify_path`] recognizes credential files and other sensitive paths.
//!
//! Redaction happens in the core pipeline **before** anything reaches the audit log, the GUI
//! or reports. All test fixtures use synthetic credentials.

mod paths;

pub use paths::{SensitiveKind, SensitivePath, classify_path, normalize_path};

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// One detected secret (never contains the secret itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretMatch {
    /// Detector id, e.g. `github_token`.
    pub kind: &'static str,
    /// Human readable name.
    pub name: &'static str,
    /// Byte range in the scanned text.
    pub start: usize,
    pub end: usize,
    /// `high` for provider-specific formats, `medium` for key/value heuristics, `low` for entropy.
    pub confidence: &'static str,
    /// Keyed fingerprint (16 hex chars).
    pub fingerprint: String,
}

struct Pattern {
    kind: &'static str,
    name: &'static str,
    re: Regex,
    /// Capture group holding the secret value (0 = whole match).
    group: usize,
    confidence: &'static str,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let p = |kind, name, re: &str, group, confidence| Pattern {
            kind,
            name,
            re: Regex::new(re).unwrap_or_else(|e| panic!("bad builtin regex {kind}: {e}")),
            group,
            confidence,
        };
        vec![
            p("private_key", "Private key block", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)", 0, "high"),
            p("anthropic_api_key", "Anthropic API key", r"\bsk-ant-[a-z0-9]{2,10}-[A-Za-z0-9_\-]{20,}", 0, "high"),
            p("openai_api_key", "OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", 0, "high"),
            p("aws_access_key_id", "AWS access key id", r"(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 0, "high"),
            p("aws_secret_access_key", "AWS secret access key", r#"(?i)aws_?secret_?access_?key["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})"#, 1, "high"),
            p("github_token", "GitHub token", r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 0, "high"),
            p("gitlab_token", "GitLab token", r"glpat-[A-Za-z0-9_\-]{20,}\b", 0, "high"),
            p("slack_token", "Slack token", r"xox[abposr]-[A-Za-z0-9\-]{10,}\b", 0, "high"),
            p("stripe_key", "Stripe key", r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0, "high"),
            p("google_api_key", "Google API key", r"AIza[0-9A-Za-z_\-]{35}\b", 0, "high"),
            p("huggingface_token", "Hugging Face token", r"hf_[A-Za-z0-9]{30,}\b", 0, "high"),
            p("npm_token", "npm token", r"npm_[A-Za-z0-9]{36}\b", 0, "high"),
            p("npm_auth", "npm _authToken", r"(?i)_auth(?:Token)?\s*=\s*([^\s]{8,})", 1, "high"),
            p("jwt", "JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 0, "high"),
            p("azure_storage_key", "Azure storage account key", r"(?i)AccountKey=([A-Za-z0-9+/=]{40,})", 1, "high"),
            p("connection_string_password", "Connection string password", r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@]+:([^\s@/]{3,})@", 1, "high"),
            p("password_in_conn", "Password= in connection string", r"(?i)\b(?:password|pwd)=([^;\s'\x22]{4,})", 1, "medium"),
            p("bearer_token", "Bearer token", r"(?i)\bbearer\s+([A-Za-z0-9._~+/\-]{20,}=*)", 1, "medium"),
            p("basic_auth_url", "Credentials in URL", r"\bhttps?://[^\s:/@]+:([^\s@/]{3,})@", 1, "medium"),
            p("docker_auth", "Docker registry auth", r#""auth"\s*:\s*"([A-Za-z0-9+/=]{12,})""#, 1, "high"),
            p("generic_secret_assignment", "Secret-looking assignment", r#"(?i)\b[A-Z0-9_.\-]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|AUTH_?KEY|CREDENTIALS?)[A-Z0-9_.\-]*["']?\s*[=:]\s*["']?([^\s"'`,;]{8,})"#, 1, "medium"),
        ]
    })
}

fn entropy_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_\-]{32,}={0,2}").unwrap_or_else(|e| panic!("{e}")))
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_like_placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    l.starts_with("${")
        || l.starts_with("$(")
        || l.starts_with('<')
        || l.starts_with("{{")
        || l.starts_with('%')
        || l.contains("example")
        || l.contains("changeme")
        || l.contains("placeholder")
        || l.contains("your_")
        || l.contains("your-")
        || l.contains("xxxx")
        || l.contains("****")
        || l.contains("[redacted")
        || l == "null"
        || l == "none"
        || l == "true"
        || l == "false"
        || l.starts_with("process.env")
        || l.starts_with("env(")
        || l.starts_with("os.environ")
        || l.starts_with("getenv")
}

/// Redacts secrets from text and JSON. Cheap to clone; holds only the fingerprint key.
#[derive(Clone)]
pub struct Redactor {
    key: [u8; 32],
    /// Enable the low-confidence entropy detector.
    pub entropy: bool,
}

impl Redactor {
    /// Create with a per-install fingerprint key.
    pub fn new(key: [u8; 32]) -> Self {
        Redactor { key, entropy: true }
    }

    /// Keyed fingerprint of a secret (first 16 hex chars of SHA-256(key || secret)).
    pub fn fingerprint(&self, secret: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(secret.as_bytes());
        hex::encode(&h.finalize()[..8])
    }

    /// Find secrets without modifying the text.
    pub fn scan(&self, text: &str) -> Vec<SecretMatch> {
        let mut found: Vec<SecretMatch> = Vec::new();
        let overlaps = |found: &[SecretMatch], s: usize, e: usize| {
            found.iter().any(|m| s < m.end && e > m.start)
        };
        for p in patterns() {
            for caps in p.re.captures_iter(text) {
                let Some(m) = caps.get(p.group) else { continue };
                let value = m.as_str();
                if p.group != 0 || p.kind == "generic_secret_assignment" {
                    if looks_like_placeholder(value) {
                        continue;
                    }
                    if p.kind == "generic_secret_assignment" && shannon_entropy(value) < 2.5 {
                        continue;
                    }
                }
                if overlaps(&found, m.start(), m.end()) {
                    continue;
                }
                found.push(SecretMatch {
                    kind: p.kind,
                    name: p.name,
                    start: m.start(),
                    end: m.end(),
                    confidence: p.confidence,
                    fingerprint: self.fingerprint(value),
                });
            }
        }
        if self.entropy {
            for m in entropy_re().find_iter(text) {
                let v = m.as_str();
                if overlaps(&found, m.start(), m.end()) || looks_like_placeholder(v) {
                    continue;
                }
                let has_upper = v.chars().any(|c| c.is_ascii_uppercase());
                let has_lower = v.chars().any(|c| c.is_ascii_lowercase());
                let has_digit = v.chars().any(|c| c.is_ascii_digit());
                // Paths and identifiers made of words are not secrets.
                let separators = v.chars().filter(|c| matches!(c, '/' | '-' | '_')).count();
                if has_upper
                    && has_lower
                    && has_digit
                    && separators <= 2
                    && shannon_entropy(v) >= 4.3
                {
                    found.push(SecretMatch {
                        kind: "high_entropy_string",
                        name: "High-entropy string (possible secret)",
                        start: m.start(),
                        end: m.end(),
                        confidence: "low",
                        fingerprint: self.fingerprint(v),
                    });
                }
            }
        }
        found.sort_by_key(|m| m.start);
        found
    }

    /// Redact all secrets in `text`.
    pub fn redact(&self, text: &str) -> (String, Vec<SecretMatch>) {
        let matches = self.scan(text);
        if matches.is_empty() {
            return (text.to_string(), matches);
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in &matches {
            out.push_str(&text[last..m.start]);
            out.push_str(&format!("[REDACTED:{}:{}]", m.kind, m.fingerprint));
            last = m.end;
        }
        out.push_str(&text[last..]);
        (out, matches)
    }

    /// Redact a JSON value recursively. Values of keys that are obviously sensitive
    /// (`password`, `token`, `authorization`, ...) are replaced entirely.
    pub fn redact_json(&self, value: &serde_json::Value) -> (serde_json::Value, Vec<SecretMatch>) {
        let mut all = Vec::new();
        let v = self.redact_json_inner(value, &mut all, 0);
        (v, all)
    }

    fn redact_json_inner(
        &self,
        value: &serde_json::Value,
        all: &mut Vec<SecretMatch>,
        depth: usize,
    ) -> serde_json::Value {
        use serde_json::Value;
        if depth > 64 {
            return Value::String("[TRUNCATED:depth]".into());
        }
        match value {
            Value::String(s) => {
                let (r, m) = self.redact(s);
                all.extend(m);
                Value::String(r)
            }
            Value::Array(a) => Value::Array(
                a.iter()
                    .map(|v| self.redact_json_inner(v, all, depth + 1))
                    .collect(),
            ),
            Value::Object(o) => {
                let mut out = serde_json::Map::new();
                for (k, v) in o {
                    if is_sensitive_key(k) && !v.is_null() && !v.is_boolean() {
                        let raw = match v {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        if !raw.is_empty() && !looks_like_placeholder(&raw) {
                            let fp = self.fingerprint(&raw);
                            all.push(SecretMatch {
                                kind: "sensitive_field",
                                name: "Sensitive field",
                                start: 0,
                                end: 0,
                                confidence: "medium",
                                fingerprint: fp.clone(),
                            });
                            out.insert(
                                k.clone(),
                                Value::String(format!("[REDACTED:sensitive_field:{fp}]")),
                            );
                            continue;
                        }
                    }
                    out.insert(k.clone(), self.redact_json_inner(v, all, depth + 1));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
}

/// Keys whose values are always treated as secrets.
pub fn is_sensitive_key(k: &str) -> bool {
    let l = k.to_ascii_lowercase().replace(['-', '.'], "_");
    const EXACT: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "set_cookie",
        "private_key",
        "client_secret",
        "session_token",
        "x_api_key",
        "auth_token",
        "bearer",
        "passphrase",
        "secret_key",
        "aws_secret_access_key",
    ];
    EXACT.contains(&l.as_str())
        || l.ends_with("_password")
        || l.ends_with("_secret")
        || l.ends_with("_token")
        || l.ends_with("_api_key")
        || l.ends_with("_apikey")
}

/// Truncate text to `max` bytes on a char boundary, appending a marker.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… [+{} bytes]", &s[..cut], s.len() - cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new([7u8; 32])
    }

    // All values below are synthetic test credentials (not real).
    const FAKE_GH: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    const FAKE_AWS_ID: &str = "AKIAABCDEFGHIJKLMNOP";
    const FAKE_ANT: &str = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const FAKE_OAI: &str = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";

    #[test]
    fn provider_tokens_are_redacted() {
        for (secret, kind) in [
            (FAKE_GH, "github_token"),
            (FAKE_AWS_ID, "aws_access_key_id"),
            (FAKE_ANT, "anthropic_api_key"),
            (FAKE_OAI, "openai_api_key"),
            ("xoxb-1234567890-abcdefghij", "slack_token"),
            ("sk_test_ABCDEFGHIJKLMNOP1234", "stripe_key"),
            ("glpat-ABCDEFGHIJKLMNOPQRST", "gitlab_token"),
        ] {
            let text = format!("export X={secret} && run");
            let (out, m) = r().redact(&text);
            assert!(!out.contains(secret), "{kind} leaked: {out}");
            assert!(
                m.iter().any(|x| x.kind == kind),
                "{kind} not detected: {m:?}"
            );
        }
    }

    #[test]
    fn private_key_block() {
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfakefakefake\n-----END OPENSSH PRIVATE KEY-----";
        let (out, m) = r().redact(text);
        assert_eq!(m[0].kind, "private_key");
        assert!(!out.contains("fakefake"));
    }

    #[test]
    fn connection_string_password_only() {
        let (out, _) = r().redact("DATABASE_URL=postgres://app:S3cr3tPw@db.local:5432/app");
        assert!(!out.contains("S3cr3tPw"));
        assert!(out.contains("db.local"));
    }

    #[test]
    fn generic_assignment_and_placeholders() {
        let (out, m) = r().redact("DB_PASSWORD=Xk9#mQ2!vL7p");
        assert!(!out.contains("Xk9#mQ2!vL7p"), "{out}");
        assert_eq!(m.len(), 1);
        for ph in [
            "API_KEY=${API_KEY}",
            "PASSWORD=changeme123",
            "TOKEN=<your-token-here>",
            "SECRET_KEY=process.env.SECRET",
        ] {
            let (o, m) = r().redact(ph);
            assert!(m.is_empty(), "placeholder flagged: {ph} -> {o}");
        }
    }

    #[test]
    fn jwt_and_bearer() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (out, _) = r().redact(&format!("Authorization: Bearer {jwt}"));
        assert!(!out.contains("dBjftJeZ4CVP"));
    }

    #[test]
    fn entropy_detector_ignores_paths_and_hashes() {
        let red = r();
        assert!(
            red.scan("C:/Users/erik/projects/agentshield/crates/secret-detector/src")
                .is_empty()
        );
        assert!(
            red.scan("commit 3f786850e387550fdab836ed7e6dc881de23001b")
                .is_empty()
        );
        let m = red.scan("value Zx8Qp2LmN7vR4tY9wK3sJ6hF1dG5bC0aXeUoIi");
        assert!(m.iter().any(|x| x.kind == "high_entropy_string"));
    }

    #[test]
    fn fingerprint_is_stable_and_keyed() {
        let a = Redactor::new([1u8; 32]);
        let b = Redactor::new([2u8; 32]);
        assert_eq!(a.fingerprint("x"), a.fingerprint("x"));
        assert_ne!(a.fingerprint("x"), b.fingerprint("x"));
        assert_eq!(a.fingerprint("x").len(), 16);
    }

    #[test]
    fn json_redaction() {
        let v = serde_json::json!({
            "command": format!("curl -H 'Authorization: token {FAKE_GH}' https://api.github.com"),
            "headers": {"Authorization": "Basic dXNlcjpwYXNz", "accept": "json"},
            "password": "hunter2hunter2",
            "nested": [{"api_key": "abcdef123456"}],
            "enabled": true
        });
        let (out, m) = r().redact_json(&v);
        let s = out.to_string();
        assert!(!s.contains(FAKE_GH));
        assert!(!s.contains("hunter2"));
        assert!(!s.contains("dXNlcjpwYXNz"));
        assert!(!s.contains("abcdef123456"));
        assert!(s.contains("\"accept\":\"json\""));
        assert!(m.len() >= 4);
    }

    #[test]
    fn truncate_is_char_safe() {
        let s = "é".repeat(100);
        let t = truncate(&s, 5);
        assert!(t.starts_with("éé"));
    }

    proptest::proptest! {
        #[test]
        fn redact_never_panics(s in "\\PC{0,300}") {
            let _ = r().redact(&s);
        }
        #[test]
        fn redacted_output_never_contains_github_token(prefix in "[a-z =:]{0,20}", suffix in "[a-z ]{0,20}") {
            let text = format!("{prefix}{FAKE_GH}{suffix}");
            let (out, _) = r().redact(&text);
            proptest::prop_assert!(!out.contains(FAKE_GH));
        }
    }
}
