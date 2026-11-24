//! Wire messages.

use agentshield_audit_log::EventQuery;
use agentshield_event_model::Mode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientHello {
    pub v: u32,
    pub client: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerHello {
    pub v: u32,
    pub nonce: String,
    /// HMAC(token, "server" | client_nonce | server_nonce)
    pub proof: String,
    pub server_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientAuth {
    /// HMAC(token, "client" | client_nonce | server_nonce)
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthResult {
    pub ok: bool,
    pub error: Option<String>,
}

/// All daemon methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Method {
    Ping,
    Status,
    /// Raw hook payload from an agent adapter. `hook_event` is the CLI hint (optional).
    Hook {
        agent: String,
        hook_event: Option<String>,
        payload: serde_json::Value,
    },
    ListEvents {
        query: EventQuery,
    },
    GetEvent {
        id: i64,
    },
    /// Number of events matching a query (export previews, pagination).
    CountEvents {
        query: EventQuery,
    },
    /// One session summary by id, regardless of age.
    GetSession {
        session_id: String,
    },
    Stats {
        window_hours: u32,
    },
    Sessions {
        limit: u32,
    },
    Incidents {
        limit: u32,
    },
    SetMode {
        mode: Mode,
        actor: String,
    },
    SetPreset {
        preset: String,
        actor: String,
    },
    SetPaused {
        paused: bool,
        actor: String,
    },
    GetConfig,
    SetConfig {
        patch: serde_json::Value,
    },
    PolicyInfo,
    ValidatePolicy {
        text: String,
    },
    SaveUserPolicy {
        text: String,
    },
    Simulate {
        input: serde_json::Value,
    },
    Replay {
        preset: String,
        session_id: Option<String>,
        limit: u32,
    },
    Verify,
    Backup,
    DeleteSession {
        session_id: String,
    },
    /// Privacy deletion of specific events (recorded as a chain break, residue purged).
    DeleteEvents {
        ids: Vec<i64>,
    },
    DeleteAll,
    ApplyRetention,
    /// Tool definitions seen by the MCP proxy in a `tools/list` response. Returns
    /// [`McpToolsVerdict`].
    McpTools {
        server: String,
        tools: Vec<McpToolDef>,
    },
    /// Accept the current tool definitions of a server (re-pin after a reviewed change).
    McpTrust {
        server: String,
        actor: String,
    },
    /// MCP servers from Claude Code config + observed MCP calls + change tracking.
    McpServers,
    /// Write a redacted export to the exports directory; returns `{path, count}`.
    Export {
        format: String,
        query: EventQuery,
    },
    /// Write an HTML report to the exports directory; returns `{path, title}`.
    Report {
        kind: String,
        window_hours: u32,
    },
    /// Stream: backlog (id > after_id) then live events. Connection is dedicated afterwards.
    Subscribe {
        after_id: i64,
    },
    Shutdown {
        actor: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    /// Input schema serialized as JSON text.
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct McpToolsVerdict {
    /// Tools the proxy must hide from `tools/list` and refuse in `tools/call`.
    pub blocked: Vec<String>,
    /// (tool, reason) for every flagged tool, blocked or not.
    pub flagged: Vec<(String, String)>,
    pub event_id: i64,
    pub enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub id: u64,
    #[serde(flatten)]
    pub method: Method,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorBody {
    /// `bad_request`, `not_found`, `busy`, `rate_limited`, `internal`, `forbidden`
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default)]
    pub error: Option<ErrorBody>,
}

/// Pushed on a subscription connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Push {
    Event {
        row: serde_json::Value,
    },
    /// The subscriber fell behind; re-fetch with `ListEvents { after_id }`.
    Lagged {
        skipped: u64,
    },
    Heartbeat,
}

/// Reply to a `Hook` request: exactly what the hook process must print/exit with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HookReply {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: i32,
    pub event_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LatencySummary {
    pub count: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
}

impl LatencySummary {
    pub fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut v = samples.to_vec();
        v.sort_unstable();
        let pick = |q: usize| v[((v.len() - 1) * q) / 100];
        LatencySummary {
            count: v.len() as u64,
            p50_us: pick(50),
            p95_us: pick(95),
            p99_us: pick(99),
            max_us: *v.last().unwrap_or(&0),
        }
    }
}
