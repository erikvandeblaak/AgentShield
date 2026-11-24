//! Local IPC between the hook / CLI / desktop app and the AgentShield daemon.
//!
//! * Transport: Windows named pipe `\\.\pipe\agentshield-<id>` (remote clients rejected,
//!   first-instance only so a squatted name makes the daemon fail loudly) or a Unix domain
//!   socket in a `0700` directory. No TCP listener.
//! * Framing: newline-delimited JSON, at most [`MAX_FRAME`] bytes per frame.
//! * Authentication: mutual HMAC-SHA256 challenge/response over a per-start random token
//!   stored in a user-private file. The token itself never crosses the wire, so a process
//!   that squats the pipe name cannot learn it, and clients verify the server first.
//! * Everything a client *says about itself* (agent name, session, paths) is telemetry,
//!   not an authenticated claim. Only "this peer can read the user's token file" is
//!   authenticated.

pub mod client;
pub mod proto;
pub mod server;

pub use client::Client;
pub use proto::*;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("daemon not reachable: {0}")]
    Unavailable(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("{code}: {message}")]
    Remote { code: String, message: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Endpoint name derived from the data directory, so isolated installs (AGENTSHIELD_HOME)
/// get isolated daemons.
pub fn endpoint(data_dir: &Path) -> PathBuf {
    let id = hex::encode(&Sha256::digest(data_dir.to_string_lossy().as_bytes())[..8]);
    if cfg!(windows) {
        PathBuf::from(format!(r"\\.\pipe\agentshield-{id}"))
    } else {
        data_dir.join("run").join("daemon.sock")
    }
}

pub fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join("daemon.token")
}

/// Generate a fresh random token (hex).
pub fn new_token() -> Result<String, IpcError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| IpcError::Protocol(format!("rng: {e}")))?;
    Ok(hex::encode(b))
}

pub fn new_nonce() -> Result<String, IpcError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| IpcError::Protocol(format!("rng: {e}")))?;
    Ok(hex::encode(b))
}

/// HMAC-SHA256(token, role | client_nonce | server_nonce) as hex.
pub fn proof(token: &str, role: &str, client_nonce: &str, server_nonce: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(role.as_bytes());
    mac.update(b"|");
    mac.update(client_nonce.as_bytes());
    mac.update(b"|");
    mac.update(server_nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time comparison of two hex proofs.
pub fn verify_proof(
    token: &str,
    role: &str,
    client_nonce: &str,
    server_nonce: &str,
    given: &str,
) -> bool {
    let Ok(given) = hex::decode(given) else {
        return false;
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"));
    mac.update(role.as_bytes());
    mac.update(b"|");
    mac.update(client_nonce.as_bytes());
    mac.update(b"|");
    mac.update(server_nonce.as_bytes());
    mac.verify_slice(&given).is_ok()
}

#[cfg(test)]
mod tests;
