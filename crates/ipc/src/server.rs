//! Async server (daemon side).

use crate::{
    AuthResult, ClientAuth, ClientHello, ErrorBody, MAX_FRAME, Method, PROTOCOL_VERSION, Push,
    Request, Response, ServerHello, endpoint, new_nonce, proof, verify_proof,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Semaphore, broadcast};

/// Error returned by a handler.
#[derive(Debug, Clone)]
pub struct HandlerError {
    pub code: &'static str,
    pub message: String,
}

impl HandlerError {
    pub fn bad_request(m: impl Into<String>) -> Self {
        HandlerError {
            code: "bad_request",
            message: m.into(),
        }
    }
    pub fn not_found(m: impl Into<String>) -> Self {
        HandlerError {
            code: "not_found",
            message: m.into(),
        }
    }
    pub fn internal(m: impl Into<String>) -> Self {
        HandlerError {
            code: "internal",
            message: m.into(),
        }
    }
}

/// Request handler. `handle` runs on a blocking thread (it may do SQLite I/O).
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, method: Method, client: &str) -> Result<serde_json::Value, HandlerError>;
    /// Backlog (id > after_id, ascending) and a live receiver.
    fn subscribe(
        &self,
        after_id: i64,
    ) -> Result<
        (
            Vec<serde_json::Value>,
            broadcast::Receiver<serde_json::Value>,
        ),
        HandlerError,
    >;
    /// Called when a `Shutdown` request was accepted.
    fn shutdown_requested(&self) {}
}

pub struct ServerConfig {
    pub data_dir: PathBuf,
    pub token: String,
    pub server_version: String,
    /// Max concurrent blocking handler calls.
    pub max_inflight: usize,
    /// Per-connection request rate (requests per second).
    pub max_rps: u32,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
}

impl ServerConfig {
    pub fn new(data_dir: &Path, token: String, server_version: &str) -> Self {
        ServerConfig {
            data_dir: data_dir.to_path_buf(),
            token,
            server_version: server_version.to_string(),
            max_inflight: 64,
            max_rps: 400,
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    let n = r
        .take(MAX_FRAME as u64 + 1)
        .read_until(b'\n', &mut buf)
        .await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large or truncated",
        ));
    }
    buf.pop();
    Ok(Some(buf))
}

async fn write_frame<W: AsyncWrite + Unpin, T: serde::Serialize>(
    w: &mut W,
    v: &T,
) -> std::io::Result<()> {
    let mut s = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    s.push(b'\n');
    w.write_all(&s).await?;
    w.flush().await
}

struct Shared {
    cfg: ServerConfig,
    handler: Arc<dyn Handler>,
    inflight: Semaphore,
}

async fn serve_conn<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    shared: Arc<Shared>,
) {
    let (r, mut w) = tokio::io::split(stream);
    let mut r = BufReader::new(r);
    // --- handshake --------------------------------------------------------------------
    let hs = tokio::time::timeout(shared.cfg.handshake_timeout, async {
        let hello: ClientHello = serde_json::from_slice(
            &read_frame(&mut r)
                .await?
                .ok_or_else(|| std::io::Error::other("closed"))?,
        )
        .map_err(std::io::Error::other)?;
        let sn = new_nonce().map_err(std::io::Error::other)?;
        if hello.v != PROTOCOL_VERSION {
            write_frame(
                &mut w,
                &ServerHello {
                    v: PROTOCOL_VERSION,
                    nonce: sn,
                    proof: String::new(),
                    server_version: shared.cfg.server_version.clone(),
                },
            )
            .await?;
            return Err(std::io::Error::other("version mismatch"));
        }
        if hello.nonce.len() < 16 || hello.nonce.len() > 128 {
            return Err(std::io::Error::other("bad nonce"));
        }
        let p = proof(&shared.cfg.token, "server", &hello.nonce, &sn);
        write_frame(
            &mut w,
            &ServerHello {
                v: PROTOCOL_VERSION,
                nonce: sn.clone(),
                proof: p,
                server_version: shared.cfg.server_version.clone(),
            },
        )
        .await?;
        let auth: ClientAuth = serde_json::from_slice(
            &read_frame(&mut r)
                .await?
                .ok_or_else(|| std::io::Error::other("closed"))?,
        )
        .map_err(std::io::Error::other)?;
        if !verify_proof(&shared.cfg.token, "client", &hello.nonce, &sn, &auth.proof) {
            write_frame(
                &mut w,
                &AuthResult {
                    ok: false,
                    error: Some("bad proof".into()),
                },
            )
            .await?;
            return Err(std::io::Error::other("auth failed"));
        }
        write_frame(
            &mut w,
            &AuthResult {
                ok: true,
                error: None,
            },
        )
        .await?;
        Ok::<String, std::io::Error>(hello.client)
    })
    .await;
    let client = match hs {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            tracing::debug!("handshake failed: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("handshake timeout");
            return;
        }
    };
    // --- request loop -----------------------------------------------------------------
    let mut window_start = Instant::now();
    let mut window_count = 0u32;
    loop {
        let frame = match tokio::time::timeout(shared.cfg.idle_timeout, read_frame(&mut r)).await {
            Ok(Ok(Some(f))) => f,
            _ => return,
        };
        let req: Request = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_frame(
                    &mut w,
                    &Response {
                        id: 0,
                        ok: false,
                        result: serde_json::Value::Null,
                        error: Some(ErrorBody {
                            code: "bad_request".into(),
                            message: format!("invalid request: {e}"),
                        }),
                    },
                )
                .await;
                return;
            }
        };
        if window_start.elapsed() >= Duration::from_secs(1) {
            window_start = Instant::now();
            window_count = 0;
        }
        window_count += 1;
        if window_count > shared.cfg.max_rps {
            let _ = write_frame(
                &mut w,
                &Response {
                    id: req.id,
                    ok: false,
                    result: serde_json::Value::Null,
                    error: Some(ErrorBody {
                        code: "rate_limited".into(),
                        message: "too many requests".into(),
                    }),
                },
            )
            .await;
            continue;
        }
        if let Method::Subscribe { after_id } = req.method {
            let handler = shared.handler.clone();
            let sub = tokio::task::spawn_blocking(move || handler.subscribe(after_id)).await;
            let (backlog, mut rx) = match sub {
                Ok(Ok(x)) => x,
                Ok(Err(e)) => {
                    let _ = write_frame(
                        &mut w,
                        &Response {
                            id: req.id,
                            ok: false,
                            result: serde_json::Value::Null,
                            error: Some(ErrorBody {
                                code: e.code.into(),
                                message: e.message,
                            }),
                        },
                    )
                    .await;
                    return;
                }
                Err(_) => return,
            };
            if write_frame(
                &mut w,
                &Response {
                    id: req.id,
                    ok: true,
                    result: serde_json::json!({ "subscribed": true }),
                    error: None,
                },
            )
            .await
            .is_err()
            {
                return;
            }
            for row in backlog {
                if write_frame(&mut w, &Push::Event { row }).await.is_err() {
                    return;
                }
            }
            loop {
                let msg = tokio::time::timeout(Duration::from_secs(15), rx.recv()).await;
                let push = match msg {
                    Ok(Ok(row)) => Push::Event { row },
                    Ok(Err(broadcast::error::RecvError::Lagged(n))) => Push::Lagged { skipped: n },
                    Ok(Err(broadcast::error::RecvError::Closed)) => return,
                    Err(_) => Push::Heartbeat,
                };
                if write_frame(&mut w, &push).await.is_err() {
                    return;
                }
            }
        }
        let is_shutdown = matches!(req.method, Method::Shutdown { .. });
        let permit =
            match tokio::time::timeout(Duration::from_secs(2), shared.inflight.acquire()).await {
                Ok(Ok(p)) => p,
                _ => {
                    let _ = write_frame(
                        &mut w,
                        &Response {
                            id: req.id,
                            ok: false,
                            result: serde_json::Value::Null,
                            error: Some(ErrorBody {
                                code: "busy".into(),
                                message: "daemon overloaded".into(),
                            }),
                        },
                    )
                    .await;
                    continue;
                }
            };
        let handler = shared.handler.clone();
        let cname = client.clone();
        let method = req.method;
        let res = tokio::task::spawn_blocking(move || handler.handle(method, &cname)).await;
        drop(permit);
        let resp = match res {
            Ok(Ok(v)) => Response {
                id: req.id,
                ok: true,
                result: v,
                error: None,
            },
            Ok(Err(e)) => Response {
                id: req.id,
                ok: false,
                result: serde_json::Value::Null,
                error: Some(ErrorBody {
                    code: e.code.into(),
                    message: e.message,
                }),
            },
            Err(e) => Response {
                id: req.id,
                ok: false,
                result: serde_json::Value::Null,
                error: Some(ErrorBody {
                    code: "internal".into(),
                    message: format!("handler panicked: {e}"),
                }),
            },
        };
        let ok = resp.ok;
        if write_frame(&mut w, &resp).await.is_err() {
            return;
        }
        if is_shutdown && ok {
            shared.handler.shutdown_requested();
            return;
        }
    }
}

/// Run the server until `shutdown` resolves.
pub async fn serve(
    cfg: ServerConfig,
    handler: Arc<dyn Handler>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    let ep = endpoint(&cfg.data_dir);
    let shared = Arc::new(Shared {
        inflight: Semaphore::new(cfg.max_inflight),
        cfg,
        handler,
    });
    tokio::pin!(shutdown);
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let name = ep.to_string_lossy().into_owned();
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot create pipe {name} (another daemon running or name squatted?): {e}"
                    ),
                )
            })?;
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                res = server.connect() => {
                    res?;
                    let connected = server;
                    server = ServerOptions::new().reject_remote_clients(true).create(&name)?;
                    let s = shared.clone();
                    tokio::spawn(async move { serve_conn(connected, s).await });
                }
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = ep.parent() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        if ep.exists() {
            // Stale socket? Only remove it if nobody is listening.
            if std::os::unix::net::UnixStream::connect(&ep).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("{} is in use (daemon already running?)", ep.display()),
                ));
            }
            std::fs::remove_file(&ep)?;
        }
        let listener = tokio::net::UnixListener::bind(&ep)?;
        std::fs::set_permissions(&ep, std::fs::Permissions::from_mode(0o600))?;
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    let _ = std::fs::remove_file(&ep);
                    return Ok(());
                }
                res = listener.accept() => {
                    let (stream, _) = res?;
                    let s = shared.clone();
                    tokio::spawn(async move { serve_conn(stream, s).await });
                }
            }
        }
    }
}
