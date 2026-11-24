//! Blocking client (used by the hook, the CLI and the desktop backend).
//!
//! The hook must never hang an agent: callers wrap requests in [`call_with_timeout`],
//! which runs the exchange on a helper thread and gives up after the deadline.

use crate::{
    AuthResult, ClientAuth, ClientHello, IpcError, MAX_FRAME, Method, PROTOCOL_VERSION, Push,
    Request, Response, ServerHello, endpoint, new_nonce, proof, token_path, verify_proof,
};
use serde::de::DeserializeOwned;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

#[cfg(unix)]
type Stream = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Stream = std::fs::File;

pub struct Client {
    reader: BufReader<Stream>,
    writer: Stream,
    next_id: u64,
    pub server_version: String,
}

fn open_stream(data_dir: &Path) -> Result<Stream, IpcError> {
    let ep = endpoint(data_dir);
    #[cfg(unix)]
    {
        Stream::connect(&ep).map_err(|e| IpcError::Unavailable(format!("{}: {e}", ep.display())))
    }
    #[cfg(windows)]
    {
        // ERROR_PIPE_BUSY (231): all instances busy. ERROR_FILE_NOT_FOUND (2): the server is
        // between accepting a client and creating the next instance (or not running).
        // Retry briefly; keep the not-found budget small so a stopped daemon costs ~50 ms.
        let mut last = None;
        let mut not_found = 0;
        for _ in 0..40 {
            match std::fs::OpenOptions::new().read(true).write(true).open(&ep) {
                Ok(f) => return Ok(f),
                Err(e) if e.raw_os_error() == Some(231) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) if e.raw_os_error() == Some(2) && not_found < 10 => {
                    not_found += 1;
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(IpcError::Unavailable(format!("{}: {e}", ep.display()))),
            }
        }
        Err(IpcError::Unavailable(format!(
            "{}: {}",
            ep.display(),
            last.map(|e| e.to_string()).unwrap_or_default()
        )))
    }
}

/// Open a raw, unauthenticated stream (tests / diagnostics only).
#[doc(hidden)]
pub fn open_raw(data_dir: &Path) -> Result<Stream, IpcError> {
    open_stream(data_dir)
}

fn read_frame<R: BufRead>(r: &mut R) -> Result<Vec<u8>, IpcError> {
    let mut buf = Vec::new();
    let n = r
        .by_ref()
        .take(MAX_FRAME as u64 + 1)
        .read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Err(IpcError::Unavailable("connection closed".into()));
    }
    if buf.last() != Some(&b'\n') {
        return Err(IpcError::Protocol("frame too large or truncated".into()));
    }
    buf.pop();
    Ok(buf)
}

fn write_frame<W: Write, T: serde::Serialize>(w: &mut W, v: &T) -> Result<(), IpcError> {
    let mut s = serde_json::to_vec(v)?;
    if s.len() > MAX_FRAME {
        return Err(IpcError::Protocol("request too large".into()));
    }
    s.push(b'\n');
    w.write_all(&s)?;
    w.flush()?;
    Ok(())
}

impl Client {
    /// Connect and authenticate (server proves knowledge of the token first).
    pub fn connect(data_dir: &Path, client_name: &str) -> Result<Client, IpcError> {
        let token = std::fs::read_to_string(token_path(data_dir)).map_err(|e| {
            IpcError::Unavailable(format!("no daemon token ({e}); is the daemon running?"))
        })?;
        let token = token.trim().to_string();
        let stream = open_stream(data_dir)?;
        #[cfg(unix)]
        let writer = stream.try_clone()?;
        #[cfg(windows)]
        let writer = stream.try_clone()?;
        let mut c = Client {
            reader: BufReader::new(stream),
            writer,
            next_id: 1,
            server_version: String::new(),
        };
        let cn = new_nonce()?;
        write_frame(
            &mut c.writer,
            &ClientHello {
                v: PROTOCOL_VERSION,
                client: client_name.chars().take(64).collect(),
                nonce: cn.clone(),
            },
        )?;
        let sh: ServerHello = serde_json::from_slice(&read_frame(&mut c.reader)?)?;
        if sh.v != PROTOCOL_VERSION {
            return Err(IpcError::Protocol(format!(
                "protocol version mismatch: daemon {}, client {PROTOCOL_VERSION}",
                sh.v
            )));
        }
        if !verify_proof(&token, "server", &cn, &sh.nonce, &sh.proof) {
            return Err(IpcError::Auth(
                "daemon could not prove knowledge of the token (wrong daemon or squatted endpoint)"
                    .into(),
            ));
        }
        write_frame(
            &mut c.writer,
            &ClientAuth {
                proof: proof(&token, "client", &cn, &sh.nonce),
            },
        )?;
        let ar: AuthResult = serde_json::from_slice(&read_frame(&mut c.reader)?)?;
        if !ar.ok {
            return Err(IpcError::Auth(
                ar.error.unwrap_or_else(|| "rejected".into()),
            ));
        }
        c.server_version = sh.server_version;
        Ok(c)
    }

    /// Send one request and wait for its response.
    pub fn call_raw(&mut self, method: Method) -> Result<serde_json::Value, IpcError> {
        let id = self.next_id;
        self.next_id += 1;
        write_frame(&mut self.writer, &Request { id, method })?;
        let resp: Response = serde_json::from_slice(&read_frame(&mut self.reader)?)?;
        if resp.id != id {
            return Err(IpcError::Protocol(format!(
                "response id {} != request id {id}",
                resp.id
            )));
        }
        if resp.ok {
            Ok(resp.result)
        } else {
            let e = resp.error.unwrap_or(crate::ErrorBody {
                code: "internal".into(),
                message: "unknown error".into(),
            });
            Err(IpcError::Remote {
                code: e.code,
                message: e.message,
            })
        }
    }

    pub fn call<T: DeserializeOwned>(&mut self, method: Method) -> Result<T, IpcError> {
        Ok(serde_json::from_value(self.call_raw(method)?)?)
    }

    /// Read the next pushed message on a subscription connection.
    pub fn next_push(&mut self) -> Result<Push, IpcError> {
        Ok(serde_json::from_slice(&read_frame(&mut self.reader)?)?)
    }
}

/// Connect + call on a helper thread with an overall deadline.
pub fn call_with_timeout<T: DeserializeOwned + Send + 'static>(
    data_dir: &Path,
    client_name: &str,
    method: Method,
    timeout: Duration,
) -> Result<T, IpcError> {
    let (tx, rx) = std::sync::mpsc::channel();
    let dir = data_dir.to_path_buf();
    let name = client_name.to_string();
    std::thread::Builder::new()
        .name("agentshield-ipc".into())
        .spawn(move || {
            let r = Client::connect(&dir, &name).and_then(|mut c| c.call::<T>(method));
            let _ = tx.send(r);
        })
        .map_err(IpcError::Io)?;
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err(IpcError::Unavailable(format!(
            "daemon did not answer within {} ms",
            timeout.as_millis()
        ))),
    }
}
