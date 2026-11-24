use super::*;
use crate::server::{Handler, HandlerError, ServerConfig, serve};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

struct Echo {
    tx: broadcast::Sender<serde_json::Value>,
}

impl Handler for Echo {
    fn handle(&self, method: Method, client: &str) -> Result<serde_json::Value, HandlerError> {
        match method {
            Method::Ping => Ok(serde_json::json!({ "pong": true, "client": client })),
            Method::GetEvent { id } if id < 0 => Err(HandlerError::bad_request("negative id")),
            Method::GetEvent { id } => {
                let _ = self.tx.send(serde_json::json!({ "id": id }));
                Ok(serde_json::json!({ "id": id }))
            }
            _ => Err(HandlerError::not_found("unsupported in test")),
        }
    }
    fn subscribe(
        &self,
        after_id: i64,
    ) -> Result<
        (
            Vec<serde_json::Value>,
            broadcast::Receiver<serde_json::Value>,
        ),
        HandlerError,
    > {
        Ok((
            vec![serde_json::json!({ "backlog_after": after_id })],
            self.tx.subscribe(),
        ))
    }
}

fn start(dir: &std::path::Path, token: &str) -> tokio::sync::oneshot::Sender<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(token_path(dir), token).unwrap();
    let cfg = ServerConfig::new(dir, token.to_string(), "test");
    let (tx, _) = broadcast::channel(16);
    let handler: Arc<dyn Handler> = Arc::new(Echo { tx });
    tokio::spawn(async move {
        serve(cfg, handler, async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });
    stop_tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roundtrip_auth_errors_and_subscribe() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let stop = start(&data, &new_token().unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let d = data.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(&d, "test-client").unwrap();
        let v = c.call_raw(Method::Ping).unwrap();
        assert_eq!(v["client"], "test-client");
        match c.call_raw(Method::GetEvent { id: -1 }) {
            Err(IpcError::Remote { code, .. }) => assert_eq!(code, "bad_request"),
            other => panic!("{other:?}"),
        }
        // connection still usable after an error
        assert_eq!(c.call_raw(Method::GetEvent { id: 7 }).unwrap()["id"], 7);
        // timeout helper
        let v: serde_json::Value =
            client::call_with_timeout(&d, "t", Method::Ping, Duration::from_secs(2)).unwrap();
        assert_eq!(v["pong"], true);
        // subscription: backlog then live
        let mut sub = Client::connect(&d, "sub").unwrap();
        sub.call_raw(Method::Subscribe { after_id: 5 }).unwrap();
        match sub.next_push().unwrap() {
            Push::Event { row } => assert_eq!(row["backlog_after"], 5),
            other => panic!("{other:?}"),
        }
        let mut c2 = Client::connect(&d, "x").unwrap();
        c2.call_raw(Method::GetEvent { id: 42 }).unwrap();
        match sub.next_push().unwrap() {
            Push::Event { row } => assert_eq!(row["id"], 42),
            other => panic!("{other:?}"),
        }
    })
    .await
    .unwrap();
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_token_is_rejected_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let stop = start(&data, &new_token().unwrap());
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Client with a different token: the *server* proof fails client-side.
    std::fs::write(token_path(&data), new_token().unwrap()).unwrap();
    let d = data.clone();
    let r = tokio::task::spawn_blocking(move || Client::connect(&d, "evil").map(|_| ()))
        .await
        .unwrap();
    assert!(matches!(r, Err(IpcError::Auth(_))), "{r:?}");
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_and_oversized_frames_do_not_crash_server() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    let token = new_token().unwrap();
    let stop = start(&data, &token);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let d = data.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut raw = client::open_raw(&d).unwrap();
        let _ = raw.write_all(
            b"this is not json
",
        );
        drop(raw);
        let mut raw2 = client::open_raw(&d).unwrap();
        let big = vec![b'a'; MAX_FRAME + 10];
        let _ = raw2.write_all(&big);
        drop(raw2);
        // Server still serves legit clients.
        let mut c = Client::connect(&d, "ok").unwrap();
        assert_eq!(c.call_raw(Method::Ping).unwrap()["pong"], true);
    })
    .await
    .unwrap();
    let _ = stop.send(());
}

#[test]
fn proofs() {
    let t = new_token().unwrap();
    let p = proof(&t, "server", "aa", "bb");
    assert!(verify_proof(&t, "server", "aa", "bb", &p));
    assert!(!verify_proof(&t, "client", "aa", "bb", &p));
    assert!(!verify_proof("other", "server", "aa", "bb", &p));
    assert!(!verify_proof(&t, "server", "aa", "bb", "zz"));
}

#[test]
fn method_wire_format() {
    let r = Request {
        id: 3,
        method: Method::SetMode {
            mode: agentshield_event_model::Mode::Enforce,
            actor: "cli".into(),
        },
    };
    let s = serde_json::to_string(&r).unwrap();
    assert_eq!(
        s,
        r#"{"id":3,"method":"set_mode","params":{"mode":"enforce","actor":"cli"}}"#
    );
    let back: Request = serde_json::from_str(&s).unwrap();
    assert_eq!(back, r);
    let p: Request = serde_json::from_str(r#"{"id":1,"method":"ping"}"#).unwrap();
    assert_eq!(p.method, Method::Ping);
}

#[test]
fn latency_summary() {
    let s = LatencySummary::from_samples(&(1..=100).collect::<Vec<u64>>());
    assert_eq!(s.p50_us, 50);
    assert_eq!(s.p95_us, 95);
    assert_eq!(s.max_us, 100);
    assert_eq!(LatencySummary::from_samples(&[]).count, 0);
}
