use super::*;
use agentshield_event_model::*;

fn rec(i: usize, session: &str, score: u8) -> AuditRecord {
    AuditRecord {
        id: 0,
        uuid: new_uuid(),
        schema_version: EVENT_SCHEMA_VERSION,
        ts_utc: now_rfc3339(),
        agent: "claude-code".into(),
        agent_version: None,
        session_id: Some(session.into()),
        workspace: Some("/w".into()),
        hook_event: "PreToolUse".into(),
        phase: Phase::Pre,
        action_type: "shell.exec".into(),
        tool: Some("Bash".into()),
        summary: format!("cmd {i}"),
        action: ActionKind::ShellExec {
            command: format!("echo {i}"),
            shell: ShellKind::Bash,
        },
        input_redacted: serde_json::json!({"command": format!("echo {i}")}),
        risk: RiskAssessment {
            score,
            level: RiskLevel::from_score(score),
            categories: if score >= 40 {
                vec![RiskCategory::SecretAccess]
            } else {
                vec![]
            },
            ..RiskAssessment::none()
        },
        policy_version: "v1".into(),
        policy_name: "p".into(),
        matched_rules: vec![],
        mode: Mode::Monitor,
        simulated_decision: if score >= 80 {
            PolicyDecision::Deny
        } else {
            PolicyDecision::Allow
        },
        decision_reason: None,
        actual_decision: ActualDecision::NoOpinion,
        outcome: Outcome::Pending,
        coverage: Coverage::Enforceable,
        latency_us: 100,
        correlation_id: Some(format!("tu-{i}")),
        via_daemon: true,
        prev_hash: String::new(),
        hash: String::new(),
    }
}

#[test]
fn insert_list_get() {
    let mut db = AuditLog::open_in_memory().unwrap();
    assert_eq!(db.schema_version().unwrap(), schema::LATEST);
    let mut batch: Vec<_> = (0..10).map(|i| rec(i, "s1", (i * 10) as u8)).collect();
    db.insert_batch(&mut batch).unwrap();
    assert_eq!(batch[0].prev_hash, GENESIS);
    assert_eq!(batch[1].prev_hash, batch[0].hash);
    let all = db.list(&EventQuery::default()).unwrap();
    assert_eq!(all.len(), 10);
    assert!(all[0].record.id > all[9].record.id, "newest first");
    let live = db
        .list(&EventQuery {
            after_id: Some(5),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(live.first().unwrap().record.id, 6);
    let risky = db
        .list(&EventQuery {
            min_score: Some(40),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(risky.len(), 6);
    let cat = db
        .list(&EventQuery {
            category: Some("secret_access".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(cat.len(), 6);
    let search = db
        .list(&EventQuery {
            search: Some("CMD 3".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(search.len(), 1);
    let pct = db
        .list(&EventQuery {
            search: Some("%".into()),
            ..Default::default()
        })
        .unwrap();
    assert!(pct.is_empty(), "LIKE wildcards must be escaped");
    let g = db.get(batch[3].id).unwrap().unwrap();
    assert_eq!(g.record.summary, "cmd 3");
    assert!(db.get(9999).unwrap().is_none());
}

#[test]
fn outcome_correlation() {
    let mut db = AuditLog::open_in_memory().unwrap();
    let mut pre = rec(1, "s", 0);
    db.insert(&mut pre).unwrap();
    let mut post = rec(1, "s", 0);
    post.phase = Phase::Post;
    post.outcome = Outcome::Executed;
    db.insert(&mut post).unwrap();
    let row = db.get(pre.id).unwrap().unwrap();
    assert_eq!(row.observed_outcome, Some(Outcome::Executed));
}

#[test]
fn verify_detects_tampering() {
    let path = tempfile::tempdir().unwrap();
    let file = path.path().join("a.db");
    let mut db = AuditLog::open(&file).unwrap();
    let mut batch: Vec<_> = (0..20).map(|i| rec(i, "s", 10)).collect();
    db.insert_batch(&mut batch).unwrap();
    assert!(db.verify().unwrap().ok);
    // Modify a record's JSON.
    db.connection()
        .execute(
            "UPDATE events SET record_json = replace(record_json, 'cmd 5', 'cmd X') WHERE id = 6",
            [],
        )
        .unwrap();
    let r = db.verify().unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_id, Some(6));
    // Restore & tamper index column instead.
    db.connection()
        .execute(
            "UPDATE events SET record_json = replace(record_json, 'cmd X', 'cmd 5') WHERE id = 6",
            [],
        )
        .unwrap();
    assert!(db.verify().unwrap().ok);
    db.connection()
        .execute(
            "UPDATE events SET risk_score = 0, simulated_decision = 'allow' WHERE id = 7",
            [],
        )
        .unwrap();
    assert!(!db.verify().unwrap().ok);
    db.connection()
        .execute("UPDATE events SET risk_score = 10 WHERE id = 7", [])
        .unwrap();
    assert!(db.verify().unwrap().ok);
    // Silent deletion is detected.
    db.connection()
        .execute("DELETE FROM events WHERE id = 10", [])
        .unwrap();
    let r = db.verify().unwrap();
    assert!(!r.ok);
    assert_eq!(r.first_bad_id, Some(11));
}

#[test]
fn recorded_deletions_are_bridged() {
    let mut db = AuditLog::open_in_memory().unwrap();
    let mut a: Vec<_> = (0..5).map(|i| rec(i, "keep", 0)).collect();
    db.insert_batch(&mut a).unwrap();
    let mut b: Vec<_> = (5..10).map(|i| rec(i, "gone", 0)).collect();
    db.insert_batch(&mut b).unwrap();
    let mut c: Vec<_> = (10..15).map(|i| rec(i, "keep", 0)).collect();
    db.insert_batch(&mut c).unwrap();
    assert_eq!(db.delete_session("gone").unwrap(), 5);
    let r = db.verify().unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.bridged_breaks, 1);
    assert_eq!(db.chain_breaks().unwrap().len(), 1);
    let mut d = rec(99, "keep", 0);
    db.insert(&mut d).unwrap();
    assert!(db.verify().unwrap().ok);
    assert_eq!(db.delete_all().unwrap(), 11);
    assert!(db.verify().unwrap().ok);
    let mut e = rec(100, "x", 0);
    db.insert(&mut e).unwrap();
    assert!(db.verify().unwrap().ok);
}

#[test]
fn stats_and_sessions() {
    let mut db = AuditLog::open_in_memory().unwrap();
    let mut batch: Vec<_> = (0..10)
        .map(|i| rec(i, if i < 5 { "a" } else { "b" }, (i * 10) as u8))
        .collect();
    db.insert_batch(&mut batch).unwrap();
    let s = db.stats(24).unwrap();
    assert_eq!(s.total_events, 10);
    assert_eq!(s.risky_events, 6);
    assert_eq!(s.would_block, 2);
    assert_eq!(s.by_category[0].key, "secret_access");
    assert!(!s.per_minute.is_empty());
    let sess = db.sessions(10).unwrap();
    assert_eq!(sess.len(), 2);
    assert_eq!(
        sess.iter().find(|x| x.session_id == "b").unwrap().max_score,
        90
    );
    db.add_dropped(3).unwrap();
    db.add_dropped(2).unwrap();
    assert_eq!(db.stats(1).unwrap().dropped_events, 5);
}

#[test]
fn incidents_dedup() {
    let mut db = AuditLog::open_in_memory().unwrap();
    let inc = Incident {
        id: 0,
        ts_utc: now_rfc3339(),
        session_id: Some("s".into()),
        rule_id: "r".into(),
        title: "t".into(),
        severity: "high".into(),
        score: 80,
        confidence: "medium".into(),
        explanation: "e".into(),
        event_ids: vec![1, 2],
    };
    assert!(db.insert_incident(&inc, None).unwrap().is_some());
    assert!(db.insert_incident(&inc, None).unwrap().is_none());
    assert_eq!(db.incidents(10).unwrap().len(), 1);
    // Grouping: same session + rule within the window merges evidence.
    let more = Incident {
        event_ids: vec![2, 3],
        score: 95,
        ..inc.clone()
    };
    let id = db
        .insert_incident(&more, Some("2000-01-01T00:00:00Z"))
        .unwrap();
    assert!(id.is_some());
    let all = db.incidents(10).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].event_ids, vec![1, 2, 3]);
    assert_eq!(all[0].score, 95);
    assert_eq!(all[0].severity, "critical");
    assert!(
        db.insert_incident(&more, Some("2000-01-01T00:00:00Z"))
            .unwrap()
            .is_none()
    );
    // Outside the window: new incident.
    let later = Incident {
        event_ids: vec![9],
        ..inc.clone()
    };
    db.insert_incident(&later, Some("2999-01-01T00:00:00Z"))
        .unwrap();
    assert_eq!(db.incidents(10).unwrap().len(), 2);
}

#[test]
fn concurrent_writers_keep_chain_linear() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("c.db");
    AuditLog::open(&file).unwrap();
    let handles: Vec<_> = (0..4)
        .map(|t| {
            let f = file.clone();
            std::thread::spawn(move || {
                let mut db = AuditLog::open(&f).unwrap();
                for i in 0..50 {
                    let mut r = rec(t * 1000 + i, "s", 0);
                    db.insert(&mut r).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let db = AuditLog::open_readonly(&file).unwrap();
    assert_eq!(db.count().unwrap(), 200);
    assert!(db.verify().unwrap().ok);
}

#[test]
fn backup_and_retention() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = AuditLog::open(&dir.path().join("x.db")).unwrap();
    let mut old = rec(1, "s", 0);
    old.ts_utc = "2020-01-01T00:00:00.000Z".into();
    db.insert(&mut old).unwrap();
    let mut new = rec(2, "s", 0);
    db.insert(&mut new).unwrap();
    db.backup(&dir.path().join("b.db")).unwrap();
    assert!(db.backup(&dir.path().join("b.db")).is_err(), "no overwrite");
    assert_eq!(
        AuditLog::open_readonly(&dir.path().join("b.db"))
            .unwrap()
            .count()
            .unwrap(),
        2
    );
    assert_eq!(db.apply_retention(30).unwrap(), 1);
    assert_eq!(db.count().unwrap(), 1);
    assert!(db.verify().unwrap().ok);
}

#[test]
fn hundred_thousand_events_perf() {
    // Spec: support >= 100k stored events. Keep the test reasonably fast.
    let mut db = AuditLog::open_in_memory().unwrap();
    let start = std::time::Instant::now();
    for chunk in 0..100 {
        let mut batch: Vec<_> = (0..1000)
            .map(|i| {
                rec(
                    chunk * 1000 + i,
                    &format!("s{}", chunk % 7),
                    (i % 100) as u8,
                )
            })
            .collect();
        db.insert_batch(&mut batch).unwrap();
    }
    let insert = start.elapsed();
    let t = std::time::Instant::now();
    let page = db
        .list(&EventQuery {
            limit: Some(200),
            min_score: Some(60),
            ..Default::default()
        })
        .unwrap();
    let list = t.elapsed();
    let t = std::time::Instant::now();
    let _ = db.stats(24).unwrap();
    let stats = t.elapsed();
    assert_eq!(page.len(), 200);
    assert_eq!(db.count().unwrap(), 100_000);
    eprintln!("100k insert {insert:?}, filtered page {list:?}, stats {stats:?}");
    assert!(list.as_millis() < 2000);
}

#[test]
fn delete_events_removes_content_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.db");
    let mut db = AuditLog::open(&file).unwrap();
    let mut batch: Vec<_> = (0..10).map(|i| rec(i, "s", 0)).collect();
    batch[4].summary = "LEAKED-FICTIONAL-VALUE-123".into();
    db.insert_batch(&mut batch).unwrap();
    assert_eq!(db.delete_events(&[batch[4].id]).unwrap(), 1);
    assert!(
        db.verify().unwrap().ok,
        "deletion is bridged, chain stays valid"
    );
    assert_eq!(db.count().unwrap(), 9);
    drop(db);
    let mut raw = Vec::new();
    for suffix in ["", "-wal"] {
        let p = dir.path().join(format!("p.db{suffix}"));
        if p.exists() {
            raw.extend(std::fs::read(p).unwrap());
        }
    }
    assert!(
        !raw.windows(26).any(|w| w == b"LEAKED-FICTIONAL-VALUE-123"),
        "content must not remain on disk"
    );
}
