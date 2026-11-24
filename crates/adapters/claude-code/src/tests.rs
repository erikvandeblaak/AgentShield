use super::*;
use crate::install::*;
use agentshield_event_model::Mode;
use serde_json::json;
use std::path::Path;

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/claude-code")
        .join(name);
    serde_json::from_str(
        &std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
    )
    .unwrap()
}

#[test]
fn normalize_pre_tool_use_bash() {
    let ev = normalize(&fixture("pre_tool_use_bash.json"), None).unwrap();
    assert_eq!(ev.phase, Phase::Pre);
    assert!(ev.enforceable);
    assert_eq!(ev.ctx.session_id.as_deref(), Some("abc123"));
    assert_eq!(ev.ctx.correlation_id.as_deref(), Some("toolu_01ABC"));
    match ev.action {
        ActionKind::ShellExec { command, .. } => assert_eq!(command, "git status"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn normalize_tools() {
    let cases = [
        ("Read", json!({"file_path": "C:\\p\\.env"}), "file.read"),
        (
            "Write",
            json!({"file_path": "/p/a.txt", "content": "hi"}),
            "file.write",
        ),
        (
            "Edit",
            json!({"file_path": "/p/a.txt", "old_string": "a", "new_string": "b"}),
            "file.edit",
        ),
        ("Glob", json!({"pattern": "**/*.rs"}), "file.search"),
        (
            "WebFetch",
            json!({"url": "https://example.com", "prompt": "x"}),
            "network.fetch",
        ),
        ("WebSearch", json!({"query": "rust"}), "network.search"),
        (
            "Agent",
            json!({"description": "explore", "prompt": "x"}),
            "agent.subagent",
        ),
        (
            "PowerShell",
            json!({"command": "Get-ChildItem"}),
            "shell.exec",
        ),
        (
            "mcp__github__create_issue",
            json!({"title": "x"}),
            "mcp.call",
        ),
        ("SomethingNew", json!({}), "tool.other"),
    ];
    for (tool, input, ty) in cases {
        let p = json!({"session_id": "s", "cwd": "/p", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "tool_use_id": "t"});
        let ev = normalize(&p, None).unwrap();
        assert_eq!(ev.action.type_name(), ty, "{tool}");
    }
    let p = json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__plugin_x_srv__do", "tool_input": {}, "mcp_server": {"name": "real-server"}});
    match normalize(&p, None).unwrap().action {
        ActionKind::McpCall { server, tool } => {
            assert_eq!(server, "real-server");
            assert_eq!(tool, "do");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn normalize_post_and_lifecycle() {
    let post = normalize(&fixture("post_tool_use_bash.json"), None).unwrap();
    assert_eq!(post.phase, Phase::Post);
    assert_eq!(post.post_failed, Some(false));
    assert!(!post.enforceable);
    let fail = normalize(&json!({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "tool_input": {"command": "false"}, "error": "exit 1"}), None).unwrap();
    assert_eq!(fail.post_failed, Some(true));
    let prompt = normalize(
        &json!({"hook_event_name": "UserPromptSubmit", "prompt": "hello there"}),
        None,
    )
    .unwrap();
    assert_eq!(prompt.action, ActionKind::UserPrompt { length: 11 });
    let ss = normalize(
        &json!({"hook_event_name": "SessionStart", "source": "startup"}),
        None,
    )
    .unwrap();
    assert_eq!(ss.action.type_name(), "session.start");
    assert!(normalize(&json!([1, 2]), None).is_err());
    assert!(normalize(&json!({}), None).is_err());
    assert_eq!(
        normalize(&json!({}), Some("Stop")).unwrap().action,
        ActionKind::Stop
    );
}

#[test]
fn render_never_allows() {
    for actual in [
        ActualDecision::NoOpinion,
        ActualDecision::NotApplicable,
        ActualDecision::Ask,
        ActualDecision::Deny,
    ] {
        for ev in [
            "PreToolUse",
            "PostToolUse",
            "SessionStart",
            "PermissionRequest",
        ] {
            let o = render(
                ev,
                &ModeOutcome {
                    actual,
                    message: Some("m".into()),
                },
            );
            assert_eq!(o.exit_code, 0);
            let out = o.stdout.unwrap_or_default();
            assert!(!out.contains("\"allow\""), "{out}");
            assert!(!out.contains("updatedInput"));
            if ev != "PreToolUse" {
                assert!(out.is_empty());
            }
        }
    }
    let d = render(
        "PreToolUse",
        &ModeOutcome {
            actual: ActualDecision::Deny,
            message: Some("AgentShield blocked: x".into()),
        },
    );
    let v: Value = serde_json::from_str(&d.stdout.unwrap()).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    let a = render(
        "PreToolUse",
        &ModeOutcome {
            actual: ActualDecision::Ask,
            message: None,
        },
    );
    assert!(a.stdout.unwrap().contains("\"ask\""));
    assert_eq!(
        render(
            "PreToolUse",
            &ModeOutcome {
                actual: ActualDecision::NoOpinion,
                message: None
            }
        ),
        HookOutput::default()
    );
    let _ = Mode::Monitor;
}

const EXISTING: &str = r#"{
  "skillOverrides": {"x": "off"},
  "permissions": {"deny": ["Read(./.env)"], "allow": ["Bash(git status)"]},
  "hooks": {
    "PreToolUse": [
      {"hooks": [{"type": "command", "command": "C:/tools/other.exe hook", "timeout": 5}]}
    ],
    "PreCompact": [
      {"hooks": [{"type": "command", "command": "other-tool"}]}
    ]
  },
  "zzz_last": true
}"#;

#[test]
fn install_is_idempotent_preserving_and_reversible() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join(".claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, EXISTING).unwrap();
    let bin = dir.path().join(if cfg!(windows) {
        "agentshield.exe"
    } else {
        "agentshield"
    });
    std::fs::write(&bin, b"bin").unwrap();
    let backups = dir.path().join("backups");

    let plan1 = plan(&settings, &bin, false, &backups).unwrap();
    assert!(!plan1.already_installed);
    assert!(
        plan1
            .changes
            .iter()
            .any(|c| c.contains("Keep 2 existing hook handler"))
    );

    let r = install(&settings, &bin, false, &backups);
    assert!(r.ok, "{r:?}");
    assert!(r.verified);
    assert!(r.backup_path.is_some());
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    // Preserved
    assert_eq!(v["permissions"]["deny"][0], "Read(./.env)");
    assert_eq!(
        v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "C:/tools/other.exe hook"
    );
    assert_eq!(
        v["hooks"]["PreCompact"][0]["hooks"][0]["command"],
        "other-tool"
    );
    // Key order preserved (first and last keys).
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys.first().unwrap().as_str(), "skillOverrides");
    assert_eq!(keys.last().unwrap().as_str(), "zzz_last");
    // Added in exec form
    let ours = &v["hooks"]["PreToolUse"][1]["hooks"][0];
    assert_eq!(ours["args"], json!(["hook"]));
    assert!(ours.get("onFailure").is_none(), "fail-open by default");
    // Idempotent
    let before = std::fs::read_to_string(&settings).unwrap();
    let r2 = install(&settings, &bin, false, &backups);
    assert!(r2.ok);
    assert!(r2.backup_path.is_none());
    assert_eq!(before, std::fs::read_to_string(&settings).unwrap());
    assert!(
        plan(&settings, &bin, false, &backups)
            .unwrap()
            .already_installed
    );
    // State
    let st = state(&settings);
    assert!(st.verified, "{st:?}");
    assert_eq!(st.events.len(), EVENTS.len());
    // Repair to fail-closed replaces, never duplicates
    let r3 = install(&settings, &bin, true, &backups);
    assert!(r3.ok);
    let st = state(&settings);
    assert!(st.fail_closed);
    assert!(st.problems.is_empty(), "{:?}", st.problems);
    // Uninstall restores the original structure exactly
    let u = uninstall(&settings, &backups);
    assert!(u.ok, "{u:?}");
    let after: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let orig: Value = serde_json::from_str(EXISTING).unwrap();
    assert_eq!(after, orig);
    let u2 = uninstall(&settings, &backups);
    assert!(u2.ok);
    assert!(u2.message.contains("not installed"));
}

#[test]
fn install_into_missing_file_and_uninstall_removes_hooks_key() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let bin = dir.path().join("agentshield.exe");
    std::fs::write(&bin, b"x").unwrap();
    assert!(install(&settings, &bin, false, &dir.path().join("b")).ok);
    assert!(state(&settings).verified);
    assert!(uninstall(&settings, &dir.path().join("b")).ok);
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(v, json!({}));
}

#[test]
fn refuses_invalid_settings_and_missing_binary() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    std::fs::write(&settings, "{ not json").unwrap();
    let bin = dir.path().join("agentshield.exe");
    std::fs::write(&bin, b"x").unwrap();
    let r = install(&settings, &bin, false, dir.path());
    assert!(!r.ok);
    assert!(r.message.contains("refusing"));
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        "{ not json",
        "file untouched"
    );
    std::fs::write(&settings, "{}").unwrap();
    let r = install(&settings, &dir.path().join("nope.exe"), false, dir.path());
    assert!(!r.ok);
    std::fs::write(&settings, r#"{"hooks": []}"#).unwrap();
    assert!(!install(&settings, &bin, false, dir.path()).ok);
}

#[test]
fn detects_legacy_and_missing_binary() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    std::fs::write(&settings, r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"agentshield hook claude-code"}]}]}}"#).unwrap();
    let st = state(&settings);
    assert!(st.installed);
    assert!(!st.verified);
    assert!(st.problems.iter().any(|p| p.contains("legacy")));
    let (stripped, n) =
        strip(&serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap());
    assert_eq!(n, 1);
    assert_eq!(stripped, json!({}));
}

#[test]
fn capability_matrix_is_honest() {
    let caps = detect::claude_capabilities(None);
    assert!(caps.iter().all(|c| c.status != "enforced"));
    assert!(caps.iter().all(|c| !c.reason.is_empty()));
    let st = IntegrationState {
        installed: true,
        verified: true,
        settings_path: String::new(),
        events: EVENTS.iter().map(|e| e.0.to_string()).collect(),
        missing_events: vec![],
        fail_closed: false,
        binary_path: None,
        problems: vec![],
    };
    let caps = detect::claude_capabilities(Some(&st));
    let get = |n: &str| {
        caps.iter()
            .find(|c| c.capability == n)
            .unwrap()
            .status
            .clone()
    };
    assert_eq!(get("Shell blocking"), "enforced");
    assert_eq!(get("Process monitoring"), "unsupported");
    assert_eq!(get("Network enforcement"), "partial");
}

#[test]
fn mcp_assessment() {
    let r = agentshield_secret_detector::Redactor::new([1u8; 32]);
    let s = mcp::assess_server(
        "gh",
        &json!({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}}),
        "user",
        Path::new("x"),
        &r,
    );
    let ids: Vec<&str> = s.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"mcp.unpinned_package"));
    assert!(ids.contains(&"mcp.literal_secret_in_config"));
    assert_eq!(s.env_keys, vec!["GITHUB_TOKEN"]);
    assert!(!serde_json::to_string(&s).unwrap().contains("ghp_ABC"));
    let ok = mcp::assess_server(
        "x",
        &json!({"type": "http", "url": "http://127.0.0.1:64342/sse"}),
        "user",
        Path::new("x"),
        &r,
    );
    assert!(ok.findings.is_empty());
    assert_eq!(ok.url_host.as_deref(), Some("127.0.0.1"));
    let env_ref = mcp::assess_server(
        "y",
        &json!({"command": "npx", "args": ["pkg@1.2.3"], "env": {"API_KEY": "${API_KEY}"}}),
        "user",
        Path::new("x"),
        &r,
    );
    assert!(env_ref.findings.is_empty(), "{:?}", env_ref.findings);
}

#[test]
fn legacy_arg_form_is_recognized_and_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let bin = dir.path().join("agentshield.exe");
    std::fs::write(&bin, b"x").unwrap();
    let legacy = json!({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": bin.to_string_lossy(), "args": ["hook", "claude-code"], "timeout": 10}]}]}});
    std::fs::write(&settings, legacy.to_string()).unwrap();
    let st = state(&settings);
    assert!(st.installed);
    assert!(
        st.problems
            .iter()
            .any(|p| p.contains("outdated hook arguments"))
    );
    assert!(install(&settings, &bin, false, &dir.path().join("b")).ok);
    let st = state(&settings);
    assert!(st.verified, "{st:?}");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(
        v["hooks"]["PreToolUse"].as_array().unwrap().len(),
        1,
        "legacy entry replaced, not duplicated"
    );
}

#[test]
fn disable_all_hooks_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("settings.json");
    let bin = dir.path().join("agentshield.exe");
    std::fs::write(&bin, b"x").unwrap();
    assert!(install(&settings, &bin, false, &dir.path().join("b")).ok);
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    v["disableAllHooks"] = json!(true);
    std::fs::write(&settings, v.to_string()).unwrap();
    let st = state(&settings);
    assert!(!st.verified);
    assert!(st.problems.iter().any(|p| p.contains("disableAllHooks")));
}

#[test]
fn config_change_is_recorded_as_lifecycle() {
    let ev = normalize(&json!({"hook_event_name": "ConfigChange", "source": "user_settings", "file_path": "/h/.claude/settings.json"}), None).unwrap();
    assert_eq!(ev.phase, Phase::Lifecycle);
    assert!(!ev.enforceable);
    assert_eq!(ev.input["source"], "user_settings");
}
