# Technical debt & deliberate gaps

| Id | Item | Why deferred | Next step |
|---|---|---|---|
| TD-001 | No code signing / update signature verification | Needs certificates and a release pipeline | Authenticode + minisign for releases; Tauri updater with signature check (opt-in) |
| TD-002 | OSV checks cover packages named on the command line only | Transitive dependencies and lockfile installs are not resolved; version matching for non-SemVer schemes is approximate | Lockfile parsing (package-lock, composer.lock, Cargo.lock, poetry.lock) |
| TD-003 | MCP proxy covers stdio servers and tool definitions only | HTTP/SSE would need an HTTP proxy; resources/prompts not analyzed yet | HTTP MCP proxy (no TLS interception), resource/prompt analysis |
| TD-004 | Interactive Mode uses Claude Code's native prompt only | Only reliable pause surface today | Own scoped approvals if Claude Code exposes a blocking approval API |
| TD-005 | Shell parser is a tokenizer, not a full AST | Robust enough for classification; full grammars are large | tree-sitter-bash / PowerShell AST for deeper analysis |
| TD-006 | Network metadata only from tool inputs | No packet capture by design | Optional ETW (Windows) / eBPF (Linux) connection telemetry for agent process trees |
| TD-007 | Same-user limitation | OS-level isolation needs admin/root | Optional service under a dedicated account; Landlock/AppContainer sandbox profiles |
| TD-008 | Linux desktop app not visually verified on a real Mint desktop | .deb + AppImage build in WSL Ubuntu 24.04; app starts and runs stable under WSLg (software rendering) | Install the .deb on Mint 22 and check the UI; Debian package name is derived from the product name (`erik-s-agent-shield`) |
| TD-009 | No OpenTelemetry export | Privacy-first; must be opt-in | OTLP exporter for redacted events |
| TD-010 | Local AI Risk Advisor (Ollama) not implemented | Spec: later phase, optional | Opt-in summaries over redacted events |
| TD-011 | Per-preset policy view (rules of a non-active preset) | Not required for MVP; `count_events` and `get_session` are implemented | `preset_info` IPC method |
| TD-012 | `freezePrototype` disabled | ECharts incompatibility (SF-005) | Re-evaluate when ECharts supports frozen prototypes |
