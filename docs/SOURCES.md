# Sources

Every URL consulted for the documentation set, with access date and a one-line finding. All accessed **2026-11-24**. "API" = GitHub/crates.io/npm registry JSON API. Pages were read through an automated fetch-and-summarise tool; long pages were read in parts. Where a page could not be read or did not contain the expected content, that is stated.

## Claude Code

| URL | Finding |
|---|---|
| https://code.claude.com/docs/en/hooks | Hooks reference (read in three parts). 33 hook events; settings locations; exec form (`command` + `args`, no shell); `timeout` default 600 s; `onFailure` "continue"\|"block" requires v2.1.295+; PreToolUse `permissionDecision` allow/deny/ask/defer, precedence deny > defer > ask > allow; "Deny and ask rules are still evaluated regardless of what the hook returns"; exit 2 blocks, other non-zero and timeouts do not; Windows Git Bash notes; `mcp_server` {name, source} since v2.1.274; ConfigChange can block settings changes in-session (not `policy_settings`); workspace-trust gating of hooks; `disableAllHooks`; disclaimer that hooks run with full user permissions. |

## Other agents

| URL | Finding |
|---|---|
| https://developers.openai.com/codex/hooks | 308 redirect to learn.chatgpt.com/docs/hooks. |
| https://learn.chatgpt.com/docs/hooks | Codex hooks: enabled by default; `hooks.json` in system/user/trusted-project locations; PreToolUse can deny; "Treat tool hooks as a useful guardrail, not a complete enforcement boundary"; errors/timeouts can let the tool run; changed hooks skipped until trusted. |
| https://cursor.com/docs/agent/hooks | Cursor hooks: `.cursor/hooks.json`; `beforeShellExecution`/`beforeMCPExecution` accept allow/deny/ask; fail-open by default, `failClosed: true` per hook; `ask` not enforced for `preToolUse`. |

## Competitors and related tools

| URL | Finding |
|---|---|
| https://api.github.com/repos/hashgraph-online/hol-guard | Apache-2.0; Rust; 1,121 stars; created 2026-03-28; pushed 2026-11-24; not archived. |
| https://raw.githubusercontent.com/hashgraph-online/hol-guard/main/README.md | "Open-source antivirus and firewall for AI agents"; native hooks + managed MCP proxies + launch integrations; many agents; Rust runtime + Python CLI (pipx); local dashboard; optional Guard Cloud; FAQ admits some events fail open or are only observed. |
| https://hol.org/guard | Pricing tiers Free/Solo $4.99/Pro $15/Team $30/Enterprise; claims "6.7K+ GitHub stars", "2.8M+ PyPI downloads" (self-reported; star figure does not match the repo's API count). |
| https://api.github.com/repos/solongate/agent-security | Apache-2.0; Go; 696 stars; created 2026-09-27; pushed 2026-11-24. |
| https://raw.githubusercontent.com/solongate/agent-security/main/README.md | Local-first hook-based gateway; policy, DLP ("70+" patterns), rate limits, audit trail, TUI; Claude Code/Codex/Antigravity/OpenCode; "no network calls. No account, no telemetry"; request-body shim for Claude Code; sandbox command. |
| https://api.github.com/repos/oktsec/oktsec | Apache-2.0; Go; 19 stars; created 2026-02-21; pushed 2026-11-14. |
| https://raw.githubusercontent.com/oktsec/oktsec/main/README.md | MCP stdio wrapping + HTTP gateway + Claude Code hooks via local HTTP; deterministic pipeline; hash-chained SQLite audit; web dashboard on 127.0.0.1:8080; observe/enforce; anonymous install telemetry (can be disabled); 268 rules. |
| https://api.github.com/repos/anthropic-experimental/sandbox-runtime | Apache-2.0; TypeScript; 7,249 stars; pushed 2026-11-13. |
| https://raw.githubusercontent.com/anthropic-experimental/sandbox-runtime/main/README.md | Research preview; macOS sandbox-exec, Linux bubblewrap + seccomp + proxies, Windows alpha (dedicated account, WFP fence, elevated install); Ubuntu 24.04 user-namespace caveat. Read first 100k characters only. |
| https://api.github.com/repos/cisco-ai-defense/mcp-scanner | Apache-2.0; Python; 1,126 stars; pushed 2026-11-23. |
| https://raw.githubusercontent.com/cisco-ai-defense/mcp-scanner/main/README.md | Scans MCP tools/prompts/resources/instructions with YARA, LLM analysis, Cisco AI Defense API; static mode; YARA-only needs no keys. |
| https://api.github.com/repos/semgrep/semgrep | LGPL-2.1; 17,920 stars; pushed 2026-11-24. |
| https://api.github.com/repos/gitleaks/gitleaks | MIT; Go; 31,302 stars; pushed 2026-10-28. |
| https://api.github.com/repos/aquasecurity/trivy | Apache-2.0; Go; 39,682 stars; pushed 2026-11-24. |
| https://api.github.com/repos/google/osv-scanner | Apache-2.0; Go; 11,611 stars; pushed 2026-11-23. |
| https://api.github.com/repos/ossf/scorecard | Apache-2.0; Go; 5,865 stars; pushed 2026-11-23. |

## MCP security

| URL | Finding |
|---|---|
| https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks | 2025-04-01. Defines tool poisoning ("instructions embedded within MCP tool descriptions … invisible to users but visible to AI models"), rug pulls, shadowing; demonstrated on Cursor; recommends pinning/hashing descriptions and cross-server boundaries. |
| https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices | MCP Security Best Practices (page text references spec revision 2025-11-25): confused deputy, token passthrough, SSRF, session hijacking, local MCP server compromise, authorization-URL validation, stdio proxy escalation, scope minimisation. |

## Standards and frameworks

| URL | Finding |
|---|---|
| https://genai.owasp.org/llm-top-10/ | OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection … LLM10 Unbounded Consumption. Page links to a 2026 edition that was not read. |
| https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/ | OWASP Top 10 for Agentic Applications 2026, released 2025-12-09; the page offers a download and does not list the ten names. |
| https://cycode.com/blog/owasp-top-10-agentic-applications/ | Secondary source for the ASI01–ASI10 names (Agent Goal Hijack … Rogue Agents). |
| https://atlas.mitre.org/techniques | HTTP 404 for the fetch tool (client-rendered site). |
| https://atlas.mitre.org/atlas-data/dist/v6/ATLAS-2026.07.yaml | ATLAS data 2026.07 (read characters 0–200,000 of ~717,000). Confirmed IDs incl. AML.T0010(.005), AML.T0011.002, AML.T0050, AML.T0051, AML.T0053, AML.T0055, AML.T0080, AML.T0081, AML.T0083, AML.T0086, AML.T0090, AML.T0098, AML.T0101, AML.T0102, AML.T0109, AML.T0110. |
| https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html | SARIF v2.1.0, OASIS Standard incorporating Approved Errata 01, 2023-08-28. Object sections were beyond the part read. |
| https://cyclonedx.org/specification/overview/ | CycloneDX 1.7 (2025-10-21); ECMA-424; SBOM/SaaSBOM/HBOM and more. |
| https://opentelemetry.io/docs/specs/semconv/gen-ai/ | GenAI semantic conventions "have moved to the OpenTelemetry GenAI semantic conventions repository"; page no longer maintained. |
| https://github.com/open-telemetry/semantic-conventions-genai | New home of GenAI/MCP conventions (spans, metrics, events); no release shown, schema URL "TODO" → treated as unstable. |

## Name availability

| URL | Finding |
|---|---|
| Web search: `"AgentShield" AI agent security product` | Many unrelated products named AgentShield / Agent Shield (Product Hunt listings, PyPI `agentshield-x`, `agentshield-fw`, `agentic-shield`, npm `agentshield-sdk`, GitHub `cdayAI/Agent-Shield`, `VinayK88/AgentShield`). |
| Web search: `"AgentShield" … security scanner Claude Code` | `affaan-m/agentshield` / npm `ecc-agentshield` (Claude Code config scanner), crate `agent-shield`, `NoNamePY/agentshield`. |
| Web search: `"AGENTSHIELD" trademark USPTO OR EUIPO …` | No AGENTSHIELD registration found by search; UK "Agent Shield" UK00004362695 (classes 36/42/45, financial risk). Trademark databases were **not** queried directly. |
| https://www.solo.io/press-releases/introducing-agentshield | Solo.io announced open-source "agentshield" on 2026-10-23. |
| https://api.github.com/repos/affaan-m/agentshield | MIT; TypeScript; 1,442 stars; created 2026-02-11; security scanner for AI agent configurations (Claude Code ecosystem). |
| https://crates.io/api/v1/crates/agentshield | Crate exists: "AI Agent Egress Firewall", Apache-2.0, v1.0.0, 2026-02-19, repo kamuimk/agentshield. |
| https://crates.io/api/v1/crates/agent-shield | Crate exists: offline security scanner for AI agent extensions, v1.1.0, repo aiconnai/agentshield. |
| https://api.github.com/repos/aiconnai/agentshield | Rust; 22 stars; license reported as "Other"/NOASSERTION by the API (crates.io lists MIT OR Apache-2.0). |
| https://registry.npmjs.org/agentshield | Package exists: hardlink-based file backup for AI agent operations, Apache-2.0, v0.1.0, 2026-01. |
| https://www.ipo.gov.uk/t-tmj/tm-journals/2026-015/UK00004362695.html | Seen in search results only (not fetched): UK Trade Mark Journal entry "Agent Shield". |

## Local evidence (not URLs)

| Source | Finding |
|---|---|
| `cargo metadata --format-version 1 --locked` (root workspace) | 171 packages, 158 third-party; license summary in LICENSING §2. |
| `cargo metadata --format-version 1 --locked` (`apps/desktop/src-tauri`) | 452 third-party packages; license summary in LICENSING §3. |
| `apps/desktop/package-lock.json`, `node_modules/*/package.json`, font `LICENSE` files | 326 packages (35 non-dev); OFL-1.1 fonts; license summary in LICENSING §4. |
| Owner-provided measurements and test results (this session) | Hook/daemon latencies, SQLite throughput, Norton delay, handle-inheritance bug, test counts. Not re-measured for this documentation. |

## Not consulted / limits

- MITRE ATT&CK website: technique IDs in RESEARCH §10 are cited from memory of the public Enterprise matrix and must be re-verified before external publication.
- USPTO, EUIPO, BOIP, WIPO trademark databases: not queried.
- None of the competitor tools was installed or run.
- OWASP Agentic Top 10 PDF: not downloaded (names from a secondary source).
