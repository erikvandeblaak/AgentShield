// DEMO-ONLY heuristic "analyzer". This is NOT the AgentShield risk engine (that lives in the
// Rust daemon). It exists so Demo Mode can produce plausible, clearly fictional results for
// screenshots and training without ever touching the real backend.

import { levelForScore } from "../lib/format";
import type {
  ActionKind, ActualDecision, Confidence, Finding, Mode, ModeOutcome, ParsedCommand, ParsedSegment,
  PolicyDecision, PolicyOutcome, RiskAssessment, RiskCategory, RuleMatch, ShellKind, SimInput, SimResult,
} from "../lib/types";

interface Detector {
  id: string;
  category: RiskCategory;
  score: number;
  confidence: Confidence;
  test: RegExp;
  explanation: string;
  mitigation: string | null;
  target?: string;
}

const SHELL_DETECTORS: Detector[] = [
  { id: "shell.rm_recursive_root", category: "destructive_operation", score: 97, confidence: "high", test: /\brm\s+(-[a-z]*r[a-z]*f?|-[a-z]*f[a-z]*r)[a-z]*\s+(--no-preserve-root\s+)?(~\/?|\/|\$HOME\/?)(\s|$)/i, explanation: "Recursive forced delete of the home or root directory.", mitigation: "Delete a specific project sub-directory instead and review the path first.", target: "~/" },
  { id: "shell.download_pipe_exec", category: "supply_chain_compromise", score: 88, confidence: "high", test: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/i, explanation: "Downloads a remote script and pipes it straight into a shell without review.", mitigation: "Download to a file, review it, then run it yourself." },
  { id: "shell.sensitive_read_and_network", category: "data_exfiltration", score: 95, confidence: "high", test: /(id_rsa|id_ed25519|\.aws\/credentials|\.env)\b.*\|\s*(nc|ncat|curl|wget)\b/i, explanation: "A credential file is read and its content is piped to a network tool.", mitigation: "Never pipe key material to network tools. Use a credential helper.", target: "~/.ssh/id_rsa" },
  { id: "git.force_push_protected", category: "git_repository_damage", score: 68, confidence: "high", test: /\bgit\s+push\b.*(--force|-f)\b.*\b(main|master|production)\b/i, explanation: "Force push to a protected branch can overwrite other people's history.", mitigation: "Use --force-with-lease on a feature branch." },
  { id: "git.reset_hard", category: "git_repository_damage", score: 45, confidence: "medium", test: /\bgit\s+reset\s+--hard\b/i, explanation: "Hard reset discards uncommitted work and moves the branch pointer.", mitigation: "Stash or commit first; prefer git revert." },
  { id: "db.migrate_fresh", category: "database_destructive", score: 74, confidence: "high", test: /\bartisan\s+migrate:(fresh|reset|refresh)\b/i, explanation: "Drops all tables and rebuilds the schema of the configured database.", mitigation: "Confirm the target database is a disposable development database." },
  { id: "db.drop_statement", category: "database_destructive", score: 76, confidence: "medium", test: /\b(drop\s+(table|database|schema)|truncate\s+table)\b/i, explanation: "Destructive SQL statement in a command line.", mitigation: "Run against a backup first, or use a reversible migration." },
  { id: "package.typosquat_suspect", category: "suspicious_package_installation", score: 72, confidence: "medium", test: /\b(pip3?|npm|pnpm|yarn)\s+(install|add|i)\b.*\b(reqeusts|requets|lodahs|expresss|crossenv|python-dateutils)\b/i, explanation: "Package name is one edit away from a very popular package (possible typosquat).", mitigation: "Check the spelling; the popular package is probably what you want." },
  { id: "package.install", category: "suspicious_package_installation", score: 22, confidence: "low", test: /\b(pip3?\s+install|npm\s+(install|i|add)|pnpm\s+add|yarn\s+add|cargo\s+add|composer\s+require)\s+[\w@]/i, explanation: "Installs third-party packages; install scripts may run with your privileges.", mitigation: "Prefer lockfile installs and review new dependencies." },
  { id: "package.remote_execute", category: "supply_chain_compromise", score: 48, confidence: "medium", test: /\b(npx\s+(-y|--yes)|pnpm\s+dlx|bunx|uvx|pipx\s+run)\b/i, explanation: "Fetches a package and executes it immediately without an install review step.", mitigation: "Pin the version and inspect the package before running." },
  { id: "package.registry_override", category: "supply_chain_compromise", score: 64, confidence: "medium", test: /(--registry[= ]|config\s+set\s+registry|--index-url|--extra-index-url)\s*\S+/i, explanation: "Overrides the package registry; packages would be resolved from a non-default source.", mitigation: "Use the organisation's approved registry configuration." },
  { id: "shell.encoded_command", category: "obfuscated_execution", score: 82, confidence: "high", test: /\b(powershell|pwsh)(\.exe)?\b.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i, explanation: "PowerShell is started with a Base64-encoded command, hiding what will run.", mitigation: "Run the decoded command in plain text so it can be reviewed." },
  { id: "tamper.defender_disable", category: "security_configuration_change", score: 90, confidence: "high", test: /Set-MpPreference\b.*-DisableRealtimeMonitoring\s+\$?true/i, explanation: "Disables Microsoft Defender real-time protection.", mitigation: "Add a narrow exclusion for the build directory instead of disabling protection." },
  { id: "security.firewall_disable", category: "security_configuration_change", score: 78, confidence: "high", test: /\b(ufw\s+disable|systemctl\s+(stop|disable)\s+(ufw|firewalld)|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off)\b/i, explanation: "Turns off the host firewall.", mitigation: "Open the single port that is needed instead." },
  { id: "privilege.sudo", category: "privilege_escalation", score: 35, confidence: "medium", test: /(^|[;&|]\s*)sudo\s+\S+/i, explanation: "Command runs with elevated privileges.", mitigation: "Run without sudo where possible." },
  { id: "infra.terraform_destroy", category: "infrastructure_modification", score: 80, confidence: "high", test: /\bterraform\s+destroy\b|\bkubectl\s+delete\s+(ns|namespace)\b/i, explanation: "Destroys managed infrastructure resources.", mitigation: "Run a plan first and target a single resource." },
  { id: "persistence.shell_profile", category: "persistence_indicator", score: 55, confidence: "medium", test: />>\s*~?\/?\S*(\.bashrc|\.zshrc|\.profile|crontab)\b|\bcrontab\s+-/i, explanation: "Appends to a shell profile or crontab, which runs on every login or on a schedule.", mitigation: "Keep project setup inside the project (e.g. direnv) instead of global profiles.", target: "~/.bashrc" },
  { id: "cred.env_secret_inline", category: "credential_exposure", score: 70, confidence: "high", test: /\[(aws_secret|github_token|api_key|private_key|jwt|slack_token):[0-9a-f]{6,}\]/i, explanation: "A secret value appears on the command line (redacted before storage).", mitigation: "Load secrets from a secret manager or an untracked env file." },
  { id: "network.metadata_endpoint", category: "unsafe_network_access", score: 85, confidence: "high", test: /169\.254\.169\.254|metadata\.google\.internal/i, explanation: "Request to a cloud instance metadata endpoint, which can hand out credentials.", mitigation: "Block metadata access for agent sessions (IMDSv2 hop limit 1)." },
  { id: "network.raw_ip", category: "unsafe_network_access", score: 42, confidence: "low", test: /\b(nc|ncat|curl|wget|ssh|scp)\b.*\b(?!127\.|10\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}\b/i, explanation: "Network tool talks to a raw IP address instead of a named host.", mitigation: "Use a named, expected host." },
  { id: "shell.chmod_exec", category: "unauthorized_file_change", score: 20, confidence: "low", test: /\bchmod\s+(\+x|7\d\d)\b/i, explanation: "Makes a file executable.", mitigation: null },
  { id: "infra.docker_privileged", category: "privilege_escalation", score: 58, confidence: "medium", test: /\bdocker\s+run\b.*(--privileged|-v\s+\/:\/)/i, explanation: "Container is started privileged or with the host root mounted.", mitigation: "Drop --privileged and mount only the project directory." },
];

const SENSITIVE_PATHS: { test: RegExp; id: string; score: number; category: RiskCategory; what: string }[] = [
  { test: /(^|[\\/])\.env(\.[\w.-]+)?$/i, id: "path.env_file", score: 55, category: "secret_access", what: "environment file that usually holds secrets" },
  { test: /[\\/]\.ssh[\\/](id_[\w]+|.*\.pem)$/i, id: "path.ssh_private_key", score: 82, category: "secret_access", what: "SSH private key" },
  { test: /[\\/]\.aws[\\/]credentials$/i, id: "path.aws_credentials", score: 80, category: "secret_access", what: "AWS credentials file" },
  { test: /[\\/]\.claude[\\/]settings(\.local)?\.json$/i, id: "path.agent_configuration", score: 66, category: "agent_configuration_tampering", what: "agent hook / permission configuration" },
  { test: /[\\/]\.git[\\/]hooks[\\/]/i, id: "path.git_hooks", score: 52, category: "persistence_indicator", what: "git hook that runs automatically" },
];

// ---------------------------------------------------------------- shell parsing (demo quality)

function splitTopLevel(cmd: string): { parts: string[]; ops: string[] } {
  const parts: string[] = [];
  const ops: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i] ?? "";
    const next = cmd[i + 1] ?? "";
    if (quote) {
      cur += c;
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      cur += c;
      continue;
    }
    const two = c + next;
    if (two === "&&" || two === "||") {
      parts.push(cur.trim());
      ops.push(two);
      cur = "";
      i++;
    } else if (c === "|" || c === ";") {
      parts.push(cur.trim());
      ops.push(c);
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return { parts: parts.filter((p) => p.length > 0), ops };
}

function tokenize(s: string): string[] {
  return (s.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((t) => t);
}

const unquote = (s: string) => s.replace(/^(['"])(.*)\1$/s, "$2");
const WRAPPERS = new Set(["sudo", "env", "nohup", "time", "xargs", "nice", "doas", "command"]);

export function demoParse(command: string, shell: ShellKind, depth = 0): ParsedCommand {
  const { parts, ops } = splitTopLevel(command);
  const nested: ParsedCommand[] = [];
  const decoded: string[] = [];
  const inline: string[] = [];
  const uncertainties: string[] = [];
  const segments: ParsedSegment[] = parts.map((part, idx) => {
    const tokens = tokenize(part);
    const env: string[] = [];
    const wrappers: string[] = [];
    const redirections: { op: string; target: string }[] = [];
    while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) env.push(tokens.shift() ?? "");
    while (tokens[0] && WRAPPERS.has(tokens[0])) wrappers.push(tokens.shift() ?? "");
    const raw = tokens.shift() ?? "";
    const args: string[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i] ?? "";
      const m = t.match(/^(\d?>>?|<|&>)(.*)$/);
      if (m) {
        const target = m[2] || tokens[++i] || "";
        redirections.push({ op: m[1] ?? ">", target });
      } else args.push(t);
    }
    const program = (raw.split(/[\\/]/).pop() ?? raw).replace(/\.exe$/i, "").toLowerCase();
    if (depth < 2) {
      const cIdx = args.findIndex((a) => a === "-c" || a === "-Command" || a === "/c");
      if (["bash", "sh", "zsh", "powershell", "pwsh", "cmd"].includes(program) && cIdx >= 0 && args[cIdx + 1]) {
        nested.push(demoParse(unquote(args[cIdx + 1] ?? ""), program.startsWith("p") ? "power_shell" : program === "cmd" ? "cmd" : "bash", depth + 1));
      }
      const eIdx = args.findIndex((a) => /^-(e|enc|encodedcommand)$/i.test(a));
      if (["powershell", "pwsh"].includes(program) && eIdx >= 0 && args[eIdx + 1]) {
        try {
          const bin = atob(args[eIdx + 1] ?? "");
          let text = "";
          for (let i = 0; i + 1 < bin.length; i += 2) text += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
          decoded.push(text);
          nested.push(demoParse(text, "power_shell", depth + 1));
        } catch {
          uncertainties.push("Encoded payload could not be decoded.");
        }
      }
      const codeIdx = args.findIndex((a) => a === "-c" || a === "-e" || a === "-r");
      if (["python", "python3", "node", "php", "ruby", "perl"].includes(program) && codeIdx >= 0 && args[codeIdx + 1]) {
        inline.push(unquote(args[codeIdx + 1] ?? ""));
      }
    }
    if (/\$\(|`/.test(part)) uncertainties.push("Command substitution is present; its output is not known before execution.");
    return {
      program, raw_program: raw, args, redirections, wrappers, env_assignments: env,
      pipes_to_next: ops[idx] === "|",
      piped_from_prev: idx > 0 && ops[idx - 1] === "|",
    };
  });
  if (/\$[A-Za-z_{]/.test(command)) uncertainties.push("Variables are expanded by the shell at run time; their values are not visible here.");
  return {
    shell, segments, operators: ops, nested, decoded_payloads: decoded, inline_code: inline,
    uncertainties: [...new Set(uncertainties)], syntax_errors: [],
  };
}

// ---------------------------------------------------------------- analysis

export interface DemoAnalysis {
  summary: string;
  action_type: string;
  action: ActionKind;
  tool: string;
  input: unknown;
  parsed: ParsedCommand | null;
  risk: RiskAssessment;
  sensitive_targets: string[];
}

function flattenText(p: ParsedCommand): string {
  return [...p.decoded_payloads, ...p.inline_code, ...p.nested.map(flattenText)].join("\n");
}

function assess(findings: Finding[], uncertainties: string[]): RiskAssessment {
  const sorted = [...findings].sort((a, b) => b.score - a.score);
  const top = sorted[0];
  const bonus = Math.min(8, Math.max(0, sorted.length - 1) * 3);
  const score = top ? Math.min(100, top.score + bonus) : 2;
  const explanation: string[] = [];
  if (!top) explanation.push("No risk indicators matched. Base score 2 (routine action).");
  else {
    explanation.push(`Highest finding ${top.id} sets the base score to ${top.score}.`);
    if (sorted.length > 1) explanation.push(`${sorted.length - 1} additional finding(s) add +${bonus} (capped).`);
    explanation.push(`Final score ${score} → level ${levelForScore(score)}.`);
  }
  const conf: Confidence = !top ? "high" : sorted.some((f) => f.confidence === "low") && sorted.length === 1 ? "low" : top.confidence;
  return {
    score, level: levelForScore(score), confidence: conf,
    categories: [...new Set(sorted.map((f) => f.category))],
    findings: sorted, explanation, uncertainties,
  };
}

const TOOL_ACTIONS: Record<string, string> = {
  Bash: "shell.exec", PowerShell: "shell.exec", Read: "file.read", Write: "file.write", Edit: "file.edit",
  Grep: "file.search", Glob: "file.search", WebFetch: "network.fetch", WebSearch: "network.search", Task: "agent.subagent",
};

export function demoAnalyze(input: SimInput): DemoAnalysis {
  const findings: Finding[] = [];
  const targets = new Set<string>();
  const uncertainties: string[] = [];

  if (input.command != null) {
    const shell: ShellKind = input.shell ?? "bash";
    const command = input.command.trim();
    const parsed = demoParse(command, shell);
    const haystack = `${command}\n${flattenText(parsed)}`;
    for (const d of SHELL_DETECTORS) {
      const m = haystack.match(d.test);
      if (!m) continue;
      // The generic install finding is superseded by the more specific typosquat finding.
      if (d.id === "privilege.sudo" && findings.length > 2) continue;
      findings.push({ id: d.id, category: d.category, score: d.score, confidence: d.confidence, explanation: d.explanation, evidence: m[0].slice(0, 160), mitigation: d.mitigation });
      if (d.target) targets.add(d.target);
    }
    for (const t of command.match(/(~|\.{0,2})?[\\/]?[\w.-]*([\\/][\w.-]+)+|\.env\b/g) ?? []) {
      for (const sp of SENSITIVE_PATHS) if (sp.test.test(t)) targets.add(t);
    }
    uncertainties.push(...parsed.uncertainties);
    return {
      summary: command.length > 140 ? `${command.slice(0, 139)}…` : command,
      action_type: "shell.exec",
      action: { type: "shell_exec", command, shell },
      tool: shell === "power_shell" ? "PowerShell" : "Bash",
      input: { command },
      parsed, risk: assess(findings, uncertainties), sensitive_targets: [...targets],
    };
  }

  const tool = input.tool ?? "Unknown";
  const ti = (input.tool_input && typeof input.tool_input === "object" ? input.tool_input : {}) as Record<string, unknown>;
  const str = (k: string) => (typeof ti[k] === "string" ? (ti[k] as string) : "");
  let action: ActionKind = { type: "other_tool", tool };
  let action_type = TOOL_ACTIONS[tool] ?? "tool.other";
  let summary = tool;
  const path = str("file_path") || str("path");

  if (tool === "Read" || tool === "Write" || tool === "Edit") {
    action = tool === "Read" ? { type: "file_read", path } : tool === "Write" ? { type: "file_write", path, content_len: str("content").length || null } : { type: "file_edit", path };
    summary = `${tool} ${path}`;
    for (const sp of SENSITIVE_PATHS) {
      if (!sp.test.test(path)) continue;
      const write = tool !== "Read";
      targets.add(path);
      findings.push({
        id: `${sp.id}.${write ? "write" : "read"}`, category: sp.category,
        score: Math.min(100, sp.score + (write && sp.category !== "secret_access" ? 6 : 0)), confidence: "high",
        explanation: `${write ? "Modifies" : "Reads"} an ${sp.what}.`, evidence: path,
        mitigation: sp.category === "secret_access" ? "Give the agent a redacted example file (.env.example) instead." : "Make this change yourself, outside the agent session.",
      });
    }
    const secret = str("content").match(/\[(\w+):[0-9a-f]{6,}\]/);
    if (secret) findings.push({ id: "content.secret_literal", category: "credential_exposure", score: 60, confidence: "high", explanation: "A secret literal is written into a file (redacted before storage).", evidence: secret[0], mitigation: "Reference an environment variable instead of the literal value." });
  } else if (tool === "WebFetch") {
    const url = str("url");
    action = { type: "network_fetch", url };
    summary = `WebFetch ${url}`;
    if (/169\.254\.169\.254|metadata\.google\.internal/.test(url)) {
      targets.add("cloud instance metadata");
      findings.push({ id: "network.metadata_endpoint", category: "unsafe_network_access", score: 85, confidence: "high", explanation: "Request to a cloud instance metadata endpoint, which can hand out credentials.", evidence: url, mitigation: "Block metadata access for agent sessions (IMDSv2 hop limit 1)." });
    } else if (/^http:\/\//.test(url)) {
      findings.push({ id: "network.plain_http", category: "unsafe_network_access", score: 28, confidence: "medium", explanation: "Unencrypted HTTP request; content can be modified in transit.", evidence: url, mitigation: "Use https." });
    }
    if (/\[(\w+):[0-9a-f]{6,}\]/.test(url)) findings.push({ id: "network.secret_in_url", category: "data_exfiltration", score: 86, confidence: "high", explanation: "A secret appears inside the request URL.", evidence: url.match(/\[(\w+):[0-9a-f]{6,}\]/)?.[0] ?? null, mitigation: "Never place credentials in URLs." });
  } else if (tool === "WebSearch") {
    action = { type: "web_search", query: str("query") };
    summary = `WebSearch ${str("query")}`;
  } else if (tool === "Grep" || tool === "Glob") {
    action = { type: "file_search", pattern: str("pattern"), path: path || null };
    summary = `${tool} ${str("pattern")}`;
  } else if (tool === "Task") {
    action = { type: "sub_agent", description: str("description") };
    summary = `Sub-agent: ${str("description")}`;
  } else if (tool.startsWith("mcp__")) {
    const [, server = "unknown", ...rest] = tool.split("__");
    const mtool = rest.join("__") || "unknown";
    action = { type: "mcp_call", server, tool: mtool };
    action_type = "mcp.call";
    summary = `MCP ${server} › ${mtool}`;
    const blob = JSON.stringify(ti);
    if (/ignore (all |any )?previous instructions|<\s*system\s*>/i.test(blob)) {
      findings.push({ id: "mcp.prompt_injection_marker", category: "prompt_injection_indicator", score: 58, confidence: "low", explanation: "Tool input contains text that looks like an instruction aimed at the model.", evidence: blob.slice(0, 120), mitigation: "Review the MCP server and the data source it reads from." });
    }
    if (/drop\s+table|truncate\s+table|delete\s+from\s+\w+\s*;?\s*$/i.test(blob)) {
      findings.push({ id: "mcp.db_destructive", category: "database_destructive", score: 76, confidence: "medium", explanation: "Destructive SQL is sent through an MCP database tool.", evidence: blob.slice(0, 120), mitigation: "Use a read-only database role for the MCP server." });
    }
    uncertainties.push("MCP calls go directly from the agent to the server; AgentShield only sees the tool call arguments.");
  }

  return { summary, action_type, action, tool, input: ti, parsed: null, risk: assess(findings, uncertainties), sensitive_targets: [...targets] };
}

// ---------------------------------------------------------------- policy (demo presets)

export interface DemoRule {
  id: string;
  name: string;
  decision: PolicyDecision;
  hard: boolean;
  finding: RegExp;
  reason: string;
  suggestion: string | null;
}

export const DEMO_RULES: DemoRule[] = [
  { id: "agentshield-self-protection", name: "Agents may not weaken AgentShield or their own hooks", decision: "deny", hard: true, finding: /^(tamper\.|path\.agent_configuration\.write)/, reason: "Changing agent hooks or security tooling is reserved for the user", suggestion: "Make this change yourself, outside the agent session." },
  { id: "block-catastrophic-deletes", name: "Root/home/system deletes", decision: "deny", hard: true, finding: /^shell\.rm_recursive_root$/, reason: "Catastrophic, irreversible deletion", suggestion: "Delete a specific sub-directory instead." },
  { id: "block-remote-code-execution", name: "Download-and-execute, obfuscated execution", decision: "deny", hard: false, finding: /^shell\.(download_pipe_exec|encoded_command)$/, reason: "Remote or obfuscated code execution", suggestion: "Download to a file, review it and run it yourself." },
  { id: "block-exfiltration-chains", name: "Credential read combined with network transfer", decision: "deny", hard: false, finding: /^(shell\.sensitive_read_and_network|network\.secret_in_url)$/, reason: "Possible credential exfiltration", suggestion: null },
  { id: "ask-secret-files", name: "Reading secret files needs a human", decision: "ask", hard: false, finding: /^path\.(env_file|ssh_private_key|aws_credentials)\.read$/, reason: "Secret material would enter the agent context", suggestion: "Provide a redacted example file instead." },
  { id: "ask-destructive-database", name: "Destructive database commands", decision: "ask", hard: false, finding: /^(db\.|mcp\.db_destructive)/, reason: "Destructive database operation", suggestion: "Confirm the target database first." },
  { id: "warn-package-installs", name: "New package installs are flagged", decision: "warn", hard: false, finding: /^package\.install$/, reason: "New dependency", suggestion: null },
];

export interface DemoPreset { id: string; title: string; description: string; warn: number | null; ask: number | null; deny: number | null; rules: boolean }

export const DEMO_PRESETS: DemoPreset[] = [
  { id: "developer-balanced", title: "Developer — balanced", description: "Demo preset. Blocks catastrophic actions, asks for risky ones, stays out of the way otherwise.", warn: 40, ask: 60, deny: 85, rules: true },
  { id: "strict-security", title: "Strict security", description: "Demo preset. Lower thresholds; anything medium-risk needs a human.", warn: 20, ask: 40, deny: 65, rules: true },
  { id: "observe-everything", title: "Observe everything", description: "Demo preset. Records and scores everything, never asks or denies.", warn: 40, ask: null, deny: null, rules: false },
];

const RANK: Record<PolicyDecision, number> = { allow: 0, warn: 1, ask: 2, require_sandbox: 3, deny: 4 };

export function demoPolicy(risk: RiskAssessment, presetId: string): PolicyOutcome {
  const preset = DEMO_PRESETS.find((p) => p.id === presetId) ?? DEMO_PRESETS[0]!;
  const matched: RuleMatch[] = [];
  if (preset.rules) {
    for (const r of DEMO_RULES) {
      if (risk.findings.some((f) => r.finding.test(f.id))) {
        matched.push({ id: r.id, name: r.name, decision: r.decision, hard: r.hard, reason: r.reason, suggestion: r.suggestion, layer: "preset", source: `${preset.id}.toml` });
      }
    }
  }
  let decision: PolicyDecision = "allow";
  let threshold: string | null = null;
  if (preset.deny != null && risk.score >= preset.deny) { decision = "deny"; threshold = `deny_at = ${preset.deny}`; }
  else if (preset.ask != null && risk.score >= preset.ask) { decision = "ask"; threshold = `ask_at = ${preset.ask}`; }
  else if (preset.warn != null && risk.score >= preset.warn) { decision = "warn"; threshold = `warn_at = ${preset.warn}`; }
  let winner: RuleMatch | null = null;
  for (const m of matched) if (!winner || RANK[m.decision] > RANK[winner.decision]) winner = m;
  let reason = threshold ? `Risk score ${risk.score} reached threshold ${threshold}` : "No rule matched and the score is below every threshold";
  if (winner && RANK[winner.decision] >= RANK[decision]) {
    decision = winner.decision;
    reason = winner.reason ?? reason;
    if (RANK[winner.decision] > 0) threshold = null;
  }
  return {
    decision, hard: matched.some((m) => m.hard && m.decision === decision), matched, reason,
    suggestion: winner?.suggestion ?? risk.findings[0]?.mitigation ?? null,
    policy_version: "demo-1", policy_name: preset.id, threshold,
  };
}

export function demoModeOutcome(mode: Mode, decision: PolicyDecision): ModeOutcome {
  const would = decision === "allow" ? null : decision === "warn" ? "warn" : decision === "ask" ? "ask" : "deny";
  let actual: ActualDecision = "no_opinion";
  let message: string | null = null;
  switch (mode) {
    case "monitor":
      message = would ? `Observed only. Policy result "${would}" is recorded, nothing is blocked.` : "Observed only.";
      break;
    case "shadow":
      message = would ? `Shadow: recorded as "would ${would}". The agent continues unaffected.` : "No policy effect.";
      break;
    case "interactive":
      if (decision === "ask" || decision === "deny" || decision === "require_sandbox") {
        actual = "ask";
        message = "AgentShield returns \"ask\": Claude Code shows its own permission prompt to you.";
      } else message = "Passes without a prompt from AgentShield.";
      break;
    case "enforce":
      if (decision === "deny" || decision === "require_sandbox") { actual = "deny"; message = "Blocked before execution. The agent receives the reason."; }
      else if (decision === "ask") { actual = "ask"; message = "Claude Code's permission prompt is requested."; }
      else message = "Allowed by policy.";
      break;
    case "lockdown":
      if (decision !== "allow") { actual = "deny"; message = "Lockdown: everything that is not explicitly allowed is denied."; }
      else message = "Explicitly allowed actions still pass.";
      break;
  }
  return { actual, message };
}

export const MODES: Mode[] = ["monitor", "shadow", "interactive", "enforce", "lockdown"];

export function demoSimulate(input: SimInput, activePreset: string): SimResult {
  const a = demoAnalyze(input);
  const policy = demoPolicy(a.risk, input.preset ?? activePreset);
  const modes = Object.fromEntries(MODES.map((m) => [m, demoModeOutcome(m, policy.decision)])) as Record<Mode, ModeOutcome>;
  return {
    summary: a.summary, action_type: a.action_type, parsed: a.parsed, risk: a.risk, policy, modes,
    limitations: [
      "DEMO MODE: this result comes from a simplified built-in demo analyzer, not from the AgentShield engine.",
      "Static analysis only: nothing was executed, so runtime behaviour (downloads, variable values) is unknown.",
      "Aliases, shell functions and scripts on disk are not resolved.",
    ],
    sensitive_targets: a.sensitive_targets,
  };
}
