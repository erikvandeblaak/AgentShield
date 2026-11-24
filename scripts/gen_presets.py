# Generates policies/*.toml (shared protections + per-preset rules). Usage: python scripts/gen_presets.py policies
import os, sys

OUT = sys.argv[1]

COMMON = r'''
# --- Shared protections ------------------------------------------------------------

[[rules]]
id = "agentshield-self-protection"
name = "Agents may not weaken AgentShield or their own hooks/permissions"
hard = true
[rules.match]
finding_ids = ["tamper.*", "path.agent_configuration.write", "path.agentshield_configuration.write", "mcp.path.agent_configuration.write", "mcp.path.agentshield_configuration.write"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Changing AI agent hooks, permissions or AgentShield itself is reserved for the user"
suggestion = "Make this change yourself, outside the agent session."

[[rules]]
id = "block-catastrophic-deletes"
name = "Root/home/system deletes and disk formatting"
hard = true
[rules.match]
finding_ids = ["shell.rm_recursive_root", "shell.rm_no_preserve_root", "shell.disk_format", "shell.dd_device", "shell.fork_bomb"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Catastrophic, irreversible deletion"

[[rules]]
id = "block-credential-dumping"
name = "Credential dumping tools and hive exports"
hard = true
[rules.match]
finding_ids = ["cred.dumping_tool", "cred.reg_save_hive"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Credential dumping"

[[rules]]
id = "block-known-malicious-packages"
name = "Packages listed as malicious in the OSV database"
hard = true
[rules.match]
finding_ids = ["supply.known_malicious_package"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Known malicious package (OSV)"
suggestion = "Check the package name for typos; never install packages flagged as malicious."

[[rules]]
id = "block-remote-code-execution"
name = "Download-and-execute, reverse shells, obfuscated execution"
[rules.match]
finding_ids = ["shell.download_pipe_exec", "shell.ps_download_exec", "shell.decode_pipe_exec", "network.reverse_shell", "shell.dev_tcp", "lolbin.*"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Remote or obfuscated code execution"
suggestion = "Download to a file, review it and run it yourself."

[[rules]]
id = "block-exfiltration-chains"
name = "Credential read combined with network transfer"
[rules.match]
finding_ids = ["shell.sensitive_read_and_network", "network.secret_in_url", "network.secret_in_search"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Possible credential exfiltration"
'''

ASK_SECRETS = r'''
[[rules]]
id = "ask-secret-files"
name = "Reading credential files needs approval"
[rules.match]
categories = ["secret_access"]
min_score = 60
[rules.effect]
action = "ask"
severity = "high"
reason = "Reads a credential file"
suggestion = "Add the needed (non-secret) values to a .env.example instead."
'''

BALANCED_REST = r'''
[[rules]]
id = "ask-git-history"
name = "History-rewriting git operations"
[rules.match]
finding_ids = ["git.force_push", "git.history_rewrite", "git.reflog_expire", "git.push_delete", "shell.rm_git_dir"]
[rules.effect]
action = "ask"
severity = "high"
reason = "Rewrites or deletes git history"

[[rules]]
id = "ask-system-changes"
name = "Persistence, security configuration and privilege changes"
[rules.match]
categories = ["persistence_indicator", "security_configuration_change", "privilege_escalation"]
min_score = 55
[rules.effect]
action = "ask"
severity = "high"
reason = "Changes system security, autostart or privileges"

[[rules]]
id = "ask-infrastructure"
name = "Cloud / cluster / infrastructure changes"
[rules.match]
categories = ["infrastructure_modification"]
min_score = 50
[rules.effect]
action = "ask"
severity = "high"
reason = "Modifies infrastructure"

[[rules]]
id = "ask-suspicious-packages"
name = "Possible typosquatted package or dependency confusion"
[rules.match]
finding_ids = ["supply.typosquat", "supply.dependency_confusion"]
[rules.effect]
action = "ask"
severity = "high"
reason = "Package name or index looks suspicious"
'''

BALANCED = ASK_SECRETS + BALANCED_REST

STRICT_SECRETS = r'''
[[rules]]
id = "deny-secret-files"
name = "Credential files are off limits"
[rules.match]
categories = ["secret_access"]
min_score = 60
[rules.effect]
action = "deny"
severity = "critical"
reason = "Reads a credential file"
'''


def header(name, desc, thresholds):
    t = "" if thresholds is None else "\n[thresholds]\nwarn_at = %d\nask_at = %d\ndeny_at = %d\n" % thresholds
    return f'''# AgentShield policy preset: {name}
# {desc}
# Rules are evaluated for every event; decisions only take effect in Interactive,
# Enforce and Lockdown mode. In Monitor/Shadow mode they are recorded as "would ...".
schema_version = 1
name = "{name}"
description = "{desc}"
{t}'''


READONLY_CMDS = r'''  "^(ls|dir|pwd|cd|echo|cat|type|head|tail|less|more|wc|stat|file|tree|which|where|whoami|date|uname|hostname|printf)( |$)",
  "^(grep|rg|find|fd|findstr|select-string|get-childitem|gci|get-content|gc|get-item|get-location|resolve-path|test-path|measure-object|sort|uniq|cut|awk|jq|yq|diff|cmp|du|df)( |$)",
  "^git (status|log|diff|show|branch|tag|remote -v|rev-parse|ls-files|blame|describe|shortlog|stash list|config --get|config --list)( |$)",
  "^(cargo|npm|node|python3?|php|composer|go|rustc|dotnet|java) (--version|-v|-V|version)$",'''

files = {}
files["observe-everything"] = header("observe-everything", "Record everything, never block. Risk scores are still computed and shown.", None)
files["developer-balanced"] = header("developer-balanced", "Normal development allowed; risky actions flagged; dangerous actions need approval or are denied.", (40, 70, 90)) + COMMON + BALANCED

files["strict-security"] = header("strict-security", "Tighter rules for secrets, outbound connections, packages and system changes.", (30, 50, 75)) + COMMON + STRICT_SECRETS + BALANCED_REST + r'''
[[rules]]
id = "deny-privilege-elevation"
name = "No sudo / RunAs"
[rules.match]
finding_ids = ["shell.privilege_elevation"]
[rules.effect]
action = "deny"
severity = "high"
reason = "Agents may not elevate privileges"

[[rules]]
id = "ask-data-egress"
name = "Uploads and data egress"
[rules.match]
categories = ["data_exfiltration"]
min_score = 30
[rules.effect]
action = "ask"
severity = "high"
reason = "Sends data to an external destination"

[[rules]]
id = "ask-package-changes"
name = "Every dependency change needs approval"
[rules.match]
finding_ids = ["supply.package_action"]
[rules.effect]
action = "ask"
severity = "medium"
reason = "Dependency change"

[[rules]]
id = "ask-unknown-web"
name = "Web fetches outside well-known documentation hosts"
[rules.match]
event_types = ["network.fetch"]
[rules.unless]
url_hosts = ["docs.rs", "*.rust-lang.org", "developer.mozilla.org", "*.github.com", "github.com", "raw.githubusercontent.com", "*.python.org", "*.npmjs.com", "laravel.com", "*.laravel.com", "*.php.net", "learn.microsoft.com", "*.anthropic.com", "*.claude.com", "stackoverflow.com"]
[rules.effect]
action = "ask"
severity = "medium"
reason = "Fetches content from a host outside the documentation allowlist"
'''

files["laravel-developer"] = header("laravel-developer", "Balanced preset tuned for Laravel: artisan, Composer, migrations, .env, MySQL, npm/Vite, PHPUnit/Pest.", (40, 70, 90)) + COMMON + BALANCED + r'''
[[rules]]
id = "laravel-allow-dev-loop"
name = "Everyday Laravel commands"
[rules.match]
event_types = ["shell.exec"]
all_segments_match = [
  "^php artisan (test|route:list|about|config:show|make:[a-z:-]+|optimize:clear|cache:clear|config:clear|view:clear|ide-helper:[a-z-]+|pail|serve|queue:work|schedule:list|migrate:status)( |$)",
  "^php artisan migrate( --(seed|step|pretend))*$",
  "^(\\./)?vendor/bin/(phpunit|pest|pint|phpstan)( |$)",
  "^composer (install|dump-autoload|test|run-script|validate|show|outdated|audit)( |$)",
  "^npm (run|test|ci|install)( |$)",
  "^npx vite( |$)",
]
[rules.effect]
action = "allow"
reason = "Normal Laravel development loop"

[[rules]]
id = "laravel-destructive-migrations"
name = "migrate:fresh / reset / refresh / db:wipe / --force"
[rules.match]
finding_ids = ["db.artisan_wipe", "db.artisan_migrate_force", "db.artisan_seed_force", "db.sql_drop", "db.sql_truncate", "db.sql_delete_all"]
[rules.effect]
action = "ask"
severity = "high"
reason = "Destroys or force-modifies database data"
suggestion = "Use a separate testing database (DB_DATABASE in .env.testing)."

[[rules]]
id = "laravel-env-write"
name = "Changes to .env"
[rules.match]
event_types = ["file.write", "file.edit"]
path_globs = ["**/.env", "**/.env.*"]
[rules.unless]
path_globs = ["**/.env.example"]
[rules.effect]
action = "ask"
severity = "medium"
reason = "Modifies the application environment file"
'''

files["python-developer"] = header("python-developer", "Balanced preset tuned for Python: pip, uv, Poetry, virtual environments, pytest.", (40, 70, 90)) + COMMON + BALANCED + r'''
[[rules]]
id = "python-allow-dev-loop"
name = "Everyday Python commands"
[rules.match]
event_types = ["shell.exec"]
all_segments_match = [
  "^(python3?|py) -m (pytest|unittest|mypy|ruff|black|isort|venv)( |$)",
  "^(python3?|py) -m pip (list|show|freeze|check)( |$)",
  "^(pytest|mypy|ruff|black|isort|tox|nox)( |$)",
  "^uv (sync|run|lock|venv|tree)( |$)",
  "^poetry (install|run|lock|show|check)( |$)",
  "^pip3? (list|show|freeze|check)( |$)",
]
[rules.effect]
action = "allow"
reason = "Normal Python development loop"

[[rules]]
id = "python-ask-global-pip"
name = "pip install with --user / --break-system-packages / sudo"
[rules.match]
event_types = ["shell.exec"]
command_contains = ["--break-system-packages", "pip install --user", "sudo pip"]
[rules.effect]
action = "ask"
severity = "medium"
reason = "Changes the system/user Python installation"
suggestion = "Use a virtual environment (python -m venv .venv) or uv."
'''

files["rust-developer"] = header("rust-developer", "Balanced preset tuned for Rust: Cargo, rustc, rustfmt, Clippy, build scripts.", (40, 70, 90)) + COMMON + BALANCED + r'''
[[rules]]
id = "rust-allow-dev-loop"
name = "Everyday Cargo commands"
[rules.match]
event_types = ["shell.exec"]
all_segments_match = [
  "^cargo (build|b|check|c|test|t|clippy|fmt|doc|run|r|bench|tree|metadata|nextest|llvm-cov|expand|audit)( |$)",
  "^cargo deny check( |$)",
  "^(rustc|rustfmt)( |$)",
  "^rustup (show|component list|target list)( |$)",
]
[rules.effect]
action = "allow"
reason = "Normal Rust development loop"

[[rules]]
id = "rust-warn-dependency-changes"
name = "cargo add / install"
[rules.match]
event_types = ["shell.exec"]
programs = ["cargo"]
finding_ids = ["supply.package_action"]
[rules.effect]
action = "warn"
severity = "low"
reason = "Adds a dependency or installs a binary; build scripts (build.rs) and proc-macros run arbitrary code at build time"
'''

files["read-only"] = header("read-only", "Observe; deny file changes and non read-only commands where the integration can enforce it.", (40, 60, 85)) + COMMON + r'''
[[rules]]
id = "readonly-deny-file-changes"
name = "No file writes or edits"
[rules.match]
event_types = ["file.write", "file.edit"]
[rules.effect]
action = "deny"
severity = "high"
reason = "Read-only policy: file changes are not allowed"

[[rules]]
id = "readonly-deny-mutating-commands"
name = "Only read-only shell commands"
[rules.match]
event_types = ["shell.exec"]
[rules.unless]
all_segments_match = [
''' + READONLY_CMDS + r'''
]
[rules.effect]
action = "deny"
severity = "high"
reason = "Read-only policy: only inspection commands are allowed"

[[rules]]
id = "readonly-deny-mutating-mcp"
name = "No mutating MCP tools"
[rules.match]
event_types = ["mcp.call"]
finding_ids = ["mcp.write_capability", "mcp.destructive_capability", "mcp.exec_capability", "mcp.egress_capability"]
[rules.effect]
action = "deny"
severity = "high"
reason = "Read-only policy: MCP tool can modify state"
''' + ASK_SECRETS

files["production-server"] = header("production-server", "Very restrictive policy for agents on servers: read-only inspection only, no network, no MCP.", (20, 30, 50)) + COMMON + r'''
[[rules]]
id = "prod-deny-file-changes"
name = "No file writes or edits"
[rules.match]
event_types = ["file.write", "file.edit"]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Production server: file changes are not allowed"

[[rules]]
id = "prod-only-inspection-commands"
name = "Only inspection commands"
[rules.match]
event_types = ["shell.exec"]
[rules.unless]
all_segments_match = [
''' + READONLY_CMDS + r'''
  "^(systemctl status|journalctl|ps|free|uptime|docker ps|docker logs|kubectl get|kubectl describe|kubectl logs)( |$)",
]
[rules.effect]
action = "deny"
severity = "critical"
reason = "Production server: only inspection commands are allowed"

[[rules]]
id = "prod-no-network"
name = "No web fetch / search"
[rules.match]
event_types = ["network.fetch", "network.search"]
[rules.effect]
action = "deny"
severity = "high"
reason = "Production server: no outbound web access from the agent"

[[rules]]
id = "prod-no-mcp"
name = "No MCP tools"
[rules.match]
event_types = ["mcp.call"]
[rules.effect]
action = "deny"
severity = "high"
reason = "Production server: MCP tools are disabled"

[[rules]]
id = "prod-deny-secret-files"
name = "Credential files are off limits"
[rules.match]
categories = ["secret_access", "credential_exposure"]
min_score = 40
[rules.effect]
action = "deny"
severity = "critical"
reason = "Production server: credential access"
'''

files["database-safety"] = header("database-safety", "Balanced preset plus strict handling of destructive database commands.", (40, 70, 90)) + COMMON + BALANCED + r'''
[[rules]]
id = "db-deny-destructive"
name = "DROP / TRUNCATE / wipe / flush"
[rules.match]
categories = ["database_destructive"]
min_score = 75
[rules.effect]
action = "deny"
severity = "critical"
reason = "Destructive database operation"
suggestion = "Take a backup and run this yourself against the intended database."

[[rules]]
id = "db-ask-risky"
name = "Risky database operations"
[rules.match]
categories = ["database_destructive"]
min_score = 40
max_score = 74
[rules.effect]
action = "ask"
severity = "high"
reason = "Database operation that may lose data"
'''

for k, v in files.items():
    with open(os.path.join(OUT, f"{k}.toml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(v.strip() + "\n")
print(sorted(files))
