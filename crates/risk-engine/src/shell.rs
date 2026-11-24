//! Shell command detectors. Operates on the parsed structure (programs, flags, pipes,
//! redirections), never on regexes over the raw string alone.

use crate::{
    RiskContext, assess_path, assess_url, expand_home, extract_urls, finding, looks_like_path,
};
use agentshield_command_parser::{ParsedCommand, Segment};
use agentshield_event_model::{Confidence as Cf, Finding, RiskCategory as C};
use agentshield_secret_detector::{SensitiveKind, classify_path, normalize_path};

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "iex",
    "invoke-expression",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "node",
    "perl",
    "ruby",
    "php",
    "cmd",
];
const NET_TOOLS: &[&str] = &[
    "curl",
    "wget",
    "iwr",
    "invoke-webrequest",
    "irm",
    "invoke-restmethod",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "scp",
    "sftp",
    "ftp",
    "tftp",
    "rsync",
    "ssh",
    "telnet",
    "http",
    "https",
    "xh",
    "aria2c",
    "start-bitstransfer",
    "bitsadmin",
    "send-mailmessage",
    "certutil",
];
const READERS: &[&str] = &[
    "cat",
    "type",
    "more",
    "less",
    "head",
    "tail",
    "get-content",
    "gc",
    "bat",
    "nl",
    "strings",
    "xxd",
    "od",
    "hexdump",
    "base64",
    "base32",
    "grep",
    "rg",
    "egrep",
    "awk",
    "sort",
    "uniq",
    "jq",
    "yq",
    "findstr",
    "select-string",
    "sls",
    "openssl",
    "gpg",
    "ssh-keygen",
    "cp",
    "copy",
    "copy-item",
    "cpi",
    "scp",
    "rsync",
    "zip",
    "tar",
    "7z",
    "compress-archive",
    "curl",
    "wget",
    "iwr",
    "invoke-webrequest",
    "irm",
    "invoke-restmethod",
    "nc",
    "ncat",
    "vim",
    "vi",
    "nano",
    "code",
    "notepad",
    "source",
    ".",
    "import-csv",
    "get-filehash",
    "md5sum",
    "sha256sum",
    "sed",
    "cut",
    "tac",
    "view",
    "pg",
    "wc",
];
const WRITERS: &[&str] = &[
    "tee",
    "tee-object",
    "set-content",
    "sc",
    "add-content",
    "ac",
    "out-file",
    "touch",
    "truncate",
    "install",
    "ln",
    "new-item",
    "ni",
    "mv",
    "move",
    "move-item",
    "mi",
    "ren",
    "rename",
    "rename-item",
    "chmod",
    "chown",
    "icacls",
    "attrib",
    "dd",
    "patch",
];
const DELETERS: &[&str] = &[
    "rm",
    "del",
    "erase",
    "rd",
    "rmdir",
    "remove-item",
    "ri",
    "unlink",
    "shred",
    "srm",
];

/// Keywords in inline interpreter code and what they indicate. Built with `concat!` so that
/// source scanners do not mistake the detector strings for actual calls.
const INLINE_CODE_HINTS: &[(&str, &str)] = &[
    ("subprocess", "spawns processes"),
    (concat!("os.", "system"), "spawns processes"),
    (concat!("child_", "process"), "spawns processes"),
    (concat!("ex", "ec("), "dynamic code execution"),
    (concat!("ev", "al("), "dynamic code execution"),
    ("socket", "opens sockets"),
    ("urllib", "network access"),
    ("requests.", "network access"),
    ("http.request", "network access"),
    ("fetch(", "network access"),
    ("b64decode", "decodes payloads"),
    ("rmtree", "recursive delete"),
    ("unlink", "deletes files"),
];

fn has_any(seg: &Segment, flags: &[&str]) -> bool {
    seg.has_flag(flags)
}

/// Short flag cluster contains a letter (e.g. `-rf` contains `r`).
fn short_has(seg: &Segment, c: char) -> bool {
    seg.args
        .iter()
        .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
}

fn ev(seg: &Segment) -> Option<String> {
    Some(seg.joined())
}

fn is_root_like(t: &str) -> bool {
    let n = normalize_path(t);
    let n = n.trim_end_matches(['*', '/']).to_string();
    matches!(
        n.as_str(),
        "" | "~"
            | "$home"
            | "${home}"
            | "."
            | ".."
            | "c:"
            | "d:"
            | "/etc"
            | "/usr"
            | "/var"
            | "/boot"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/opt"
            | "/home"
            | "/root"
            | "/srv"
            | "c:/windows"
            | "c:/users"
            | "c:/program files"
            | "c:/program files (x86)"
            | "$env:userprofile"
            | "%userprofile%"
            | "$env:systemroot"
            | "%systemroot%"
            | "/system"
            | "/users"
    ) || n.starts_with("/home/") && n.matches('/').count() == 2
        || n.starts_with("c:/users/") && n.matches('/').count() == 2
        || n.starts_with("/users/") && n.matches('/').count() == 2
}

pub(crate) fn assess_parsed(pc: &ParsedCommand, raw: &str, ctx: &RiskContext) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let segs = pc.all_segments();
    let lraw = raw.to_ascii_lowercase();

    // --- whole-command patterns -------------------------------------------------------
    let downloads = segs.iter().any(|s| {
        matches!(
            s.program.as_str(),
            "curl" | "wget" | "iwr" | "invoke-webrequest" | "irm" | "invoke-restmethod" | "fetch"
        )
    });
    if downloads && pc.pipes_into(SHELLS) {
        out.push(finding("shell.download_pipe_exec", C::SupplyChainCompromise, 90, Cf::High,
            "Downloads a script and pipes it straight into an interpreter (remote code execution without review)",
            Some(raw.to_string()), Some("Download the script to a file, review it, verify a checksum, then run it.")));
    }
    if (lraw.contains("downloadstring")
        || lraw.contains("downloadfile")
        || lraw.contains("net.webclient"))
        && (lraw.contains("iex") || lraw.contains("invoke-expression"))
    {
        out.push(finding(
            "shell.ps_download_exec",
            C::SupplyChainCompromise,
            90,
            Cf::High,
            "PowerShell download cradle (DownloadString + Invoke-Expression)",
            Some(raw.to_string()),
            None,
        ));
    }
    if segs.iter().any(|s| {
        matches!(s.program.as_str(), "base64" | "base32" | "xxd" | "openssl")
            && (has_any(s, &["-d", "--decode", "-r", "-D"])
                || s.args.iter().any(|a| a == "enc" || a == "-base64"))
    }) && pc.pipes_into(SHELLS)
    {
        out.push(finding(
            "shell.decode_pipe_exec",
            C::ObfuscatedExecution,
            85,
            Cf::High,
            "Decodes an encoded payload and executes it (obfuscated execution)",
            Some(raw.to_string()),
            None,
        ));
    }
    if !pc.all_decoded().is_empty() {
        out.push(finding("shell.encoded_command", C::ObfuscatedExecution, 60, Cf::High,
            "Uses an encoded command payload (PowerShell -EncodedCommand); decoded content was analyzed",
            pc.all_decoded().first().cloned(), Some("Run plain, readable commands.")));
    }
    if lraw.contains("/dev/tcp/") || lraw.contains("/dev/udp/") {
        out.push(finding(
            "shell.dev_tcp",
            C::DataExfiltration,
            90,
            Cf::High,
            "Uses /dev/tcp network redirection (typical for reverse shells or raw data transfer)",
            Some(raw.to_string()),
            None,
        ));
    }
    if raw.contains(":(){") || raw.contains(":() {") {
        out.push(finding(
            "shell.fork_bomb",
            C::DestructiveOperation,
            80,
            Cf::High,
            "Fork bomb pattern",
            Some(raw.to_string()),
            None,
        ));
    }
    for code in pc.all_inline_code() {
        let lc = code.to_ascii_lowercase();
        let mut hits: Vec<&str> = Vec::new();
        for (k, d) in INLINE_CODE_HINTS {
            if lc.contains(k) && !hits.contains(d) {
                hits.push(d);
            }
        }
        if !hits.is_empty() {
            out.push(finding(
                "shell.inline_code_capabilities",
                C::ObfuscatedExecution,
                45,
                Cf::Low,
                format!("Inline interpreter code: {}", hits.join(", ")),
                Some(code.clone()),
                Some("Write the script to a file in the project so it can be reviewed."),
            ));
        }
        for u in extract_urls(&code) {
            out.extend(assess_url(&u).findings);
        }
        for tok in
            code.split(|c: char| c == '\'' || c == '"' || c.is_whitespace() || c == '(' || c == ')')
        {
            if looks_like_path(tok) {
                out.extend(
                    assess_path(tok, false, ctx)
                        .into_iter()
                        .filter(|f| f.score >= 60),
                );
            }
        }
    }

    // --- per-segment detectors --------------------------------------------------------
    let mut sensitive_read = false;
    let mut network_seg = false;
    for seg in &segs {
        let p = seg.program.as_str();
        if NET_TOOLS.contains(&p) {
            network_seg = true;
        }
        if seg.elevated() {
            out.push(finding("shell.privilege_elevation", C::PrivilegeEscalation, 60, Cf::High,
                format!("Runs '{}' with elevated privileges ({})", p, seg.wrappers.join(" ")), ev(seg),
                Some("Agents should not run commands as root/administrator; do it yourself if needed.")));
        }
        destructive(seg, &mut out);
        git(seg, &mut out);
        network(seg, &mut out);
        credentials(seg, &mut out);
        persistence(seg, &mut out);
        security_config(seg, &lraw, &mut out);
        infra(seg, &mut out);
        database(seg, &mut out);
        lolbins(seg, &mut out);
        agent_tamper(seg, &mut out);
        if let Some(pa) = agentshield_supply_chain::detect(seg) {
            let mut fs = agentshield_supply_chain::assess(&pa);
            if seg.elevated() {
                for f in &mut fs {
                    f.score = f.score.saturating_add(10).min(100);
                }
            }
            out.extend(fs);
        }

        // Paths in arguments and redirections.
        let write_semantics = WRITERS.contains(&p)
            || DELETERS.contains(&p)
            || (p == "sed" && seg.args.iter().any(|a| a.starts_with("-i")));
        let positional = seg.positional();
        for (i, a) in positional.iter().enumerate() {
            if !looks_like_path(a) {
                continue;
            }
            let expanded = expand_home(a, ctx);
            let Some(sp) = classify_path(&expanded) else {
                continue;
            };
            // For cp/mv/copy the last positional is the destination.
            let is_dest = matches!(
                p,
                "cp" | "copy" | "copy-item" | "cpi" | "mv" | "move" | "move-item" | "mi"
            ) && i == positional.len() - 1
                && positional.len() > 1;
            let write = write_semantics || is_dest;
            if !write && sp.kind.read_is_secret_access() {
                sensitive_read = true;
            }
            let mut fs = assess_path(a, write, ctx);
            if !write && !READERS.contains(&p) {
                for f in &mut fs {
                    f.score = f.score.saturating_sub(10);
                    f.confidence = Cf::Medium;
                    f.explanation = format!("{} (referenced by '{p}')", f.explanation);
                }
            }
            if DELETERS.contains(&p)
                && matches!(
                    sp.kind,
                    SensitiveKind::AgentShieldConfiguration | SensitiveKind::AgentConfiguration
                )
            {
                for f in &mut fs {
                    f.explanation =
                        format!("Deletes {}", f.explanation.trim_start_matches("Modifies "));
                }
            }
            out.extend(fs);
        }
        for r in &seg.redirections {
            if r.writes_file() {
                out.extend(assess_path(&r.target, true, ctx));
            } else if r.op.starts_with('<') && !r.target.is_empty() {
                if classify_path(&expand_home(&r.target, ctx))
                    .is_some_and(|s| s.kind.read_is_secret_access())
                {
                    sensitive_read = true;
                }
                out.extend(assess_path(&r.target, false, ctx));
            }
        }
        for a in &seg.args {
            for u in extract_urls(a) {
                out.extend(assess_url(&u).findings);
            }
        }
    }

    // Sensitive read + network in the same command line => likely exfiltration.
    if sensitive_read && network_seg {
        out.push(finding("shell.sensitive_read_and_network", C::DataExfiltration, 92, Cf::Medium,
            "Reads a credential file and uses a network tool in the same command (possible exfiltration)",
            Some(raw.to_string()), Some("Never let an agent combine credential files with network transfers.")));
    }
    out
}

fn destructive(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let pos = seg.positional();
    match p {
        "rm" | "srm" => {
            let recursive =
                short_has(seg, 'r') || short_has(seg, 'R') || has_any(seg, &["--recursive"]);
            let force = short_has(seg, 'f') || has_any(seg, &["--force"]);
            let roots: Vec<&str> = pos.iter().copied().filter(|t| is_root_like(t)).collect();
            if has_any(seg, &["--no-preserve-root"]) {
                out.push(finding(
                    "shell.rm_no_preserve_root",
                    C::DestructiveOperation,
                    98,
                    Cf::High,
                    "rm with --no-preserve-root",
                    ev(seg),
                    None,
                ));
            } else if recursive && !roots.is_empty() {
                out.push(finding(
                    "shell.rm_recursive_root",
                    C::DestructiveOperation,
                    95,
                    Cf::High,
                    format!(
                        "Recursively deletes a root, home or system directory ({})",
                        roots.join(", ")
                    ),
                    ev(seg),
                    Some("Delete specific build artefacts only, e.g. rm -rf ./target."),
                ));
            } else if recursive
                && pos.iter().any(|t| {
                    let n = normalize_path(t);
                    n == ".git" || n.ends_with("/.git") || n.ends_with("/.git/") || n == ".git/"
                })
            {
                out.push(finding(
                    "shell.rm_git_dir",
                    C::GitRepositoryDamage,
                    80,
                    Cf::High,
                    "Deletes the .git directory (entire repository history)",
                    ev(seg),
                    None,
                ));
            } else if recursive && force {
                out.push(finding(
                    "shell.rm_recursive_force",
                    C::DestructiveOperation,
                    50,
                    Cf::High,
                    "Recursive forced delete",
                    ev(seg),
                    Some("Double-check the target directory."),
                ));
            } else if recursive {
                out.push(finding(
                    "shell.rm_recursive",
                    C::DestructiveOperation,
                    35,
                    Cf::High,
                    "Recursive delete",
                    ev(seg),
                    None,
                ));
            }
        }
        "remove-item" | "ri" | "rd" | "rmdir" | "del" | "erase" => {
            let recursive = has_any(seg, &["-recurse", "-r", "/s"]);
            let force = has_any(seg, &["-force", "/q", "/f"]);
            let roots: Vec<&str> = seg
                .args
                .iter()
                .map(|s| s.as_str())
                .filter(|t| {
                    !t.starts_with('-') && !(t.starts_with('/') && t.len() == 2) && is_root_like(t)
                })
                .collect();
            if recursive && !roots.is_empty() {
                out.push(finding(
                    "shell.rm_recursive_root",
                    C::DestructiveOperation,
                    95,
                    Cf::High,
                    format!(
                        "Recursively deletes a root, profile or system directory ({})",
                        roots.join(", ")
                    ),
                    ev(seg),
                    None,
                ));
            } else if recursive && force {
                out.push(finding(
                    "shell.rm_recursive_force",
                    C::DestructiveOperation,
                    50,
                    Cf::High,
                    "Recursive forced delete",
                    ev(seg),
                    None,
                ));
            } else if recursive {
                out.push(finding(
                    "shell.rm_recursive",
                    C::DestructiveOperation,
                    35,
                    Cf::High,
                    "Recursive delete",
                    ev(seg),
                    None,
                ));
            }
        }
        "find"
            if has_any(seg, &["-delete"])
                || seg
                    .args
                    .windows(2)
                    .any(|w| w[0] == "-exec" && matches!(w[1].as_str(), "rm" | "shred")) =>
        {
            let root = seg.args.first().map(|a| is_root_like(a)).unwrap_or(false);
            out.push(finding(
                "shell.find_delete",
                C::DestructiveOperation,
                if root { 90 } else { 50 },
                Cf::High,
                "find with -delete / -exec rm",
                ev(seg),
                None,
            ));
        }
        "mkfs" | "mkfs.ext4" | "mkfs.ext3" | "mkfs.xfs" | "mkfs.btrfs" | "mkfs.vfat"
        | "mkfs.ntfs" | "mke2fs" | "wipefs" | "format" | "format-volume" | "clear-disk"
        | "diskpart" | "fdisk" | "parted" | "sgdisk" => {
            out.push(finding(
                "shell.disk_format",
                C::DestructiveOperation,
                97,
                Cf::High,
                format!("Disk partitioning / formatting tool '{p}'"),
                ev(seg),
                None,
            ));
        }
        "dd" if seg
            .args
            .iter()
            .any(|a| a.starts_with("of=/dev/") && !a.starts_with("of=/dev/null")) =>
        {
            out.push(finding(
                "shell.dd_device",
                C::DestructiveOperation,
                97,
                Cf::High,
                "dd writes directly to a block device",
                ev(seg),
                None,
            ));
        }
        "shred" => out.push(finding(
            "shell.shred",
            C::DestructiveOperation,
            60,
            Cf::High,
            "Irrecoverably overwrites files",
            ev(seg),
            None,
        )),
        "chmod" => {
            let recursive = short_has(seg, 'R') || has_any(seg, &["--recursive"]);
            if seg.args.iter().any(|a| {
                a.contains("+s")
                    || (a.len() == 4
                        && (a.starts_with('4') || a.starts_with('2') || a.starts_with('6'))
                        && a.chars().all(|c| c.is_ascii_digit()))
            }) {
                out.push(finding(
                    "shell.setuid",
                    C::PrivilegeEscalation,
                    80,
                    Cf::High,
                    "Sets the setuid/setgid bit",
                    ev(seg),
                    None,
                ));
            } else if seg
                .args
                .iter()
                .any(|a| a == "777" || a == "a+rwx" || a == "0777" || a == "o+w")
            {
                let root = pos.iter().any(|t| is_root_like(t));
                out.push(finding(
                    "shell.chmod_world_writable",
                    C::SecurityConfigurationChange,
                    if recursive && root { 85 } else { 40 },
                    Cf::High,
                    "Makes files world-writable",
                    ev(seg),
                    Some("Use the narrowest permissions possible (e.g. 644/755)."),
                ));
            }
        }
        "chown"
            if (short_has(seg, 'R') || has_any(seg, &["--recursive"]))
                && pos.iter().any(|t| is_root_like(t)) =>
        {
            out.push(finding(
                "shell.chown_root_recursive",
                C::DestructiveOperation,
                80,
                Cf::High,
                "Recursively changes ownership of a system or home directory",
                ev(seg),
                None,
            ));
        }
        "icacls"
            if seg.args.iter().any(|a| {
                a.to_ascii_lowercase().contains("everyone:") || a.eq_ignore_ascii_case("/grant")
            }) =>
        {
            out.push(finding(
                "shell.icacls_grant",
                C::SecurityConfigurationChange,
                50,
                Cf::Medium,
                "Changes Windows file ACLs",
                ev(seg),
                None,
            ));
        }
        "docker" | "podman"
            if seg.args.first().map(|a| a.as_str()) == Some("system")
                && has_any(seg, &["prune"])
                && has_any(seg, &["-a", "--all", "--volumes"]) =>
        {
            out.push(finding(
                "shell.docker_prune_all",
                C::DestructiveOperation,
                55,
                Cf::High,
                "Removes all unused Docker images/volumes",
                ev(seg),
                None,
            ));
        }
        "docker" | "podman"
            if seg.args.first().map(|a| a.as_str()) == Some("volume")
                && seg.args.get(1).is_some_and(|a| a == "rm" || a == "prune") =>
        {
            out.push(finding(
                "shell.docker_volume_rm",
                C::DestructiveOperation,
                60,
                Cf::High,
                "Deletes Docker volumes (persistent data)",
                ev(seg),
                None,
            ));
        }
        _ => {}
    }
}

fn git(seg: &Segment, out: &mut Vec<Finding>) {
    if seg.program != "git" {
        return;
    }
    // Skip global options like `-C dir`, `-c k=v` before the subcommand.
    let mut args: Vec<String> = Vec::new();
    let mut raw_args: Vec<&str> = Vec::new();
    let mut skip = false;
    for a in &seg.args {
        if skip {
            skip = false;
            continue;
        }
        if args.is_empty() && matches!(a.as_str(), "-c" | "-C" | "--git-dir" | "--work-tree") {
            skip = true;
            continue;
        }
        args.push(a.to_ascii_lowercase());
        raw_args.push(a.as_str());
    }
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    let has = |f: &str| args.iter().any(|a| a == f);
    let has_raw = |f: &str| raw_args.contains(&f);
    let e = ev(seg);
    match sub {
        "push" => {
            if has("--force") || has("-f") || args.iter().skip(1).any(|a| a.starts_with('+')) {
                out.push(finding(
                    "git.force_push",
                    C::GitRepositoryDamage,
                    72,
                    Cf::High,
                    "Force push rewrites remote history (others can lose commits)",
                    e,
                    Some("Use --force-with-lease, or push a new branch."),
                ));
            } else if args.iter().any(|a| a.starts_with("--force-with-lease")) {
                out.push(finding(
                    "git.force_with_lease",
                    C::GitRepositoryDamage,
                    45,
                    Cf::High,
                    "Force push with lease rewrites remote history",
                    e,
                    None,
                ));
            } else if has("--mirror")
                || has("--delete")
                || has("-d")
                || args.iter().skip(1).any(|a| a.starts_with(':'))
            {
                out.push(finding(
                    "git.push_delete",
                    C::GitRepositoryDamage,
                    65,
                    Cf::High,
                    "Deletes remote refs or mirrors the repository",
                    e,
                    None,
                ));
            } else {
                out.push(finding(
                    "git.push",
                    C::DataExfiltration,
                    15,
                    Cf::High,
                    "Publishes commits to a remote",
                    e,
                    None,
                ));
            }
        }
        "reset" if has("--hard") => out.push(finding(
            "git.reset_hard",
            C::GitRepositoryDamage,
            50,
            Cf::High,
            "Discards uncommitted work (git reset --hard)",
            e,
            Some("Stash first: git stash push -u."),
        )),
        "clean"
            if args
                .iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
                || has("--force") =>
        {
            let x = args.iter().any(|a| {
                a.starts_with('-') && !a.starts_with("--") && (a.contains('x') || a.contains('d'))
            });
            out.push(finding(
                "git.clean_force",
                C::GitRepositoryDamage,
                if x { 58 } else { 45 },
                Cf::High,
                "Deletes untracked files permanently (git clean)",
                e,
                Some("Preview with git clean -n."),
            ));
        }
        "checkout" | "restore" if has(".") => out.push(finding(
            "git.discard_changes",
            C::GitRepositoryDamage,
            45,
            Cf::Medium,
            "Discards local modifications",
            e,
            None,
        )),
        "branch" if has_raw("-D") || (has("-d") && has("--force")) => out.push(finding(
            "git.branch_force_delete",
            C::GitRepositoryDamage,
            40,
            Cf::High,
            "Force-deletes a branch",
            e,
            None,
        )),
        "filter-branch" | "filter-repo" => out.push(finding(
            "git.history_rewrite",
            C::GitRepositoryDamage,
            72,
            Cf::High,
            "Rewrites the entire repository history",
            e,
            None,
        )),
        "reflog" if has("expire") => out.push(finding(
            "git.reflog_expire",
            C::GitRepositoryDamage,
            62,
            Cf::High,
            "Expires the reflog (removes recovery points)",
            e,
            None,
        )),
        "gc" if args.iter().any(|a| a.starts_with("--prune=now")) => out.push(finding(
            "git.gc_prune_now",
            C::GitRepositoryDamage,
            55,
            Cf::High,
            "Prunes unreachable objects immediately (no recovery)",
            e,
            None,
        )),
        "stash" if has("clear") || has("drop") => out.push(finding(
            "git.stash_drop",
            C::GitRepositoryDamage,
            40,
            Cf::High,
            "Drops stashed work",
            e,
            None,
        )),
        "remote" if has("add") || has("set-url") => out.push(finding(
            "git.remote_change",
            C::DataExfiltration,
            45,
            Cf::Medium,
            "Adds or changes a git remote (code could be pushed elsewhere)",
            e,
            None,
        )),
        "config" => {
            if args.iter().any(|a| {
                a == "core.hookspath"
                    || a == "core.fsmonitor"
                    || a == "core.sshcommand"
                    || a.starts_with("alias.")
            }) {
                out.push(finding("git.config_exec", C::PersistenceIndicator, 65, Cf::High, "Configures git to run a program automatically (hooksPath/fsmonitor/sshCommand/alias)", e, None));
            } else if args.iter().any(|a| a.starts_with("credential")) {
                out.push(finding(
                    "git.config_credential",
                    C::CredentialExposure,
                    50,
                    Cf::Medium,
                    "Reads or changes git credential configuration",
                    e,
                    None,
                ));
            }
        }
        "credential" | "credential-manager" | "credential-store" => out.push(finding(
            "git.credential_access",
            C::SecretAccess,
            75,
            Cf::High,
            "Queries the git credential helper (returns stored passwords/tokens)",
            e,
            None,
        )),
        _ => {}
    }
}

fn network(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let e = ev(seg);
    match p {
        "curl" | "http" | "https" | "xh" => {
            let file_upload = seg
                .args
                .iter()
                .any(|a| a.starts_with('@') || a.contains("=@") || a.starts_with("-d@"))
                || la.iter().any(|a| a == "-t" || a == "--upload-file");
            let body = la.iter().any(|a| {
                a == "-d"
                    || a.starts_with("--data")
                    || a == "-f"
                    || a.starts_with("--form")
                    || a == "--json"
            });
            if file_upload {
                out.push(finding(
                    "network.file_upload",
                    C::DataExfiltration,
                    60,
                    Cf::High,
                    "Uploads a local file to a remote server",
                    e,
                    None,
                ));
            } else if body {
                out.push(finding(
                    "network.data_upload",
                    C::DataExfiltration,
                    30,
                    Cf::Medium,
                    "Sends data in a request body",
                    e,
                    None,
                ));
            }
            if la.iter().any(|a| a == "-k" || a == "--insecure") {
                out.push(finding(
                    "network.tls_disabled",
                    C::UnsafeNetworkAccess,
                    40,
                    Cf::High,
                    "TLS certificate verification disabled",
                    ev(seg),
                    None,
                ));
            }
        }
        "wget" => {
            if la
                .iter()
                .any(|a| a.starts_with("--post-file") || a.starts_with("--body-file"))
            {
                out.push(finding(
                    "network.file_upload",
                    C::DataExfiltration,
                    60,
                    Cf::High,
                    "Uploads a local file to a remote server",
                    e,
                    None,
                ));
            }
            if la.iter().any(|a| a == "--no-check-certificate") {
                out.push(finding(
                    "network.tls_disabled",
                    C::UnsafeNetworkAccess,
                    40,
                    Cf::High,
                    "TLS certificate verification disabled",
                    ev(seg),
                    None,
                ));
            }
        }
        "iwr" | "invoke-webrequest" | "irm" | "invoke-restmethod" => {
            if la.iter().any(|a| a == "-infile") {
                out.push(finding(
                    "network.file_upload",
                    C::DataExfiltration,
                    60,
                    Cf::High,
                    "Uploads a local file to a remote server",
                    e,
                    None,
                ));
            } else if la.iter().any(|a| a == "-body")
                && la
                    .windows(2)
                    .any(|w| w[0] == "-method" && matches!(w[1].as_str(), "post" | "put" | "patch"))
            {
                out.push(finding(
                    "network.data_upload",
                    C::DataExfiltration,
                    30,
                    Cf::Medium,
                    "Sends data in a request body",
                    e,
                    None,
                ));
            }
            if la.iter().any(|a| a == "-skipcertificatecheck") {
                out.push(finding(
                    "network.tls_disabled",
                    C::UnsafeNetworkAccess,
                    40,
                    Cf::High,
                    "TLS certificate verification disabled",
                    ev(seg),
                    None,
                ));
            }
        }
        "nc" | "ncat" | "netcat" | "socat" => {
            let exec = la.iter().any(|a| {
                a == "-e"
                    || a == "-c"
                    || a == "--exec"
                    || a == "--sh-exec"
                    || a.starts_with("exec:")
                    || a.starts_with("system:")
            });
            let listen = la.iter().any(|a| {
                a == "-l"
                    || a == "-lp"
                    || a == "-lvp"
                    || a == "-nlvp"
                    || a.starts_with("tcp-listen")
            });
            if exec {
                out.push(finding(
                    "network.reverse_shell",
                    C::PrivilegeEscalation,
                    95,
                    Cf::High,
                    "Netcat/socat bound to a shell (reverse or bind shell)",
                    e,
                    None,
                ));
            } else if listen {
                out.push(finding(
                    "network.listener",
                    C::UnsafeNetworkAccess,
                    60,
                    Cf::High,
                    "Opens a raw network listener",
                    e,
                    None,
                ));
            } else {
                out.push(finding(
                    "network.raw_socket",
                    C::UnsafeNetworkAccess,
                    55,
                    Cf::High,
                    "Raw TCP/UDP connection tool",
                    e,
                    None,
                ));
            }
        }
        "scp" | "rsync" | "sftp" => {
            let remote = seg
                .positional()
                .iter()
                .any(|a| a.contains(':') && !(a.len() > 1 && a.as_bytes()[1] == b':'));
            if remote {
                out.push(finding(
                    "network.remote_copy",
                    C::DataExfiltration,
                    50,
                    Cf::Medium,
                    "Copies files to/from a remote host",
                    e,
                    None,
                ));
            }
        }
        "ssh" => {
            if seg.has_flag(&["-R", "-D", "-w"]) || seg.args.iter().any(|a| a == "-R" || a == "-D")
            {
                out.push(finding(
                    "network.ssh_tunnel",
                    C::UnsafeNetworkAccess,
                    55,
                    Cf::High,
                    "Creates an SSH tunnel / port forward",
                    e,
                    None,
                ));
            } else {
                out.push(finding(
                    "network.ssh",
                    C::UnsafeNetworkAccess,
                    30,
                    Cf::High,
                    "Opens an SSH session to another host",
                    e,
                    None,
                ));
            }
        }
        "telnet" | "ftp" | "tftp" => out.push(finding(
            "network.plaintext_tool",
            C::UnsafeNetworkAccess,
            45,
            Cf::High,
            format!("Plaintext network tool '{p}'"),
            e,
            None,
        )),
        "send-mailmessage" => out.push(finding(
            "network.send_mail",
            C::DataExfiltration,
            55,
            Cf::High,
            "Sends e-mail",
            e,
            None,
        )),
        _ => {}
    }
}

fn credentials(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let first = la.first().map(|s| s.as_str()).unwrap_or("");
    let e = ev(seg);
    match p {
        "env" | "printenv" if seg.positional().is_empty() => out.push(finding(
            "cred.dump_environment",
            C::CredentialExposure,
            45,
            Cf::High,
            "Dumps all environment variables (often contain API keys)",
            e,
            Some("Print only the variable you need."),
        )),
        "set" if seg.args.is_empty() => out.push(finding(
            "cred.dump_environment",
            C::CredentialExposure,
            40,
            Cf::Medium,
            "Dumps all environment variables (cmd 'set')",
            e,
            None,
        )),
        "get-childitem" | "gci" | "ls" | "dir" | "get-item"
            if la.iter().any(|a| a.starts_with("env:")) =>
        {
            out.push(finding(
                "cred.dump_environment",
                C::CredentialExposure,
                45,
                Cf::High,
                "Lists environment variables",
                e,
                None,
            ))
        }
        "echo" | "printf" | "write-host" | "write-output" => {
            let names = [
                "secret",
                "token",
                "password",
                "passwd",
                "api_key",
                "apikey",
                "access_key",
                "private_key",
                "credential",
            ];
            if seg.args.iter().any(|a| {
                (a.contains('$') || a.contains('%'))
                    && names.iter().any(|n| a.to_ascii_lowercase().contains(n))
            }) {
                out.push(finding(
                    "cred.print_secret_var",
                    C::CredentialExposure,
                    55,
                    Cf::High,
                    "Prints a secret-looking environment variable",
                    e,
                    None,
                ));
            }
        }
        "history" if !la.iter().any(|a| a == "-c" || a == "-w") => out.push(finding(
            "cred.shell_history",
            C::CredentialExposure,
            25,
            Cf::Medium,
            "Reads shell history (may contain credentials)",
            e,
            None,
        )),
        "cmdkey" if la.iter().any(|a| a == "/list") => out.push(finding(
            "cred.cmdkey_list",
            C::SecretAccess,
            55,
            Cf::High,
            "Lists stored Windows credentials",
            e,
            None,
        )),
        "vaultcmd" | "get-storedcredential" | "secret-tool" | "keyring" | "op" | "bw" | "lpass" => {
            out.push(finding(
                "cred.secret_store",
                C::SecretAccess,
                75,
                Cf::High,
                format!("Accesses a credential store via '{p}'"),
                e,
                None,
            ));
        }
        "security" if first.starts_with("find-") || first == "dump-keychain" => out.push(finding(
            "cred.secret_store",
            C::SecretAccess,
            75,
            Cf::High,
            "Reads the macOS keychain",
            e,
            None,
        )),
        "gh" if first == "auth"
            && (la.iter().any(|a| a == "token")
                || la.iter().any(|a| a == "--show-token" || a == "-t")) =>
        {
            out.push(finding(
                "cred.gh_token",
                C::SecretAccess,
                75,
                Cf::High,
                "Prints the GitHub CLI token",
                e,
                None,
            ));
        }
        "aws"
            if (first == "configure"
                && la.iter().any(|a| a == "get" || a == "export-credentials"))
                || la.iter().any(|a| a == "get-session-token") =>
        {
            out.push(finding(
                "cred.aws_credentials",
                C::SecretAccess,
                70,
                Cf::High,
                "Reads AWS credentials via the CLI",
                e,
                None,
            ));
        }
        "az" if la
            .windows(2)
            .any(|w| w[0] == "account" && w[1] == "get-access-token") =>
        {
            out.push(finding(
                "cred.az_token",
                C::SecretAccess,
                72,
                Cf::High,
                "Prints an Azure access token",
                e,
                None,
            ))
        }
        "gcloud"
            if la
                .iter()
                .any(|a| a == "print-access-token" || a == "print-identity-token") =>
        {
            out.push(finding(
                "cred.gcloud_token",
                C::SecretAccess,
                72,
                Cf::High,
                "Prints a Google Cloud access token",
                e,
                None,
            ))
        }
        "kubectl"
            if la
                .windows(2)
                .any(|w| w[0] == "get" && (w[1] == "secret" || w[1] == "secrets"))
                || (la.windows(2).any(|w| w[0] == "config" && w[1] == "view")
                    && la.iter().any(|a| a == "--raw")) =>
        {
            out.push(finding(
                "cred.k8s_secrets",
                C::SecretAccess,
                72,
                Cf::High,
                "Reads Kubernetes secrets or raw kubeconfig",
                e,
                None,
            ));
        }
        "mimikatz" | "procdump" | "lazagne" | "secretsdump.py" | "secretsdump" => {
            out.push(finding(
                "cred.dumping_tool",
                C::SecretAccess,
                98,
                Cf::High,
                format!("Credential dumping tool '{p}'"),
                e,
                None,
            ))
        }
        "reg"
            if first == "save"
                && la.iter().any(|a| {
                    a.ends_with("\\sam") || a.ends_with("\\security") || a.ends_with("\\system")
                }) =>
        {
            out.push(finding(
                "cred.reg_save_hive",
                C::SecretAccess,
                95,
                Cf::High,
                "Exports a Windows credential registry hive",
                e,
                None,
            ));
        }
        _ => {}
    }
}

fn persistence(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let first = la.first().map(|s| s.as_str()).unwrap_or("");
    let e = ev(seg);
    match p {
        "crontab" if !la.iter().any(|a| a == "-l") => out.push(finding(
            "persist.crontab",
            C::PersistenceIndicator,
            62,
            Cf::High,
            "Installs or edits scheduled cron jobs",
            e,
            None,
        )),
        "systemctl" if la.iter().any(|a| a == "enable" || a == "link") => out.push(finding(
            "persist.systemd_enable",
            C::PersistenceIndicator,
            58,
            Cf::High,
            "Enables a service to start automatically",
            e,
            None,
        )),
        "launchctl" if la.iter().any(|a| a == "load" || a == "bootstrap") => out.push(finding(
            "persist.launchd",
            C::PersistenceIndicator,
            58,
            Cf::High,
            "Loads a launchd agent",
            e,
            None,
        )),
        "schtasks" if la.iter().any(|a| a == "/create" || a == "/change") => out.push(finding(
            "persist.schtasks",
            C::PersistenceIndicator,
            68,
            Cf::High,
            "Creates a Windows scheduled task",
            e,
            None,
        )),
        "register-scheduledtask" | "new-scheduledtask" => out.push(finding(
            "persist.schtasks",
            C::PersistenceIndicator,
            68,
            Cf::High,
            "Creates a Windows scheduled task",
            e,
            None,
        )),
        "at" if !seg.args.is_empty() => out.push(finding(
            "persist.at",
            C::PersistenceIndicator,
            50,
            Cf::Medium,
            "Schedules a job with 'at'",
            e,
            None,
        )),
        "reg"
            if first == "add"
                && la.iter().any(|a| {
                    a.contains("\\currentversion\\run")
                        || a.contains("\\winlogon")
                        || a.contains("\\image file execution options")
                }) =>
        {
            out.push(finding(
                "persist.registry_run",
                C::PersistenceIndicator,
                78,
                Cf::High,
                "Adds a registry autostart entry",
                e,
                None,
            ));
        }
        "new-itemproperty" | "set-itemproperty" | "sp"
            if la
                .iter()
                .any(|a| a.contains("currentversion\\run") || a.contains("currentversion/run")) =>
        {
            out.push(finding(
                "persist.registry_run",
                C::PersistenceIndicator,
                78,
                Cf::High,
                "Adds a registry autostart entry",
                e,
                None,
            ));
        }
        "sc" if first == "create" || first == "config" => out.push(finding(
            "persist.service",
            C::PersistenceIndicator,
            72,
            Cf::High,
            "Creates or reconfigures a Windows service",
            e,
            None,
        )),
        "new-service" | "set-service" => out.push(finding(
            "persist.service",
            C::PersistenceIndicator,
            72,
            Cf::High,
            "Creates or reconfigures a Windows service",
            e,
            None,
        )),
        "wmic"
            if la
                .iter()
                .any(|a| a.contains("eventfilter") || a.contains("commandlineeventconsumer")) =>
        {
            out.push(finding(
                "persist.wmi",
                C::PersistenceIndicator,
                85,
                Cf::High,
                "WMI event subscription persistence",
                e,
                None,
            ))
        }
        _ => {}
    }
}

fn security_config(seg: &Segment, lraw: &str, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let e = ev(seg);
    match p {
        "set-mppreference" | "add-mppreference" => out.push(finding(
            "sec.defender_change",
            C::SecurityConfigurationChange,
            92,
            Cf::High,
            "Changes Microsoft Defender settings or exclusions",
            e,
            Some("Never let an agent change antivirus settings."),
        )),
        "netsh" if la.iter().any(|a| a.contains("firewall")) => out.push(finding(
            "sec.firewall_change",
            C::SecurityConfigurationChange,
            85,
            Cf::High,
            "Changes Windows firewall configuration",
            e,
            None,
        )),
        "set-netfirewallprofile"
        | "new-netfirewallrule"
        | "disable-netfirewallrule"
        | "remove-netfirewallrule" => out.push(finding(
            "sec.firewall_change",
            C::SecurityConfigurationChange,
            85,
            Cf::High,
            "Changes Windows firewall configuration",
            e,
            None,
        )),
        "ufw"
            if la
                .iter()
                .any(|a| a == "disable" || a == "allow" || a == "reset" || a == "delete") =>
        {
            out.push(finding(
                "sec.firewall_change",
                C::SecurityConfigurationChange,
                80,
                Cf::High,
                "Changes the ufw firewall",
                e,
                None,
            ))
        }
        "iptables" | "ip6tables" | "nft"
            if la.iter().any(|a| {
                a == "-f"
                    || a == "--flush"
                    || a == "-p"
                    || a == "flush"
                    || a == "-a"
                    || a == "-i"
                    || a == "-d"
            }) =>
        {
            out.push(finding(
                "sec.firewall_change",
                C::SecurityConfigurationChange,
                80,
                Cf::High,
                "Changes packet filter rules",
                e,
                None,
            ))
        }
        "setenforce" if la.iter().any(|a| a == "0" || a == "permissive") => out.push(finding(
            "sec.selinux_off",
            C::SecurityConfigurationChange,
            88,
            Cf::High,
            "Disables SELinux enforcement",
            e,
            None,
        )),
        "aa-disable" | "aa-complain" => out.push(finding(
            "sec.apparmor_off",
            C::SecurityConfigurationChange,
            85,
            Cf::High,
            "Weakens AppArmor",
            e,
            None,
        )),
        "systemctl"
            if la
                .iter()
                .any(|a| a == "stop" || a == "disable" || a == "mask")
                && la.iter().any(|a| {
                    [
                        "apparmor",
                        "firewalld",
                        "ufw",
                        "auditd",
                        "fail2ban",
                        "clamav",
                        "windefend",
                        "sshguard",
                    ]
                    .iter()
                    .any(|s| a.starts_with(s))
                }) =>
        {
            out.push(finding(
                "sec.security_service_stop",
                C::SecurityConfigurationChange,
                88,
                Cf::High,
                "Stops or disables a security service",
                e,
                None,
            ));
        }
        "set-executionpolicy" if la.iter().any(|a| a == "unrestricted" || a == "bypass") => out
            .push(finding(
                "sec.execution_policy",
                C::SecurityConfigurationChange,
                55,
                Cf::High,
                "Lowers the PowerShell execution policy",
                e,
                None,
            )),
        "bcdedit" => out.push(finding(
            "sec.bcdedit",
            C::SecurityConfigurationChange,
            85,
            Cf::High,
            "Changes Windows boot configuration",
            e,
            None,
        )),
        "auditctl" if la.iter().any(|a| a == "-d" || a == "-e") => out.push(finding(
            "sec.audit_change",
            C::SecurityConfigurationChange,
            80,
            Cf::High,
            "Changes Linux audit rules",
            e,
            None,
        )),
        "wevtutil" if la.iter().any(|a| a == "cl" || a == "clear-log") => out.push(finding(
            "sec.clear_logs",
            C::SecurityConfigurationChange,
            88,
            Cf::High,
            "Clears Windows event logs (anti-forensics)",
            e,
            None,
        )),
        "clear-eventlog" | "clear-history" => out.push(finding(
            "sec.clear_logs",
            C::SecurityConfigurationChange,
            60,
            Cf::High,
            "Clears logs or history",
            e,
            None,
        )),
        "history" if la.iter().any(|a| a == "-c" || a == "-w") => out.push(finding(
            "sec.clear_history",
            C::SecurityConfigurationChange,
            55,
            Cf::High,
            "Clears shell history",
            e,
            None,
        )),
        "unset" if la.iter().any(|a| a == "histfile") => out.push(finding(
            "sec.clear_history",
            C::SecurityConfigurationChange,
            55,
            Cf::High,
            "Disables shell history",
            e,
            None,
        )),
        "chattr" => out.push(finding(
            "sec.chattr",
            C::SecurityConfigurationChange,
            50,
            Cf::Medium,
            "Changes immutable file attributes",
            e,
            None,
        )),
        "visudo" => out.push(finding(
            "sec.sudoers",
            C::PrivilegeEscalation,
            90,
            Cf::High,
            "Edits sudoers",
            e,
            None,
        )),
        "usermod" | "useradd" | "add-localgroupmember" | "new-localuser" | "chpasswd" => {
            out.push(finding(
                "sec.account_change",
                C::PrivilegeEscalation,
                75,
                Cf::High,
                "Creates or modifies OS user accounts / groups",
                e,
                None,
            ));
        }
        "net"
            if la.first().is_some_and(|a| a == "user" || a == "localgroup")
                && la.iter().any(|a| a == "/add") =>
        {
            out.push(finding(
                "sec.account_change",
                C::PrivilegeEscalation,
                75,
                Cf::High,
                "Creates or modifies OS user accounts / groups",
                e,
                None,
            ));
        }
        _ => {}
    }
    if p == "export" && (lraw.contains("histfile=/dev/null") || lraw.contains("histsize=0")) {
        out.push(finding(
            "sec.clear_history",
            C::SecurityConfigurationChange,
            55,
            Cf::High,
            "Disables shell history",
            ev(seg),
            None,
        ));
    }
}

fn infra(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let first = la.first().map(|s| s.as_str()).unwrap_or("");
    let e = ev(seg);
    let auto = la.iter().any(|a| {
        a == "-auto-approve" || a == "--auto-approve" || a == "--yes" || a == "-y" || a == "--force"
    });
    match p {
        "terraform" | "tofu" | "terragrunt" | "pulumi" | "cdk" => match first {
            "destroy" => out.push(finding(
                "infra.destroy",
                C::InfrastructureModification,
                90,
                Cf::High,
                "Destroys provisioned infrastructure",
                e,
                None,
            )),
            "apply" | "up" | "deploy" => out.push(finding(
                "infra.apply",
                C::InfrastructureModification,
                if auto { 72 } else { 50 },
                Cf::High,
                if auto {
                    "Applies infrastructure changes without confirmation"
                } else {
                    "Applies infrastructure changes"
                },
                e,
                None,
            )),
            "state" if la.iter().any(|a| a == "rm" || a == "push") => out.push(finding(
                "infra.state_change",
                C::InfrastructureModification,
                70,
                Cf::High,
                "Manipulates infrastructure state",
                e,
                None,
            )),
            _ => {}
        },
        "kubectl" | "oc" => match first {
            "delete" => out.push(finding(
                "infra.k8s_delete",
                C::InfrastructureModification,
                if la
                    .iter()
                    .any(|a| a == "--all" || a == "namespace" || a == "ns")
                {
                    88
                } else {
                    72
                },
                Cf::High,
                "Deletes Kubernetes resources",
                e,
                None,
            )),
            "apply" | "create" | "replace" | "patch" | "scale" | "edit" => out.push(finding(
                "infra.k8s_change",
                C::InfrastructureModification,
                45,
                Cf::High,
                "Changes Kubernetes resources",
                e,
                None,
            )),
            "exec" => out.push(finding(
                "infra.k8s_exec",
                C::InfrastructureModification,
                45,
                Cf::High,
                "Executes inside a running container",
                e,
                None,
            )),
            _ => {}
        },
        "helm" if matches!(first, "uninstall" | "delete") => out.push(finding(
            "infra.helm_uninstall",
            C::InfrastructureModification,
            75,
            Cf::High,
            "Uninstalls a Helm release",
            e,
            None,
        )),
        "helm" if matches!(first, "install" | "upgrade") => out.push(finding(
            "infra.helm_change",
            C::InfrastructureModification,
            45,
            Cf::High,
            "Installs or upgrades a Helm release",
            e,
            None,
        )),
        "aws" => {
            let destructive = la
                .iter()
                .any(|a| a.starts_with("delete-") || a.starts_with("terminate-") || a == "rb")
                || (la.iter().any(|a| a == "rm") && la.iter().any(|x| x == "--recursive"));
            let iam = first == "iam"
                && la.iter().any(|a| {
                    a.starts_with("create-")
                        || a.starts_with("attach-")
                        || a.starts_with("put-")
                        || a.starts_with("update-")
                });
            if destructive {
                out.push(finding(
                    "infra.cloud_delete",
                    C::InfrastructureModification,
                    85,
                    Cf::High,
                    "Deletes cloud resources (AWS)",
                    e,
                    None,
                ));
            } else if iam {
                out.push(finding(
                    "infra.cloud_iam",
                    C::PrivilegeEscalation,
                    70,
                    Cf::High,
                    "Changes AWS IAM permissions",
                    e,
                    None,
                ));
            }
        }
        "az" if la.iter().any(|a| a == "delete" || a == "purge") => out.push(finding(
            "infra.cloud_delete",
            C::InfrastructureModification,
            if first == "group" { 92 } else { 85 },
            Cf::High,
            "Deletes cloud resources (Azure)",
            e,
            None,
        )),
        "az" if first == "role" && la.iter().any(|a| a == "create") => out.push(finding(
            "infra.cloud_iam",
            C::PrivilegeEscalation,
            70,
            Cf::High,
            "Creates Azure role assignments",
            e,
            None,
        )),
        "gcloud" | "gsutil" if la.iter().any(|a| a == "delete" || a == "rm" || a == "rb") => out
            .push(finding(
                "infra.cloud_delete",
                C::InfrastructureModification,
                85,
                Cf::High,
                "Deletes cloud resources (Google Cloud)",
                e,
                None,
            )),
        "doctl" | "hcloud" | "flyctl" | "fly" | "vercel" | "netlify" | "heroku"
            if la
                .iter()
                .any(|a| a == "delete" || a == "destroy" || a == "rm" || a == "remove") =>
        {
            out.push(finding(
                "infra.cloud_delete",
                C::InfrastructureModification,
                80,
                Cf::High,
                "Deletes hosted resources",
                e,
                None,
            ));
        }
        "vercel" | "netlify" | "flyctl" | "fly" | "firebase" | "wrangler"
            if la
                .iter()
                .any(|a| a == "deploy" || a == "--prod" || a == "publish") =>
        {
            out.push(finding(
                "infra.deploy",
                C::InfrastructureModification,
                50,
                Cf::High,
                "Deploys to a hosting environment",
                e,
                None,
            ));
        }
        _ => {}
    }
}

fn database(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let e = ev(seg);
    if p == "php" && la.first().map(|s| s.as_str()) == Some("artisan") {
        let sub = la.get(1).map(|s| s.as_str()).unwrap_or("");
        let force = la.iter().any(|a| a == "--force");
        match sub {
            "migrate:fresh" | "migrate:reset" | "migrate:refresh" | "db:wipe" => out.push(finding(
                "db.artisan_wipe",
                C::DatabaseDestructive,
                if force { 90 } else { 80 },
                Cf::High,
                format!("Laravel '{sub}' drops all tables / data"),
                e.clone(),
                Some("Run against a disposable local database only."),
            )),
            "migrate" | "migrate:rollback" if force => out.push(finding(
                "db.artisan_migrate_force",
                C::DatabaseDestructive,
                62,
                Cf::High,
                "Runs migrations with --force (bypasses the production safety prompt)",
                e.clone(),
                None,
            )),
            "migrate:rollback" => out.push(finding(
                "db.artisan_rollback",
                C::DatabaseDestructive,
                45,
                Cf::High,
                "Rolls back migrations (may drop columns/tables)",
                e.clone(),
                None,
            )),
            "db:seed" if force => out.push(finding(
                "db.artisan_seed_force",
                C::DatabaseDestructive,
                50,
                Cf::High,
                "Seeds the database with --force",
                e.clone(),
                None,
            )),
            "tinker" => out.push(finding(
                "db.artisan_tinker",
                C::ObfuscatedExecution,
                35,
                Cf::Low,
                "Interactive Laravel shell (arbitrary PHP)",
                e.clone(),
                None,
            )),
            _ => {}
        }
    }
    if matches!(p, "rails" | "rake")
        && la
            .iter()
            .any(|a| a == "db:drop" || a == "db:reset" || a == "db:schema:load" || a == "db:purge")
    {
        out.push(finding(
            "db.rails_drop",
            C::DatabaseDestructive,
            82,
            Cf::High,
            "Drops or resets the database",
            e.clone(),
            None,
        ));
    }
    let prisma =
        p == "prisma" || (matches!(p, "npx" | "pnpm" | "bunx") && la.iter().any(|a| a == "prisma"));
    if prisma
        && (la.windows(2).any(|w| w[0] == "migrate" && w[1] == "reset")
            || (la.windows(2).any(|w| w[0] == "db" && w[1] == "push")
                && la
                    .iter()
                    .any(|a| a == "--force-reset" || a == "--accept-data-loss")))
    {
        out.push(finding(
            "db.prisma_reset",
            C::DatabaseDestructive,
            82,
            Cf::High,
            "Resets the database schema (data loss)",
            e.clone(),
            None,
        ));
    }
    if matches!(p, "python" | "python3" | "py")
        && la.iter().any(|a| a == "manage.py")
        && la
            .iter()
            .any(|a| a == "flush" || a == "reset_db" || a == "sqlflush")
    {
        out.push(finding(
            "db.django_flush",
            C::DatabaseDestructive,
            80,
            Cf::High,
            "Deletes all data from the database (Django)",
            e.clone(),
            None,
        ));
    }
    if p == "dropdb" || (p == "mysqladmin" && la.iter().any(|a| a == "drop")) {
        out.push(finding(
            "db.drop_database",
            C::DatabaseDestructive,
            90,
            Cf::High,
            "Drops a database",
            e.clone(),
            None,
        ));
    }
    if p == "redis-cli" && la.iter().any(|a| a == "flushall" || a == "flushdb") {
        out.push(finding(
            "db.redis_flush",
            C::DatabaseDestructive,
            82,
            Cf::High,
            "Flushes Redis data",
            e.clone(),
            None,
        ));
    }
    let sql_clients = [
        "mysql",
        "mariadb",
        "psql",
        "sqlite3",
        "sqlcmd",
        "mongosh",
        "mongo",
        "cockroach",
        "clickhouse-client",
        "invoke-sqlcmd",
        "duckdb",
    ];
    for a in &seg.args {
        if a.len() < 8 {
            continue;
        }
        let s = a.to_ascii_lowercase();
        if s.contains("drop table")
            || s.contains("drop database")
            || s.contains("drop schema")
            || s.contains("dropdatabase(")
        {
            out.push(finding(
                "db.sql_drop",
                C::DatabaseDestructive,
                88,
                Cf::High,
                "SQL DROP statement",
                Some(a.clone()),
                Some("Take a backup first and run it yourself."),
            ));
        } else if s.contains("truncate table")
            || (s.starts_with("truncate ") && sql_clients.contains(&p))
        {
            out.push(finding(
                "db.sql_truncate",
                C::DatabaseDestructive,
                78,
                Cf::High,
                "SQL TRUNCATE statement",
                Some(a.clone()),
                None,
            ));
        } else if let Some(i) = s.find("delete from") {
            let stmt = s[i..].split(';').next().unwrap_or("");
            if !stmt.contains(" where ") {
                out.push(finding(
                    "db.sql_delete_all",
                    C::DatabaseDestructive,
                    75,
                    Cf::High,
                    "SQL DELETE without WHERE clause (deletes all rows)",
                    Some(a.clone()),
                    None,
                ));
            }
        } else if sql_clients.contains(&p)
            && let Some(i) = s.find("update ")
        {
            let stmt = s[i..].split(';').next().unwrap_or("");
            if stmt.contains(" set ") && !stmt.contains(" where ") {
                out.push(finding(
                    "db.sql_update_all",
                    C::DatabaseDestructive,
                    60,
                    Cf::Medium,
                    "SQL UPDATE without WHERE clause",
                    Some(a.clone()),
                    None,
                ));
            }
        }
    }
}

fn lolbins(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let e = ev(seg);
    match p {
        "certutil"
            if la.iter().any(|a| {
                a == "-urlcache" || a == "-decode" || a == "-decodehex" || a == "/urlcache"
            }) =>
        {
            out.push(finding(
                "lolbin.certutil",
                C::ObfuscatedExecution,
                78,
                Cf::High,
                "certutil used to download or decode payloads (living-off-the-land)",
                e,
                None,
            ))
        }
        "bitsadmin" if la.iter().any(|a| a == "/transfer" || a == "/addfile") => out.push(finding(
            "lolbin.bitsadmin",
            C::ObfuscatedExecution,
            70,
            Cf::High,
            "bitsadmin used for downloads",
            e,
            None,
        )),
        "mshta" | "regsvr32" | "rundll32" | "installutil" | "msbuild" | "cmstp" => {
            out.push(finding(
                "lolbin.proxy_exec",
                C::ObfuscatedExecution,
                80,
                Cf::High,
                format!("Signed Windows binary '{p}' used to proxy code execution"),
                e,
                None,
            ));
        }
        "wmic"
            if la.iter().any(|a| a == "process")
                && la.iter().any(|a| a == "call" || a == "create") =>
        {
            out.push(finding(
                "lolbin.proxy_exec",
                C::ObfuscatedExecution,
                75,
                Cf::High,
                "wmic process call create",
                e,
                None,
            ));
        }
        "start-process" if la.windows(2).any(|w| w[0] == "-verb" && w[1] == "runas") => {
            out.push(finding(
                "shell.privilege_elevation",
                C::PrivilegeEscalation,
                62,
                Cf::High,
                "Starts a process elevated (UAC)",
                e,
                None,
            ))
        }
        "eval" | "invoke-expression" | "iex" if !seg.piped_from_prev => out.push(finding(
            "shell.dynamic_eval",
            C::ObfuscatedExecution,
            50,
            Cf::Medium,
            "Evaluates a dynamically built command string",
            e,
            None,
        )),
        _ => {}
    }
}

fn agent_tamper(seg: &Segment, out: &mut Vec<Finding>) {
    let p = seg.program.as_str();
    let la = seg.args_lower();
    let e = ev(seg);
    if p == "agentshield" {
        let first = la.first().map(|s| s.as_str()).unwrap_or("");
        let weakening = (first == "mode"
            && la.get(1).is_some_and(|m| m == "monitor" || m == "shadow"))
            || (first == "agent" && la.get(1).is_some_and(|m| m == "uninstall"))
            || (first == "policy"
                && la
                    .get(1)
                    .is_some_and(|m| m == "use" || m == "import" || m == "set"))
            || first == "pause"
            || (first == "daemon" && la.get(1).is_some_and(|m| m == "stop"));
        if weakening {
            out.push(finding(
                "tamper.agentshield_weaken",
                C::AgentConfigurationTampering,
                97,
                Cf::High,
                "The agent tries to weaken or disable AgentShield itself",
                e.clone(),
                Some("Only you should change AgentShield's mode or policies."),
            ));
        }
    }
    if p == "claude"
        && la.first().is_some_and(|f| f == "config" || f == "mcp")
        && la
            .iter()
            .any(|a| a == "add" || a == "set" || a == "remove" || a == "add-json")
    {
        out.push(finding(
            "tamper.claude_config",
            C::AgentConfigurationTampering,
            75,
            Cf::High,
            "Changes Claude Code configuration or MCP servers",
            e.clone(),
            None,
        ));
    }
    if matches!(
        p,
        "stop-process" | "kill" | "pkill" | "taskkill" | "killall"
    ) && la.iter().any(|a| a.contains("agentshield"))
    {
        out.push(finding(
            "tamper.kill_agentshield",
            C::AgentConfigurationTampering,
            95,
            Cf::High,
            "Attempts to stop the AgentShield process",
            e,
            None,
        ));
    }
}
