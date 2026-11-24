// Pure helpers for the Supply Chain Center: derive package manager + package names from a
// (redacted) shell command. Presentation only — the risk assessment itself comes from the daemon.

export type PackageAction = "install" | "execute";
export interface PackageRef { manager: string; name: string; action: PackageAction }

const WRAPPERS = new Set(["sudo", "doas", "env", "nohup", "time", "nice", "command", "exec"]);

/** sub-commands that install packages, per manager */
const INSTALL: Record<string, string[]> = {
  npm: ["install", "i", "add", "ci"],
  pnpm: ["add", "install", "i"],
  yarn: ["add"],
  bun: ["add", "install", "i"],
  pip: ["install"],
  pip3: ["install"],
  uv: ["add"],
  poetry: ["add"],
  cargo: ["add", "install"],
  composer: ["require"],
  gem: ["install"],
  go: ["install", "get"],
  brew: ["install"],
  apt: ["install"],
  "apt-get": ["install"],
  dnf: ["install"],
  yum: ["install"],
  apk: ["add"],
  choco: ["install"],
  winget: ["install"],
  dotnet: ["add"],
};

/** fetch-and-run launchers: [program, optional sub-command] */
const EXECUTE: [string, string | null][] = [
  ["npx", null], ["bunx", null], ["uvx", null], ["pnpx", null],
  ["pnpm", "dlx"], ["yarn", "dlx"], ["pipx", "run"], ["npm", "exec"], ["bun", "x"],
];

/** flags whose next token is a value, not a package */
const VALUE_FLAGS = new Set([
  "--registry", "--index-url", "--extra-index-url", "-i", "-r", "--requirement", "-c", "--constraint", "--prefix",
  "--target", "-t", "--tag", "--cache", "--cwd", "-C", "--dir", "--features", "--version", "--git", "--branch",
  "--path", "--root", "-p", "--package", "--python", "--from", "--with", "-w", "--workspace", "--filter", "--source",
  "--find-links", "-f", "--platform", "--group", "-e", "--editable",
]);

function splitSegments(command: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i] ?? "";
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
    if (c === ";" || c === "|" || c === "&" || c === "\n") {
      if (cur.trim()) parts.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

function tokens(segment: string): string[] {
  return (segment.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((t) => t.replace(/^(['"])(.*)\1$/s, "$2"));
}

/** `lodash@4.17.21` → `lodash`, `@scope/pkg@1` → `@scope/pkg`, `requests==2.0` → `requests`, `pkg[extra]>=1` → `pkg`. */
export function stripVersion(spec: string): string {
  let s = spec.trim();
  const at = s.lastIndexOf("@");
  if (at > 0) s = s.slice(0, at);
  s = s.replace(/(===|==|>=|<=|~=|!=|>|<|\^).*$/, "").replace(/\[.*$/, "");
  return s;
}

function looksLikePackage(arg: string): boolean {
  if (!arg || arg.startsWith("-")) return false;
  if (/^[.~/\\]/.test(arg) || /^[A-Za-z]:[\\/]/.test(arg)) return false; // local paths
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) return false; // URLs
  if (/[<>|$`*(){}]/.test(arg.replace(/(>=|<=|>|<).*$/, ""))) return false; // shell syntax
  return /^@?[A-Za-z0-9]/.test(arg);
}

function packageArgs(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a.startsWith("-")) {
      if (VALUE_FLAGS.has(a) && !a.includes("=")) i++;
      continue;
    }
    if (/^\d?>>?$|^<$/.test(a)) {
      i++; // redirection target
      continue;
    }
    if (looksLikePackage(a)) out.push(a);
  }
  return out;
}

/** Package manager invocations found in a shell command. Flags, paths, URLs and versions are ignored. */
export function parsePackages(command: string): PackageRef[] {
  const out: PackageRef[] = [];
  const seen = new Set<string>();
  const push = (manager: string, spec: string, action: PackageAction) => {
    const name = stripVersion(spec);
    const key = `${manager}\u0000${name}\u0000${action}`;
    if (!name || seen.has(key)) return;
    seen.add(key);
    out.push({ manager, name, action });
  };
  for (const segment of splitSegments(command)) {
    const tk = tokens(segment);
    while (tk[0] && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(tk[0]) || WRAPPERS.has(tk[0]))) tk.shift();
    let program = (tk.shift() ?? "").split(/[\\/]/).pop()?.replace(/\.(exe|cmd)$/i, "").toLowerCase() ?? "";
    if (!program) continue;
    // python -m pip install …
    if (/^(python|python3|py)$/.test(program) && tk[0] === "-m" && tk[1]) {
      program = tk[1].toLowerCase();
      tk.splice(0, 2);
    }
    const firstPositional = tk.findIndex((a) => !a.startsWith("-"));
    const sub = firstPositional >= 0 ? (tk[firstPositional] ?? "").toLowerCase() : "";

    const exec = EXECUTE.find(([p, s]) => p === program && (s === null || s === sub));
    if (exec) {
      const rest = exec[1] === null ? tk : tk.slice(firstPositional + 1);
      const first = packageArgs(rest)[0]; // only the first positional is the package; the rest are its arguments
      if (first) push(program === "pnpm" || program === "yarn" || program === "npm" || program === "bun" ? `${program} ${sub}` : program, first, "execute");
      continue;
    }
    const subs = INSTALL[program];
    if (subs && subs.includes(sub)) {
      let rest = tk.slice(firstPositional + 1);
      if (program === "dotnet") rest = rest[0] === "package" ? rest.slice(1) : [];
      for (const a of packageArgs(rest)) push(program === "pip3" ? "pip" : program, a, "install");
    }
  }
  return out;
}

export type SupplyKind = "typosquat" | "registry" | "remote" | "scripts" | "other";

/** Coarse classification of a supply-chain finding id (ids are owned by the daemon; this is display grouping only). */
export function supplyKind(findingId: string): SupplyKind {
  const id = findingId.toLowerCase();
  if (id.includes("typosquat")) return "typosquat";
  if (id.includes("registry") || id.includes("index_url") || id.includes("index-url")) return "registry";
  if (id.includes("remote_exec") || id.includes("remote_execute") || id.includes("download_pipe")) return "remote";
  if (id.includes("install_script") || id.includes("lifecycle") || id === "package.install") return "scripts";
  return "other";
}
