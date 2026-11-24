# Licensing

Snapshot 2026-11-24. This is an engineering review, **not legal advice**. License identifiers are the SPDX expressions declared by each package (`cargo metadata` `license` field; `package-lock.json` / `node_modules/*/package.json`). License *texts* inside packages were not individually read except for the two fonts.

## 1. Project license

- AgentShield is licensed under **Apache-2.0** (`license = "Apache-2.0"` in the workspace `Cargo.toml`, in `apps/desktop/src-tauri/Cargo.toml` and in `apps/desktop/package.json`). Copyright © 2026 Erik van de Blaak.
- Why Apache-2.0: permissive, explicit patent grant and patent-retaliation clause, common for security tooling (the reviewed competitors HOL Guard, SolonGate, Oktsec, sandbox-runtime, mcp-scanner, Trivy, OSV-Scanner, Scorecard all use it), compatible with every dependency license found below.
- **Open items (not present in the repository on the review date):**
  1. No `LICENSE` file at the repository root — required for the license to be unambiguous and for Apache-2.0 §4(a) redistribution.
  2. No `NOTICE` file (optional under Apache-2.0, recommended to carry the copyright line and third-party attributions).
  3. No generated third-party notices bundle for binary distributions (see §4).
  4. No SPDX headers in source files (optional).
- No competitor code is included (see COMPETITOR_ANALYSIS).

## 2. Rust dependencies — core workspace

Method: `cargo metadata --format-version 1 --locked` on the root workspace. This lists the full resolved graph for **all targets and including dev-dependencies**: 171 packages, of which 13 are first-party and **158 third-party**. Fewer are compiled into a given release binary (e.g. `wasi`, `r-efi`, `android_system_properties`, `libredox` are other-platform only; `proptest`, `tempfile`, `rusty-fork` are test-only).

| License family (declared) | Packages | Examples | Obligations / remarks |
|---|---:|---|---|
| MIT OR Apache-2.0 (incl. spellings `Apache-2.0 OR MIT`, `MIT/Apache-2.0`, `Apache-2.0 / MIT`) | 118 | serde, serde_json, clap, regex, toml, sha2, hmac, hex, base64, chrono, uuid, getrandom, thiserror, anyhow, tracing, tempfile, windows-sys | Permissive. Keep copyright/license notices in distributions. |
| MIT | 24 | tokio, bytes, rusqlite, libsqlite3-sys, generic-array, matchers | Permissive; notice required. |
| Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 5 | rustix, linux-raw-sys, wasi, wasip2, wit-bindgen | Permissive. |
| Unlicense OR MIT | 3 | aho-corasick, memchr, globset | Permissive. |
| Zlib | 2 | foldhash (two versions) | Permissive. |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 2 | r-efi (two versions; UEFI target only) | Choose MIT or Apache-2.0. Not compiled for Windows/Linux desktop targets. **No copyleft obligation.** |
| Apache-2.0 | 1 | borsh-derive (transitive, optional-feature path) | Permissive. |
| BSD-3-Clause | 1 | subtle | Permissive; notice + no-endorsement clause. |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 | unicode-ident | Permissive; Unicode data license notice. |
| **MPL-2.0** | 1 | **option-ext** (transitive via `dirs` → `dirs-sys`) | **Weak, file-level copyleft** — see §2.1. |

Bundled C code: `libsqlite3-sys` with feature `bundled` compiles the **SQLite** amalgamation into the binary. SQLite is in the **public domain**; the Rust wrapper is MIT.

### 2.1 Copyleft flags (Rust, core)

| Package | License | Assessment |
|---|---|---|
| `option-ext` 0.2.0 | MPL-2.0 | File-level copyleft: modifications **to that crate's files** must be published under MPL-2.0; linking it into an Apache-2.0 binary is permitted (MPL-2.0 §3.3 "Larger Work"). We use it unmodified from crates.io → obligation is limited to making its source available (it is, via crates.io) and including the license notice. **Acceptable**; list it in third-party notices. Avoidable only by replacing `dirs`. |
| `r-efi` | MIT OR Apache-2.0 OR LGPL-2.1-or-later | Disjunctive: we elect MIT/Apache-2.0. Not a copyleft issue. |

No GPL, AGPL, LGPL-only, SSPL, BUSL or "source-available" licensed crate was found in the core workspace.

## 3. Rust dependencies — desktop shell (`apps/desktop/src-tauri`, separate workspace)

Method: `cargo metadata --locked` on that manifest: **452 third-party packages** across all targets (Tauri 2, tao, wry, GTK/WebKit bindings for Linux, objc2 bindings for macOS, ICU data crates, image/compression codecs).

| License family (declared) | Packages | Remarks |
|---|---:|---|
| MIT OR Apache-2.0 (all spellings, incl. Tauri itself: `Apache-2.0 OR MIT`) | ~265 | Permissive. |
| MIT | 103 | Includes the GTK-rs bindings (`atk`, `gtk`, `gdk`, `webkit2gtk` …) — the *bindings* are MIT. |
| Unicode-3.0 | 18 | ICU4X data/code crates; permissive with notice. |
| Zlib OR Apache-2.0 OR MIT / Zlib / MIT OR Zlib OR Apache-2.0 | 23 | Permissive. |
| Unlicense OR MIT (both spellings) | 18 | Permissive. |
| BSD-3-Clause (incl. `AND MIT`, `OR Apache-2.0`, `OR MIT …` variants) | 9 | Permissive; notices. |
| Apache-2.0 (only) / with LLVM-exception | 6 | e.g. `tao`, `sync_wrapper`, `target-lexicon`. |
| ISC, CC0-1.0 OR MIT-0 OR Apache-2.0, 0BSD OR MIT OR Apache-2.0 | 3 | Permissive. |
| MIT OR Apache-2.0 OR LGPL-2.1-or-later | 2 | `r-efi` — elect MIT/Apache-2.0. |
| **MPL-2.0** | **5** | **cssparser, cssparser-macros, selectors, dtoa-short** (Servo CSS stack, transitive dependencies of Tauri) and `option-ext`. Same assessment as §2.1: unmodified, file-level copyleft, compatible with distribution inside an Apache-2.0 application; include notices. |

### 3.1 System components the desktop app links or loads at runtime (not Rust crates)

| Component | Platform | License | Assessment |
|---|---|---|---|
| **WebKitGTK**, GTK 3, GLib, libsoup, libdbus, (optionally) libayatana-appindicator for the tray | Linux | **LGPL-2.1+ / LGPL-2.0+** (libdbus: AFL-2.1 OR GPL-2.0+) | **Copyleft flag.** Dynamically linked system libraries. For `.deb` they are declared dependencies and not redistributed by us → LGPL obligations are met by dynamic linking. **AppImage bundles these libraries inside the image** → we then *redistribute* LGPL binaries and must ship their license texts and offer/point to corresponding source, and must not prevent relinking. Decide before publishing an AppImage; simplest compliant path is to publish `.deb` first and add a `THIRD-PARTY-LICENSES` + source pointers to the AppImage. |
| **Microsoft Edge WebView2 Runtime** | Windows | Proprietary (Microsoft), not redistributed with the default "download bootstrapper"/evergreen assumption | No copyleft. If the installer embeds the fixed-version runtime or the bootstrapper, Microsoft's redistribution terms apply. Tauri's NSIS default downloads the bootstrapper at install time — note this is a **network access during installation**, to be mentioned next to the "no network" claim (which concerns the running product). |
| NSIS / WiX (build tools for `nsis`/`msi` targets) | build time | zlib/libpng-style (NSIS), MS-RL (WiX v3) | Build tools; not part of the product. WiX's MS-RL does not extend to the generated MSI. |

## 4. npm dependencies (`apps/desktop`)

Method: `package-lock.json` (326 packages incl. dev tooling), licenses from the lockfile / `node_modules/*/package.json`.

### 4.1 Shipped in the application bundle (35 non-dev packages)

| License | Packages | Which |
|---|---:|---|
| MIT | 28 | react, react-dom, scheduler, zustand, @tanstack/react-table, @tanstack/react-virtual (+ cores), codemirror, @codemirror/* (autocomplete, commands, language, legacy-modes, lint, search, state, view), @lezer/* (common, highlight, lr), style-mod, crelt, w3c-keyname, @marijn/find-cluster-break, use-sync-external-store, csstype, @types/react |
| Apache-2.0 | 1 | **echarts** 6.1.0 (Apache Software Foundation project; ships a `NOTICE` file → Apache-2.0 §4(d) requires propagating its NOTICE content in our distribution) |
| BSD-3-Clause | 1 | zrender 6.1.0 (ECharts renderer) |
| Apache-2.0 OR MIT | 1 | @tauri-apps/api |
| ISC | 1 | lucide-react (icons; Lucide is ISC, with some icons derived from Feather under MIT) |
| 0BSD | 1 | tslib |
| **OFL-1.1** | 2 | **@fontsource-variable/geist**, **@fontsource-variable/jetbrains-mono** — see §4.3 |

No copyleft license among the shipped JavaScript packages.

### 4.2 Development/build tooling only (not shipped)

MIT (majority: Vite, Vitest, TypeScript-ESLint, Babel, Testing Library, jsdom …), Apache-2.0 (TypeScript, ESLint core packages), ISC, BSD-2-Clause, BlueOak-1.0.0, 0BSD, and:

| Package | License | Assessment |
|---|---|---|
| **lightningcss** (+ 11 platform binaries; via Tailwind CSS 4 / Vite) | **MPL-2.0** | Weak copyleft, **build tool only** — it transforms our CSS; its code is not included in the output. No obligation on the product. Flagged for completeness. |
| caniuse-lite | CC-BY-4.0 | Data used at build time by Browserslist; not shipped. Attribution only if redistributed. |

### 4.3 Fonts

| Font | Package | License | Copyright line (from the package's `LICENSE`) |
|---|---|---|---|
| Geist (variable) | `@fontsource-variable/geist` 5.3.0 | SIL Open Font License 1.1 | "Copyright 2024 The Geist Project Authors (https://github.com/vercel/geist-font)" |
| JetBrains Mono (variable) | `@fontsource-variable/jetbrains-mono` 5.3.0 | SIL Open Font License 1.1 | "Copyright 2020 The JetBrains Mono Project Authors (https://github.com/JetBrains/JetBrainsMono)" |

OFL-1.1 permits bundling and redistribution with software of any license. Conditions that apply to us: include the copyright notice and the OFL text with the distribution (OFL §2); do not sell the fonts by themselves (§1); do not use a Reserved Font Name for a *modified* version (§3) — we ship them unmodified (Fontsource repackages upstream files as WOFF2 subsets; if this is considered a modification, neither copyright line above declares a Reserved Font Name, so §3 is not triggered); do not use the authors' names for promotion (§4). The fonts stay under OFL; this does not affect the Apache-2.0 license of the code (§5 applies to the fonts only). The fonts are bundled locally — no font CDN request.

Brand assets in `apps/desktop/brand/` and icons in `src-tauri/icons/` are project-own (not reviewed for third-party content).

## 5. Compliance to-do before the first binary release

1. Add `LICENSE` (Apache-2.0 text) and `NOTICE` at the repository root.
2. Generate a third-party license file for both Rust workspaces (e.g. `cargo about` or `cargo-license`) and for the shipped npm packages; include ECharts' NOTICE, the two OFL texts, MPL-2.0 text + source pointers for `option-ext`, `cssparser`, `cssparser-macros`, `selectors`, `dtoa-short`, and the Unicode-3.0 text.
3. Show the notices in the app (About page) and ship them next to the binary.
4. Decide the AppImage question (§3.1) before enabling that bundle target.
5. Add `cargo deny check licenses` (allow-list: MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, Unicode-3.0, Unlicense, 0BSD, CC0-1.0, MPL-2.0 with explicit exceptions) to CI so a future copyleft or unlicensed transitive dependency fails the build.

## 6. Name availability: "AgentShield"

Method: web search and registry lookups on 2026-11-24 (crates.io API, npm registry, GitHub API, vendor pages). **No trademark-office database (USPTO TESS/TSDR, EUIPO eSearch, BOIP, WIPO Global Brand DB) was queried directly** — the search tooling cannot do that — so the trademark part is incomplete by construction.

### 6.1 Findings — the name is heavily used in exactly this product category

| Who / what | Name as used | What it is | Evidence |
|---|---|---|---|
| **Solo.io** | "agentshield" | Open-source project announced **2026-10-23** (press release): a protection layer for infrastructure against AI agents an organisation does not control. Solo.io is an established infrastructure vendor (Gloo, kgateway, agentgateway). | solo.io press release |
| **affaan-m/agentshield** (npm `ecc-agentshield`) | "AgentShield" | **Security scanner for Claude Code configurations** (secrets, permissions, hook injection, MCP risks); CLI, GitHub Action, GitHub App. MIT. 1,442 GitHub stars; created 2026-02-11; part of the "Everything Claude Code" ecosystem. | GitHub API, npm |
| crates.io **`agentshield`** | "agentshield" | "AI Agent Egress Firewall - Default-deny egress control for AI agents" (kamuimk), Apache-2.0, v1.0.0, 2026-02-19. **The crate name is taken.** | crates.io API |
| crates.io **`agent-shield`** | "AgentShield" (repo `aiconnai/agentshield`) | "Security scanner for AI agent extensions - offline-first, multi-framework, SARIF output", Rust, v1.1.0, updated 2026-11-13. | crates.io API, GitHub API |
| npm **`agentshield`** | "agentshield" | "Instant file protection for AI agent operations - hardlink-based zero-copy backup system" (tomsun28), Apache-2.0, 2026-01. **The npm name is taken.** | npm registry |
| npm `agentshield-sdk`, PyPI `agentshield-x`, `agentshield-fw`, `agentic-shield` | "Agent Shield" / "AgentShield" | Several unrelated runtime-security SDKs / firewalls for AI agents. | search results |
| Product Hunt | "AgentShield" (several listings: `agentshield-3`, `agentshield-4`, `agent-shield-2`) | Prompt-injection API, "runtime security mesh for autonomous AI coding agents", shadow-agent discovery. | search results |
| GitHub | `cdayAI/Agent-Shield`, `VinayK88/AgentShield`, `NoNamePY/agentshield` | Further similarly named agent-security projects. | search results |
| UK IPO | "Agent Shield" (UK00004362695), classes 36, 42, 45 | Financial risk management services (different field, but class 42 overlaps with software services). Published in the UK Trade Mark Journal 2026/015 (10 April 2026). Status not checked. | search result |

No registered **"AGENTSHIELD"** word mark in Nice classes 9/42 at USPTO or EUIPO was *found by web search*. That is **absence of evidence only**: pending applications by any of the parties above are plausible and would not show up this way.

### 6.2 Assessment

- The name is **not distinctive** and **not available as a unique identifier**: at least ten independent projects use it for AI-agent security, including one from a funded vendor (Solo.io) and one with more GitHub stars than most competitors that targets **the same niche — Claude Code security** (affaan-m/agentshield).
- Practical consequences today: `cargo install agentshield` and `npm i agentshield` install *other people's software*; search results for "AgentShield Claude Code" lead to another project; users and security teams cannot tell the projects apart; bug reports and (worse) vulnerability reports may be misdirected. For a security tool, binary-name confusion is itself a supply-chain risk.
- Legal risk: unregistered-mark / passing-off / unfair-competition claims generally favour the earlier user in the same field; several parties have earlier public use (February 2026 onwards). The risk of a cease-and-desist grows with visibility. Conversely, the crowding means *nobody* is likely to obtain strong exclusive rights to the plain term, so the name could never be defended by this project either.
- The crates in this repository are named `agentshield-*` and are not published; the binary is `agentshield`; the bundle identifier is `com.vandeblaak.agentshield`.

### 6.3 Recommendation

1. **Rename before the first public release.** Changing later costs users, links and trust; today it costs a search-and-replace (crate prefix, binary name, pipe name prefix, data directory, bundle identifier, env var `AGENTSHIELD_HOME`, project policy path `.agentshield/policy.toml`, hook-handler detection in `install.rs` — keep recognising the old binary name for uninstall/migration).
2. Pick a coined or compound name and check, in this order: USPTO, EUIPO, BOIP (Benelux) and WIPO Global Brand Database for classes 9 and 42; crates.io, npm, PyPI; GitHub organisation; `.com`/`.dev`/`.nl` domains; winget and Debian package names.
3. If the owner decides to keep the name for now: always use the qualified form "**AgentShield by Erik van de Blaak**" / "vandeblaak AgentShield" in the README, About page and installer; do **not** publish under the bare `agentshield` name on any registry (taken anyway); state explicitly in the README that the project is unrelated to Solo.io agentshield, ecc-agentshield and the crates/npm packages of the same name; do not file a trademark for the bare word.
4. Obtain a professional clearance search before spending on a signing certificate or domain bound to the name — the certificate's subject will be the owner's legal name, so signing is not blocked by this decision.
