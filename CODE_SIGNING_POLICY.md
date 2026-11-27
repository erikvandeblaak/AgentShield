# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

> **Status:** pending (SignPath Foundation). Releases up to and including 0.1.0 are **not** code-signed. This page
> describes how signed releases are produced once the SignPath Foundation has approved the project.

## What is signed

Only files built from this repository by the GitHub Actions workflow
[`.github/workflows/release.yml`](.github/workflows/release.yml) on GitHub-hosted runners:

| File | Contents |
|---|---|
| `agentshield.exe` | CLI, Claude Code hook and daemon (also inside the installers and the `*_windows_x64.zip`) |
| `agentshield-desktop.exe` | desktop app (inside the installers) |
| `ErikAgentShield_<version>_x64-setup.exe` | per-user NSIS installer |
| `ErikAgentShield_<version>_x64_en-US.msi` | MSI installer |

Upstream components that are bundled unchanged (such as the NSIS and WiX helper libraries added by the
Tauri bundler) are not signed with this certificate. Linux packages are not code-signed.

Every signing request is checked by SignPath against the GitHub build that produced it (origin
verification) and must be approved manually for each release. The SignPath artifact configurations
are kept in [`packaging/signpath/`](packaging/signpath/).

## Team and roles

| Role | Member |
|---|---|
| Committer and reviewer | [Erik van de Blaak](https://github.com/erikvandeblaak) |
| Approver (signing requests) | [Erik van de Blaak](https://github.com/erikvandeblaak) |

Contributions from people outside the team arrive as pull requests and are reviewed before merge.
Every team member must use multi-factor authentication for GitHub and SignPath.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically
requested by the user or the person installing or operating it.

AgentShield works locally: no account, no cloud, no telemetry. The only network access is the
optional command `agentshield osv update`, which the user starts to download the public
[OSV](https://osv.dev) vulnerability data from `osv-vulnerabilities.storage.googleapis.com`. That
download sends no data about the user, the machine or its projects.

## Verifying a download

Each release lists SHA-256 checksums in `SHA256SUMS.txt`. On Windows you can check the signature in
the file properties (tab *Digital Signatures*) or with PowerShell:

```powershell
Get-AuthenticodeSignature .\ErikAgentShield_0.1.1_x64-setup.exe | Format-List Status, SignerCertificate
```

## Reporting

Report a problem with a signed file, or a suspected misuse of the certificate, as described in
[SECURITY.md](SECURITY.md).
