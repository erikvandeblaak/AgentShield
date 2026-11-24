# Builds the agentshield CLI and stages it as the Tauri sidecar (bundle.externalBin).
# Usage: pwsh scripts/stage-sidecar.ps1 [-Profile release|debug]
param([ValidateSet('release', 'debug')][string]$Profile = 'release')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if ($Profile -eq 'release') { cargo build --release -p agentshield } else { cargo build -p agentshield }
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    $triple = (rustc -vV | Select-String '^host: (.+)$').Matches[0].Groups[1].Value
    $ext = if ($IsWindows -or $env:OS -eq 'Windows_NT') { '.exe' } else { '' }
    $dest = Join-Path $root "apps/desktop/src-tauri/binaries"
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item "target/$Profile/agentshield$ext" (Join-Path $dest "agentshield-$triple$ext") -Force
    Write-Host "Sidecar staged: binaries/agentshield-$triple$ext"
} finally { Pop-Location }
