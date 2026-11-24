# Builds the Windows installers (per-user NSIS + MSI) into dist\.
# Requires: Rust (MSVC), Node 22, WebView2 runtime (present on Windows 11).
# Builds are UNSIGNED unless you configure signing; the script prints a warning and
# writes SHA-256 checksums next to the artifacts.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    & "$PSScriptRoot/stage-sidecar.ps1" -Profile release
    # Remove stale bundles so dist\ only contains this build.
    Remove-Item -Recurse -Force 'apps/desktop/src-tauri/target/release/bundle' -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force 'dist' -ErrorAction SilentlyContinue
    Push-Location apps/desktop
    try {
        if (-not (Test-Path node_modules)) { npm ci; if ($LASTEXITCODE -ne 0) { throw "npm ci failed" } }
        npx tauri build --bundles nsis,msi
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
    } finally { Pop-Location }
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force $dist | Out-Null
    $bundle = 'apps/desktop/src-tauri/target/release/bundle'
    Get-ChildItem "$bundle/nsis/*.exe", "$bundle/msi/*.msi" | ForEach-Object { Copy-Item $_ $dist -Force }
    Copy-Item 'target/release/agentshield.exe' $dist -Force
    $sums = Get-ChildItem $dist -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | ForEach-Object {
        "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    $sums | Set-Content -Encoding utf8 (Join-Path $dist 'SHA256SUMS.txt')
    Write-Host "`nArtifacts in dist\:" -ForegroundColor Green
    Get-ChildItem $dist | Format-Table Name, Length
    Write-Warning "These builds are NOT code-signed. Antivirus products (observed: Norton) may delay or flag unsigned binaries. See docs/SECURITY_FINDINGS.md SF-003."
} finally { Pop-Location }
