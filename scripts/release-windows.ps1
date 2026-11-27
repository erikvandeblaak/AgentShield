# Windows release in three steps, so code signing (SignPath) can happen between them.
#
#   Prepare   after `cargo build --release -p agentshield` + `npx tauri build --no-bundle`:
#             writes the binaries to sign into  -OutDir (default out/unsigned-binaries).
#   Bundle    takes the (signed) binaries from -BinariesDir, builds the NSIS and MSI installers
#             from exactly those files and writes them into -OutDir (default out/unsigned-installers).
#   Finalize  takes the (signed) installers from -InstallersDir and the CLI from -BinariesDir,
#             writes the release files + SHA256SUMS.txt into -OutDir (default out/release).
#
# Why the desktop binary is signed twice: the Tauri bundler patches the bundle type
# (__TAURI_BUNDLE_TYPE_VAR_UNK -> NSS / MSI) into the main binary while bundling. Patching a signed
# binary breaks its signature, so Prepare writes one pre-patched copy per installer type. The bundler
# then finds no marker, prints a warning and leaves the file byte-for-byte unchanged (verified with
# tauri-cli 2.12; AgentShield does not use the updater plugin, the only consumer of that marker).
#
# -RequireSignature makes Bundle and Finalize fail unless every binary/installer carries a valid
# Authenticode signature (used in CI when SignPath is configured).
param(
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Bundle', 'Finalize')][string]$Step,
    [string]$OutDir,
    [string]$BinariesDir = 'out/signed-binaries',
    [string]$InstallersDir = 'out/signed-installers',
    [switch]$RequireSignature
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$tauriRelease = 'apps/desktop/src-tauri/target/release'
$desktopExe = "$tauriRelease/agentshield-desktop.exe"
$cliExe = 'target/release/agentshield.exe'
$triple = (rustc -vV | Select-String '^host: (.+)$').Matches[0].Groups[1].Value
$sidecar = "apps/desktop/src-tauri/binaries/agentshield-$triple.exe"
$version = (Get-Content apps/desktop/src-tauri/tauri.conf.json -Raw | ConvertFrom-Json).version
$marker = '__TAURI_BUNDLE_TYPE_VAR_'

function New-CleanDir([string]$Path) {
    Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $Path | Out-Null
}

function Set-BundleType([string]$Source, [string]$Destination, [string]$Type) {
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $Source))
    $text = [Text.Encoding]::Latin1.GetString($bytes)   # 1 byte = 1 char, offsets stay equal
    $needle = "${marker}UNK"
    $first = $text.IndexOf($needle, [StringComparison]::Ordinal)
    if ($first -lt 0 -or $text.IndexOf($needle, $first + 1, [StringComparison]::Ordinal) -ge 0) {
        throw "$Source must contain '$needle' exactly once (Tauri bundle-type marker); was it already bundled?"
    }
    $patch = [Text.Encoding]::ASCII.GetBytes("$marker$Type")
    [Array]::Copy($patch, 0, $bytes, $first, $patch.Length)
    [IO.File]::WriteAllBytes((Join-Path (Get-Location) $Destination), $bytes)
}

function Assert-Metadata([string]$Path) {
    $vi = (Get-Item $Path).VersionInfo
    if ($vi.ProductName -ne "Erik$([char]0x2019)s AgentShield" -or $vi.ProductVersion -ne $version) {
        throw "$Path has ProductName '$($vi.ProductName)' / ProductVersion '$($vi.ProductVersion)'; expected Erik’s AgentShield / $version"
    }
}

function Assert-Signed([string]$Path) {
    if (-not $RequireSignature) { return }
    $sig = Get-AuthenticodeSignature $Path
    if ($sig.Status -ne 'Valid') { throw "$Path is not validly signed: $($sig.Status) $($sig.StatusMessage)" }
    Write-Host "signed: $(Split-Path -Leaf $Path) — $($sig.SignerCertificate.Subject)"
}

switch ($Step) {
    'Prepare' {
        if (-not $OutDir) { $OutDir = 'out/unsigned-binaries' }
        New-CleanDir $OutDir
        foreach ($f in $cliExe, $desktopExe) { if (-not (Test-Path $f)) { throw "missing $f — build first" } }
        Copy-Item $cliExe "$OutDir/agentshield.exe"
        Set-BundleType $desktopExe "$OutDir/agentshield-desktop-nsis.exe" 'NSS'
        Set-BundleType $desktopExe "$OutDir/agentshield-desktop-msi.exe" 'MSI'
        Get-ChildItem "$OutDir/*.exe" | ForEach-Object { Assert-Metadata $_.FullName }
    }
    'Bundle' {
        if (-not $OutDir) { $OutDir = 'out/unsigned-installers' }
        New-CleanDir $OutDir
        $cli = "$BinariesDir/agentshield.exe"
        foreach ($f in $cli, "$BinariesDir/agentshield-desktop-nsis.exe", "$BinariesDir/agentshield-desktop-msi.exe") {
            if (-not (Test-Path $f)) { throw "missing $f" }
            Assert-Metadata $f
            Assert-Signed $f
        }
        # The bundler takes the sidecar from binaries/ (verified: byte-identical in both installers).
        Copy-Item $cli $sidecar -Force
        Copy-Item $cli "$tauriRelease/agentshield.exe" -Force
        Remove-Item -Recurse -Force "$tauriRelease/bundle" -ErrorAction SilentlyContinue
        Push-Location apps/desktop
        try {
            foreach ($b in @(@{ Kind = 'nsis'; Exe = 'agentshield-desktop-nsis.exe' }, @{ Kind = 'msi'; Exe = 'agentshield-desktop-msi.exe' })) {
                Copy-Item (Join-Path $root "$BinariesDir/$($b.Exe)") (Join-Path $root $desktopExe) -Force
                $expected = (Get-FileHash (Join-Path $root $desktopExe)).Hash
                npx tauri bundle --bundles $b.Kind
                if ($LASTEXITCODE -ne 0) { throw "tauri bundle $($b.Kind) failed" }
                if ((Get-FileHash (Join-Path $root $desktopExe)).Hash -ne $expected) {
                    throw "the bundler modified agentshield-desktop.exe ($($b.Kind)); its signature would be broken"
                }
            }
        } finally { Pop-Location }
        Get-ChildItem "$tauriRelease/bundle/nsis/*.exe", "$tauriRelease/bundle/msi/*.msi" | ForEach-Object {
            # ASCII names: the product name has a curly apostrophe, awkward in URLs and shells.
            $ext = $_.Extension
            $name = if ($ext -eq '.msi') { "ErikAgentShield_${version}_x64_en-US.msi" } else { "ErikAgentShield_${version}_x64-setup.exe" }
            Copy-Item $_.FullName (Join-Path $OutDir $name)
        }
    }
    'Finalize' {
        if (-not $OutDir) { $OutDir = 'out/release' }
        New-CleanDir $OutDir
        $setup = Get-ChildItem "$InstallersDir/*-setup.exe"
        $msi = Get-ChildItem "$InstallersDir/*.msi"
        if ($setup.Count -ne 1 -or $msi.Count -ne 1) { throw "expected one setup.exe and one .msi in $InstallersDir" }
        Assert-Metadata $setup.FullName
        foreach ($f in $setup, $msi) { Assert-Signed $f.FullName; Copy-Item $f.FullName $OutDir }
        $cli = "$BinariesDir/agentshield.exe"
        Assert-Signed $cli
        $zipDir = Join-Path ([IO.Path]::GetTempPath()) "agentshield-zip-$PID"
        New-CleanDir $zipDir
        # Same layout as the 0.1.0 release: one renamed CLI binary in the zip.
        Copy-Item $cli "$zipDir/agentshield_${version}_windows_x64.exe"
        Compress-Archive -Path "$zipDir/*" -DestinationPath "$OutDir/agentshield_${version}_windows_x64.zip"
        Remove-Item -Recurse -Force $zipDir
        $sums = Get-ChildItem $OutDir -File | Sort-Object Name | ForEach-Object {
            "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
        }
        $sums | Set-Content -Encoding utf8NoBOM "$OutDir/SHA256SUMS.txt"
        Get-ChildItem $OutDir | Format-Table Name, Length
        if (-not $RequireSignature) { Write-Warning 'Release files are NOT code-signed (SignPath not configured).' }
    }
}
