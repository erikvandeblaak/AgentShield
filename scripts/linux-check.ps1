# Linux validation in WSL Ubuntu 24.04 (base of Linux Mint 22): copies the repo into the WSL
# home (never builds over /mnt/c) and runs fmt-check, clippy -D warnings and all tests.
param([string]$Distro = 'Ubuntu')
$ErrorActionPreference = 'Stop'
$root = (Split-Path -Parent $PSScriptRoot) -replace '\\', '/'
$drive = $root.Substring(0, 1).ToLower()
$wslPath = "/mnt/$drive" + $root.Substring(2)
$script = @"
set -e
source ~/.cargo/env
mkdir -p ~/agentshield-linux-test
rsync -a --delete --exclude target --exclude node_modules --exclude .git --exclude apps/desktop $wslPath/ ~/agentshield-linux-test/
cd ~/agentshield-linux-test
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
echo LINUX_OK
"@
wsl -d $Distro -- bash -lc $script
if ($LASTEXITCODE -ne 0) { throw "Linux validation failed" }
