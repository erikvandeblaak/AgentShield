#!/usr/bin/env bash
# Builds Linux artifacts (CLI binary, .deb, AppImage) into dist/.
# Run on Linux Mint 22 / Ubuntu 24.04 (or WSL). Requires system packages for Tauri:
#   sudo apt-get install -y libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev \
#        build-essential curl wget file libssl-dev libxdo-dev
# plus Rust (rustup) and Node 22. Builds are unsigned; SHA-256 sums are written to dist/.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo build --release -p agentshield
triple="$(rustc -vV | sed -n 's/^host: //p')"
mkdir -p apps/desktop/src-tauri/binaries dist
cp target/release/agentshield "apps/desktop/src-tauri/binaries/agentshield-$triple"
(cd apps/desktop && { [ -d node_modules ] || npm ci; } && npx tauri build --bundles deb,appimage)
cp target/release/agentshield dist/
find apps/desktop/src-tauri/target/release/bundle \( -name '*.deb' -o -name '*.AppImage' \) -exec cp {} dist/ \;
(cd dist && sha256sum -- * | grep -v SHA256SUMS > SHA256SUMS.txt)
ls -la dist
echo "NOTE: unsigned build. Verify with: (cd dist && sha256sum -c SHA256SUMS.txt)"
