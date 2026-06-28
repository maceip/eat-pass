#!/usr/bin/env bash
# Build libeat_pass_mobile.so for Android ABIs into sdk-android/eatpass-mobile/src/main/jniLibs
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root/.."

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "Install cargo-ndk: cargo install cargo-ndk" >&2
  exit 1
fi

cargo ndk -t arm64-v8a -t x86_64 build -p eat-pass-mobile --release

dest="$here/sdk-android/eatpass-mobile/src/main/jniLibs"
rm -rf "$dest"
mkdir -p "$dest/arm64-v8a" "$dest/x86_64"

cp target/aarch64-linux-android/release/libeat_pass_mobile.so "$dest/arm64-v8a/"
cp target/x86_64-linux-android/release/libeat_pass_mobile.so "$dest/x86_64/"
echo "Native libs → $dest"
