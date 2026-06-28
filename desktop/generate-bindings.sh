#!/usr/bin/env bash
# Regenerate UniFFI bindings (Kotlin, Swift, Python) from eat-pass-mobile cdylib.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

cargo build -p eat-pass-mobile

lib=""
for cand in \
  target/debug/libeat_pass_mobile.dylib \
  target/debug/libeat_pass_mobile.so \
  target/debug/eat_pass_mobile.dll; do
  if [ -f "$cand" ]; then lib="$cand"; break; fi
done
[ -n "$lib" ] || { echo "error: built cdylib not found under target/debug" >&2; exit 1; }
echo "using library: $lib"

run_bindgen() { cargo run -q -p eat-pass-mobile --features cli --bin uniffi-bindgen -- "$@"; }

run_bindgen generate --library "$lib" --language kotlin --out-dir mobile/bindings/kotlin
run_bindgen generate --library "$lib" --language swift  --out-dir mobile/bindings/swift
run_bindgen generate --library "$lib" --language python  --out-dir desktop/sdk-python/eatpass_desktop/native

mkdir -p desktop/sdk-macos/RustBridge mobile/sdk-ios/RustBridge
cp mobile/bindings/swift/* desktop/sdk-macos/RustBridge/
cp mobile/bindings/swift/* mobile/sdk-ios/RustBridge/

echo "bindings: mobile/bindings/{kotlin,swift}, desktop/sdk-python/.../native, RustBridge copies"
