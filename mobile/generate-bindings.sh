#!/usr/bin/env bash
# Regenerate the Kotlin + Swift UniFFI bindings from the built cdylib.
# Run from the repo root or anywhere; paths are resolved relative to this file.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"

cargo build -p eat-pass-mobile

# Locate the freshly-built dynamic library (.dylib macOS / .so linux / .dll win).
# Checked file-by-file so a missing candidate doesn't trip `set -o pipefail`.
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

echo "bindings written to mobile/bindings/{kotlin,swift}"
