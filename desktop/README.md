# eat-pass SDKs (all platforms)

Coupled mint: **platform attestation bound to eat-pass channel binding** → attester `/authorize` → issuer `/sign` → `Authorization: PrivateToken …`.

| Platform | SDK path | Attestation | Crypto |
|----------|----------|-------------|--------|
| Android | `mobile/sdk-android/` | Key Attestation | UniFFI → `libeat_pass_mobile.so` |
| iOS | `mobile/sdk-ios/` | App Attest | UniFFI → static/dylib |
| macOS | `desktop/sdk-macos/` | App Attest | UniFFI → `libeat_pass_mobile.dylib` |
| Linux | `desktop/sdk-python/` | TPM2 (`collect-desktop-tpm.sh`) | UniFFI Python |
| Windows | `desktop/sdk-windows/` | TPM2 (`.ps1`) | `eat-pass-mobile-ffi` subprocess |

Shared Rust crate: **`eat-pass-mobile`** (`EatPassClient.begin` / `finalize`, hash helpers).

## Build native crypto once

```bash
cd eat-pass
cargo build -p eat-pass-mobile
cargo build -p eat-pass-mobile --bin eat-pass-mobile-ffi   # Windows C# helper
./desktop/generate-bindings.sh   # Kotlin, Swift, Python + RustBridge copies
```

## Python (Linux / Windows agents)

```bash
pip install -e desktop/sdk-python
export PYTHONPATH=desktop/sdk-python   # after generate-bindings

python - <<'PY'
from eatpass_desktop import EatPassConfig, EatPassDesktopClient, PlatformAttest

client = EatPassDesktopClient(EatPassConfig(
    attester_url="http://127.0.0.1:8087",
    issuer_url="http://127.0.0.1:8088",
    build_digest_hex="<sha256-hex-of-agent-binary>",
    platform=PlatformAttest.LINUX_TPM,
))
print(client.mint_authorization_header().authorization_header)
PY
```

Policy: `desktop_build_id_hash(build_digest)` — `eat-pass desktop-hash-build ./agent`.

## macOS (Swift)

Add `desktop/sdk-macos` as a local Swift package. Enroll App Attest key once; pass `keyId` + `credentialPublicKeyHex` to `EatPassDesktopClient`.

## iOS (Swift)

Same as Android flow; see `mobile/sdk-ios/Sources/EatPassMobile/EatPassMobileClient.swift`.

## Windows (C#)

```bash
dotnet build desktop/sdk-windows/EatPass.Desktop
# ensure eat-pass-mobile-ffi on PATH (target/debug/eat-pass-mobile-ffi.exe)
```

Set `BUILD_DIGEST` policy field via `TpmAttestation.DesktopBuildIdHashHex`.

## Wire protocol

See [docs/desktop-coupled-protocol.md](docs/desktop-coupled-protocol.md) and [../docs/mobile-coupled-protocol.md](../docs/mobile-coupled-protocol.md).

## Attester gates

| Gate | SDK |
|------|-----|
| `android-key` | Android |
| `ios-app-attest` | iOS |
| `macos-app-attest` | macOS |
| `desktop-tpm` | Linux / Windows |
