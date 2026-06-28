# eat-pass-mobile

Client crypto (Kotlin / Swift / Python via UniFFI): blind → authorize → sign → finalize.

**Mint is coupled on every platform:** host attestation + eat-pass binding in one flow.

| Platform | Orchestrator SDK |
|----------|------------------|
| Android | `sdk-android/.../EatPassMobileClient.kt` |
| iOS | `sdk-ios/Sources/EatPassMobile/EatPassMobileClient.swift` |
| macOS | `../desktop/sdk-macos/.../EatPassDesktopClient.swift` |
| Linux / Win | `../desktop/sdk-python/.../EatPassDesktopClient` |
| Windows C# | `../desktop/sdk-windows/.../EatPassDesktopClient.cs` |

See [../desktop/README.md](../desktop/README.md) for build steps.

## Rust API (FFI)

```
EatPassClient(issuerPkJson, issuerName, originInfo)
  .begin(count)    → { requestJson, bindingHex }
  .finalize(sign)   → Authorization headers

desktop_build_id_hash_hex(buildDigestHex)   // TPM policy
ios_client_data_hash_hex(bindingHex)        // App Attest clientDataHash
```

Regenerate bindings: `./desktop/generate-bindings.sh` (Kotlin, Swift, Python, RustBridge).

Windows C# uses `eat-pass-mobile-ffi` (stdio JSON) when UniFFI C# is not generated:

```bash
cargo build -p eat-pass-mobile --bin eat-pass-mobile-ffi
```

## Protocol

- Mobile: [../docs/mobile-coupled-protocol.md](../docs/mobile-coupled-protocol.md)
- Desktop: [../desktop/docs/desktop-coupled-protocol.md](../desktop/docs/desktop-coupled-protocol.md)
