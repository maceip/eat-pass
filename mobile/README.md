# eat-pass-mobile

The eat-pass **client** crypto for Android (Kotlin) and iOS (Swift), via
[UniFFI](https://mozilla.github.io/uniffi-rs/).

Mobile is a client: it blinds token inputs, has them blind-signed by an issuer,
and finalizes them into unlinkable tokens it presents to an origin. The two
halves that touch the network and the secure element — **HTTP** and
**attestation** — are deliberately left to the host app, because on mobile the
attestation evidence comes from a platform API (Android KeyMint / Play
Integrity, iOS App Attest) rather than a unified-quote TEE. This crate exposes
only the unlinkable-credential math; blinding secrets never cross the FFI
boundary.

## API

```
EatPassClient(issuerPkJson, issuerName, originInfo)   // from /keys + challenge ids
  .tokenKeyIdHex()            -> String               // pin / KT-check before issuance
  .begin(count)              -> BeginResult            // { requestJson, bindingHex }
  // host attests over bindingHex, POSTs requestJson + eat to /sign, gets back JSON
  .finalize(signResponseJson) -> [String]             // "Authorization: PrivateToken token=…"
```

Typical flow (Kotlin):

```kotlin
val client = EatPassClient(keysJson, "issuer.example", "origin.example")
val begin = client.begin(3u)
// 1) attest over begin.bindingHex with the platform attestation API
// 2) POST { req: begin.requestJson, eat_b64: <base64 eat> } to <issuer>/sign
val headers = client.finalize(signResponseJson)   // present headers[i] to the origin
```

## Regenerate bindings

The checked-in bindings under `bindings/` are generated from the built cdylib.
The `uniffi` version is pinned by the workspace `Cargo.lock`, so generation is
deterministic.

```sh
./mobile/generate-bindings.sh        # writes bindings/{kotlin,swift}
```

## Build the native libraries

- **Android**: build `libeat_pass_mobile.so` per ABI with
  [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk)
  (`cargo ndk -t arm64-v8a -t x86_64 build -p eat-pass-mobile --release`),
  drop them under `jniLibs/`, and add `bindings/kotlin` to your source set.
- **iOS**: build `aarch64-apple-ios` (+ `*-sim`) static libs, package an
  `.xcframework`, and add `bindings/swift` to your target. The `*FFI.modulemap`
  + `*FFI.h` wire the Swift shim to the static lib.
