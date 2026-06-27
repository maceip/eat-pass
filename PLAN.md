# eat-pass — implementation plan

attestation-gated, unlinkable authorization tokens. this document specifies what
we build and why, grounded in (a) google's decompiled anonymous-tokens / aratea
surface, (b) chromium + android private-access-token sources, and (c) the ietf
rfcs those implement.

---

## 1. goal & differentiator

an origin accepts a request only from a client running an attested build it
trusts, while learning nothing that links the request to a specific client or to
the moment the client proved itself.

we get there with **blind signatures**: a client blinds a random token, an issuer
signs the blinded form (so it never sees the token), the client unblinds, and an
origin later verifies the signature with the issuer's public key. unlinkability
is information-theoretic in the blinding step.

the one thing we change versus everyone else: **the right to be issued a token is
gated on a `unified-quote` eat** — a hardware-rooted attestation whose measurement
the issuer accepts — rather than on a google/apple account or a device-integrity
verdict. eligibility is "you are this attested build," proven to silicon.

---

## 2. prior art we mirror

### google — anonymous tokens / blindsignauth ("aratea")
from the decompiled surface (`com.google.privacy.privatemembership.anonymoustokens.proto`):

- crypto: **rsa blind signatures in privacy-pass token format** —
  `RSABlindSignaturePrivacyPassToken`, `RSABlindSignaturePublicKey`, `RSAPrivateKey`.
- knobs we adopt:
  - `MessageMaskType` = `AT_MESSAGE_MASK_NO_MASK | CONCAT | XOR` — how the client
    randomizes the message (rfc 9474 message randomization).
  - `HashType` = `AT_HASH_TYPE_SHA256 | SHA384` — fdh / pss hash.
  - `AnonymousTokensUseCase` — a domain-separator tag bound into every token so a
    token minted for use-case A can't be redeemed for use-case B.
- wire messages we mirror:
  - `AnonymousTokensPublicKeysGetResponse` — publish issuer keys (+ versions).
  - `AnonymousTokensSignRequest { BlindedToken[], use_case, key_version }`.
  - `AnonymousTokensSignResponse { AnonymousToken[] }`.
  - `AnonymousTokensRedemptionRequest/Response` — redeem + result.
- transport: **aratea** (`com.google.search.mdi.aratea`, endpoint
  `aratea-labs-pa.sandbox.googleapis.com`) is the *private-inference rpc* that the
  tokens authorize. auth failures surface as `ArateaAuthError`:
  `AUTH_ERROR_LACKS_CAPABILITY`, `PER_USER_QUOTA_EXCEEDED`, `USER_IS_A_MINOR`,
  `UNKNOWN`. our gate emits the attestation analogs (see §4).

takeaway: google splits **anonymous-tokens (the unlinkable credential)** from
**aratea (the gated service)**. we mirror that split: eat-pass is the credential
layer; any origin (an "aratea") gates on it.

### apple — private access tokens / arc
privacy pass (rfc 9578) publicly-verifiable tokens, token type `0x0002` =
blind-rsa (rfc 9474). issuer/attester/origin separation. arc adds rate-limiting
over the same primitive. we are wire-compatible with the blind-rsa token in
spirit; we don't require apple's attester.

### ietf
- **rfc 9474** rsa blind signatures (rsabssa) — the signing primitive.
- **rfc 9578** privacy pass token types — token struct + the `0x0002` blind-rsa type.
- **rfc 9577** the issuance/redemption http protocol shapes.
we follow these so tokens are interoperable and reviewable, not bespoke.

---

## 3. crypto

primitive: **RSABSSA (rfc 9474)**, publicly verifiable.

- rust crate: [`blind-rsa-signatures`](https://crates.io/crates/blind-rsa-signatures)
  (jedisct1) — a direct rfc 9474 implementation; cross-platform, no system deps.
- key size: rsa-3072 default (2048 supported for parity with deployed privacy-pass
  issuers; configurable per key version).
- message: client picks a random 32-byte `nonce`; signed message is
  `H(use_case ‖ nonce)` with message randomization per `MessageMaskType`
  (default `CONCAT`, i.e. rfc 9474 randomized).
- hash: sha384 default (`HashType`), sha256 selectable.
- a **token** = `(use_case, nonce, msg_randomizer?, signature)`. publicly verified
  against the issuer public key; offline; one-time-spendable via `nonce`.

why blind-rsa and not voprf (rfc 9497): publicly verifiable (origin needs only a
public key, no issuer round-trip at redemption), matches google + apple choices,
and keeps the origin trivially deployable. voprf is a possible second token type
later for the privately-verifiable / rate-limited use case.

---

## 4. the eat gate (our addition)

issuance is a `/sign` endpoint that blind-signs **iff** the request carries a
valid attestation. the gate, in order:

1. **parse + verify the eat.** delegate to `unified-quote`'s portable verifier
   (`unified_quote::eat::EatToken` + the platform `verify_*`). reject if the
   hardware signature / cert chain doesn't root in a pinned vendor ca.
2. **measurement allowlist.** the eat's measurement / `value_x` must be in the
   issuer's accepted set (config: exact digests and/or a `unified-quote` registry
   trust-root). this is "you are a build i trust."
3. **channel binding.** the eat's `binding_bytes()` must equal
   `sha256(serialized blinded request)`. this ties *this* attestation to *this*
   blind request, so a captured eat can't be replayed to mint unrelated tokens.
4. **issue.** blind-sign every `BlindedToken` in the request; return the response.

gate-failure verdicts (mirroring `ArateaAuthError`):
`ATTESTATION_INVALID`, `MEASUREMENT_NOT_ALLOWED`, `BINDING_MISMATCH`,
`QUOTA_EXCEEDED`, `UNKNOWN`.

note: the issuer learns the measurement (the *build*), never an identity, and
cannot link the blinded request to the later token. attestation proves
eligibility; the blind signature severs linkage.

verifier paths:
- **portable dev path** (`DevVerifier`): ed25519-signed measurement statements, so
  core + ci build and test on every platform with no tee hardware.
- **real path** (`UqVerifier`): the unified-quote eat + the live azure sev-snp node
  we already run (`attest.secure.build`). reuses the exact verifier the rest of
  the stack uses — no second implementation, no fakery.

---

## 5. wire protocol (v0 = json; v1 = cbor/protobuf)

mirrors the anonymous-tokens messages, http/1.1 + json for v0.

- `GET  /keys`
  → `{ keys: [{ version, alg: "RSABSSA-SHA384-PSS-Deterministic" | "...Randomized",
       n, e, not_after }] }`
- `POST /sign`   (the gated issuance endpoint)
  req: `{ use_case, key_version, blinded: [b64...], eat: b64, binding: hex32 }`
  → `{ blind_sigs: [b64...] }`  or  `{ error: "<verdict>" }`
- redemption is origin-local (publicly verifiable): the origin verifies the token
  against `/keys` and tracks spent nonces. an optional `POST /redeem` exists for
  centralized double-spend tracking / hidden-metadata variants.

origin integration is a thin middleware: read token from `EAT-Pass` header,
verify signature + use_case + freshness, reject replays.

---

## 6. crate layout

```
eat-pass/
  core/    eat-pass-core   blind-rsa tokens, message types, channel binding,
                           AttestationVerifier trait + Measurement + DevVerifier.
                           no tee deps → builds + tests everywhere.
  gate/    eat-pass-gate   UqVerifier: unified-quote eat → Measurement (real path),
                           measurement allowlist + registry trust-root.
  cli/     eat-pass        one binary, subcommands:
                             keygen   — issuer keypair / publish /keys
                             issuer   — run the gated /sign service (axum)
                             request  — client: attest, blind, finalize, store token
                             origin   — example gated server + middleware
                             verify   — offline-verify a token against a pubkey
```

workspace, edition 2021, mit. core depends only on `blind-rsa-signatures`, `sha2`,
`rand`, `serde`. gate depends on `unified-quote` (git, portable verifier). cli adds
`axum` + `reqwest` + `clap`.

---

## 7. security properties (and what we must prove)

- **unlinkability:** issuer's view (blinded message) is independent of the token
  (rfc 9474 blinding). must not leak via timing/use_case cardinality → fixed
  use-case set, batched issuance.
- **unforgeability:** a token is an rsa signature; forging = breaking rsa.
- **no-replay of attestation:** channel binding (§4.3) + eat freshness/nonce.
- **double-spend:** origin tracks spent token nonces (bloom + persistent set);
  optional central `/redeem`.
- **measurement integrity:** allowlist is the trust boundary; rotating an accepted
  build = updating the allowlist, ideally itself signed.

---

## 8. cross-platform

core + gate are pure rust → linux/macos/windows today (same release matrix the
other four repos now use). the client is the interesting target:

- **windows/macos/linux:** native binary `eat-pass`.
- **android/ios:** wrap `core` with `uniffi` to ship a kotlin/swift client lib —
  this is the direct analog of google shipping the bsa token client inside the app.
  (roadmap; gated behind the `mobile` feature.)

---

## 9. milestones

- **m0 — core (this is the next pr).** blind-rsa issue/finalize/verify, token type,
  channel binding, `AttestationVerifier` trait + `DevVerifier`, roundtrip + tamper
  tests. green on all platforms.
- **m1 — issuer + client + origin.** axum `/keys` + `/sign`, client `request`,
  origin middleware + example, end-to-end test with `DevVerifier`.
- **m2 — real eat gate.** `UqVerifier` against unified-quote; demo: a token minted
  only when the request carries a valid eat from the live azure node; measurement
  allowlist.
- **m3 — hardening.** double-spend store, key rotation/versions, use-case registry,
  rate-limit verdicts, fuzz the parsers.
- **m4 — mobile + pages.** uniffi android/ios client; github pages site (family
  style + canon scroll); cross-platform release of `eat-pass`.

---

## 10. open questions

- token type id: register our own privacy-pass `0x0002` profile, or stay json-only
  until interop is needed?
- should the allowlist itself be an attested artifact (turtles all the way down)?
- central redemption (hidden-metadata / global double-spend) vs purely
  origin-local — pick per deployment, support both.
