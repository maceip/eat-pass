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
- profile: **RSABSSA-SHA384-PSS-Deterministic** (no per-message randomizer) — the
  Privacy Access Token (PAT) profile, so any rfc-9578 origin can verify our
  tokens (implemented; was Randomized in m0's first cut).
- message: client picks a random 32-byte `nonce`; the signed message is the rfc
  9578 **token_input** = `token_type(0x0002) ‖ nonce ‖ challenge_digest ‖
  token_key_id`. `challenge_digest = SHA256(TokenChallenge)` (rfc 9577);
  `token_key_id = SHA256(SPKI)` pins the issuer key into the token.
- hash: sha384 (pss).
- a **token** = rfc 9578 `Token{token_type, nonce, challenge_digest,
  token_key_id, authenticator}`. publicly verified against the issuer public key;
  offline; one-time-spendable via `nonce`. `Token::{to_bytes,from_bytes}` is the
  wire form; `http::{www_authenticate,authorization,parse_authorization}` is the
  rfc 9577 `PrivateToken` http carriage.

why blind-rsa and not voprf (rfc 9497): publicly verifiable (origin needs only a
public key, no issuer round-trip at redemption), matches google + apple choices,
and keeps the origin trivially deployable. voprf is a possible second token type
later for the privately-verifiable / rate-limited use case.

### partially-blind variant (the anonymity-set + auditable-policy design)

the centerpiece of the gate is **partially-blind rsa (rsapbssa)**, in
[`core/src/pbrsa.rs`](core/src/pbrsa.rs). the issuer binds a **measurement policy
class** (e.g. `accepted-builds@v1`) into the signature as *public metadata* via a
metadata-derived key, while the token stays blind. result: the origin sees only
"issued under policy X" (it derives the per-policy key to verify), the issuer
still can't link issuance to redemption, and the class is cryptographically
auditable. anonymity is over everyone sharing a `(class, key_version)` — far
larger than per-`value_x`.

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

- **m0 — core (done).** blind-rsa issue/finalize/verify, token type, channel
  binding, `AttestationVerifier` trait + `DevVerifier`, roundtrip + tamper tests.
  green on all platforms.
- **m0.5 — review-driven hardening (done, this pr).** folded the privacy-pass
  review into the credential layer:
  - **deterministic profile** (RSABSSA-SHA384-PSS-Deterministic), dropping the
    message randomizer for pat interop (E.3).
  - **rfc 9578 token** (`token_type/nonce/challenge_digest/token_key_id/
    authenticator`) + `to_bytes`/`from_bytes`, and **rfc 9577** `PrivateToken`
    http helpers (E.1).
  - **`TokenChallenge`** (issuer_name, origin_info, redemption_context) replaces
    the coarse `UseCase`; `redemption_context` doubles as the per-request
    freshness nonce (E.2, and the L1.1 tie-in on the eat side).
  - **`token_key_id = SHA256(SPKI)`** pinned in every token + a
    `check_key_consistency` helper (E.4).
  - **`MeasurementClass`** gating (anonymity set, E.5) and **partially-blind
    rsa** carrying the class as auditable public metadata (E.6).
  - **rate limiting** (`ratelimit::InMemoryRateLimiter` + `issue_gated_with_limit`,
    backing `QuotaExceeded`, E.7) and an **epoched double-spend store**
    (`spend::InMemorySpentStore`, E.8).
  - **issuance batching** documented on `Client::begin` (E.9).
  - attester/issuer **trust-boundary** documented + seamed in `gate` (A.2).
- **m1 — issuer + client + origin (done).** the `eat-pass` binary (`cli/`) is
  all three roles: `issuer` serves axum `GET /keys` + gated `POST /sign`
  (via `issue_gated_with_limit`), `token` is the client (fetch key → blind batch
  → attest → `/sign` → finalize → present), and `origin` is an example resource
  server that answers `401` + rfc 9577 `WWW-Authenticate: PrivateToken` and
  spends a presented token once. `demo` runs all three in-process; covered by
  `cli/tests/e2e.rs` and a cross-platform release workflow.
- **m2 — real eat gate + key transparency.** `UqVerifier` against unified-quote
  (live azure sev-snp node); wire the **measurement class** to the unified-quote
  registry trust-root + the new signed snapshot (R.2); plan/stand up an
  **append-only key-transparency log** so pinned `token_key_id`s are globally
  consistent (the second half of E.4). depends on R.1 (registry sig verification,
  done) and the snapshot (R.2, done).
- **m3 — operational hardening.** persist the spend store + rate limiter behind a
  shared backend (multi-replica issuer); origin-local vs central `/redeem` (E.8);
  tune issuance batch size against the rate-limit policy (E.9); fuzz the token +
  challenge parsers; key rotation/versioning end-to-end.
- **m4 — mobile + pages.** uniffi android/ios client; github pages site (family
  style + canon scroll).

### recommended execution order (carried from the review)

`R.1 → E.1+E.2 → E.3 → E.4 → E.5+E.6 → E.7+E.8 → A.2`. R.1 and the credential-layer
items (E.1–E.9) plus A.2 are implemented in m0.5; the remaining work (key
transparency, the real `UqVerifier`, shared-state hardening) is m2–m3 above.

---

## 10. open questions

- **key transparency** (E.4, m2): origin-pinned `token_key_id` defeats a static
  split-view, but a fully consistent guarantee needs an append-only log of issuer
  keys that clients can audit. host our own (sigstore-style) or piggyback an
  existing transparency log? what witness/gossip model?
- **measurement class as an attested artifact** (E.5): should the
  `MeasurementClass`/accepted-build set itself be a signed unified-quote registry
  snapshot (R.2) so "what counts as the class" is itself attestable + revocable —
  turtles all the way down. (leaning yes; the snapshot machinery now exists.)
- **central redemption vs origin-local** (E.8): the epoched `SpentStore` trait
  supports both; pick per deployment. central `/redeem` enables global
  double-spend + hidden-metadata variants at the cost of an origin→service hop.
- **rate-limit identity** (E.7): the per-attestation id is currently a hash of the
  *build* (caps farming per accepted build per epoch). an ARC-style per-client
  anonymous counter would be finer-grained without deanonymizing — worth it?
- **attester/issuer split** (A.2): when do we actually run the
  `AttestationVerifier` as a separate service that mints a signed issuance
  authorization, vs. the documented collapsed (single-process) trust assumption?
