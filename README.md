# eat-pass

attestation-gated, unlinkable authorization tokens.

a server should be able to accept requests *only* from clients running an
attested build it trusts — without learning *which* client. eat-pass issues
anonymous, publicly-verifiable tokens (**PoMFRIT** blind signatures — MAYO1 +
VOLE-in-the-head, Privacy Pass–shaped wire format) where the right to mint a
token is gated on a valid [unified-quote](https://github.com/maceip/unified-quote)
eat whose measurement the issuer accepts.

it is the open analog of google's *aratea / blindsignauth* anonymous tokens and
apple's *private access tokens / arc*, with one change that matters: issuance is
gated on hardware attestation (an eat), not on an account.

## the shape

```
  client (attested build)            issuer                         origin
  ───────────────────────            ──────                         ──────
  hold a unified-quote eat
  blind a random nonce  ───────────▶ verify eat to a hw root
                                     check measurement allowlist
                                     check channel binding
                        ◀─────────── blind-sign the nonce
  finalize → token
  POST + token  ─────────────────────────────────────────────────▶ verify token
                                                                    (issuer pubkey)
                                                                    spend nonce, serve
```

- the **issuer** never sees the unblinded token, so it cannot link an issued
  token to a redemption. attestation proves *eligibility*, not *identity*.
- the **origin** only needs the issuer's public key to gate a route. no callback,
  no per-request attestation, no shared secret.
- the **token** is a PoMFRIT blind signature over a client-chosen nonce —
  publicly verifiable, offline-checkable, one-time-spendable (~7 KiB on the wire).

## where it sits in the stack

```
[ cvm-agent ]            agent platform / product
[ attestation-service ]  /attest flow, stage0→stage1
[ eat-pass ]             anonymous authorization gated on an eat   ◀── this repo
[ unified-quote ]        the eat / quote format + verifier
[ attested-workload ]    the in-tee runtime
```

eat-pass consumes unified-quote's portable verifier to check the gate, and emits
tokens any origin can verify with nothing but a public key.

## use it

the `eat-pass` binary is issuer, client, origin, and redeemer in one. **there is
no dev/insecure mode**: issuance is always gated on a real hardware attestation
and key-transparency is mandatory — there are no flags to weaken either. the
client runs inside the attested CVM and collects a genuine SEV-SNP vTPM quote
bound to each request.

```bash
# attester: verifies attestation and signs short-lived issuance authorizations.
#   Policy JSON replaces inline --allow/--class (see policy/examples/).
#   Optional: EATPASS_POLICY_TRUSTED_PUB + policy.json.sig for signed sidecars.
export EATPASS_ATTESTER_SEED=$(openssl rand -hex 32)
eat-pass attester --gate azure --policy policy/examples/uqaz1-example.json

# issuer: PoMFRIT blind-signs tokens after FAEST-128f attester authorization.
export EATPASS_KT_SEED=$(openssl rand -hex 32)
eat-pass issuer --listen 127.0.0.1:8088
#   prints "kt log pubkey <hex>" → clients AND origins MUST pin it.

# redeemer: the central double-spend authority every origin replica shares.
eat-pass redeem --listen 127.0.0.1:8100

# origin: gates GET /resource on a valid PrivateToken (RFC 9577), trusting only
#   issuer keys included in the transparency log signed by the pinned key.
#   Each 401 issues a fresh challenge with a 32-byte redemption_context (default).
#   --redeemer is required: double-spend is always enforced centrally, never
#   origin-locally (which would let a token be spent once per replica).
eat-pass origin --issuer http://127.0.0.1:8088 \
  --redeemer http://127.0.0.1:8100 --kt-log-pub <hex>

# client (inside the attested CVM): fetch origin challenge, collect quote, mint, present
eat-pass token --kt-log-pub <hex> \
  --uq-collect "sudo /home/azureuser/unified-quote/target/release/uq azure collect" \
  --count 2 --present http://127.0.0.1:8099/resource

# operator policy tooling
eat-pass policy validate --file policy/examples/uqaz1-example.json
eat-pass policy diff --left old.json --right new.json

# verify a captured live azure node to the AMD root, through the gate
eat-pass verify-azure-tls --cert live-leaf.der --binding <value_x_hex>
```

> the full protocol can be exercised without TEE hardware **in tests only** via
> `cargo test -p eat-pass-cli --features dev-sim`; the dev-sim attestation
> stand-ins are compiled out of every shipped binary.

## status

- **m0 / m0.5 — done.** the credential layer: **PoMFRIT** spend tokens
  (`PoMFRIT-MAYO1-FV1-128`, token type `0x4550`), the Privacy Pass–shaped RFC 9577
  http flow, `TokenChallenge` origin binding, `token_key_id` pinning,
  measurement-class anonymity sets, rate-limiting, and an epoched double-spend
  store. Attester authorization, KT log, and policy sidecars use **FAEST-128f**.
  Native build requires Linux x86_64 (see `scripts/build-pomfrit-deps.sh`).
- **m1 — done.** the `eat-pass` binary above (issuer service, client, origin
  example) with an end-to-end test and a cross-platform release.
- **m2 — done.** the real attestation gate. [`eat-pass-gate`](gate/) verifies a
  genuine [unified-quote](https://github.com/maceip/unified-quote) attestation
  (`UqVerifier` for the cbor eat; `AzureUqVerifier` / `AzureTlsVerifier` for the
  azure sev-snp vtpm path) to the **AMD/Intel hardware root** and extracts the
  gated measurement; the issuer selects it with `--gate uq|azure|azure-tls`
  (there is no dev/software gate). verified end-to-end against the live
  `attest.secure.build` sev-snp node (`eat-pass verify-azure-tls`). plus
  **mandatory key transparency** — the issuer publishes a signed, append-only
  key log at `/kt` and both the client and origin pin it with `--kt-log-pub`
  (inclusion + consistency checks; not optional), and a **central redeemer**
  (`eat-pass redeem` + `origin --redeemer`) for shared cross-replica
  double-spend. (gcp/tdx node still blocked; the tdx verifier path is compiled
  and ready.)
- **m3 — done.** operational hardening. a networked **redis** backend (cargo
  feature `redis`) behind the same atomic `SpentStore` / `RateLimiter` traits —
  `eat-pass redeem --backend redis://…` and `issuer --rate-backend redis://…`
  give a multi-replica issuer/redeemer shared, durable state (fail-closed on
  outage); **key rotation end-to-end** — `POST /rotate` (admin-gated) mints a new
  signing key, appends it to the transparency log, and keeps serving the old one
  at `/keys/{version}`, while the client proves the log stayed consistent across
  the rotation with `--kt-known-head`; and the token + auth-header **parsers are
  fuzzed** (libFuzzer harness in `core/fuzz/` + an always-on deterministic smoke
  test). verified live: a clean in-CVM `--attest azure` mint (the client binds
  `value_x = channel binding` via the vTPM AK quote) gated through
  `AzureUqVerifier` to the AMD Milan root on `attest.secure.build`.
- **m4 — done.** reach. a [GitHub Pages site](https://maceip.github.io/eat-pass/)
  in the family style, and [`eat-pass-mobile`](mobile/) — the client credential
  math exposed to **Android (Kotlin)** and **iOS (Swift)** via UniFFI (HTTP +
  attestation stay host-native; blinding secrets never cross FFI).
- **still blocked.** the gcp/tdx node; the tdx verifier path is compiled and
  ready and slots into the same gate the moment a live node is available.

the protocol, crypto choice, and crate layout are specified in [`PLAN.md`](PLAN.md),
grounded in google's decompiled anonymous-tokens surface, chromium/android
private-access-token sources, and the relevant ietf rfcs.

## literature (incremental hardening)

These papers inform the **policy and challenge layers** only — we did not
redesign attester/issuer split, coupled mint, or unified-quote verifiers.
Full mapping: [`docs/literature-pull-in.md`](docs/literature-pull-in.md).

| Topic | Citation | Pull-in |
|-------|----------|---------|
| Coupled mint / redemption context | Hanff, Lehmann, Özbay. ACM CCS 2025. [DOI 10.1145/3719027.3765172](https://doi.org/10.1145/3719027.3765172) | Fresh 32-byte `redemption_context` per origin challenge; channel binding in attestation |
| Privacy Pass formal verification | Ivanova et al. ePrint 2025/2022 | Audit KT pin + key rotation path |
| Attestation results (EAR) | Fossati et al. [draft-ietf-rats-ear](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/) | `/authorize` returns `AppraisalResult` (EAR-shaped summary) |
| Reference-value manifests | Ferro & Lioy. ITASEC 2024 (Veraison/CoRIM). [CEUR Vol-3731](https://ceur-ws.org/Vol-3731/paper28.pdf) | Operator JSON policy + optional FAEST-128f `.json.sig` sidecar |
| Policy validate/simulate/diff | Lin et al. USENIX Security 2025 (Verdict) | `eat-pass policy validate\|simulate\|diff` |
| CVM trust boundaries | Galanou et al. ACSAC 2025 / [arXiv:2503.08256](https://arxiv.org/abs/2503.08256) | Policy `notes` field for operator trust assumptions |
| Proof of Cloud (awareness) | Rezabek & Passerat-Palmbach. [arXiv:2510.12469](https://arxiv.org/abs/2510.12469) | Documented in policy notes — quote ≠ location |
| Android attestation replay | Fahl et al. ASIACCS 2023 | Server nonce = channel binding; reject stale challenges |
| Mobile app identity | Leierzopf et al. SPICES 2025 (AVBTestKeyInTheWild) | Mobile allow entries use `app_id_hash` only |
| RATS / EAT / policy shape | RFC 9334, RFC 9711, IETF CoRIM draft | Roles, attestation results, reference values |

## EAT vs EAR (quick)

- **EAT** — raw attestation evidence you collect (`uq collect`, mobile bundle). RFC 9711.
- **EAR** — verifier **result** after checks (pass/fail, appraisal). IETF draft; eat-pass exposes a small **EAR-shaped** `AppraisalResult` on `/authorize`, not in the PrivateToken.

See [`docs/rats-glossary.md`](docs/rats-glossary.md).

## vs Google PAT and Apple ARC

| | Google PAT | Apple ARC / PAT | eat-pass |
|---|------------|-----------------|----------|
| Token crypto | Blind RSA (+ extensions) | Blind RSA (RFC 9474 type 2) | **PoMFRIT** (MAYO1 + VOLE-in-the-head) |
| Abuse / trust coloring | **Private metadata bit** — issuer-only secret at mint/redeem; can flag bad actors without client visibility | Platform attester + partner issuers; device/account signals | **No private metadata bit** — explicit `VerificationPolicy` + registry + appraisal logs |
| Attestation gate | Platform / mediator signals | Apple Secure Enclave + iCloud attester | **Hardware EAT** (CVM / mobile) |

**Google private metadata bit:** issuers can embed secret issuance metadata read only at redemption to re-score or throttle clients opaquely ([ePrint 2020/072](https://eprint.iacr.org/2020/072)). eat-pass deliberately does **not** implement PMB — operators revoke via policy/registry instead of hidden issuer coloring.

**Post-quantum:** eat-pass ships PQ spend tokens (PoMFRIT) and FAEST-128f attester
authorization today — see [`docs/post-quantum-roadmap.md`](docs/post-quantum-roadmap.md).

Full comparison: [`docs/competitive.md`](docs/competitive.md).

## license

mit

<!-- agentic-canon -->
## agentic canon

<table>
<tr>
<td width="200" valign="top"><img src="docs/assets/canon-scroll.png" width="180" alt="agentic canon" /></td>
<td valign="top">

**no proof, no privilege.**

1. **make behavior enforceable.** replace conventions with hardware quotes, attested gates, and runtime checks.
2. **turn failures into evolution.** each failed verification hardens the shared verifier, not just one deployment.
3. **compose through proofs.** every layer declares what it accepts, returns, and can prove.
4. **carry trust forward.** a proof from one stage becomes the ground the next stands on.

</td>
</tr>
</table>
