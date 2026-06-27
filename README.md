# eat-pass

attestation-gated, unlinkable authorization tokens.

a server should be able to accept requests *only* from clients running an
attested build it trusts — without learning *which* client. eat-pass issues
anonymous, publicly-verifiable tokens (rfc 9474 blind rsa, privacy-pass format)
where the right to mint a token is gated on a valid [unified-quote](https://github.com/maceip/unified-quote)
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
- the **token** is a standard blind-rsa signature over a client-chosen nonce —
  publicly verifiable, offline-checkable, one-time-spendable.

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
# issuer: publishes its key, gates /sign on a real attestation backend
#   (uq = unified-quote CBOR EAT | azure = SEV-SNP vTPM bundle | azure-tls).
#   EATPASS_KT_SEED is the stable transparency-log seed clients pin (required).
export EATPASS_KT_SEED=$(openssl rand -hex 32)
eat-pass issuer --gate azure --allow <measurement_hex> --class accepted-builds
#   prints "kt log pubkey <hex>" → clients AND origins MUST pin it.

# redeemer: the central double-spend authority every origin replica shares.
eat-pass redeem --listen 127.0.0.1:8100

# origin: gates GET /resource on a valid PrivateToken (RFC 9577), trusting only
#   issuer keys included in the transparency log signed by the pinned key.
#   --redeemer is required: double-spend is always enforced centrally, never
#   origin-locally (which would let a token be spent once per replica).
eat-pass origin --issuer http://127.0.0.1:8088 \
  --redeemer http://127.0.0.1:8100 --kt-log-pub <hex>

# client (inside the attested CVM): collect a real quote, mint a batch, spend one
eat-pass token --kt-log-pub <hex> \
  --uq-collect "sudo /home/azureuser/unified-quote/target/release/uq azure collect" \
  --count 2 --present http://127.0.0.1:8099/resource

# verify a captured live azure node to the AMD root, through the gate
eat-pass verify-azure-tls --cert live-leaf.der --binding <value_x_hex>
```

> the full protocol can be exercised without TEE hardware **in tests only** via
> `cargo test -p eat-pass-cli --features dev-sim`; the dev-sim attestation
> stand-ins are compiled out of every shipped binary.

## status

- **m0 / m0.5 — done.** the credential layer: blind-rsa issuance
  (RSABSSA-SHA384-PSS-Deterministic), the RFC 9578 token + RFC 9577 http flow,
  `TokenChallenge` origin binding, `token_key_id` pinning, measurement-class
  anonymity sets, partially-blind policy metadata, rate-limiting, and an epoched
  double-spend store. green on linux/macos/windows.
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
