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

the `eat-pass` binary is issuer, client, and origin in one. the whole flow runs
in-process with no network:

```bash
cargo run -p eat-pass-cli --bin eat-pass -- demo
```

or wire the three roles over http:

```bash
# 1. a dev attester identity (stands in for a TEE producing a unified-quote eat)
eat-pass attester-key
#   seed          <hex>   → give to the client
#   verifying-key <hex>   → give to the issuer

# 2. issuer: publishes its key, gates /sign on an accepted measurement class
eat-pass issuer --attester-key <vk> --allow <value_x_hex> --class accepted-builds

# 3. origin: gates GET /resource on a valid PrivateToken (RFC 9577)
eat-pass origin --issuer http://127.0.0.1:8088

# 4. client: mint a batch, then spend one against the origin
eat-pass token --attester-seed <seed> --value-x <value_x_hex> \
  --count 2 --present http://127.0.0.1:8099/resource
```

an unauthenticated request gets `401` + `WWW-Authenticate: PrivateToken
challenge=…, token-key=…`; a request carrying a finalized token gets `200`, and
a replay of the same token is rejected as a double-spend.

### real attestation (m2)

gate issuance on a genuine hardware quote instead of the dev attester, verify a
live azure sev-snp node, pin the key log, and share double-spend across replicas:

```bash
# verify the live azure attested-TLS node to the AMD root, through the gate
eat-pass verify-azure-tls --cert live-leaf.der --binding <value_x_hex>

# issuer gating on a real attestation backend (cbor eat | azure bundle | azure-tls)
eat-pass issuer --gate uq        --allow <measurement_hex> --class accepted-builds
#   prints "kt log pubkey <hex>" → clients pin it:
eat-pass token  --kt-log-pub <hex> --attester-seed <seed> --value-x <hex>

# shared double-spend for horizontally-scaled origins
eat-pass redeem --listen 127.0.0.1:8100
eat-pass origin --redeemer http://127.0.0.1:8100   # every replica points here
```

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
  gated measurement; the issuer selects it with `--gate dev|uq|azure|azure-tls`.
  verified end-to-end against the live `attest.secure.build` sev-snp node
  (`eat-pass verify-azure-tls`). plus **key transparency** — the issuer publishes
  a signed, append-only key log at `/kt` and the client pins it with
  `--kt-log-pub` (inclusion + consistency checks), and a **central redeemer**
  (`eat-pass redeem` + `origin --redeemer`) for shared cross-replica
  double-spend. (gcp/tdx node still blocked; the tdx verifier path is compiled
  and ready.)
- **m3+ — next.** persistent shared backends (redis/db) behind the spend +
  rate-limit traits, key rotation end-to-end, mobile (uniffi) client, pages.

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
