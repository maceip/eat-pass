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

## status

design phase. the protocol, crypto choice, and crate layout are specified in
[`PLAN.md`](PLAN.md), grounded in google's decompiled anonymous-tokens surface,
chromium/android private-access-token sources, and the relevant ietf rfcs.
implementation lands against the milestones in that doc.

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
