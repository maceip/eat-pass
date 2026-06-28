# Post-quantum cryptography (shipped profile)

Status: **implemented** in eat-pass. There is no classical blind-RSA or ed25519
attester profile — we never shipped a v1, so there is no dual-epoch migration.

## Shipped instantiations

| Component | Algorithm | Notes |
|-----------|-----------|-------|
| Blind spend token (issuer) | **PoMFRIT** — MAYO1 + VOLE-in-the-head (`FV1_128`) | Token type `0x4550`, alg `PoMFRIT-MAYO1-FV1-128` |
| Attester `IssuanceAuthorization` | **FAEST-128f** | ~6 KiB signatures; domain `eat-pass/issuance-auth` |
| Policy / registry sidecars | **FAEST-128f** | Base64 `.json.sig` sidecar |
| KT log `SignedHead` | **FAEST-128f** | Base64 signature in JSON |
| Channel binding / digests | SHA-256 | Unchanged |
| TLS (deploy) | classical KEM + signatures | Independent of token math; hybrid PQ TLS optional |

Native PoMFRIT build: Linux **x86_64** with AVX2 (`scripts/build-pomfrit-deps.sh`).
Target deployment: Azure CVM tool-gate stack.

## What stays the same (protocol roles)

PQ is **orthogonal** to these design choices:

- Attester / issuer split
- Coupled mint + channel binding + public `redemption_context`
- `VerificationPolicy` appraisal
- Key transparency + central redeemer
- No Google **private metadata bit** (see [`competitive.md`](competitive.md))

Only the **cryptographic instantiations** changed from the original research plan.

## dev-sim (tests only)

`cargo test --features dev-sim` uses ed25519-signed **dev EAT** stand-ins for
hardware attestation. Production attester authorization and policy sidecars remain
FAEST-128f.

## References

- PoMFRIT / pq_blind_signatures: [shibammukherjee/pq_blind_signatures](https://github.com/shibammukherjee/pq_blind_signatures)
- FAEST: [https://faest.info/](https://faest.info/)
- MAYO: [PQCMayo/MAYO-C](https://github.com/PQCMayo/MAYO-C)
