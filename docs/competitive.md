# How eat-pass differs from Google PAT and Apple ARC

This is **documentation only** — not a product commitment. It explains tradeoffs
operators should understand when comparing eat-pass to platform PAT deployments.

## Shared shape

All three use the **Privacy Pass** pattern (RFC 9576–9578):

- Client blinds a nonce → attester proves a property → issuer blind-signs →
  origin verifies with a public key only.
- Origins do not learn identity from the token alone.

eat-pass adds **hardware attestation (EAT)** as the attester gate instead of
device account reputation or CAPTCHA heuristics.

---

## Google: Private Access Tokens and the **private metadata bit**

Google’s Trust Token / Privacy Pass ecosystem includes an extension called the
**private metadata bit (PMB)** — see [Dodis et al., ePrint 2020/072](https://eprint.iacr.org/2020/072)
(*Anonymous Tokens with Private Metadata Bit*) and IETF Privacy Pass issuance
metadata work.

**What it is:** a secret bit (or small secret payload) embedded in a token at
**issuance** that only the **issuer** can read when the token is **redeemed**.
The client does not see it.

**Why Google uses it:** the issuer can **color** or **re-score** clients over
time — e.g. mark abusive mint patterns, downgrade trust, or silently throttle
bad actors — while the token still **looks valid** to the origin until traffic
is dropped. Recent formal analyses (e.g. ePrint 2025/1847) note this can link
issuance and redemption from the issuer’s perspective and is **not** part of
the core unlinkability story unless carefully bounded.

**What eat-pass does instead:**

| Google PAT + PMB | eat-pass |
|------------------|----------|
| Issuer-held secret metadata colors clients | **No private metadata bit** — we do not embed issuer-only abuse flags in tokens |
| Abuse handled via opaque issuer state + metadata | Abuse handled via **explicit** operator policy (`VerificationPolicy`), registry status, rate limits, central redeemer |
| Bad actor may not know they are flagged until requests fail | Deny/revoke is **visible at attestation** (policy appraisal fails) or at spend (409 double-spend) |

**What we gain:** no hidden issuer scoring layer; operators audit allow lists and
appraisal results; open attester/issuer/KT deploy.

**What we give up:** no “silent” abuse funnel inside the token format. Operators
must maintain **registry + policy hygiene** and issuer rate limits themselves —
there is no Google-scale private metadata graph.

**Public vs private metadata:** eat-pass uses **public** challenge fields
(`redemption_context`, origin binding) visible to the client — aligned with
Hanff et al. (CCS 2025) coupled mint, not Google’s PMB.

---

## Apple: ARC / Private Access Tokens on device

Apple’s PAT integration (WWDC 2022, [draft PAT architecture](https://datatracker.ietf.org/doc/html/draft-private-access-tokens))
uses **token type 2: publicly verifiable RSA blind signatures** (RFC 9474) — the
same blind-RSA family eat-pass uses today, not a separate “non-RSA” MAC or
blockchain scheme.

Attestation is **Apple device / iCloud attester** (“account in good standing”,
Secure Enclave certificates). Issuers are CDNs/partners Apple trusts (Fastly,
Cloudflare, etc.).

| Apple ARC / PAT | eat-pass |
|-----------------|----------|
| Apple attester + Apple-trusted issuers | **Your** attester + **your** issuer + **your** policy |
| Device + platform reputation graph | **Hardware measurement / app_id_hash** in operator policy |
| Works on consumer iOS/macOS without a CVM | CVM path (SNP/TDX/Nitro) + optional mobile gates |
| Global PAT issuer registry via Apple | Self-hosted KT + pinned log key |

**What we gain:** cross-cloud operator control, coupled mint to **your** build
policy, no App Store–only issuer list.

**What we give up:** no built-in global device reputation; you run attester/issuer
infra and policy.

Mobile eat-pass (`android-key`, `ios-app-attest` gates) reuses **similar device
evidence** but under **your** `VerificationPolicy`, not Apple’s centralized
good-standing check alone.

---

## Rate limits vs reputation

eat-pass **does** rate-limit mint batches at the issuer and enforce one-time
spend at the redeemer. That controls **volume**, not **who may mint** based on
hidden history.

Google’s edge is **issuance gating** via private metadata and platform signals
before a token is even minted. Ours is **“genuine attested build in policy”**
— explicit, revocable, auditable.

---

## Further reading

- [`post-quantum-roadmap.md`](post-quantum-roadmap.md) — PQ migration research (no code yet)
- [`rats-glossary.md`](rats-glossary.md) — EAT vs EAR vs appraisal
- [`literature-pull-in.md`](literature-pull-in.md) — paper mapping
