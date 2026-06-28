# Literature pull-in (full stack)

**Scope:** incremental hardening only. We are **not** redoing attester/issuer split,
coupled mint, unified-quote verifiers, `ClassGated`, or registry shape.

Papers below → small pull-ins. Policy cites also in `verification-policy.md`.

## What we keep (unchanged)

| Piece | Why touch it |
|-------|----------------|
| Attester verifies EAT → issuer blind-signs | RFC 9576 RATS mapping; Hanff CCS 2025 |
| `binding_of(blinded)` in hardware / bundle | Key-binding draft; Hanff targeted context |
| `UqVerifier` / `AzureUqVerifier` / mobile verifiers | Crypto layer stays in `eat-pass-gate` |
| `MeasurementClass` + registry status | Already PCS/registry hygiene |
| `eat-pass policy validate\|simulate` | Verdict-style operator tooling |

---

## Scholar-indexed pull-ins (by layer)

### Coupled mint — tighten, don’t redesign

| Cite | Small improvement | Skip |
|------|-------------------|------|
| Hanff, Lehmann, Özbay. CCS 2025. [DOI 10.1145/3719027.3765172](https://doi.org/10.1145/3719027.3765172) | Document that redemption_context + binding are **one** security property in ops runbooks. | New issuance protocol. |
| Ivanova et al. ePrint 2025/2022 | Audit issuer key rotation + KT pin path once per release. | Privacy Pass Plus fork. |
| Whalen et al. SOUPS 2022. *Let The Right One In* | UX goal: one attestation → many actions (batch mint) — already E.9. | CAPTCHA replacement research stack. |

### Policy / appraisal — shape output, not rewrite engine

| Cite | Small improvement | Skip |
|------|-------------------|------|
| Ferro & Lioy. ITASEC 2024. *Veraison* [CEUR Vol-3731](https://ceur-ws.org/Vol-3731/paper28.pdf) | Our JSON policy ≈ CoRIM intent; later: optional signed policy sidecar like registry `.sig`. | Deploy Veraison as a service. |
| Fossati et al. draft-ietf-rats-ear (EAR) | Attester returns `AppraisalResult` (pass/fail checks) for operators — **not** a second client token; see `docs/rats-glossary.md` |
| Lin et al. USENIX Sec 2025 (Verdict) | Keep `validate` / `simulate`; add `policy diff` when needed. | Full Verdict DSL. |

### CVM / Azure — document trust, don’t add Proof of Cloud

| Cite | Small improvement | Skip |
|------|-------------------|------|
| Galanou et al. ACSAC 2025 / arXiv:2503.08256 (CVM SoK) | `notes` in policy + registry: “MAA trust”, “paravisor owns report_data”. | DCEA / Frankenstein mitigation stack. |
| Rezabek & Passerat-Palmbach. arXiv:2510.12469 | Awareness in docs: quote ≠ location; uqaz1 accepts MAA boundary explicitly. | New attestation protocol. |
| Misiani et al. SIGMETRICS 2025 (*Confidential VMs Explained*) | Policy keys on **launch measurement** only — ignore noisy perf claims. | Re-pick TDX vs SNP. |

### Mobile SDK (later) — verifier bugs only

| Cite | Small improvement | Skip |
|------|-------------------|------|
| Fahl et al. ASIACCS 2023. *Symbolic modelling… Android* | Server nonce = our binding; reject if stale. | New mobile attestation API. |
| Leierzopf et al. SPICES 2025 (AVBTestKeyInTheWild) | Policy = `app_id_hash` + cert digest only. | Boot-state / root checks. |
| Gonzalez, Black Hat 2025 (*Breaking Chains*) | Chain verify root→leaf; first attestation extension only (already in unified-quote). | Custom X.509 stack. |

---

## Explicit non-goals (simplicity)

- Cedar, Oak, GVRF Privacy Pass, Veraison deployment, Proof of Cloud DCEA.
- Second attestation path or optional “attest-only” mint.
- Replacing registry with a new trust store.

