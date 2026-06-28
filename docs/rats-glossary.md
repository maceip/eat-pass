# RATS glossary: EAT vs EAR (and where eat-pass uses each)

Quick reference for operators coming from unified-quote / cvm-agent who know
**EAT** but not **EAR**.

## EAT — Entity Attestation Token

**What:** evidence from the **attester** (hardware or platform). In this stack,
that is the unified-quote CBOR token, Azure vTPM bundle, or mobile attestation
JSON bound to a channel nonce.

**RFC:** [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) (EAT, 2025).

**Who produces it:** the workload or platform inside/at the device (`uq collect`,
Key Attest, App Attest, etc.).

**Who verifies crypto:** `eat-pass-gate` / unified-quote verifiers → AMD/Intel/
Apple/Google roots.

**You already build this** when you run attestation in a CVM or mobile app.

---

## EAR — Entity Attestation Result

**What:** the **verifier’s output** after checking evidence — pass/fail, which
checks ran, optional normalized claims. It is **not** another token the client
carries to origins.

**Draft:** [draft-ietf-rats-ear](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/)
(Fossati et al., IETF RATS working group).

**Analogy:**

```text
EAT  = “here is my lab report” (raw evidence)
EAR  = “here is the grader’s scored sheet” (appraisal result)
```

**In eat-pass today:** attester `POST /authorize` returns JSON
`AppraisalResult` — a **small, EAR-shaped summary** (policy id, class, check
list, pass/fail, optional notes). It is for **operators and logs**, not for
PrivateToken redemption.

Origins and tool-gates still verify **PrivateTokens** only; they do not parse
EAR on each request unless you add that separately.

---

## Appraisal policy (VerificationPolicy)

**What:** operator JSON (`eat-pass policy validate`) — reference values, expiry,
registry floor. Decides allow/deny **after** crypto verification.

**CoRIM-shaped intent:** reference-value manifest (Ferro & Lioy, ITASEC 2024).

This is **not** an EAT and **not** a full EAR document — it is the **policy
input** to appraisal.

---

## Role map (RFC 9334)

| RATS role | eat-pass component |
|-----------|-------------------|
| Attester | CVM / mobile app producing EAT |
| Verifier (crypto) | `eat-pass-gate` |
| Verifier (policy) | `eat-pass-policy` on attester |
| Relying party | origin, tool-gate |

---

## Related docs

- [`verification-policy.md`](verification-policy.md) — policy file format
- [`competitive.md`](competitive.md) — vs Google PMB / Apple PAT
