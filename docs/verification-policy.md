# Verification policy

Operator-owned appraisal policy for eat-pass. Crypto verification stays in
`eat-pass-gate`; this blob decides **allow / deny** after evidence is genuine.

## Citations (what we implement against)

| Source | Use |
|--------|-----|
| Birkholz et al., RFC 9334 (RATS Architecture) | Attester / Verifier / RP roles; appraisal policy |
| Lundblade et al., RFC 9711 (EAT, 2025) | Attestation results; verifier policy is local |
| IETF draft-ietf-rats-corim | Reference values + signed manifests shape |
| Hanff, Lehmann, Özbay, ACM CCS 2025 | Coupled mint binding / redemption context |
| Lin et al., USENIX Security 2025 (Verdict) | Policy validate + simulate CLI pattern |
| Rezabek & Passerat-Palmbach, arXiv:2510.12469 (2025) | CVM trust boundary in policy notes |
| Leierzopf et al., SPICES 2025 (AVBTestKeyInTheWild) | Mobile: app identity in policy, not root flags |

## File format (`version: 1`)

```json
{
  "version": 1,
  "id": "uqaz1-prod",
  "valid_until": "2027-01-01T00:00:00Z",
  "evidence_profile": "azure-snp-bundle",
  "class": { "name": "accepted-builds", "version": 1 },
  "registry_minimum": "recommended",
  "allow": [{ "measurement": "<64-hex SNP launch measurement>" }]
}
```

`evidence_profile` values: `uq-eat`, `azure-snp-bundle`, `azure-attested-tls`,
`android-key-attestation`, `ios-app-attest`.

Mobile entries use `app_id_hash` instead of `measurement`.

## CLI (human + agent)

```bash
eat-pass policy validate --file policy/examples/uqaz1-example.json
eat-pass policy simulate --policy policy/examples/uqaz1-example.json --claims claims.json
```

`claims.json` is **post crypto-verify** normalized input (RFC 9711 attestation-results input):

```json
{
  "evidence_profile": "azure-snp-bundle",
  "platform": "sev-snp",
  "measurement": "<hex>",
  "binding_ok": true,
  "registry_status": "recommended"
}
```

## Stack placement

1. Gate crates — crypto only → normalized claims  
2. **`eat-pass-policy`** — this file  
3. Attester — loads `--policy` → crypto verify + appraisal → `MeasurementClass`  
4. Mobile SDK (later) — no embedded allowlists; server policy version only
