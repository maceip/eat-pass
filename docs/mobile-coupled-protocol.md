# Mobile coupled gate (app attestation + eat-pass)

Protected mobile APIs require **both** in one mint flow. No attestation-only or token-only paths.

## Flow

```
1. Fetch origin/gate challenge (WWW-Authenticate)  → TokenChallenge + redemption_context
2. EatPassClient.begin(challenge)                  → binding (32 bytes)
3. Platform attest over binding                    → JSON bundle
4. POST attester /authorize                        → authorization + appraisal
5. POST issuer /sign                               → PrivateToken
6. POST origin/API with token                      → action (redeemer spends nonce)
```

Steps 4–5 must complete before any protected call. Issuer rate limits + redeemer block spam.

## Attester

```
eat-pass attester --gate android-key --policy policy/mobile-android.json
eat-pass attester --gate ios-app-attest --policy policy/mobile-ios.json
```

Policy `allow[]` uses **`app_id_hash` only** (32 bytes hex), not SNP measurement
(Leierzopf SPICES 2025). See `policy/examples/` and `docs/verification-policy.md`.

### POST /authorize (or /capability)

```json
{
  "eat_b64": "<base64 UTF-8 JSON bundle>",
  "binding": "<64 hex chars = binding_of(blinded)>",
  "max_batch": 1
}
```

Response includes EAR-shaped `appraisal` (Fossati draft-ietf-rats-ear).

## Android bundle (`platform: android-key-attestation`)

Device: `KeyGenParameterSpec.setAttestationChallenge(binding)` — server nonce = binding
(Fahl ASIACCS 2023). Reject stale challenges at origin/gate.

```json
{
  "version": 1,
  "platform": "android-key-attestation",
  "attestation_chain": ["<leaf hex DER>", "..."],
  "binding": "<64 hex>",
  "package_name": "com.example.app",
  "signing_cert_digest": "<64 hex SHA-256 of signing cert>"
}
```

`app_id_hash = SHA256("uq/mobile/android/v1\\0" || package || 0 || signing_cert_sha256)`

## iOS bundle (`platform: ios-app-attest`)

No iCloud login. `clientDataHash = SHA256("uq/mobile/ios/v1\\0" || binding)` → `generateAssertion`.

```json
{
  "version": 1,
  "platform": "ios-app-attest",
  "key_id": "...",
  "assertion": "<base64 CBOR>",
  "credential_public_key": "<65-byte uncompressed P-256 hex>",
  "team_id": "ABCDE12345",
  "bundle_id": "com.example.app",
  "app_id_hash": "<64 hex>",
  "binding": "<64 hex>",
  "client_data_hash": "<64 hex>"
}
```

`app_id_hash = SHA256("uq/mobile/ios-app-id/v1\\0" || team_id || 0 || bundle_id)`

## Origin / API

Reject requests without valid `Authorization: PrivateToken …` on protected routes.
Origins must issue fresh `redemption_context` per challenge (Hanff CCS 2025).
