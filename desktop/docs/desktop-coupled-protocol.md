# Desktop coupled gate (TPM / App Attest + eat-pass)

Same flow as [mobile coupled protocol](../../docs/mobile-coupled-protocol.md):

```
1. GET issuer /keys (+ optional KT pin)
2. EatPassClient.begin(1)           → binding (32 bytes)
3. Host collects evidence JSON      → bound to binding
4. POST attester /authorize         → authorization_b64
5. POST issuer /sign                → blind signatures
6. EatPassClient.finalize           → PrivateToken header
```

No step is optional for protected routes.

## Linux / Windows TPM bundle

```json
{
  "version": 1,
  "platform": "linux-tpm-client",
  "binding": "<64 hex>",
  "build_digest": "<64 hex sha256(agent binary)>",
  "ak_cert": "<hex DER>",
  "quote_msg": "<hex>",
  "quote_sig": "<hex>",
  "qualifying_data": "<64 hex = binding>"
}
```

Windows uses `"platform": "windows-tpm-client"`.

Policy `allow[].measurement` = `desktop_build_id_hash(build_digest)`.

Collectors:

- Linux: `scripts/collect-desktop-tpm.sh`
- Windows: `scripts/collect-desktop-tpm-windows.ps1`

## macOS App Attest bundle

Same JSON shape as iOS; `"platform": "macos-app-attest"`. Policy uses `app_id_hash`.

## Attester

```bash
eat-pass attester --gate desktop-tpm --policy policy/examples/desktop-linux-tpm-example.json
eat-pass attester --gate macos-app-attest --policy policy/examples/desktop-macos-app-attest-example.json
```

## SDK entrypoints

| Host | One-call API |
|------|----------------|
| Linux (CVM / TEE) | `EatPassLinuxTeeClient` |
| Linux (no TEE) | `EatPassLinuxWorkloadClient` |
| Python (Windows TPM) | `EatPassDesktopClient` |
| C# | `EatPassDesktopClient.MintAuthorizationHeaderAsync()` |
| Swift macOS | `EatPassDesktopClient.mintAuthorizationHeader()` |

See [../../docs/linux-sdk.md](../../docs/linux-sdk.md) for the Linux dual-surface model.

All use the same `/authorize` and `/sign` bodies as the CLI `eat-pass token` path.
