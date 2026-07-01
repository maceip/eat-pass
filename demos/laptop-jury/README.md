# Laptop jury

**What PAT can't show:** a projector laptop re-verifies the CVM's hardware quote
against the **AMD Milan root** — without trusting your slides or your server.

## Act 1 — Remote attestation (no TEE on laptop)

From any machine with `uq` built (`unified-quote`):

```bash
./verify-live.sh
```

Expected: Azure `verdict: verified`, AWS SNP `uq check` PASS.

## Act 2 — Coupled mint (inside CVM)

On the Azure CVM (`uqaz1`), with eat-pass services running:

```bash
eat-pass token --kt-log-pub "$KT_LOG_PUB" \
  --uq-collect "uq azure collect" \
  --present http://127.0.0.1:8099/resource
```

The attester only signs when `binding` matches the hardware quote.

## Fail cases to show live

| Try | Expected |
|-----|----------|
| Reuse quote with new binding | Attester reject |
| Wrong launch measurement in policy | Attester reject before mint |
| Call issuer without `/authorize` | Issuer reject |

Policy example: [`policy/examples/uqaz1-example.json`](../../policy/examples/uqaz1-example.json)
