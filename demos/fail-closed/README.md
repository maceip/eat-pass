# Fail-closed demos (Tier S)

Scripts exercise **operator policy** — the interface every platform shares.
Crypto verification is assumed done; these show appraisal **pass / reject**.

| Script | Shows | PAT can't |
|--------|-------|-----------|
| [`wrong-binary.sh`](./wrong-binary.sh) | Launch digest not in `allow` → reject | Build-level allowlist on silicon |
| [`binding-or-bust.sh`](./binding-or-bust.sh) | `binding_ok: false` → reject | Hardware-signed per-mint binding |
| [`two-ghosts.sh`](./two-ghosts.sh) | Two builds, same class, both pass | Unlinkable spend after RA class gate |
| [`run-all.sh`](./run-all.sh) | All three | — |

```bash
./demos/fail-closed/run-all.sh
# uses `eat-pass policy simulate` when built; otherwise demos/fail-closed/policy_simulate.py
```

Fixtures: [`../fixtures/`](../fixtures/) · Policy: [`../fixtures/uqaz1-live-policy.json`](../fixtures/uqaz1-live-policy.json)

On hardware: attester runs the same checks after `eat-pass-gate` crypto verify.
Use `eat-pass policy simulate` to rehearse the narrative without a CVM.
