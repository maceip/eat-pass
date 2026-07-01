#!/usr/bin/env python3
"""Self-test for policy_simulate.py — run via test-all.sh or CI."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
POLICY = ROOT.parent / "fixtures" / "uqaz1-live-policy.json"
CASES = [
    ("claims-good-build.json", 0),
    ("claims-wrong-build.json", 1),
    ("claims-wrong-binding.json", 1),
    ("claims-ghost-b.json", 0),
]


def main() -> int:
    script = ROOT / "policy_simulate.py"
    failed = 0
    for claims_name, want_rc in CASES:
        claims = ROOT.parent / "fixtures" / claims_name
        proc = subprocess.run(
            [sys.executable, str(script), str(POLICY), str(claims)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != want_rc:
            print(f"FAIL {claims_name}: want exit {want_rc}, got {proc.returncode}", file=sys.stderr)
            print(proc.stdout, proc.stderr, file=sys.stderr)
            failed += 1
        else:
            print(f"OK   {claims_name} → exit {want_rc}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
