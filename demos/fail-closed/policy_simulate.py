#!/usr/bin/env python3
"""Mirror eat-pass policy appraisal for demo scripts (no PoMFRIT build required)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def hex_bytes(s: str | None) -> bytes | None:
    if not s:
        return None
    return bytes.fromhex(s.strip())


def is_expired(valid_until: str | None) -> bool:
    if not valid_until:
        return False
    dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    return datetime.now(timezone.utc) > dt


def registry_ok(minimum: str, status: str | None) -> bool:
    if status is None:
        return True
    if minimum == "recommended":
        return status == "recommended"
    return status in ("recommended", "deprecated")


def appraise(policy: dict, claims: dict) -> dict:
    checks: list[tuple[str, bool]] = []
    checks.append(("PolicyNotExpired", not is_expired(policy.get("valid_until"))))
    checks.append(
        ("ProfileMatch", claims["evidence_profile"] == policy["evidence_profile"])
    )
    checks.append(("BindingOk", bool(claims.get("binding_ok"))))

    identity = hex_bytes(claims.get("measurement")) or hex_bytes(claims.get("app_id_hash"))
    allowed = []
    for entry in policy.get("allow", []):
        m = hex_bytes(entry.get("measurement"))
        a = hex_bytes(entry.get("app_id_hash"))
        if m:
            allowed.append(m)
        if a:
            allowed.append(a)
    in_allow = identity is not None and identity in allowed
    checks.append(("ReferenceValueMatch", in_allow))

    minimum = policy.get("registry_minimum", "recommended")
    checks.append(
        ("RegistryStatus", registry_ok(minimum, claims.get("registry_status")))
    )

    passed = all(ok for _, ok in checks)
    reason = None
    if not passed:
        failed = next(name for name, ok in checks if not ok)
        reason = f"failed check: {failed}"

    cls = policy["class"]
    return {
        "pass": passed,
        "policy_id": policy["id"],
        "class_label": f"{cls['name']}@v{cls['version']}",
        "checks": [[name, ok] for name, ok in checks],
        "reason": reason,
        "measurement": claims.get("measurement") if passed else None,
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: policy_simulate.py <policy.json> <claims.json>", file=sys.stderr)
        return 2
    policy = load_json(Path(sys.argv[1]))
    claims = load_json(Path(sys.argv[2]))
    result = appraise(policy, claims)
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
