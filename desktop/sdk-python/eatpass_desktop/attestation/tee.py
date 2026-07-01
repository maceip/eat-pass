from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Sequence

from ..config import EatPassLinuxTeeConfig


class AttestationError(Exception):
    pass


def collect_tee_bundle(config: EatPassLinuxTeeConfig, binding_hex: str) -> str:
    """Run ``unified-quote`` collect with ``--value-x <binding>`` (CVM / TEE path)."""

    argv = _parse_collect_cmd(config.collect_cmd)
    if not argv:
        raise AttestationError("collect_cmd is empty")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="eatpass-tee-"
    ) as tmp:
        out_path = tmp.name

    try:
        proc = subprocess.run(
            [*argv, "--value-x", binding_hex.strip(), "-o", out_path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AttestationError(
                f"TEE collect failed ({proc.returncode}): {proc.stderr or proc.stdout}"
            )
        bundle = open(out_path, encoding="utf-8").read()
        json.loads(bundle)
        return bundle
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _parse_collect_cmd(cmd: str) -> Sequence[str]:
    return [part for part in cmd.strip().split() if part]
