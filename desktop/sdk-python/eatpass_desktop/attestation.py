"""Collect desktop attestation bundles (TPM or pre-built JSON)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from .config import EatPassConfig, PlatformAttest


class AttestationError(Exception):
    pass


def _repo_collect_script(platform: PlatformAttest) -> Optional[Path]:
    root = Path(__file__).resolve().parents[3]
    if platform == PlatformAttest.LINUX_TPM:
        p = root / "scripts" / "collect-desktop-tpm.sh"
    elif platform == PlatformAttest.WINDOWS_TPM:
        p = root / "scripts" / "collect-desktop-tpm-windows.ps1"
    else:
        return None
    return p if p.is_file() else None


def collect_tpm_bundle(config: EatPassConfig, binding_hex: str) -> str:
    """Return UTF-8 JSON bundle for POST /authorize eat_b64."""
    if config.platform == PlatformAttest.BUNDLE_FILE:
        raise AttestationError("use load_bundle_file for BUNDLE_FILE mode")

    build = config.build_digest_hex
    if not build or len(build.strip()) != 64:
        raise AttestationError("build_digest_hex must be 64 hex chars (sha256 of agent binary)")

    script = Path(config.collect_script) if config.collect_script else _repo_collect_script(
        config.platform
    )
    if script is None or not script.is_file():
        raise AttestationError(
            f"no collect script for {config.platform.value}; set collect_script in EatPassConfig"
        )

    env = os.environ.copy()
    env["BINDING"] = binding_hex.strip()
    env["BUILD_DIGEST"] = build.strip()

    if config.platform == PlatformAttest.WINDOWS_TPM:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                "-OutFile",
                "-",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    else:
        proc = subprocess.run(
            [str(script)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    if proc.returncode != 0:
        raise AttestationError(
            f"collect script failed ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    out = proc.stdout.strip()
    if not out:
        raise AttestationError("collect script produced no output")
    # Script may print path on last line; JSON is either stdout or file.
    if out.startswith("{"):
        bundle = out
    else:
        lines = [ln for ln in out.splitlines() if ln.strip()]
        path = Path(lines[-1])
        bundle = path.read_text(encoding="utf-8")
    json.loads(bundle)  # validate
    return bundle


def load_bundle_file(config: EatPassConfig) -> str:
    path = config.bundle_path
    if not path:
        raise AttestationError("bundle_path required for BUNDLE_FILE mode")
    text = Path(path).read_text(encoding="utf-8")
    json.loads(text)
    return text
