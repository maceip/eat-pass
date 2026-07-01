from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Optional

from ..config import EatPassLinuxWorkloadConfig, PlatformAttest


class AttestationError(Exception):
    pass


def collect_tpm_bundle_linux(config: EatPassLinuxWorkloadConfig, binding_hex: str) -> str:
    build = config.build_digest_hex
    if not build or len(build.strip()) != 64:
        raise AttestationError("build_digest_hex must be 64 hex chars (sha256 of agent binary)")

    script = Path(config.collect_script) if config.collect_script else _repo_collect_script()
    if script is None or not script.is_file():
        raise AttestationError(
            "collect script not found; set collect_script on EatPassLinuxWorkloadConfig"
        )

    env = os.environ.copy()
    env["BINDING"] = binding_hex.strip()
    env["BUILD_DIGEST"] = build.strip()

    proc = subprocess.run(
        [str(script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise AttestationError(
            f"TPM collect failed ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    return _parse_collect_output(proc.stdout)


def collect_tpm_bundle_windows(
    *,
    binding_hex: str,
    build_digest_hex: str,
    collect_script: Optional[str],
) -> str:
    script = Path(collect_script) if collect_script else _repo_collect_script_windows()
    if script is None or not script.is_file():
        raise AttestationError("Windows TPM collect script not found")

    env = os.environ.copy()
    env["BINDING"] = binding_hex.strip()
    env["BUILD_DIGEST"] = build_digest_hex.strip()

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
    if proc.returncode != 0:
        raise AttestationError(
            f"TPM collect failed ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    return _parse_collect_output(proc.stdout)


def collect_tpm_bundle_legacy(
    platform: PlatformAttest,
    binding_hex: str,
    *,
    build_digest_hex: Optional[str],
    collect_script: Optional[str],
) -> str:
    if platform == PlatformAttest.WINDOWS_TPM:
        if not build_digest_hex:
            raise AttestationError("build_digest_hex required for Windows TPM")
        return collect_tpm_bundle_windows(
            binding_hex=binding_hex,
            build_digest_hex=build_digest_hex,
            collect_script=collect_script,
        )
    cfg = EatPassLinuxWorkloadConfig(
        attester_url="",
        issuer_url="",
        build_digest_hex=build_digest_hex or "",
        collect_script=collect_script,
    )
    return collect_tpm_bundle_linux(cfg, binding_hex)


def _parse_collect_output(stdout: str) -> str:
    out = stdout.strip()
    if not out:
        raise AttestationError("collect script produced no output")
    if out.startswith("{"):
        bundle = out
    else:
        lines = [ln for ln in out.splitlines() if ln.strip()]
        bundle = Path(lines[-1]).read_text(encoding="utf-8")
    json.loads(bundle)
    return bundle


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _repo_collect_script() -> Optional[Path]:
    p = _repo_root() / "scripts" / "collect-desktop-tpm.sh"
    return p if p.is_file() else None


def _repo_collect_script_windows() -> Optional[Path]:
    p = _repo_root() / "scripts" / "collect-desktop-tpm-windows.ps1"
    return p if p.is_file() else None
