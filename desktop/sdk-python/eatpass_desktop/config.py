from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PlatformAttest(str, Enum):
    """How this host collects attestation evidence."""

    LINUX_TPM = "linux-tpm"
    WINDOWS_TPM = "windows-tpm"
    BUNDLE_FILE = "bundle-file"


@dataclass(frozen=True)
class EatPassConfig:
    attester_url: str
    issuer_url: str
    issuer_name: str = "issuer.eat-pass.dev"
    origin_info: str = "tool-gate.secure.build/v1/tools/email.send"
    kt_log_pub_hex: Optional[str] = None
    timeout_seconds: float = 30.0
    platform: PlatformAttest = PlatformAttest.LINUX_TPM
    """sha256(agent binary) hex — required for TPM modes."""
    build_digest_hex: Optional[str] = None
    """Pre-collected evidence JSON path — required for BUNDLE_FILE mode."""
    bundle_path: Optional[str] = None
    """Override path to collect-desktop-tpm.sh (Linux) or .ps1 (Windows)."""
    collect_script: Optional[str] = None
