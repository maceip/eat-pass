from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PlatformAttest(str, Enum):
    """Legacy selector for :class:`EatPassDesktopClient`. Prefer platform SDKs."""

    LINUX_TPM = "linux-tpm"
    WINDOWS_TPM = "windows-tpm"
    BUNDLE_FILE = "bundle-file"


@dataclass(frozen=True)
class EatPassBaseConfig:
    """Shared endpoints for every platform SDK surface."""

    attester_url: str
    issuer_url: str
    issuer_name: str = "issuer.eat-pass.dev"
    origin_info: str = "tool-gate.secure.build/v1/tools/email.send"
    kt_log_pub_hex: Optional[str] = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class EatPassLinuxTeeConfig(EatPassBaseConfig):
    """Linux hosts **inside** a CVM (SEV-SNP, TDX, …).

    Attester gate: ``azure`` or ``uq``. Evidence via ``unified-quote collect``.
    Policy field: ``allow[].measurement`` (launch digest / MRENCLAVE-style).
    """

    collect_cmd: str = "uq azure collect"
    """Command prefix before ``--value-x <binding> -o <file>`` (no shell)."""


@dataclass(frozen=True)
class EatPassLinuxWorkloadConfig(EatPassBaseConfig):
    """Linux agents **without** a confidential VM — bare metal, VM, laptop, k8s pod.

    Attester gate: ``desktop-tpm``. Evidence: host TPM2 AK quote + build digest.
    Policy field: ``allow[].measurement`` = ``desktop_build_id_hash(sha256(agent))``.
    """

    build_digest_hex: str = ""
    collect_script: Optional[str] = None
    bundle_path: Optional[str] = None
    """Use a pre-collected JSON bundle instead of running the collect script."""


@dataclass(frozen=True)
class EatPassConfig(EatPassBaseConfig):
    """Windows + legacy one-client entry. Linux callers should use ``linux.tee`` / ``linux.workload``."""

    platform: PlatformAttest = PlatformAttest.LINUX_TPM
    build_digest_hex: Optional[str] = None
    bundle_path: Optional[str] = None
    collect_script: Optional[str] = None
