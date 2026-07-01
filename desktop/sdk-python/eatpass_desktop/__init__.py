"""eat-pass platform SDKs — coupled mint (attest → policy → FAEST → PoMFRIT)."""

from .client import EatPassDesktopClient, EatPassException
from .config import (
    EatPassBaseConfig,
    EatPassConfig,
    EatPassLinuxTeeConfig,
    EatPassLinuxWorkloadConfig,
    PlatformAttest,
)
from .linux import EatPassLinuxTeeClient, EatPassLinuxWorkloadClient
from .mint import MintError, MintResult

__all__ = [
    "EatPassBaseConfig",
    "EatPassConfig",
    "EatPassDesktopClient",
    "EatPassException",
    "EatPassLinuxTeeClient",
    "EatPassLinuxTeeConfig",
    "EatPassLinuxWorkloadClient",
    "EatPassLinuxWorkloadConfig",
    "MintError",
    "MintResult",
    "PlatformAttest",
]
