"""eat-pass desktop SDK — coupled mint for Linux and Windows agents."""

from .client import EatPassDesktopClient, EatPassException, MintResult
from .config import EatPassConfig, PlatformAttest

__all__ = [
    "EatPassConfig",
    "EatPassDesktopClient",
    "EatPassException",
    "MintResult",
    "PlatformAttest",
]
