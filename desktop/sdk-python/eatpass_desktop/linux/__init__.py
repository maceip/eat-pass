"""Linux SDK — two attestation surfaces, one mint protocol."""

from .tee import EatPassLinuxTeeClient
from .workload import EatPassLinuxWorkloadClient

__all__ = ["EatPassLinuxTeeClient", "EatPassLinuxWorkloadClient"]
