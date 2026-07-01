from __future__ import annotations

from ..attestation.bundle import AttestationError as BundleError
from ..attestation.bundle import load_bundle_file
from ..attestation.tpm import AttestationError as TpmError
from ..attestation.tpm import collect_tpm_bundle_linux
from ..config import EatPassLinuxWorkloadConfig
from ..mint import MintError, MintResult, mint_authorization_header


class EatPassLinuxWorkloadClient:
    """Mint from a **non-CVM Linux host** (TPM2 + pinned agent binary digest).

    Attester: ``--gate desktop-tpm``. No TEE required — host TPM proves binding + build.
    """

    def __init__(self, config: EatPassLinuxWorkloadConfig) -> None:
        self._config = config

    def mint_authorization_header(self) -> MintResult:
        cfg = self._config

        if cfg.bundle_path:
            try:
                bundle = load_bundle_file(cfg.bundle_path)
            except (BundleError, OSError) as e:
                raise MintError(str(e)) from e
            return mint_authorization_header(cfg, lambda _: bundle)

        def collect(binding_hex: str) -> str:
            try:
                return collect_tpm_bundle_linux(cfg, binding_hex)
            except TpmError as e:
                raise MintError(str(e)) from e

        return mint_authorization_header(cfg, collect)
