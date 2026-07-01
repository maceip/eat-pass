from __future__ import annotations

import json

from ..attestation.bundle import AttestationError as BundleError
from ..attestation.bundle import load_bundle_file
from ..attestation.tee import AttestationError as TeeError
from ..attestation.tee import collect_tee_bundle
from ..config import EatPassLinuxTeeConfig
from ..mint import MintError, MintResult, mint_authorization_header


class EatPassLinuxTeeClient:
    """Mint from **inside a confidential VM** (SEV-SNP, TDX, …).

    Attester: ``--gate azure`` or ``--gate uq``. Evidence: ``uq … collect --value-x <binding>``.
    """

    def __init__(self, config: EatPassLinuxTeeConfig) -> None:
        self._config = config

    def mint_authorization_header(self) -> MintResult:
        cfg = self._config

        def collect(binding_hex: str) -> str:
            try:
                return collect_tee_bundle(cfg, binding_hex)
            except TeeError as e:
                raise MintError(str(e)) from e

        return mint_authorization_header(cfg, collect)

    def mint_from_bundle_file(self, bundle_path: str) -> MintResult:
        try:
            bundle = load_bundle_file(bundle_path)
        except (BundleError, OSError, json.JSONDecodeError) as e:
            raise MintError(str(e)) from e

        return mint_authorization_header(self._config, lambda _: bundle)
