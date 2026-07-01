"""Legacy combined client (Windows TPM + backward compat). Linux: use ``linux.tee`` / ``linux.workload``."""

from __future__ import annotations

from .attestation.bundle import AttestationError as BundleError
from .attestation.bundle import load_bundle_file
from .attestation.tpm import AttestationError as TpmError
from .attestation.tpm import collect_tpm_bundle_legacy
from .config import EatPassConfig, PlatformAttest
from .mint import MintError, MintResult, mint_authorization_header

EatPassException = MintError


class EatPassDesktopClient:
    """Windows TPM + legacy entry. Prefer :class:`~eatpass_desktop.linux.tee.EatPassLinuxTeeClient`."""

    def __init__(self, config: EatPassConfig) -> None:
        self._config = config

    def mint_authorization_header(self) -> MintResult:
        cfg = self._config

        if cfg.platform == PlatformAttest.BUNDLE_FILE:
            if not cfg.bundle_path:
                raise MintError("bundle_path required for BUNDLE_FILE mode")
            try:
                bundle = load_bundle_file(cfg.bundle_path)
            except (BundleError, OSError) as e:
                raise MintError(str(e)) from e
            return mint_authorization_header(cfg, lambda _: bundle)

        def collect(binding_hex: str) -> str:
            try:
                return collect_tpm_bundle_legacy(
                    cfg.platform,
                    binding_hex,
                    build_digest_hex=cfg.build_digest_hex,
                    collect_script=cfg.collect_script,
                )
            except TpmError as e:
                raise MintError(str(e)) from e

        return mint_authorization_header(cfg, collect)
