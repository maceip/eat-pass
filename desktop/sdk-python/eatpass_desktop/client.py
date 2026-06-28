"""Coupled desktop mint: TPM attestation + eat-pass blind sign."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from .attestation import AttestationError, collect_tpm_bundle, load_bundle_file
from .config import EatPassConfig, PlatformAttest
from .crypto import load_crypto


class EatPassException(Exception):
    pass


@dataclass(frozen=True)
class MintResult:
    authorization_header: str
    binding_hex: str


class EatPassDesktopClient:
    """One-call coupled mint for Linux/Windows agent hosts."""

    def __init__(self, config: EatPassConfig) -> None:
        self._config = config
        self._crypto = load_crypto()

    def mint_authorization_header(self) -> MintResult:
        cfg = self._config
        issuer_base = cfg.issuer_url.rstrip("/")
        attester_base = cfg.attester_url.rstrip("/")

        keys_json = self._get(f"{issuer_base}/keys")
        if cfg.kt_log_pub_hex:
            kt = json.loads(self._get(f"{issuer_base}/kt"))
            served = kt.get("log_pub", "")
            if served.lower() != cfg.kt_log_pub_hex.lower():
                raise EatPassException("issuer KT log pubkey does not match pinned key")

        client = self._crypto.EatPassClient(
            issuer_pk_json=keys_json,
            issuer_name=cfg.issuer_name,
            origin_info=cfg.origin_info,
        )
        begin = client.begin(1)
        binding_hex = begin.binding_hex

        if cfg.platform == PlatformAttest.BUNDLE_FILE:
            try:
                bundle_json = load_bundle_file(cfg)
            except AttestationError as e:
                raise EatPassException(str(e)) from e
        else:
            try:
                bundle_json = collect_tpm_bundle(cfg, binding_hex)
            except AttestationError as e:
                raise EatPassException(str(e)) from e

        eat_b64 = base64.b64encode(bundle_json.encode("utf-8")).decode("ascii")
        auth_body = json.dumps(
            {
                "eat_b64": eat_b64,
                "binding": binding_hex,
                "max_batch": 1,
            }
        )
        auth_resp = json.loads(self._post(f"{attester_base}/authorize", auth_body))
        authorization_b64 = auth_resp["authorization_b64"]

        sign_body = json.dumps(
            {
                "req": json.loads(begin.request_json),
                "authorization_b64": authorization_b64,
            }
        )
        sign_resp = self._post(f"{issuer_base}/sign", sign_body)
        headers = client.finalize(sign_resp)
        if not headers:
            raise EatPassException("issuer returned no token")
        return MintResult(authorization_header=headers[0], binding_hex=binding_hex)

    def _request(self, url: str, method: str, body: Optional[str] = None) -> str:
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if body else {},
        )
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=self._config.timeout_seconds, context=ctx) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")
            raise EatPassException(f"{method} {url} failed ({e.code}): {text}") from e
        except urllib.error.URLError as e:
            raise EatPassException(f"{method} {url} failed: {e}") from e

    def _get(self, url: str) -> str:
        return self._request(url, "GET")

    def _post(self, url: str, body: str) -> str:
        return self._request(url, "POST", body)
