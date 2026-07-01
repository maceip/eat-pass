from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Callable

from .config import EatPassBaseConfig
from .crypto import load_crypto
from .http import HttpClient, HttpError


class MintError(Exception):
    pass


@dataclass(frozen=True)
class MintResult:
    authorization_header: str
    binding_hex: str


def mint_authorization_header(
    config: EatPassBaseConfig,
    collect_bundle_json: Callable[[str], str],
) -> MintResult:
    """Coupled mint: ``collect_bundle_json(binding_hex)`` → attester → issuer → token."""

    http = HttpClient(config)
    issuer_base = config.issuer_url.rstrip("/")
    attester_base = config.attester_url.rstrip("/")

    try:
        keys_json = http.get(f"{issuer_base}/keys")
        if config.kt_log_pub_hex:
            kt = json.loads(http.get(f"{issuer_base}/kt"))
            served = kt.get("log_pub", "")
            if served.lower() != config.kt_log_pub_hex.lower():
                raise MintError("issuer KT log pubkey does not match pinned key")

        crypto = load_crypto()
        client = crypto.EatPassClient(
            issuer_pk_json=keys_json,
            issuer_name=config.issuer_name,
            origin_info=config.origin_info,
        )
        begin = client.begin(1)
        binding_hex = begin.binding_hex

        bundle_json = collect_bundle_json(binding_hex)
        eat_b64 = base64.b64encode(bundle_json.encode("utf-8")).decode("ascii")

        auth_resp = json.loads(
            http.post_json(
                f"{attester_base}/authorize",
                {"eat_b64": eat_b64, "binding": binding_hex, "max_batch": 1},
            )
        )
        authorization_b64 = auth_resp["authorization_b64"]

        sign_resp = http.post_json(
            f"{issuer_base}/sign",
            {
                "req": json.loads(begin.request_json),
                "authorization_b64": authorization_b64,
            },
        )
        headers = client.finalize(sign_resp)
        if not headers:
            raise MintError("issuer returned no token")
        return MintResult(authorization_header=headers[0], binding_hex=binding_hex)
    except HttpError as e:
        raise MintError(str(e)) from e
