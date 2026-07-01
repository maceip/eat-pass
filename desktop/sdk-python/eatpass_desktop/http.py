from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Optional

from .config import EatPassBaseConfig


class HttpError(Exception):
    pass


class HttpClient:
    def __init__(self, config: EatPassBaseConfig) -> None:
        self._config = config
        self._ctx = ssl.create_default_context()

    def get(self, url: str) -> str:
        return self._request(url, "GET")

    def post_json(self, url: str, body: dict) -> str:
        return self._request(url, "POST", json.dumps(body))

    def _request(self, url: str, method: str, body: Optional[str] = None) -> str:
        data = body.encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if body else {},
        )
        try:
            with urllib.request.urlopen(
                req, timeout=self._config.timeout_seconds, context=self._ctx
            ) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", errors="replace")
            raise HttpError(f"{method} {url} failed ({e.code}): {text}") from e
        except urllib.error.URLError as e:
            raise HttpError(f"{method} {url} failed: {e}") from e
