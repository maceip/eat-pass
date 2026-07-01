from __future__ import annotations

import json
from pathlib import Path


class AttestationError(Exception):
    pass


def load_bundle_file(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    json.loads(text)
    return text
