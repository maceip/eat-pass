"""Load UniFFI `eat_pass_mobile` from generated bindings."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_NATIVE_DIR = Path(__file__).resolve().parent / "native"


def load_crypto() -> Any:
    """Return the UniFFI module (EatPassClient, hash helpers)."""
    if str(_NATIVE_DIR) not in sys.path:
        sys.path.insert(0, str(_NATIVE_DIR))
    try:
        import eat_pass_mobile  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "eat_pass_mobile native module not found. Build and generate bindings:\n"
            "  cd eat-pass && cargo build -p eat-pass-mobile\n"
            "  ./desktop/generate-bindings.sh\n"
            f"Expected Python bindings under {_NATIVE_DIR}"
        ) from exc
    return eat_pass_mobile
