from __future__ import annotations

import sys
from pathlib import Path

_VENDOR_DIR = str(Path(__file__).parent)

def ensure_on_path() -> None:
    if _VENDOR_DIR not in sys.path:
        sys.path.append(_VENDOR_DIR)
