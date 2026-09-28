from __future__ import annotations
from .base import TIProvider, TIResult
from .null_provider import NullProvider


def get_ti_provider() -> TIProvider:
    """Returns NullProvider. Add your own TI provider by implementing
    TIProvider and registering it here. No commercial TI APIs bundled."""
    return NullProvider()
