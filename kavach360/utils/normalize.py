"""String normalization for detection."""
from __future__ import annotations
import re
import unicodedata

_NULL = re.compile(r"\x00")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS = re.compile(r"\s+")


def normalize_field(value, max_len: int = 4096) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    try:
        value = unicodedata.normalize("NFKC", value)
    except Exception:
        pass
    value = _NULL.sub("", value)
    value = _CTRL.sub(" ", value)
    value = value.replace("\\", "/")
    value = value.lower()
    value = _WS.sub(" ", value).strip()
    return value[:max_len]


def iterative_unquote(value: str, max_rounds: int = 5) -> str:
    from urllib.parse import unquote
    prev, cur = None, value
    for _ in range(max_rounds):
        if cur == prev:
            break
        prev = cur
        cur = unquote(cur)
    return cur


def check_json_depth(obj, max_depth: int = 20, _depth: int = 0) -> bool:
    if _depth > max_depth:
        return False
    if isinstance(obj, dict):
        return all(check_json_depth(v, max_depth, _depth + 1)
                   for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return all(check_json_depth(v, max_depth, _depth + 1) for v in obj)
    return True
