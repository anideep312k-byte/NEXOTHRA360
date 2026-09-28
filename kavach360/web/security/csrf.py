"""Strict double-submit CSRF and Origin verification."""
from __future__ import annotations
import functools
import hmac
from urllib.parse import urlparse
from flask import jsonify, request
from ...config import config

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def _norm(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}".lower().rstrip("/")


ALLOWED_ORIGINS = frozenset(_norm(o) for o in config.CORS_ORIGINS if o)


def origin_ok() -> bool:
    if request.method in SAFE_METHODS:
        return True
    origin = request.headers.get("Origin")
    return bool(origin and _norm(origin) in ALLOWED_ORIGINS)


def csrf_ok() -> bool:
    if request.method in SAFE_METHODS:
        return True
    cookie = request.cookies.get("kavach_csrf")
    header = request.headers.get(config.CSRF_HEADER_NAME)
    if not cookie or not header:
        return False
    if len(cookie) < 40 or len(header) < 40:
        return False
    return hmac.compare_digest(cookie, header)


def require_browser_security(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not origin_ok():
            return jsonify({"error": "invalid_origin"}), 403
        if not csrf_ok():
            return jsonify({"error": "csrf_failed"}), 403
        return fn(*a, **kw)
    return wrapper
