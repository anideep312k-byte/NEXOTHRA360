"""Redis-backed TI cache."""
from __future__ import annotations
import hashlib
import json
from typing import Any
from ..web.security.redis_rate_limit import (
    RedisSecurityUnavailableError, security_store)


class TICache:
    MAX_TTL = 24 * 3600

    @staticmethod
    def _key(provider: str, kind: str, value: str) -> str:
        h = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:32]
        return f"k360:cache:ti:{provider}:{kind}:{h}"

    @classmethod
    def get(cls, provider: str, kind: str, value: str) -> dict[str, Any] | None:
        try:
            raw = security_store.client.get(cls._key(provider, kind, value))
        except RedisSecurityUnavailableError:
            return None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    @classmethod
    def set(cls, provider: str, kind: str, value: str,
            payload: dict[str, Any], ttl: int = 3600) -> None:
        ttl = max(1, min(int(ttl), cls.MAX_TTL))
        try:
            security_store.client.setex(
                cls._key(provider, kind, value), ttl,
                json.dumps(payload, separators=(",", ":"), default=str))
        except RedisSecurityUnavailableError:
            return
