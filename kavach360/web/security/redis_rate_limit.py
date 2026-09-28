"""Redis security controls."""
from __future__ import annotations
import functools
import hashlib
import json
import logging
import re
import secrets
import time
from typing import Any, Callable

import redis
from redis.exceptions import ConnectionError, RedisError, TimeoutError

log = logging.getLogger("kavach360.security.redis")


class RedisSecurityUnavailableError(RuntimeError):
    pass


WINDOW_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {n, redis.call('TTL', KEYS[1])}
"""

FAILURE_SCRIPT = """
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
local threshold = tonumber(ARGV[2])
local base = tonumber(ARGV[3])
local maximum = tonumber(ARGV[4])
local lock = 0
if n >= threshold then
    local exponent = math.floor(n / threshold) - 1
    lock = math.min(maximum, base * (2 ^ exponent))
    redis.call('SET', KEYS[2], '1', 'EX', lock)
end
return {n, lock}
"""

PEEK_MFA_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return nil end
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then
    redis.call('DEL', KEYS[1])
    return nil
end
return raw
"""

BURN_MFA_ATTEMPT_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return {0, 0} end
local ttl = redis.call('PTTL', KEYS[1])
local data = cjson.decode(raw)
data['attempts'] = (data['attempts'] or 0) + 1
local max_attempts = tonumber(ARGV[1])
if data['attempts'] >= max_attempts then
    redis.call('DEL', KEYS[1])
    return {0, 1}
end
redis.call('SET', KEYS[1], cjson.encode(data), 'PX', ttl)
return {1, 0}
"""

CONSUME_MFA_CHALLENGE_SCRIPT = """
local key = KEYS[1]
local expected_ip = ARGV[1]
local expected_tx = ARGV[2]
local raw = redis.call('GET', key)
if not raw then return {0, 'challenge_not_found'} end
local ttl = redis.call('PTTL', key)
if ttl <= 0 then
    redis.call('DEL', key)
    return {0, 'challenge_expired'}
end
local data = cjson.decode(raw)
if data['tx_id'] ~= expected_tx then
    return {0, 'tx_mismatch'}
end
if data['ip'] ~= expected_ip then
    return {0, 'client_binding_mismatch'}
end
redis.call('DEL', key)
return {1, cjson.encode(data)}
"""

CORRELATION_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local event_id = ARGV[3]
local threshold = tonumber(ARGV[4])
local max_retained = tonumber(ARGV[5]) or 100
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('ZADD', key, now, event_id)
redis.call('EXPIRE', key, window + 60)
local total = redis.call('ZCARD', key)
if total > max_retained then
    redis.call('ZREMRANGEBYRANK', key, 0, total - max_retained - 1)
end
local count = redis.call('ZCARD', key)
local limit = math.min(count, 10)
local members = {}
if limit > 0 then members = redis.call('ZREVRANGE', key, 0, limit - 1) end
return {(count >= threshold) and 1 or 0, count, members}
"""

_RATELIMIT_RE = re.compile(
    r"^\s*(?P<limit>\d+)\s+per\s+(?:(?P<mult>\d+)\s+)?"
    r"(?P<unit>second|minute|hour|day)s?\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
_MAX_WINDOW = 30 * 86400
_MAX_LIMIT = 1_000_000


def parse_limit(spec: str) -> tuple[int, int]:
    if not isinstance(spec, str):
        raise ValueError("Rate limit spec must be a string")
    m = _RATELIMIT_RE.match(spec)
    if not m:
        raise ValueError(f"Invalid rate limit specification: {spec!r}")
    limit = int(m.group("limit"))
    mult = int(m.group("mult")) if m.group("mult") else 1
    unit = m.group("unit").lower()
    if limit <= 0 or mult <= 0:
        raise ValueError(f"Rate limit values must be positive: {spec!r}")
    window = mult * _UNIT_SECONDS[unit]
    if limit > _MAX_LIMIT or window > _MAX_WINDOW:
        raise ValueError(f"Rate limit out of bounds: {spec!r}")
    return limit, window


class RedisSecurity:
    def __init__(self, url: str) -> None:
        if not url:
            raise RuntimeError("Redis URL required")
        self.client = redis.Redis.from_url(
            url, decode_responses=True,
            socket_connect_timeout=2.0, socket_timeout=2.0, health_check_interval=30,
        )
        self.window_script = self.client.register_script(WINDOW_SCRIPT)
        self.failure_script = self.client.register_script(FAILURE_SCRIPT)
        self.peek_mfa_script = self.client.register_script(PEEK_MFA_SCRIPT)
        self.burn_mfa_attempt_script = self.client.register_script(BURN_MFA_ATTEMPT_SCRIPT)
        self.consume_mfa_script = self.client.register_script(CONSUME_MFA_CHALLENGE_SCRIPT)
        self.correlation_script = self.client.register_script(CORRELATION_SCRIPT)

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("Redis unreachable") from exc

    def deduplicate_event(self, tenant_id: str, fingerprint: str, ttl: int = 60) -> bool:
        key = f"k360:dedup:{tenant_id}:{fingerprint}"
        try:
            return bool(self.client.set(key, "1", nx=True, ex=ttl))
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("dedup store unavailable") from exc

    def revoke_token_family(self, user_id: str) -> None:
        key = f"k360:token_revocation:{self.digest(user_id)}"
        try:
            self.client.setex(key, 86400 * 8, str(int(time.time() * 1000)))
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("revocation store unavailable") from exc

    def is_token_revoked(self, user_id: str, issued_at_ms: int) -> bool:
        key = f"k360:token_revocation:{self.digest(user_id)}"
        try:
            revoked_at = self.client.get(key)
            return bool(revoked_at and issued_at_ms <= int(revoked_at))
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("revocation check unavailable") from exc

    def rate(self, namespace: str, identity: str, limit: int, window: int) -> tuple[bool, int]:
        key = f"k360:rl:{namespace}:{self.digest(identity)}"
        try:
            count, ttl = self.window_script(keys=[key], args=[window])
            return int(count) <= limit, max(int(ttl), 1)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("rate limit unavailable") from exc

    def lock_status(self, namespace: str, identity: str) -> tuple[bool, int]:
        key = f"k360:lock:{namespace}:{self.digest(identity)}"
        try:
            ttl = self.client.ttl(key)
            return (ttl <= 0), max(int(ttl), 1)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("lock store unavailable") from exc

    def record_failure(self, namespace: str, identity: str, threshold: int,
                       base: int, maximum: int) -> tuple[bool, int]:
        prefix = self.digest(identity)
        try:
            _, lock = self.failure_script(
                keys=[f"k360:fail:{namespace}:{prefix}", f"k360:lock:{namespace}:{prefix}"],
                args=[3600, threshold, base, maximum])
            return int(lock) == 0, int(lock)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("lockout store unavailable") from exc

    def clear_failures(self, namespace: str, identity: str) -> None:
        prefix = self.digest(identity)
        try:
            self.client.delete(f"k360:fail:{namespace}:{prefix}",
                               f"k360:lock:{namespace}:{prefix}")
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("clear failures unavailable") from exc

    def create_mfa_challenge(self, user_id: str, client_ip: str,
                             transaction_id: str, ttl: int = 300) -> str:
        token = secrets.token_urlsafe(32)
        payload = json.dumps({"user_id": str(user_id), "ip": client_ip,
                              "tx_id": transaction_id, "attempts": 0,
                              "created_at": int(time.time())})
        try:
            self.client.setex(f"k360:mfa:{token}", ttl, payload)
            return token
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("MFA creation unavailable") from exc

    def peek_mfa_challenge(self, token: str) -> dict | None:
        try:
            raw = self.peek_mfa_script(keys=[f"k360:mfa:{token}"])
            if not raw:
                return None
            return json.loads(raw)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("MFA peek unavailable") from exc

    def burn_mfa_attempt(self, token: str, max_attempts: int = 3) -> bool:
        try:
            res = self.burn_mfa_attempt_script(
                keys=[f"k360:mfa:{token}"], args=[max_attempts])
            return bool(res[0] == 1)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("MFA burn unavailable") from exc

    def consume_mfa_challenge(self, token: str, client_ip: str,
                              transaction_id: str) -> dict | None:
        try:
            res = self.consume_mfa_script(
                keys=[f"k360:mfa:{token}"],
                args=[client_ip, transaction_id])
            if res[0] == 1:
                return json.loads(res[1])
            log.warning("MFA challenge rejected: %s", res[1])
            return None
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("MFA consume unavailable") from exc

    def claim_totp_code(self, user_id: str, code: str, ttl: int = 90) -> bool:
        key = f"k360:totp_used:{self.digest(user_id)}:{code}"
        try:
            return bool(self.client.set(key, "1", nx=True, ex=ttl))
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("TOTP claim unavailable") from exc

    def track_correlation(self, key_id: str, event_id: str, now: float, window: int,
                          threshold: int, max_retained: int = 100) -> tuple[bool, int, list[str]]:
        key = f"k360:corr:{self.digest(key_id)}"
        try:
            res = self.correlation_script(keys=[key],
                                          args=[now, window, event_id, threshold, max_retained])
            return bool(res[0] == 1), int(res[1]), list(res[2]) if len(res) > 2 else []
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RedisSecurityUnavailableError("correlation unavailable") from exc

    def stream_length(self, stream: str) -> int:
        try:
            return int(self.client.xlen(stream))
        except Exception:
            return 0


_SECURITY_STORE_INSTANCE = None


def get_security_store() -> RedisSecurity:
    global _SECURITY_STORE_INSTANCE
    if _SECURITY_STORE_INSTANCE is None:
        from ...config import config as _cfg
        _SECURITY_STORE_INSTANCE = RedisSecurity(_cfg.REDIS_URL)
    return _SECURITY_STORE_INSTANCE


class _SecurityStoreProxy:
    def __getattr__(self, name: str):
        return getattr(get_security_store(), name)

    def __repr__(self) -> str:
        return "<security_store proxy>"


security_store = _SecurityStoreProxy()


def rate_limit(namespace: str, spec: str, identity_fn: Callable[[], str]) -> Callable:
    from flask import jsonify
    limit, window = parse_limit(spec)

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            try:
                allowed, retry = security_store.rate(namespace, identity_fn(), limit, window)
                if not allowed:
                    r = jsonify({"error": "rate_limit_exceeded", "retry_after": retry})
                    r.status_code = 429
                    r.headers["Retry-After"] = str(retry)
                    return r
            except RedisSecurityUnavailableError:
                return jsonify({"error": "service_unavailable",
                                "message": "Security state engine offline"}), 503
            return fn(*a, **kw)
        return wrapper
    return deco


def protected_auth(namespace: str, spec: str, identity_fn: Callable[[], str]) -> Callable:
    from flask import jsonify, request
    limit, window = parse_limit(spec)

    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            ip = request.remote_addr or "unknown"
            identity = identity_fn()
            try:
                ok, retry = security_store.lock_status(namespace, identity)
                if not ok:
                    r = jsonify({"error": "temporarily_locked", "retry_after": retry})
                    r.status_code = 429
                    r.headers["Retry-After"] = str(retry)
                    return r
                for key in (identity, f"ip:{ip}"):
                    allowed, retry = security_store.rate(namespace, key, limit, window)
                    if not allowed:
                        r = jsonify({"error": "rate_limit_exceeded", "retry_after": retry})
                        r.status_code = 429
                        r.headers["Retry-After"] = str(retry)
                        return r
            except RedisSecurityUnavailableError:
                return jsonify({"error": "service_unavailable",
                                "message": "Authentication engine offline"}), 503
            return fn(*a, **kw)
        return wrapper
    return deco
