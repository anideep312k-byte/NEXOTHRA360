"""Kavach360 configuration with strict production validation."""
from __future__ import annotations
import ipaddress
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    if raw.lower() in _TRUE:
        return True
    if raw.lower() in _FALSE:
        return False
    raise ValueError(f"{name} must be a boolean")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    val = default if raw is None else int(raw)
    if not (lo <= val <= hi):
        raise ValueError(f"{name} must be in [{lo},{hi}], got {val}")
    return val


class Config:
    APP_NAME = os.getenv("APP_NAME", "Kavach360")
    APP_VERSION = "1.0.0"
    APP_ENV = os.getenv("APP_ENV", "development").lower()
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me-strictly-unusable-in-prod")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-change-me-strictly-unusable-in-prod")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    CORS_ORIGINS = [x.strip() for x in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080").split(",") if x.strip()]

    REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/kavach360.db")

    RATELIMIT_LOGIN = os.getenv("RATELIMIT_LOGIN", "5 per minute")
    RATELIMIT_MFA = os.getenv("RATELIMIT_MFA", "5 per 5 minutes")
    RATELIMIT_REFRESH = os.getenv("RATELIMIT_REFRESH", "20 per minute")
    RATELIMIT_RESET = os.getenv("RATELIMIT_RESET", "3 per hour")
    RATELIMIT_INGEST = os.getenv("RATELIMIT_INGEST", "600 per minute")
    RATELIMIT_READ = os.getenv("RATELIMIT_READ", "200 per minute")

    LOGIN_FAILURE_THRESHOLD = _int("LOGIN_FAILURE_THRESHOLD", 10, 1, 100)
    LOGIN_LOCKOUT_BASE_SECONDS = _int("LOGIN_LOCKOUT_BASE_SECONDS", 30, 1, 86400)
    LOGIN_LOCKOUT_MAX_SECONDS = _int("LOGIN_LOCKOUT_MAX_SECONDS", 900, 1, 86400)

    MFA_FAILURE_THRESHOLD = _int("MFA_FAILURE_THRESHOLD", 5, 1, 100)
    MFA_LOCKOUT_BASE_SECONDS = _int("MFA_LOCKOUT_BASE_SECONDS", 30, 1, 86400)
    MFA_LOCKOUT_MAX_SECONDS = _int("MFA_LOCKOUT_MAX_SECONDS", 1800, 1, 86400)

    PASSWORD_MIN_LENGTH = _int("PASSWORD_MIN_LENGTH", 12, 8, 128)
    PASSWORD_MAX_LENGTH = 72

    BCRYPT_ROUNDS = _int("BCRYPT_ROUNDS", 12, 10, 15)

    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = _int("PORT", 8080, 1, 65535)
    TRUSTED_PROXY_COUNT = _int("TRUSTED_PROXY_COUNT", 0, 0, 10)

    MAX_REQUEST_BYTES = _int("MAX_REQUEST_BYTES", 1048576, 1024, 10485760)
    MAX_AUDIT_DETAILS_BYTES = _int("MAX_AUDIT_DETAILS_BYTES", 16384, 1024, 262144)
    MAX_STREAM_LAG = _int("MAX_STREAM_LAG", 100000, 100, 10000000)
    MAX_JSON_DEPTH = _int("MAX_JSON_DEPTH", 20, 5, 100)

    COOKIE_SECURE = _bool("COOKIE_SECURE", APP_ENV == "production")
    COOKIE_SAMESITE = "Strict"
    COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN") or None
    CSRF_HEADER_NAME = "X-CSRF-TOKEN"

    JWT_ACCESS_TOKEN_EXPIRES_MIN = _int("JWT_ACCESS_TOKEN_EXPIRES_MIN", 15, 1, 1440)
    JWT_REFRESH_TOKEN_EXPIRES_DAYS = _int("JWT_REFRESH_TOKEN_EXPIRES_DAYS", 7, 1, 90)

    METRICS_ALLOW_CIDR = os.getenv("METRICS_ALLOW_CIDR", "127.0.0.1/32")
    METRICS_TOKEN = os.getenv("METRICS_TOKEN", "").strip()
    LLM_BACKEND = os.getenv("LLM_BACKEND", "null").lower()

    PASSWORD_RESET_TTL_SECONDS = _int("PASSWORD_RESET_TTL_SECONDS", 3600, 300, 86400)
    WEBHOOK_HMAC_SECRET = os.getenv("WEBHOOK_HMAC_SECRET", "").strip()

    ENRICHMENT_WORKERS = _int("ENRICHMENT_WORKERS", 8, 1, 64)
    ENRICHMENT_QUEUE_MAX = _int("ENRICHMENT_QUEUE_MAX", 50000, 100, 1000000)
    ENRICHMENT_BATCH_SIZE = _int("ENRICHMENT_BATCH_SIZE", 50, 1, 500)

    GRAPH_MAX_NODES = _int("GRAPH_MAX_NODES", 50000, 1000, 500000)
    GRAPH_MAX_EDGES = _int("GRAPH_MAX_EDGES", 200000, 1000, 2000000)

    LOG_ANALYZER_MAX_LINES = _int("LOG_ANALYZER_MAX_LINES", 100000, 100, 10000000)

    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"

    def __init__(self) -> None:
        if self.APP_ENV not in {"development", "testing", "production"}:
            raise ValueError(f"Invalid APP_ENV: {self.APP_ENV}")

        try:
            self._metrics_cidrs = [
                ipaddress.ip_network(c.strip(), strict=False)
                for c in self.METRICS_ALLOW_CIDR.split(",") if c.strip()]
        except ValueError as exc:
            raise ValueError(f"Invalid METRICS_ALLOW_CIDR: {exc}") from exc

        if self.APP_ENV == "production":
            if len(self.SECRET_KEY) < 32 or self.SECRET_KEY.startswith("dev-"):
                raise ValueError("Production SECRET_KEY must be >= 32 chars and not dev-")
            if len(self.JWT_SECRET_KEY) < 32 or self.JWT_SECRET_KEY.startswith("dev-"):
                raise ValueError("Production JWT_SECRET_KEY must be >= 32 chars and not dev-")
            if not self.REDIS_URL.startswith(("redis://", "rediss://")):
                raise ValueError("Production REDIS_URL must use redis:// or rediss://")
            if not self.DATABASE_URL.startswith("postgresql+pg8000://"):
                raise ValueError(
                    "Production DATABASE_URL must be postgresql+pg8000:// (BSD-3 license)")
            if not self.CORS_ORIGINS or "*" in self.CORS_ORIGINS:
                raise ValueError("Production CORS_ORIGINS must be explicit")
            if any(o.startswith("http://") for o in self.CORS_ORIGINS):
                raise ValueError("Production CORS_ORIGINS must use https://")
            if not self.COOKIE_SECURE:
                raise ValueError("Production COOKIE_SECURE must be true")
            if self.TRUSTED_PROXY_COUNT == 0:
                raise ValueError("Production TRUSTED_PROXY_COUNT must be >= 1")
            if len(self.METRICS_TOKEN) < 32:
                raise ValueError("Production METRICS_TOKEN must be >= 32 chars")
            if len(self.WEBHOOK_HMAC_SECRET) < 32:
                raise ValueError("Production WEBHOOK_HMAC_SECRET must be >= 32 chars")

        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def metrics_ip_allowed(self, ip: str | None) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._metrics_cidrs)


config = Config()
