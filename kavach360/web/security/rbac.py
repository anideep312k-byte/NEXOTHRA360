"""RBAC middleware with RLS tenant context."""
from __future__ import annotations
import functools
from typing import Callable
from flask import g, jsonify
from flask_jwt_extended import get_jwt, get_jwt_identity, verify_jwt_in_request

from ...observability.metrics import RLS_CONTEXT_ERRORS
from ...storage.database import User, set_tenant_context
from .csrf import origin_ok
from .redis_rate_limit import RedisSecurityUnavailableError, security_store


def _iat_ms(claims: dict) -> int:
    iat = claims.get("iat")
    if iat is None:
        return 0
    return int(iat * 1000) if iat < 10_000_000_000 else int(iat)


def _require_g_db():
    db = getattr(g, "db", None)
    if db is None:
        raise RuntimeError("DB session not initialized")
    return db


def _load_user() -> None:
    verify_jwt_in_request(locations=["cookies"])
    claims = get_jwt() or {}
    if claims.get("mfa_verified") is not True:
        raise PermissionError("MFA required")
    user_id = get_jwt_identity()
    try:
        if security_store.is_token_revoked(user_id, _iat_ms(claims)):
            raise PermissionError("Session revoked")
    except RedisSecurityUnavailableError as exc:
        raise RuntimeError("Security engine offline") from exc
    db = _require_g_db()
    user = db.query(User).filter(User.id == user_id).one_or_none()
    if not user or not user.is_active:
        raise PermissionError("Unauthorized")
    try:
        set_tenant_context(db, str(user.tenant_id))
    except Exception as exc:
        RLS_CONTEXT_ERRORS.inc()
        raise RuntimeError("Tenant context setup failed") from exc
    g.current_user = user
    g.claims = claims


def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        if not origin_ok():
            return jsonify({"error": "invalid_origin"}), 403
        try:
            _load_user()
            return fn(*a, **kw)
        except PermissionError as exc:
            return jsonify({"error": "unauthorized", "message": str(exc)}), 401
        except RuntimeError as exc:
            return jsonify({"error": "service_unavailable", "message": str(exc)}), 503
        except Exception:
            return jsonify({"error": "unauthorized"}), 401
    return wrapper


def require_role(*roles: str) -> Callable:
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not origin_ok():
                return jsonify({"error": "invalid_origin"}), 403
            try:
                _load_user()
                role = g.claims.get("role") or g.current_user.role
                if role not in roles:
                    return jsonify({"error": "forbidden"}), 403
                return fn(*a, **kw)
            except PermissionError:
                return jsonify({"error": "unauthorized"}), 401
            except RuntimeError as exc:
                return jsonify({"error": "service_unavailable", "message": str(exc)}), 503
            except Exception:
                return jsonify({"error": "unauthorized"}), 401
        return wrapper
    return deco


def require_permission(permission: str) -> Callable:
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not origin_ok():
                return jsonify({"error": "invalid_origin"}), 403
            try:
                _load_user()
                perms = set(g.claims.get("permissions") or [])
                if permission not in perms and "read:all" not in perms and "write:all" not in perms:
                    return jsonify({"error": "forbidden", "required": permission}), 403
                return fn(*a, **kw)
            except PermissionError:
                return jsonify({"error": "unauthorized"}), 401
            except RuntimeError as exc:
                return jsonify({"error": "service_unavailable", "message": str(exc)}), 503
            except Exception:
                return jsonify({"error": "unauthorized"}), 401
        return wrapper
    return deco


def get_current_user() -> User | None:
    return getattr(g, "current_user", None)


def current_tenant_id() -> str | None:
    user = get_current_user()
    return str(user.tenant_id) if user else None
