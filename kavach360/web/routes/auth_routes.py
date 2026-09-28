"""Authentication routes."""
from __future__ import annotations
from datetime import datetime, timezone
import secrets
import uuid

from flask import Blueprint, g, jsonify, make_response, request
from flask_jwt_extended import (
    create_access_token, create_refresh_token, get_jwt, get_jwt_identity,
    jwt_required, set_access_cookies, set_refresh_cookies, unset_jwt_cookies,
)

from ...auth.service import get_auth_service
from ...config import config
from ...storage.database import User
from ..security.audit import write_audit
from ..security.csrf import require_browser_security
from ..security.redis_rate_limit import (
    RedisSecurityUnavailableError, protected_auth, rate_limit, security_store,
)

auth_bp = Blueprint("auth", __name__)

_DUMMY_HASH = get_auth_service().hash_password(
    "this-is-a-dummy-password-for-timing-only")


def _login_email_key() -> str:
    data = request.get_json(silent=True) or {}
    return str(data.get("email") or "").strip().lower() or "empty"


def _login_ip_key() -> str:
    return request.remote_addr or "unknown"


def _mfa_id() -> str:
    token = request.cookies.get("kavach_mfa", "")
    return f"{request.remote_addr or 'unknown'}:{token or 'nocookie'}"


def _claims(user: User) -> dict:
    perms = get_auth_service().ROLES.get(user.role, {}).get("permissions", [])
    return {"role": user.role, "tenant_id": str(user.tenant_id),
            "permissions": perms, "mfa_verified": True}


def _session_response(payload: dict, user: User):
    response = make_response(jsonify(payload))
    access = create_access_token(identity=user.id, additional_claims=_claims(user))
    refresh = create_refresh_token(identity=user.id,
                                   additional_claims={"tenant_id": str(user.tenant_id)})
    set_access_cookies(response, access,
                       max_age=config.JWT_ACCESS_TOKEN_EXPIRES_MIN * 60)
    set_refresh_cookies(response, refresh,
                        max_age=config.JWT_REFRESH_TOKEN_EXPIRES_DAYS * 86400)
    new_csrf = secrets.token_urlsafe(32)
    response.set_cookie("kavach_csrf", new_csrf, max_age=3600,
                        secure=config.COOKIE_SECURE, httponly=False,
                        samesite=config.COOKIE_SAMESITE,
                        domain=config.COOKIE_DOMAIN, path="/")
    return response


@auth_bp.post("/register")
@require_browser_security
@rate_limit("register", config.RATELIMIT_RESET,
            lambda: request.remote_addr or "unknown")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    existing = g.db.query(User).filter(User.email == email.lower()).first()
    if existing:
        get_auth_service().verify_password(password, _DUMMY_HASH)
        return jsonify({"success": True, "message": "check_email"}), 201
    result = get_auth_service().register_user(g.db, email, password)
    if result.get("success"):
        write_audit(g.db, tenant_id=result["tenant_id"],
                    user_id=result["user_id"], action="user_registered",
                    resource="user",
                    details={"email": email.lower(), "role": "analyst"},
                    ip_address=request.remote_addr,
                    request_id=getattr(g, "request_id", None))
        g.db.commit()
        return jsonify({"success": True,
                        "user_id": result["user_id"]}), 201
    g.db.rollback()
    return jsonify(result), 400


@auth_bp.post("/login")
@require_browser_security
@protected_auth("login", config.RATELIMIT_LOGIN, _login_email_key)
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if not isinstance(password, str) or len(password) > config.PASSWORD_MAX_LENGTH:
        return jsonify({"error": "invalid_credentials"}), 401
    try:
        allowed, retry = security_store.rate("login_ip", _login_ip_key(), 20, 60)
        if not allowed:
            r = jsonify({"error": "rate_limit_exceeded", "retry_after": retry})
            r.status_code = 429
            r.headers["Retry-After"] = str(retry)
            return r
    except RedisSecurityUnavailableError:
        return jsonify({"error": "service_unavailable"}), 503
    user = get_auth_service().authenticate(g.db, email, password)
    if not user:
        try:
            ok, lock = security_store.record_failure(
                "login", _login_email_key(),
                config.LOGIN_FAILURE_THRESHOLD,
                config.LOGIN_LOCKOUT_BASE_SECONDS,
                config.LOGIN_LOCKOUT_MAX_SECONDS)
            if not ok:
                r = jsonify({"error": "temporarily_locked", "retry_after": lock})
                r.status_code = 429
                r.headers["Retry-After"] = str(lock)
                return r
        except RedisSecurityUnavailableError:
            return jsonify({"error": "service_unavailable"}), 503
        return jsonify({"error": "invalid_credentials"}), 401
    try:
        security_store.clear_failures("login", _login_email_key())
    except RedisSecurityUnavailableError:
        return jsonify({"error": "service_unavailable"}), 503
    if user.mfa_enabled:
        tx_id = uuid.uuid4().hex
        challenge = security_store.create_mfa_challenge(
            user.id, request.remote_addr or "unknown", tx_id, 300)
        response = make_response(jsonify({"mfa_required": True, "tx_id": tx_id,
                                          "expires_in": 300}))
        response.set_cookie("kavach_mfa", challenge, max_age=300,
                            secure=config.COOKIE_SECURE, httponly=True,
                            samesite=config.COOKIE_SAMESITE,
                            domain=config.COOKIE_DOMAIN,
                            path="/api/v1/auth/")
        return response
    user.last_login = datetime.now(timezone.utc)
    write_audit(g.db, tenant_id=str(user.tenant_id), user_id=user.id,
                action="user_login", resource="auth",
                details={"email": user.email, "mfa": False},
                ip_address=request.remote_addr,
                request_id=getattr(g, "request_id", None))
    g.db.commit()
    return _session_response({"authenticated": True, "mfa_required": False,
                              "user": {"id": user.id, "email": user.email,
                                       "username": user.username, "role": user.role,
                                       "tenant_id": user.tenant_id,
                                       "mfa_enabled": False}}, user)


@auth_bp.post("/2fa/verify")
@require_browser_security
@protected_auth("mfa", config.RATELIMIT_MFA, _mfa_id)
def verify_2fa_login():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or "").strip()
    tx_id = str(data.get("tx_id") or "").strip()[:64]
    token = request.cookies.get("kavach_mfa", "")
    if not token or not code.isdigit() or len(code) != 6 or not tx_id:
        return jsonify({"error": "invalid_mfa_challenge"}), 401
    try:
        challenge = security_store.peek_mfa_challenge(token)
    except RedisSecurityUnavailableError:
        return jsonify({"error": "service_unavailable"}), 503
    if not challenge:
        return jsonify({"error": "invalid_or_consumed_mfa_challenge"}), 401
    if (challenge.get("ip") != (request.remote_addr or "unknown")
            or challenge.get("tx_id") != tx_id):
        try:
            security_store.burn_mfa_attempt(token)
        except RedisSecurityUnavailableError:
            return jsonify({"error": "service_unavailable"}), 503
        return jsonify({"error": "invalid_or_consumed_mfa_challenge"}), 401
    user = g.db.query(User).filter(User.id == challenge["user_id"]).first()
    if not user or not user.is_active or not user.mfa_enabled:
        return jsonify({"error": "unauthorized"}), 401
    if not get_auth_service().verify_2fa(user, code):
        try:
            alive = security_store.burn_mfa_attempt(token, max_attempts=3)
            ok, lock = security_store.record_failure(
                "mfa", _mfa_id(), config.MFA_FAILURE_THRESHOLD,
                config.MFA_LOCKOUT_BASE_SECONDS, config.MFA_LOCKOUT_MAX_SECONDS)
            if not ok:
                r = jsonify({"error": "temporarily_locked", "retry_after": lock})
                r.status_code = 429
                r.headers["Retry-After"] = str(lock)
                return r
            if not alive:
                return jsonify({"error": "mfa_challenge_exhausted",
                                "message": "restart login"}), 401
        except RedisSecurityUnavailableError:
            return jsonify({"error": "service_unavailable"}), 503
        return jsonify({"error": "invalid_mfa_code"}), 401
    try:
        consumed = security_store.consume_mfa_challenge(
            token, request.remote_addr or "unknown", tx_id)
        if not consumed:
            return jsonify({"error": "challenge_consumed_by_other"}), 409
        if not security_store.claim_totp_code(user.id, code):
            return jsonify({"error": "totp_code_replayed"}), 401
        security_store.clear_failures("mfa", _mfa_id())
    except RedisSecurityUnavailableError:
        return jsonify({"error": "service_unavailable"}), 503
    user.last_login = datetime.now(timezone.utc)
    write_audit(g.db, tenant_id=str(user.tenant_id), user_id=user.id,
                action="user_login", resource="auth",
                details={"email": user.email, "mfa": True},
                ip_address=request.remote_addr,
                request_id=getattr(g, "request_id", None))
    g.db.commit()
    response = _session_response({"authenticated": True, "mfa_required": False,
                                  "user": {"id": user.id, "email": user.email,
                                           "username": user.username, "role": user.role,
                                           "tenant_id": user.tenant_id,
                                           "mfa_enabled": True}}, user)
    response.delete_cookie("kavach_mfa", path="/api/v1/auth/",
                           domain=config.COOKIE_DOMAIN)
    return response


@auth_bp.post("/refresh")
@require_browser_security
@rate_limit("refresh", config.RATELIMIT_REFRESH,
            lambda: request.remote_addr or "unknown")
@jwt_required(refresh=True, locations=["cookies"])
def refresh():
    user_id = get_jwt_identity()
    claims = get_jwt() or {}
    iat = claims.get("iat", 0)
    iat_ms = int(iat * 1000) if iat < 10_000_000_000 else int(iat)
    try:
        if security_store.is_token_revoked(user_id, iat_ms):
            return jsonify({"error": "unauthorized", "message": "Session revoked"}), 401
    except RedisSecurityUnavailableError:
        return jsonify({"error": "service_unavailable"}), 503
    user = g.db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        return jsonify({"error": "unauthorized"}), 401
    access = create_access_token(identity=user.id, additional_claims=_claims(user))
    response = jsonify({"refreshed": True})
    set_access_cookies(response, access,
                       max_age=config.JWT_ACCESS_TOKEN_EXPIRES_MIN * 60)
    return response


@auth_bp.post("/logout")
@require_browser_security
@jwt_required(optional=True, locations=["cookies"])
def logout():
    user_id = get_jwt_identity()
    if user_id:
        claims = get_jwt() or {}
        try:
            write_audit(g.db, tenant_id=claims.get("tenant_id") or "unknown",
                        user_id=user_id, action="user_logout", resource="auth",
                        details={"token_type": claims.get("type", "unknown")},
                        ip_address=request.remote_addr,
                        request_id=getattr(g, "request_id", None))
            g.db.commit()
        except Exception:
            g.db.rollback()
        try:
            security_store.revoke_token_family(user_id)
        except RedisSecurityUnavailableError:
            return jsonify({"error": "service_unavailable"}), 503
    response = make_response(jsonify({"logged_out": True}))
    unset_jwt_cookies(response)
    response.delete_cookie("kavach_mfa", path="/api/v1/auth/",
                           domain=config.COOKIE_DOMAIN)
    response.delete_cookie("kavach_csrf", path="/", domain=config.COOKIE_DOMAIN)
    return response


@auth_bp.get("/csrf")
def csrf():
    token = secrets.token_urlsafe(32)
    response = make_response(jsonify({"csrf_token": token}))
    response.set_cookie("kavach_csrf", token, max_age=3600,
                        secure=config.COOKIE_SECURE, httponly=False,
                        samesite=config.COOKIE_SAMESITE,
                        domain=config.COOKIE_DOMAIN, path="/")
    return response


@auth_bp.post("/2fa/setup")
@require_browser_security
@jwt_required(locations=["cookies"])
def setup_2fa():
    user_id = get_jwt_identity()
    user = g.db.query(User).filter(User.id == user_id).first()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    result = get_auth_service().setup_2fa(g.db, user)
    return jsonify(result)


@auth_bp.post("/2fa/enable")
@require_browser_security
@jwt_required(locations=["cookies"])
def enable_2fa():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or "").strip()
    user_id = get_jwt_identity()
    user = g.db.query(User).filter(User.id == user_id).first()
    if not user or not user.mfa_secret:
        return jsonify({"error": "setup_required"}), 400
    if not get_auth_service().verify_2fa(user, code):
        return jsonify({"error": "invalid_code"}), 401
    user.mfa_enabled = True
    write_audit(g.db, tenant_id=str(user.tenant_id), user_id=user.id,
                action="mfa_enabled", resource="auth", details={},
                ip_address=request.remote_addr,
                request_id=getattr(g, "request_id", None))
    g.db.commit()
    return jsonify({"mfa_enabled": True})
