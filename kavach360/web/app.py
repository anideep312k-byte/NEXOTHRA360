"""Hardened Flask factory."""
from __future__ import annotations
from datetime import timedelta
import time
from typing import Any
import uuid

from flask import Flask, Response, g, jsonify, redirect, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from werkzeug.middleware.proxy_fix import ProxyFix

from ..config import config
from ..observability.metrics import HTTP_LATENCY, HTTP_REQUESTS
from ..storage.database import SessionLocal, init_db, set_tenant_context
from ..utils.logger import get_logger
from .security.redis_rate_limit import (
    RedisSecurityUnavailableError, security_store)

log = get_logger("web")
jwt = JWTManager()


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        JWT_SECRET_KEY=config.JWT_SECRET_KEY,
        JWT_ALGORITHM=config.JWT_ALGORITHM,
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=config.JWT_ACCESS_TOKEN_EXPIRES_MIN),
        JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=config.JWT_REFRESH_TOKEN_EXPIRES_DAYS),
        JWT_TOKEN_LOCATION=["cookies"],
        JWT_COOKIE_SECURE=config.COOKIE_SECURE,
        JWT_COOKIE_SAMESITE=config.COOKIE_SAMESITE,
        JWT_COOKIE_CSRF_PROTECT=False,
        JWT_ACCESS_COOKIE_PATH="/",
        JWT_REFRESH_COOKIE_PATH="/api/v1/auth/",
        JWT_COOKIE_DOMAIN=config.COOKIE_DOMAIN,
        MAX_CONTENT_LENGTH=config.MAX_REQUEST_BYTES,
    )
    if config.TRUSTED_PROXY_COUNT > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app,
                                x_for=config.TRUSTED_PROXY_COUNT,
                                x_proto=config.TRUSTED_PROXY_COUNT,
                                x_host=config.TRUSTED_PROXY_COUNT,
                                x_port=1, x_prefix=1)
    jwt.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": config.CORS_ORIGINS}},
         supports_credentials=True,
         allow_headers=["Content-Type", config.CSRF_HEADER_NAME, "X-Request-ID"],
         expose_headers=["X-Request-ID", "Retry-After"])
    if config.APP_ENV == "production":
        try:
            security_store.ping()
        except RedisSecurityUnavailableError as exc:
            raise SystemExit(f"FATAL: Redis unavailable at startup: {exc}")
    else:
        init_db()

    @app.before_request
    def _ctx() -> None:
        g.request_start_time = time.time()
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        g.db = SessionLocal()
        try:
            set_tenant_context(g.db, None)
        except Exception:
            pass

    @app.after_request
    def _headers(response: Any) -> Any:
        try:
            endpoint = request.endpoint or "unknown"
            HTTP_REQUESTS.labels(method=request.method, endpoint=endpoint,
                                 status=str(response.status_code)).inc()
            if hasattr(g, "request_start_time"):
                HTTP_LATENCY.labels(method=request.method,
                                    endpoint=endpoint).observe(
                    time.time() - g.request_start_time)
        except Exception:
            pass
        response.headers["X-Request-ID"] = getattr(g, "request_id", uuid.uuid4().hex)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/v1/auth/"):
            response.headers["Cache-Control"] = "no-store"
        if config.APP_ENV == "production":
            response.headers["Strict-Transport-Security"] = \
                "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                "connect-src 'self'")
        return response

    @app.teardown_appcontext
    def _teardown(exception: Any = None) -> None:
        db = getattr(g, "db", None)
        if db is not None:
            try:
                if exception is not None:
                    db.rollback()
            finally:
                db.close()

    @app.errorhandler(400)
    def _400(e): return jsonify({"error": "bad_request",
                                  "request_id": getattr(g, "request_id", "")}), 400
    @app.errorhandler(404)
    def _404(e): return jsonify({"error": "not_found",
                                  "request_id": getattr(g, "request_id", "")}), 404
    @app.errorhandler(405)
    def _405(e): return jsonify({"error": "method_not_allowed",
                                  "request_id": getattr(g, "request_id", "")}), 405
    @app.errorhandler(413)
    def _413(e): return jsonify({"error": "request_too_large",
                                  "request_id": getattr(g, "request_id", "")}), 413
    @app.errorhandler(429)
    def _429(e): return jsonify({"error": "rate_limit_exceeded",
                                  "request_id": getattr(g, "request_id", "")}), 429

    @app.errorhandler(Exception)
    def _500(e: Any) -> Any:
        log.exception("Unhandled exception")
        return jsonify({"error": "internal_server_error",
                        "request_id": getattr(g, "request_id", "")}), 500

    from .routes.auth_routes import auth_bp
    from .routes.soc_routes import soc_bp
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(soc_bp)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": config.APP_NAME,
                        "version": config.APP_VERSION})

    @app.get("/api/ready")
    def ready():
        try:
            security_store.ping()
        except RedisSecurityUnavailableError as exc:
            return jsonify({"ready": False, "redis": False, "error": str(exc)}), 503
        from sqlalchemy import text
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            return jsonify({"ready": False, "database": False, "error": str(exc)}), 503
        finally:
            db.close()
        return jsonify({"ready": True, "database": True, "redis": True})

    @app.get("/api/v1/metrics")
    def metrics():
        if not config.metrics_ip_allowed(request.remote_addr):
            return jsonify({"error": "forbidden"}), 403
        if not config.METRICS_TOKEN:
            return jsonify({"error": "metrics_token_not_configured"}), 403
        import hmac
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {config.METRICS_TOKEN}"
        if not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "forbidden"}), 403
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    @app.get("/api/v1/meta")
    def meta():
        return jsonify({"name": config.APP_NAME, "version": config.APP_VERSION})

    @app.get("/")
    def _root():
        return redirect("/static/login.html")

    return app
