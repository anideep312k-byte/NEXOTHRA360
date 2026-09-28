"""Authentication service."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import hashlib
import secrets
import uuid

import bcrypt
import pyotp

from ..config import config
from ..storage.database import PasswordReset, RoleEnum, Tenant, User


class AuthService:
    ROLES = {
        RoleEnum.ADMIN.value: {"permissions": ["read:all", "write:all", "delete:all",
                                                "manage:users", "manage:tenants"]},
        RoleEnum.ANALYST.value: {"permissions": ["read:alerts", "write:alerts",
                                                  "read:cases", "write:cases"]},
        RoleEnum.VIEWER.value: {"permissions": ["read:alerts", "read:cases"]},
    }

    WEAK = frozenset({
        "password", "password1", "password123", "passw0rd", "123456", "12345678",
        "qwerty", "qwerty123", "letmein", "welcome", "admin", "admin123", "changeme",
        "secret", "kavach", "kavach360",
    })

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"),
                             bcrypt.gensalt(rounds=config.BCRYPT_ROUNDS)).decode("utf-8")

    @classmethod
    def verify_password(cls, password: str, hashed: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

    @classmethod
    def validate_password_strength(cls, password: str) -> tuple[bool, str]:
        if not isinstance(password, str):
            return False, "Password must be a string"
        if len(password) < config.PASSWORD_MIN_LENGTH:
            return False, f"Password must be >= {config.PASSWORD_MIN_LENGTH} chars"
        if len(password.encode("utf-8")) > config.PASSWORD_MAX_LENGTH:
            return False, f"Password must be <= {config.PASSWORD_MAX_LENGTH} bytes"
        if password.lower() in cls.WEAK:
            return False, "Password is too common"
        if not any(c.isupper() for c in password):
            return False, "Requires at least 1 uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Requires at least 1 lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Requires at least 1 digit"
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Requires at least 1 special character"
        return True, ""

    @classmethod
    def register_user(cls, db, email: str, password: str, username: str | None = None,
                      tenant_id: str | None = None,
                      role: str = RoleEnum.ANALYST.value) -> dict:
        ok, err = cls.validate_password_strength(password)
        if not ok:
            return {"success": False, "error": err}
        email_clean = (email or "").strip().lower()
        if not email_clean or "@" not in email_clean:
            return {"success": False, "error": "Invalid email"}
        if db.query(User).filter(User.email == email_clean).first():
            return {"success": False, "error": "Email already registered"}
        if role not in cls.ROLES:
            return {"success": False, "error": "Invalid role"}
        if not tenant_id:
            local = email_clean.split("@")[0].lower()
            tenant = Tenant(id=str(uuid.uuid4()), name=f"{local}'s Org",
                            slug=f"{local}-{uuid.uuid4().hex[:8]}")
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
        user = User(id=str(uuid.uuid4()), tenant_id=tenant_id, email=email_clean,
                    username=username or email_clean.split("@")[0],
                    password_hash=cls.hash_password(password), role=role)
        db.add(user)
        db.flush()
        return {"success": True, "user_id": user.id, "tenant_id": tenant_id}

    @classmethod
    def authenticate(cls, db, email: str, password: str) -> User | None:
        if not isinstance(password, str) or len(password) > config.PASSWORD_MAX_LENGTH:
            return None
        user = db.query(User).filter(User.email == email.strip().lower()).first()
        if not user or not user.is_active:
            return None
        if not cls.verify_password(password, user.password_hash):
            return None
        return user

    @classmethod
    def setup_2fa(cls, db, user: User) -> dict:
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        db.commit()
        return {"secret": secret,
                "uri": pyotp.totp.TOTP(secret).provisioning_uri(
                    name=user.email, issuer_name="Kavach360")}

    @classmethod
    def verify_2fa(cls, user: User, code: str) -> bool:
        return bool(user.mfa_secret and
                    pyotp.TOTP(user.mfa_secret).verify(str(code), valid_window=1))

    @classmethod
    def create_password_reset(cls, db, user: User) -> tuple[str, PasswordReset]:
        raw = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=config.PASSWORD_RESET_TTL_SECONDS)
        row = PasswordReset(id=str(uuid.uuid4()), tenant_id=user.tenant_id,
                            user_id=user.id, token_hash=token_hash,
                            expires_at=expires_at)
        db.add(row)
        db.flush()
        return raw, row

    @classmethod
    def consume_password_reset(cls, db, raw_token: str,
                                new_password: str) -> dict:
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        row = (db.query(PasswordReset)
               .filter(PasswordReset.token_hash == token_hash)
               .with_for_update()
               .first())
        if not row:
            return {"success": False, "error": "invalid_or_used_token"}
        now = datetime.now(timezone.utc)
        if row.used_at is not None:
            return {"success": False, "error": "invalid_or_used_token"}
        if row.expires_at < now:
            return {"success": False, "error": "expired_token"}
        ok, err = cls.validate_password_strength(new_password)
        if not ok:
            return {"success": False, "error": err}
        user = db.query(User).filter(User.id == row.user_id).first()
        if not user:
            return {"success": False, "error": "invalid_user"}
        user.password_hash = cls.hash_password(new_password)
        row.used_at = now
        db.flush()
        return {"success": True, "user_id": user.id,
                "tenant_id": str(user.tenant_id)}


_auth = AuthService()


def get_auth_service() -> AuthService:
    return _auth
