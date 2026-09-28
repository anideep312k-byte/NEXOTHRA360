"""Password policy tests."""
from kavach360.auth.service import AuthService


def test_weak_rejected():
    ok, _ = AuthService.validate_password_strength("short")
    assert not ok


def test_strong_accepted():
    ok, _ = AuthService.validate_password_strength("Str0ng!Passw0rd#2024")
    assert ok


def test_hash_roundtrip():
    h = AuthService.hash_password("Str0ng!Passw0rd#2024")
    assert AuthService.verify_password("Str0ng!Passw0rd#2024", h)
    assert not AuthService.verify_password("wrong", h)
