"""Redaction tests."""
from kavach360.utils.redact import redact_payload, payload_fingerprint


def test_password_redacted():
    r = redact_payload({"password": "secret", "user": "alice"})
    assert r["password"] == "[REDACTED]"
    assert r["user"] == "alice"


def test_fingerprint():
    size, sha = payload_fingerprint("hello")
    assert size == 5
    assert len(sha) == 64
