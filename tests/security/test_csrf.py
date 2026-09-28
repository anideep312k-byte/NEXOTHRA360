"""CSRF tests."""
import pytest
from kavach360.config import config as app_config


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(app_config, "APP_ENV", "testing")
    from kavach360.web.app import create_app
    a = create_app()
    a.config.update({"TESTING": True})
    return a


def test_csrf_endpoint_sets_cookie(app):
    with app.test_client() as c:
        r = c.get("/api/v1/auth/csrf")
        assert r.status_code == 200
        assert "csrf_token" in r.get_json()
