"""Detection rule tests."""
from kavach360.detection.engine import RuleEngine
from kavach360.detection import rules  # noqa: F401


def _e(**kw):
    base = {"event_id": "e1"}
    base.update(kw)
    return base


def test_encoded_powershell():
    ds = RuleEngine().evaluate(_e(process="powershell -enc AAA"))
    assert any(d.rule_id == "KVC-ENDPOINT-002" for d in ds)


def test_credential_dump():
    ds = RuleEngine().evaluate(_e(message="mimikatz sekurlsa"))
    assert any(d.rule_id == "KVC-CRED-001" for d in ds)


def test_sqli_union():
    ds = RuleEngine().evaluate(_e(url="/x?q=1 union select 1"))
    assert any(d.rule_id == "KVC-SQLI-001" for d in ds)


def test_xss_event_handler():
    ds = RuleEngine().evaluate(_e(url="/s?q=<img src=x onerror=alert(1)>"))
    assert any(d.rule_id == "KVC-XSS-003" for d in ds)


def test_path_traversal():
    ds = RuleEngine().evaluate(_e(url="/d?f=../../etc/passwd"))
    assert any(d.rule_id == "KVC-WEB-002" for d in ds)


def test_cloud_root():
    ds = RuleEngine().evaluate(_e(user="root", source_type="cloud"))
    assert any(d.rule_id == "KVC-CLOUD-001" for d in ds)
