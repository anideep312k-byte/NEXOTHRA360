"""Detection regression tests."""
from kavach360.detection.engine import RuleEngine
from kavach360.detection import rules  # noqa: F401


def test_benign_double_dot_ok():
    ds = RuleEngine().evaluate({"event_id": "1", "url": "/files/abc..def.txt"})
    assert not any(d.rule_id == "KVC-WEB-002" for d in ds)


def test_traversal_flagged():
    ds = RuleEngine().evaluate({"event_id": "1", "url": "/d?f=../../etc/passwd"})
    assert any(d.rule_id == "KVC-WEB-002" for d in ds)
