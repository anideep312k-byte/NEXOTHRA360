"""Normalizer fuzz tests."""
from kavach360.ingestion.pipeline import Normalizer


def test_empty():
    ev = Normalizer.normalize({})
    assert ev.event_id


def test_oversized():
    ev = Normalizer.normalize({"message": "x" * 100000})
    assert len(ev.message) <= 4096


def test_wrong_types():
    Normalizer.normalize({"src_ip": 12345, "url": ["a"]})


def test_future_timestamp_clamped():
    ev = Normalizer.normalize({"timestamp": "9999-01-01T00:00:00Z"})
    assert ev.timestamp.startswith("20")


def test_severity_whitelisted():
    ev = Normalizer.normalize({"severity": "💥"})
    assert ev.severity == "low"
