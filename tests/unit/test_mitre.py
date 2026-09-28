"""MITRE mapping tests."""
from kavach360.detection.mitre import map_text, map_alert, TECHNIQUES, TACTICS


def test_mimikatz_mapping():
    r = map_text("mimikatz sekurlsa")
    ids = [t["technique_id"] for t in r]
    assert "T1003" in ids


def test_all_tactics_valid():
    for tid, tech in TECHNIQUES.items():
        assert tech["tactic"] in TACTICS


def test_alert_shape():
    r = map_alert({"event_id": "x", "message": "phishing"})
    assert r["alert_id"] == "x"
