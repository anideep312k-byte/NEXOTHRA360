"""Normalization tests."""
from kavach360.utils.normalize import normalize_field, iterative_unquote, check_json_depth


def test_null_bytes_stripped():
    assert "\x00" not in normalize_field("a\x00b")


def test_unicode_nfkc():
    assert normalize_field("ＰＯＷＥＲ") == "power"


def test_iterative_unquote():
    assert iterative_unquote("%25252541") == "A"


def test_json_depth():
    assert check_json_depth({"a": 1}, max_depth=5)
    deep = cur = {"a": {}}
    for _ in range(30):
        cur["a"]["a"] = {}
        cur = cur["a"]
    assert not check_json_depth(deep, max_depth=20)
