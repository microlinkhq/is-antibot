"""Cookie parsing tests — port of test/set-cookie.js."""

from __future__ import annotations

from is_antibot import create_has_cookie


def test_array_got_style():
    has_cookie = create_has_cookie({"set-cookie": ["foo=bar", "trkCode=bf; Max-Age=5"]})
    assert has_cookie("trkCode=bf") is True
    assert has_cookie("foo=bar") is True
    assert has_cookie("missing=value") is False


def test_comma_joined_string_fetch_style():
    has_cookie = create_has_cookie({"set-cookie": "foo=bar; Max-Age=5, trkCode=bf; Max-Age=5"})
    assert has_cookie("trkCode=bf") is True
    assert has_cookie("foo=bar") is True
    assert has_cookie("missing=value") is False


def test_single_string():
    has_cookie = create_has_cookie({"set-cookie": "trkCode=bf; Max-Age=5"})
    assert has_cookie("trkCode=bf") is True
    assert has_cookie("missing=value") is False


def test_fetch_headers_object():
    """Test with a dict that has a get method (simulating Fetch Headers)."""
    has_cookie = create_has_cookie({"set-cookie": "foo=bar, trkCode=bf; Max-Age=5"})
    assert has_cookie("trkCode=bf") is True
    assert has_cookie("missing=value") is False


def test_comma_in_expires_no_false_split():
    has_cookie = create_has_cookie({"set-cookie": "trkCode=bf; expires=Thu, 26-Mar-26 09:08:53 GMT; path=/"})
    assert has_cookie("trkCode=bf") is True


def test_no_set_cookie_header():
    has_cookie = create_has_cookie({})
    assert has_cookie("trkCode=bf") is False


def test_undefined_set_cookie():
    has_cookie = create_has_cookie({"set-cookie": None})
    assert has_cookie("trkCode=bf") is False


def test_empty_string():
    has_cookie = create_has_cookie({"set-cookie": ""})
    assert has_cookie("trkCode=bf") is False


def test_empty_array():
    has_cookie = create_has_cookie({"set-cookie": []})
    assert has_cookie("trkCode=bf") is False
