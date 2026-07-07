"""Unit tests for JCS-subset canonicalization."""

from __future__ import annotations

import json

import pytest

from verifier.canonical import CanonicalizationError, canonicalize


def test_key_ordering():
    """Keys must be sorted by UTF-16 code unit order."""
    obj = {"z": 1, "a": 2, "m": 3}
    result = canonicalize(obj)
    assert result == b'{"a":2,"m":3,"z":1}'


def test_nested_key_ordering():
    """Nested object keys must also be sorted."""
    obj = {"b": {"z": 1, "a": 2}, "a": 1}
    result = canonicalize(obj)
    assert result == b'{"a":1,"b":{"a":2,"z":1}}'


def test_string_escaping():
    """Control characters must be escaped per JCS rules."""
    obj = {"s": "tab\there"}
    result = canonicalize(obj)
    assert result == b'{"s":"tab\\there"}'


def test_newline_escaping():
    obj = {"s": "line\nbreak"}
    result = canonicalize(obj)
    assert result == b'{"s":"line\\nbreak"}'


def test_null_char_escaping():
    """Null byte must be escaped as \\u0000."""
    obj = {"s": "null\x00here"}
    result = canonicalize(obj)
    assert result == b'{"s":"null\\u0000here"}'


def test_quote_escaping():
    obj = {"s": 'say "hello"'}
    result = canonicalize(obj)
    assert result == b'{"s":"say \\"hello\\""}'


def test_backslash_escaping():
    obj = {"s": "path\\to"}
    result = canonicalize(obj)
    assert result == b'{"s":"path\\\\to"}'


def test_unicode_preserved():
    """Unicode characters above U+001F must be preserved as-is (UTF-8)."""
    obj = {"s": "\u00e9"}
    result = canonicalize(obj)
    assert result == '{"s":"\u00e9"}'.encode("utf-8")


def test_integer_serialization():
    """Integers must be serialized without decimal point."""
    obj = {"n": 42}
    result = canonicalize(obj)
    assert result == b'{"n":42}'


def test_negative_integer():
    obj = {"n": -1}
    result = canonicalize(obj)
    assert result == b'{"n":-1}'


def test_zero():
    obj = {"n": 0}
    result = canonicalize(obj)
    assert result == b'{"n":0}'


def test_boolean_true():
    obj = {"b": True}
    result = canonicalize(obj)
    assert result == b'{"b":true}'


def test_boolean_false():
    obj = {"b": False}
    result = canonicalize(obj)
    assert result == b'{"b":false}'


def test_null():
    obj = {"n": None}
    result = canonicalize(obj)
    assert result == b'{"n":null}'


def test_array():
    obj = {"a": [1, "two", True, None]}
    result = canonicalize(obj)
    assert result == b'{"a":[1,"two",true,null]}'


def test_empty_object():
    assert canonicalize({}) == b'{}'


def test_empty_array():
    obj = {"a": []}
    result = canonicalize(obj)
    assert result == b'{"a":[]}'


def test_float_rejected():
    """Floats are forbidden in v0.1."""
    with pytest.raises(CanonicalizationError):
        canonicalize({"n": 1.5})


def test_nan_rejected():
    """NaN must be independently rejected."""
    with pytest.raises(CanonicalizationError, match="NaN"):
        canonicalize({"n": float("nan")})


def test_infinity_rejected():
    """Infinity must be independently rejected."""
    with pytest.raises(CanonicalizationError, match="Infinity"):
        canonicalize({"n": float("inf")})


def test_emoji_string():
    """Emoji (surrogate pair in UTF-16) must be preserved in UTF-8."""
    obj = {"s": "\U0001f600"}
    result = canonicalize(obj)
    expected = '{"s":"\U0001f600"}'.encode("utf-8")
    assert result == expected


def test_utf16_key_sort_order():
    """Keys with characters above BMP should sort by UTF-16 code units."""
    # U+00E9 (0x00E9) < U+4E16 (0x4E16) < U+1F600 (0xD83D,0xDE00)
    obj = {"\U0001f600": 3, "\u00e9": 1, "\u4e16": 2}
    result = canonicalize(obj)
    # Build expected output: keys sorted by UTF-16 code unit order
    expected = (
        '{"'
        + "\u00e9"
        + '":1,"'
        + "\u4e16"
        + '":2,"'
        + "\U0001f600"
        + '":3}'
    ).encode("utf-8")
    assert result == expected


def test_supplementary_plane_surrogate_pair_sort():
    """Sort order between supplementary-plane keys depends on correct
    surrogate pair calculation (high and low surrogates independently).

    This test uses exactly two astral-plane keys whose high surrogates differ,
    mixed with a BMP key. The correct UTF-16 sort is:

      "a"      → [0x0061]                  (BMP)
      U+10400  → [0xD801, 0xDC00]          (Deseret Capital Letter Long I)
      U+1F600  → [0xD83D, 0xDE00]          (Grinning Face)

    If the + in the high-surrogate formula `0xD800 + (cp >> 10)` is mutated
    to -, the high surrogate for U+1F600 becomes 0xD800 - 0x3D = 0xD7C3,
    which is LESS than 0xD801 for U+10400.  That reverses the two astral keys.
    """
    obj = {"\U0001f600": 3, "a": 1, "\U00010400": 2}
    result = canonicalize(obj)
    expected = (
        '{"a":1,"'
        + "\U00010400"
        + '":2,"'
        + "\U0001f600"
        + '":3}'
    ).encode("utf-8")
    assert result == expected


def test_supplementary_plane_low_surrogate_sort():
    """Sort order depending on correct low-surrogate calculation.

    U+10000 → [0xD800, 0xDC00]
    U+10001 → [0xD800, 0xDC01]

    Same high surrogate; order decided by the low surrogate.
    If `0xDC00 + (cp & 0x3FF)` is mutated to `0xDC00 - (cp & 0x3FF)`,
    U+10001's low surrogate becomes 0xDBFF < 0xDC00, reversing the pair.
    """
    obj = {"\U00010001": 2, "\U00010000": 1}
    result = canonicalize(obj)
    expected = (
        '{"' + "\U00010000" + '":1,"' + "\U00010001" + '":2}'
    ).encode("utf-8")
    assert result == expected
