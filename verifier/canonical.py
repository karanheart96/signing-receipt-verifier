"""JCS-subset canonicalizer for Receipt Chain Verification Protocol v0.1.

WARNING: This is a limited canonicalizer sufficient for the v0.1 test vectors.
It is NOT a complete RFC 8785 implementation. Do not use in production without
replacing with a fully conformant JCS library.

It implements:
- Sorted object keys (by UTF-16 code unit order per RFC 8785)
- No whitespace
- Strings with minimal escaping per RFC 8785
- Integers without decimal points
- No floating-point support (v0.1 forbids floats)
"""

from __future__ import annotations

import json
import math


class CanonicalizationError(Exception):
    pass


def _to_utf16_code_units(s: str) -> list[int]:
    """Encode a string as a sequence of UTF-16 code units."""
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            units.append(cp)
        else:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
    return units


def _compare_keys_jcs(a: str, b: str) -> int:
    """Compare two keys by UTF-16 code unit values, per RFC 8785 Section 3.2.3."""
    a_units = _to_utf16_code_units(a)
    b_units = _to_utf16_code_units(b)

    for au, bu in zip(a_units, b_units):
        if au < bu:
            return -1
        if au > bu:
            return 1
    if len(a_units) < len(b_units):
        return -1
    if len(a_units) > len(b_units):
        return 1
    return 0


def _sorted_keys_jcs(keys: list[str]) -> list[str]:
    """Sort keys by UTF-16 code unit order per RFC 8785."""
    import functools
    return sorted(keys, key=functools.cmp_to_key(_compare_keys_jcs))


def _serialize_string(s: str) -> str:
    """Serialize a string per RFC 8785 / ES6 JSON.stringify rules."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif cp < 0x20:
            out.append(f'\\u{cp:04x}')
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _serialize_number(n: int | float) -> str:
    """Serialize a number per RFC 8785 rules."""
    if isinstance(n, float):
        if math.isnan(n):
            raise CanonicalizationError("NaN is not a valid JSON value")
        if math.isinf(n):
            raise CanonicalizationError("Infinity is not a valid JSON value")
        if n == 0.0:
            return "0"
        raise CanonicalizationError(
            "Floating-point values are forbidden in v0.1 receipt bodies"
        )
    return str(n)


def canonicalize(obj: object) -> bytes:
    """Canonicalize a Python object to JCS-subset bytes.

    The input should be a parsed JSON value (dict, list, str, int, bool, None).
    """
    return _serialize(obj).encode("utf-8")


def _serialize(obj: object) -> str:
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, int) and not isinstance(obj, bool):
        return _serialize_number(obj)
    if isinstance(obj, float):
        return _serialize_number(obj)
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, list):
        items = [_serialize(item) for item in obj]
        return "[" + ",".join(items) + "]"
    if isinstance(obj, dict):
        sorted_keys = _sorted_keys_jcs(list(obj.keys()))
        pairs = []
        for key in sorted_keys:
            pairs.append(_serialize_string(key) + ":" + _serialize(obj[key]))
        return "{" + ",".join(pairs) + "}"
    raise CanonicalizationError(f"Unsupported type: {type(obj)}")
