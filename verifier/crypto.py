"""Cryptographic operations for the Receipt Chain Verification Protocol v0.1."""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import (
    SUPPORTED_KEY_STATUSES,
    ErrorCode,
    Severity,
    VerificationError,
    VerificationResult,
)

TIMESTAMP_PROFILE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$"
)


def sha256_hex(data: bytes) -> str:
    """Return sha256:<lowercase_hex> for the given bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def base64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def base64url_encode(data: bytes) -> str:
    """Encode bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def lookup_key(
    keys_data: dict,
    tenant: str,
    kid: str,
    alg: str,
    result: VerificationResult,
) -> dict | None:
    """Look up a verification key by exact tenant + kid + alg match.

    Returns the key dict or None (and adds errors to result).
    """
    if keys_data.get("tenant") != tenant:
        result.add_error(
            ErrorCode.KEY_NOT_FOUND,
            "receipt_integrity",
            Severity.FATAL,
            f"Key set tenant '{keys_data.get('tenant')}' does not match receipt tenant '{tenant}'",
        )
        return None

    keys_list = keys_data.get("keys", [])
    if not isinstance(keys_list, list):
        result.add_error(
            ErrorCode.INVALID_JSON,
            "receipt_integrity",
            Severity.FATAL,
            "Key set 'keys' must be an array",
        )
        return None

    candidates = []
    for key in keys_list:
        if not isinstance(key, dict):
            result.add_error(
                ErrorCode.INVALID_JSON,
                "receipt_integrity",
                Severity.FATAL,
                f"Key entry must be an object, got {type(key).__name__}",
            )
            return None
        if key.get("kid") == kid:
            candidates.append(key)

    if not candidates:
        result.add_error(
            ErrorCode.KEY_NOT_FOUND,
            "receipt_integrity",
            Severity.FATAL,
            f"No key found with kid '{kid}'",
        )
        return None

    # Filter by alg
    alg_matches = [k for k in candidates if k.get("alg") == alg]
    if not alg_matches:
        result.add_error(
            ErrorCode.KEY_ALGORITHM_MISMATCH,
            "receipt_integrity",
            Severity.FATAL,
            f"Key found for kid '{kid}' but algorithm does not match '{alg}'",
        )
        return None

    if len(alg_matches) > 1:
        result.add_error(
            ErrorCode.AMBIGUOUS_KEY,
            "receipt_integrity",
            Severity.FATAL,
            f"Multiple keys match tenant/kid/alg: {tenant}/{kid}/{alg}",
        )
        return None

    return alg_matches[0]


def check_key_validity(
    key: dict,
    receipt_ts: str,
    result: VerificationResult,
) -> None:
    """Check key validity window and revocation status.

    Errors are recorded via result.add_error(FATAL), which auto-sets
    receipt_integrity = FAIL.  Callers check the layer status directly.
    """
    ts = _parse_ts(receipt_ts)
    if ts is None:
        result.add_error(
            ErrorCode.INVALID_FIELD_TYPE,
            "receipt_integrity",
            Severity.FATAL,
            f"Cannot parse receipt timestamp: {receipt_ts}",
        )
        return

    not_before = key.get("not_before")
    not_after = key.get("not_after")

    if not_before:
        nb = _parse_ts(not_before)
        if nb is None:
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                f"Cannot parse key validity start: {not_before}",
            )
            return
        if ts < nb:
            result.add_error(
                ErrorCode.KEY_NOT_VALID_AT_RECEIPT_TIME,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt timestamp {receipt_ts} is before key validity start {not_before}",
            )
            return

    if not_after:
        na = _parse_ts(not_after)
        if na is None:
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                f"Cannot parse key validity end: {not_after}",
            )
            return
        if ts >= na:
            result.add_error(
                ErrorCode.KEY_NOT_VALID_AT_RECEIPT_TIME,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt timestamp {receipt_ts} is at or after key validity end {not_after}",
            )
            return

    status = key.get("status", "active")

    if status not in SUPPORTED_KEY_STATUSES:
        result.add_error(
            ErrorCode.INVALID_FIELD_TYPE,
            "receipt_integrity",
            Severity.FATAL,
            f"Unsupported key status: {status}",
        )
        return

    if status == "revoked_all":
        if not key.get("revocation_time"):
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                "revoked_all keys require revocation_time",
            )
            return
        result.add_error(
            ErrorCode.KEY_REVOKED,
            "receipt_integrity",
            Severity.FATAL,
            "Key has been revoked for all receipts",
        )
        return

    if status == "revoked_future_only":
        revocation_time = key.get("revocation_time")
        rt = _parse_ts(revocation_time)
        if rt is None:
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                "revoked_future_only keys require parseable revocation_time",
            )
            return
        if ts >= rt:
            result.add_error(
                ErrorCode.KEY_REVOKED,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt timestamp {receipt_ts} is at or after revocation time {revocation_time}",
            )
            return

    if status in ("active", "retired") and key.get("revocation_time") is not None:
        result.add_error(
            ErrorCode.INVALID_FIELD_TYPE,
            "receipt_integrity",
            Severity.FATAL,
            f"{status} keys must not set revocation_time",
        )
        return


def verify_signature(
    key: dict,
    canonical_body_bytes: bytes,
    sig_value_b64url: str,
    result: VerificationResult,
) -> None:
    """Verify an Ed25519 signature.

    Errors are recorded via result.add_error(FATAL), which auto-sets
    receipt_integrity = FAIL.  Callers check the layer status directly.
    """
    alg = key.get("alg")
    if alg != "EdDSA":
        result.add_error(
            ErrorCode.UNSUPPORTED_ALGORITHM,
            "receipt_integrity",
            Severity.FATAL,
            f"Unsupported signature algorithm: {alg}",
        )
        return

    try:
        pub_bytes = base64url_decode(key["x"])
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64url_decode(sig_value_b64url)
        public_key.verify(sig_bytes, canonical_body_bytes)
    except (InvalidSignature, Exception) as exc:
        if isinstance(exc, InvalidSignature):
            result.add_error(
                ErrorCode.SIGNATURE_INVALID,
                "receipt_integrity",
                Severity.FATAL,
                "Ed25519 signature verification failed",
            )
        else:
            result.add_error(
                ErrorCode.SIGNATURE_INVALID,
                "receipt_integrity",
                Severity.FATAL,
                f"Signature verification error: {exc}",
            )


def _parse_ts(ts_str: str) -> datetime | None:
    """Parse an RFC 3339 timestamp in v0.1 profile (uppercase T and Z, milliseconds)."""
    if not isinstance(ts_str, str):
        return None
    if not TIMESTAMP_PROFILE.match(ts_str):
        return None
    try:
        ts_str = ts_str[:-1] + "+00:00"
        parsed = datetime.fromisoformat(ts_str)
        if parsed.tzinfo is None:
            return None
        return parsed
    except (ValueError, TypeError):
        return None
