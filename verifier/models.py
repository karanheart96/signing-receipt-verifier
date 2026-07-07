"""Data models and error codes for the Receipt Chain Verification Protocol v0.1."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LayerStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"


class ErrorCode(str, Enum):
    INVALID_JSON = "INVALID_JSON"
    DUPLICATE_FIELD = "DUPLICATE_FIELD"
    UNSUPPORTED_RECEIPT_VERSION = "UNSUPPORTED_RECEIPT_VERSION"
    UNKNOWN_RECEIPT_FIELD = "UNKNOWN_RECEIPT_FIELD"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    CANONICALIZATION_FAILED = "CANONICALIZATION_FAILED"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_HASH_FORMAT = "INVALID_HASH_FORMAT"
    RECEIPT_HASH_MISMATCH = "RECEIPT_HASH_MISMATCH"
    KEY_NOT_FOUND = "KEY_NOT_FOUND"
    AMBIGUOUS_KEY = "AMBIGUOUS_KEY"
    KEY_ALGORITHM_MISMATCH = "KEY_ALGORITHM_MISMATCH"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_VALID_AT_RECEIPT_TIME = "KEY_NOT_VALID_AT_RECEIPT_TIME"
    KID_MISMATCH = "KID_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    DUPLICATE_SEQUENCE = "DUPLICATE_SEQUENCE"
    FORKED_SEQUENCE = "FORKED_SEQUENCE"
    MISSING_PREVIOUS_RECEIPT = "MISSING_PREVIOUS_RECEIPT"
    ANCHOR_PROOF_INVALID = "ANCHOR_PROOF_INVALID"
    MERKLE_PATH_INVALID = "MERKLE_PATH_INVALID"
    ANCHOR_ROOT_MISMATCH = "ANCHOR_ROOT_MISMATCH"
    ANCHOR_TX_NOT_FOUND = "ANCHOR_TX_NOT_FOUND"
    ANCHOR_UNCHECKED = "ANCHOR_UNCHECKED"
    RANGE_NOT_COVERED = "RANGE_NOT_COVERED"
    OVERLAPPING_RANGE_CONFLICT = "OVERLAPPING_RANGE_CONFLICT"
    COMPLETENESS_NOT_PROVABLE = "COMPLETENESS_NOT_PROVABLE"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    DUPLICATE_RECEIPT_HASH = "DUPLICATE_RECEIPT_HASH"
    INCOMPLETE_RANGE = "INCOMPLETE_RANGE"


class Severity(str, Enum):
    FATAL = "fatal"
    WARNING = "warning"


@dataclass
class VerificationError:
    code: str
    layer: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "layer": self.layer,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass
class VerificationResult:
    receipt_integrity: LayerStatus = LayerStatus.INCONCLUSIVE
    anchor_validity: LayerStatus = LayerStatus.INCONCLUSIVE
    completeness: LayerStatus = LayerStatus.INCONCLUSIVE
    errors: list[VerificationError] = field(default_factory=list)

    # Map layer name strings to their corresponding attribute names.
    _LAYER_ATTRS = {
        "receipt_integrity": "receipt_integrity",
        "anchor_validity": "anchor_validity",
        "completeness": "completeness",
    }

    def add_error(
        self,
        code: ErrorCode | str,
        layer: str,
        severity: Severity | str = Severity.FATAL,
        message: str = "",
    ) -> None:
        code_str = code.value if isinstance(code, ErrorCode) else code
        sev_str = severity.value if isinstance(severity, Severity) else severity
        self.errors.append(VerificationError(code_str, layer, sev_str, message))
        # Structural invariant: a FATAL error forces the layer to FAIL,
        # unless it was already set to a terminal state (FAIL or
        # UNSUPPORTED_VERSION).  This prevents any code path from
        # leaving a layer at PASS/INCONCLUSIVE after recording a FATAL.
        if sev_str == Severity.FATAL.value:
            attr = self._LAYER_ATTRS.get(layer)
            if attr is not None:
                current = getattr(self, attr)
                if current in (LayerStatus.PASS, LayerStatus.INCONCLUSIVE):
                    setattr(self, attr, LayerStatus.FAIL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_integrity": self.receipt_integrity.value,
            "anchor_validity": self.anchor_validity.value,
            "completeness": self.completeness.value,
            "errors": [e.to_dict() for e in self.errors],
        }

    def has_error_code(self, code: ErrorCode | str) -> bool:
        code_str = code.value if isinstance(code, ErrorCode) else code
        return any(e.code == code_str for e in self.errors)


# Receipt body required fields for v1
RECEIPT_BODY_REQUIRED_FIELDS = frozenset({
    "v", "tenant", "seq", "ts", "request_digest",
    "policy_version", "decision", "reasons", "prev_receipt",
})

# Fields that must be strings (not JSON numbers)
STRING_REQUIRED_FIELDS = frozenset({
    "seq", "range_start", "range_end", "block_number", "leaf_index", "chain_id",
})

GENESIS_PREV_RECEIPT = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
POSITIVE_DECIMAL_PATTERN = re.compile(r"^[1-9][0-9]*$")

SUPPORTED_DECISIONS = frozenset({"approve", "deny"})

SUPPORTED_KEY_STATUSES = frozenset({
    "active",
    "retired",
    "revoked_future_only",
    "revoked_all",
})
