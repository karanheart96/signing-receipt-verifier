"""Audit verification tests — proving tests for remediation audit.

These tests verify fail-closed semantics for each audit finding.
"""

from __future__ import annotations
import json, sys
from pathlib import Path

import pytest
from verifier.verify import verify

REPO_ROOT = Path(__file__).parent.parent
VECTORS_DIR = REPO_ROOT / "test-vectors"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from generate_vectors import (
    GENESIS_PREV_RECEIPT, make_keys_json, sign_body,
    make_receipt_body, build_chain, receipt_hash,
)
from verifier.merkle import compute_batch_root, leaf_hash, node_hash


def load_vector(name):
    d = VECTORS_DIR / name
    with open(d / "receipts.json") as f: receipts = json.load(f)
    with open(d / "keys.json") as f: keys = json.load(f)
    anchor = None
    ap = d / "anchor-proof.json"
    if ap.exists():
        with open(ap) as f: anchor = json.load(f)
    return receipts, keys, anchor


def codes(rd): return {e["code"] for e in rd["errors"]}


# === #2 FIXED: Non-empty unverified tx must yield INCONCLUSIVE ===

class TestIssue2_TxInconclusive:
    """verify.py sets anchor_validity=INCONCLUSIVE when tx is non-empty
    but not independently verified (v0.1 offline mode)."""

    def test_unverified_tx_yields_inconclusive(self):
        """TV-002 has tx='0xdead...' which is NOT independently verified.
        anchor_validity must be INCONCLUSIVE, not PASS."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        assert anchor["tx"]  # tx is non-empty
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "INCONCLUSIVE"
        assert "ANCHOR_UNCHECKED" in codes(result)

    def test_empty_tx_also_yields_inconclusive(self):
        """An anchor with empty tx should also be INCONCLUSIVE."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["tx"] = ""
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "INCONCLUSIVE"


# === #3 FIXED: leaf_index direction-bound against proof path ===

class TestIssue3_LeafIndexDirectionBinding:
    """leaf_index is bounds-checked AND direction-bound. The expected sibling
    side at each tree level is derived from leaf_index parity, with odd-leaf
    promotion accounted for. A wrong leaf_index causes a direction mismatch
    even when the hash-based proof would otherwise verify."""

    def test_leaf_index_999_on_3leaf_batch_fails(self):
        """The audit requires leaf_index=999 on a 3-leaf batch to FAIL."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["leaf_index"] = "999"
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_leaf_index_3_on_3leaf_batch_fails(self):
        """leaf_index=3 is out of range [0,2] for a 3-leaf batch."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["leaf_index"] = "3"
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_in_range_wrong_direction_fails(self):
        """leaf_index=1 with leaf0's proof (positions right,right) must FAIL.
        Index 1 expects position=left at level 0 but the proof says right."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        # Swap leaf_index on the first proof: 0 -> 1
        anchor["proofs"][0]["leaf_index"] = "1"
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "FAIL"
        assert "MERKLE_PATH_INVALID" in codes(result)

    def test_valid_leaf_indices_still_pass(self):
        """Correct leaf_index values 0, 1, 2 on a 3-leaf batch must not FAIL."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] != "FAIL"

    def test_negative_leaf_index_fails(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["leaf_index"] = "-1"
        result = verify(receipts, keys, anchor).to_dict()
        assert result["anchor_validity"] == "FAIL"


# === #5 edge: seq="0" rejected (not just "01") ===

class TestIssue5_SeqZero:
    def test_seq_zero_rejected(self):
        body = make_receipt_body(seq="0", prev_receipt=GENESIS_PREV_RECEIPT)
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        assert r["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(r)

    def test_seq_negative_rejected(self):
        body = make_receipt_body(seq="-1", prev_receipt=GENESIS_PREV_RECEIPT)
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        assert r["receipt_integrity"] == "FAIL"

    def test_seq_leading_plus_rejected(self):
        body = make_receipt_body(seq="+1", prev_receipt=GENESIS_PREV_RECEIPT)
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        assert r["receipt_integrity"] == "FAIL"


# === Timestamp profile: variable fractional digits ===

class TestTimestampProfile:
    """The v0.1 spec says MUST use uppercase T/Z, SHOULD use millisecond
    precision. The regex accepts 0..n fractional digits to avoid false-FAILs
    on legitimate RFC 3339 forms."""

    def test_no_fractional_digits_accepted(self):
        """2026-05-10T19:42:00Z is valid RFC 3339 with uppercase T/Z."""
        body = make_receipt_body(seq="1", prev_receipt=GENESIS_PREV_RECEIPT,
                                ts="2026-05-10T19:42:00Z")
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        # Should not fail on timestamp parsing
        ts_errors = [e for e in r["errors"]
                     if "timestamp" in e["message"].lower() or
                     e["code"] == "INVALID_FIELD_TYPE"]
        assert not ts_errors, f"Unexpected timestamp error: {ts_errors}"

    def test_microsecond_precision_accepted(self):
        """2026-05-10T19:42:00.123456Z is valid with 6 fractional digits."""
        body = make_receipt_body(seq="1", prev_receipt=GENESIS_PREV_RECEIPT,
                                ts="2026-05-10T19:42:00.123456Z")
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        ts_errors = [e for e in r["errors"]
                     if "timestamp" in e["message"].lower() or
                     e["code"] == "INVALID_FIELD_TYPE"]
        assert not ts_errors, f"Unexpected timestamp error: {ts_errors}"

    def test_millisecond_precision_accepted(self):
        """Standard 3-digit fractional still works."""
        body = make_receipt_body(seq="1", prev_receipt=GENESIS_PREV_RECEIPT,
                                ts="2026-05-10T19:42:00.123Z")
        env = sign_body(body)
        r = verify([env], make_keys_json(), None).to_dict()
        ts_errors = [e for e in r["errors"]
                     if "timestamp" in e["message"].lower() or
                     e["code"] == "INVALID_FIELD_TYPE"]
        assert not ts_errors, f"Unexpected timestamp error: {ts_errors}"

    def test_lowercase_t_still_rejected(self):
        from verifier.crypto import _parse_ts
        assert _parse_ts("2026-05-10t19:42:00.123Z") is None

    def test_bare_offset_still_rejected(self):
        from verifier.crypto import _parse_ts
        assert _parse_ts("2026-05-10T19:42:00.123+00:00") is None

    def test_no_z_suffix_still_rejected(self):
        from verifier.crypto import _parse_ts
        assert _parse_ts("2026-05-10T19:42:00.123") is None
