"""Regression tests from an external security audit (June 2026).

Each test is named after the audit finding ID (RCV-001 through RCV-007) and
exercises the specific vulnerability or weakness described in the audit report.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from verifier.verify import verify

REPO_ROOT = Path(__file__).parent.parent
VECTORS_DIR = REPO_ROOT / "test-vectors"

# --- Helpers ---

# Reuse the generator's deterministic key infrastructure
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from generate_vectors import (
    GENESIS_PREV_RECEIPT,
    PRIVATE_KEY,
    TENANT,
    KID,
    build_chain,
    make_keys_json,
    make_receipt_body,
    receipt_hash,
    sign_body,
)
from verifier.merkle import compute_batch_root, leaf_hash, node_hash


def signed_receipt(
    seq: str = "1",
    prev_receipt: str = GENESIS_PREV_RECEIPT,
    ts: str = "2026-05-10T19:42:00.123Z",
    **overrides,
) -> dict:
    body = make_receipt_body(seq=seq, prev_receipt=prev_receipt, ts=ts, **overrides)
    return sign_body(body)


def make_keys_with(**kwargs) -> dict:
    return make_keys_json(**kwargs)


def load_vector(name: str):
    vec_dir = VECTORS_DIR / name
    with open(vec_dir / "receipts.json") as f:
        receipts = json.load(f)
    with open(vec_dir / "keys.json") as f:
        keys = json.load(f)
    anchor = None
    ap = vec_dir / "anchor-proof.json"
    if ap.exists():
        with open(ap) as f:
            anchor = json.load(f)
    return receipts, keys, anchor


def codes(result_dict: dict) -> set[str]:
    return {e["code"] for e in result_dict["errors"]}


def assert_any_code(result_dict: dict, expected_codes: set[str]) -> None:
    actual = codes(result_dict)
    assert actual & expected_codes, (
        f"Expected one of {expected_codes}, got {actual}"
    )


# ============================================================
# RCV-001: Anchor Validity Can Pass For Unrelated Evidence (#2)
# ============================================================

class TestRCV001:
    def test_rejects_unsupported_anchor_root_algorithm(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["root_alg"] = "evil-merkle"

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_rejects_anchor_for_wrong_tenant(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["tenant"] = "other-tenant"

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_unrelated_empty_anchor_proof_does_not_pass(self):
        receipts, keys, _ = load_vector("TV-001-valid-chain-no-anchor")
        anchor = {
            "v": "1",
            "tenant": "test-tenant-001",
            "range_start": "999",
            "range_end": "1000",
            "root_alg": "merkle-sha256-v1",
            "batch_root": "sha256:" + ("11" * 32),
            "chain": "base",
            "chain_id": "8453",
            "tx": "0x1",
            "commitment_location": "calldata",
            "commitment_value": "sha256:" + ("11" * 32),
            "proofs": [],
        }

        result = verify([receipts[0]], keys, anchor).to_dict()

        assert result["anchor_validity"] != "PASS"


# ============================================================
# RCV-002: Merkle Proof Schema Is Not Strictly Validated (#3)
# ============================================================

class TestRCV002:
    def test_rejects_invalid_merkle_path_position(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["merkle_path"][0]["position"] = "middle"

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert_any_code(result, {"ANCHOR_PROOF_INVALID", "MERKLE_PATH_INVALID"})

    def test_rejects_negative_leaf_index(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["leaf_index"] = "-1"

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert_any_code(result, {"ANCHOR_PROOF_INVALID", "MERKLE_PATH_INVALID"})


# ============================================================
# RCV-003: Duplicate JSON Properties Are Accepted (#4)
# ============================================================

class TestRCV003:
    def test_cli_rejects_duplicate_receipt_body_fields(self, tmp_path):
        vector_dir = VECTORS_DIR / "TV-001-valid-chain-no-anchor"
        receipts_text = (vector_dir / "receipts.json").read_text()
        receipts_text = receipts_text.replace(
            '"decision": "approve"',
            '"decision": "deny",\n      "decision": "approve"',
            1,
        )

        receipts_path = tmp_path / "receipts.json"
        keys_path = tmp_path / "keys.json"
        receipts_path.write_text(receipts_text)
        keys_path.write_text((vector_dir / "keys.json").read_text())

        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "verifier.cli",
                "verify",
                "--receipts",
                str(receipts_path),
                "--keys",
                str(keys_path),
            ],
            cwd=str(REPO_ROOT),
            text=True,
            capture_output=True,
            check=False,
        )

        # CLI exits with 1 on parse error, but still produces JSON output
        result = json.loads(proc.stdout)
        assert result["receipt_integrity"] == "FAIL"
        assert "DUPLICATE_FIELD" in codes(result)


# ============================================================
# RCV-004: Sequence Grammar And Segment Boundaries (#5)
# ============================================================

class TestRCV004:
    def test_rejects_noncanonical_sequence_string(self):
        result = verify(
            [signed_receipt(seq="01")], make_keys_json(), None
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)

    def test_rejects_unbridged_non_genesis_segment_start(self):
        result = verify(
            [signed_receipt(seq="2", prev_receipt="sha256:" + ("22" * 32))],
            make_keys_json(),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert_any_code(result, {"MISSING_PREVIOUS_RECEIPT", "INCOMPLETE_RANGE"})


# ============================================================
# RCV-005: Malformed Key Lifecycle Metadata Can Pass (#6)
# ============================================================

class TestRCV005:
    def test_rejects_unknown_key_status(self):
        result = verify(
            [signed_receipt()],
            make_keys_json(status="mystery"),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)

    def test_rejects_malformed_key_validity_window(self):
        result = verify(
            [signed_receipt()],
            make_keys_json(not_before="not-a-date"),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)

    def test_rejects_revoked_future_key_without_revocation_time(self):
        result = verify(
            [signed_receipt()],
            make_keys_json(status="revoked_future_only", revocation_time=None),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)


# ============================================================
# RCV-006: Timestamp Profile Is Too Permissive (#7)
# ============================================================

class TestRCV006:
    def test_rejects_timestamp_with_lowercase_t_separator(self):
        result = verify(
            [signed_receipt(ts="2026-05-10t19:42:00.123Z")],
            make_keys_json(),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)

    def test_rejects_naive_timestamp_without_throwing(self):
        result = verify(
            [signed_receipt(ts="2026-05-10T19:42:00.123")],
            make_keys_json(),
            None,
        ).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_FIELD_TYPE" in codes(result)


# ============================================================
# RCV-007: Malformed JSON-Shaped Inputs Can Raise Raw Exceptions (#8)
# ============================================================

class TestRCV007:
    def test_rejects_non_object_receipt_envelope_without_throwing(self):
        result = verify([None], make_keys_json(), None).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_JSON" in codes(result)

    def test_rejects_non_list_anchor_proofs_without_throwing(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"] = "not-a-list"

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_rejects_merkle_path_step_missing_hash_without_throwing(self):
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        del anchor["proofs"][0]["merkle_path"][0]["hash"]

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert_any_code(result, {"ANCHOR_PROOF_INVALID", "MERKLE_PATH_INVALID"})

    def test_rejects_non_list_receipts_input(self):
        result = verify("not-a-list", make_keys_json(), None).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_JSON" in codes(result)

    def test_rejects_non_dict_keys_input(self):
        result = verify([signed_receipt()], ["not", "a", "dict"], None).to_dict()

        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_JSON" in codes(result)

    def test_rejects_non_dict_anchor_proof(self):
        result = verify(
            [signed_receipt()], make_keys_json(), "not-a-dict"
        ).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)

    def test_rejects_non_string_receipt_hash_in_proof_without_throwing(self):
        """Non-string receipt_hash (e.g. list) must not raise TypeError in set comprehension."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["proofs"][0]["receipt_hash"] = []

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert_any_code(result, {"ANCHOR_PROOF_INVALID"})

    def test_rejects_non_string_commitment_value_as_proof_invalid(self):
        """Non-string commitment_value must return ANCHOR_PROOF_INVALID, not ANCHOR_ROOT_MISMATCH."""
        receipts, keys, anchor = load_vector("TV-002-valid-anchored-batch")
        anchor["commitment_value"] = 12345

        result = verify(receipts, keys, anchor).to_dict()

        assert result["anchor_validity"] == "FAIL"
        assert "ANCHOR_PROOF_INVALID" in codes(result)
        assert "ANCHOR_ROOT_MISMATCH" not in codes(result)


# ============================================================
# Post-audit hardening: FAIL propagation through void-converted
# validation functions.  Each test verifies that add_error(FATAL)
# correctly sets receipt_integrity = FAIL when routed through
# the structural invariant.
# ============================================================

class TestFailPropagation:
    """Verify FAIL propagation for error paths in void-converted functions."""

    def test_unknown_receipt_field_fails(self):
        """_validate_body_fields: unknown field → FAIL."""
        body = make_receipt_body(
            seq="1", prev_receipt=GENESIS_PREV_RECEIPT,
            extra_fields={"unexpected_extra": "value"},
        )
        envelope = sign_body(body)
        # sign_body uses the body as-is; the extra field survives
        result = verify([envelope], make_keys_json(), None).to_dict()
        assert result["receipt_integrity"] == "FAIL"
        assert "UNKNOWN_RECEIPT_FIELD" in codes(result)

    def test_invalid_hash_format_fails(self):
        """_validate_field_types: bad hash format → FAIL."""
        body = make_receipt_body(seq="1", prev_receipt=GENESIS_PREV_RECEIPT)
        body["request_digest"] = "not-a-valid-hash"
        envelope = sign_body(body)
        result = verify([envelope], make_keys_json(), None).to_dict()
        assert result["receipt_integrity"] == "FAIL"
        assert "INVALID_HASH_FORMAT" in codes(result)

    def test_key_not_valid_before_fails(self):
        """check_key_validity: receipt before not_before → FAIL."""
        # Receipt at 2025-01-01, key valid from 2026-05-01
        result = verify(
            [signed_receipt(ts="2025-01-01T00:00:00.000Z")],
            make_keys_json(not_before="2026-05-01T00:00:00.000Z"),
            None,
        ).to_dict()
        assert result["receipt_integrity"] == "FAIL"
        assert "KEY_NOT_VALID_AT_RECEIPT_TIME" in codes(result)

    def test_key_revoked_all_fails(self):
        """check_key_validity: revoked_all with revocation_time → FAIL."""
        result = verify(
            [signed_receipt()],
            make_keys_json(
                status="revoked_all",
                revocation_time="2026-05-01T00:00:00.000Z",
            ),
            None,
        ).to_dict()
        assert result["receipt_integrity"] == "FAIL"
        assert "KEY_REVOKED" in codes(result)
