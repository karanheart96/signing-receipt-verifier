"""Core verification logic for the Receipt Chain Verification Protocol v0.1."""

from __future__ import annotations

import json
from typing import Any

from .canonical import CanonicalizationError, canonicalize
from .crypto import (
    check_key_validity,
    lookup_key,
    sha256_hex,
    verify_signature,
)
from .merkle import compute_batch_root, verify_merkle_proof
from .models import (
    GENESIS_PREV_RECEIPT,
    HASH_PATTERN,
    POSITIVE_DECIMAL_PATTERN,
    RECEIPT_BODY_REQUIRED_FIELDS,
    STRING_REQUIRED_FIELDS,
    SUPPORTED_DECISIONS,
    ErrorCode,
    LayerStatus,
    Severity,
    VerificationResult,
)


def verify(
    receipts_data: list[dict[str, Any]],
    keys_data: dict[str, Any],
    anchor_proof_data: dict[str, Any] | None = None,
) -> VerificationResult:
    """Run full verification across all three layers."""
    result = VerificationResult()

    if not isinstance(receipts_data, list):
        result.receipt_integrity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.INVALID_JSON,
            "receipt_integrity",
            Severity.FATAL,
            "Receipts input must be an array",
        )
        return result

    if not isinstance(keys_data, dict):
        result.receipt_integrity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.INVALID_JSON,
            "receipt_integrity",
            Severity.FATAL,
            "Key set input must be an object",
        )
        return result

    # Layer 1: Receipt integrity
    receipt_hashes = _verify_receipt_integrity(receipts_data, keys_data, result)

    # Layer 2: Anchor validity
    _verify_anchor_validity(receipts_data, receipt_hashes, anchor_proof_data, result)

    # Layer 3: Completeness
    _verify_completeness(receipts_data, receipt_hashes, anchor_proof_data, result)

    return result


def _validate_body_fields(body: dict, result: VerificationResult) -> None:
    """Validate receipt body has exactly the required fields.

    Errors are recorded via result.add_error(FATAL), which auto-sets
    receipt_integrity = FAIL.  Callers check the layer status directly.
    """
    body_keys = set(body.keys())

    # Check version first
    v = body.get("v")
    if v is not None and v != "1":
        result.receipt_integrity = LayerStatus.UNSUPPORTED_VERSION
        result.add_error(
            ErrorCode.UNSUPPORTED_RECEIPT_VERSION,
            "receipt_integrity",
            Severity.FATAL,
            f"Unsupported receipt version: {v}",
        )
        return

    # Check for unknown fields
    unknown = body_keys - RECEIPT_BODY_REQUIRED_FIELDS
    if unknown:
        result.add_error(
            ErrorCode.UNKNOWN_RECEIPT_FIELD,
            "receipt_integrity",
            Severity.FATAL,
            f"Unknown receipt body fields: {sorted(unknown)}",
        )
        return

    # Check for missing required fields
    missing = RECEIPT_BODY_REQUIRED_FIELDS - body_keys
    if missing:
        result.add_error(
            ErrorCode.MISSING_REQUIRED_FIELD,
            "receipt_integrity",
            Severity.FATAL,
            f"Missing required fields: {sorted(missing)}",
        )
        return


def _validate_field_types(body: dict, result: VerificationResult) -> None:
    """Validate field types.

    Errors are recorded via result.add_error(FATAL), which auto-sets
    receipt_integrity = FAIL.  Callers check the layer status directly.
    """
    # String-required fields
    for f in STRING_REQUIRED_FIELDS:
        if f in body and not isinstance(body[f], str):
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                f"Field '{f}' must be a string, got {type(body[f]).__name__}",
            )
            return

    # Check all string fields
    for f in ("v", "tenant", "seq", "ts", "request_digest", "policy_version", "decision", "prev_receipt"):
        if f in body and not isinstance(body[f], str):
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                f"Field '{f}' must be a string, got {type(body[f]).__name__}",
            )
            return

    # reasons must be array of strings
    reasons = body.get("reasons")
    if reasons is not None:
        if not isinstance(reasons, list):
            result.add_error(
                ErrorCode.INVALID_FIELD_TYPE,
                "receipt_integrity",
                Severity.FATAL,
                "Field 'reasons' must be an array",
            )
            return
        for r in reasons:
            if not isinstance(r, str):
                result.add_error(
                    ErrorCode.INVALID_FIELD_TYPE,
                    "receipt_integrity",
                    Severity.FATAL,
                    "All items in 'reasons' must be strings",
                )
                return

    # decision must be supported
    if body.get("decision") not in SUPPORTED_DECISIONS:
        result.add_error(
            ErrorCode.INVALID_FIELD_TYPE,
            "receipt_integrity",
            Severity.FATAL,
            f"Unsupported decision value: {body.get('decision')}",
        )
        return

    # Sequence must be canonical positive decimal
    if "seq" in body and not POSITIVE_DECIMAL_PATTERN.match(body["seq"]):
        result.add_error(
            ErrorCode.INVALID_FIELD_TYPE,
            "receipt_integrity",
            Severity.FATAL,
            f"Field 'seq' must be a positive canonical decimal string: {body['seq']}",
        )
        return

    # Hash format validation
    for f in ("request_digest", "policy_version", "prev_receipt"):
        val = body.get(f)
        if val and not HASH_PATTERN.match(val) and val != GENESIS_PREV_RECEIPT:
            result.add_error(
                ErrorCode.INVALID_HASH_FORMAT,
                "receipt_integrity",
                Severity.FATAL,
                f"Invalid hash format for '{f}': {val}",
            )
            return


def _verify_receipt_integrity(
    receipts: list[dict],
    keys_data: dict,
    result: VerificationResult,
) -> dict[str, str]:
    """Verify Layer 1: receipt integrity. Returns {seq: receipt_hash}."""
    receipt_hashes: dict[str, str] = {}

    if not receipts:
        result.receipt_integrity = LayerStatus.INCONCLUSIVE
        return receipt_hashes

    # Check for duplicate sequences and forks
    seen_seqs: dict[str, str] = {}  # seq -> receipt_hash

    for envelope in receipts:
        if not isinstance(envelope, dict):
            result.add_error(
                ErrorCode.INVALID_JSON,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt envelope must be an object, got {type(envelope).__name__}",
            )
            continue

        body = envelope.get("body")
        sig = envelope.get("sig")

        if body is None or sig is None:
            result.add_error(
                ErrorCode.INVALID_JSON,
                "receipt_integrity",
                Severity.FATAL,
                "Receipt envelope must contain 'body' and 'sig'",
            )
            continue

        if not isinstance(body, dict):
            result.add_error(
                ErrorCode.INVALID_JSON,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt body must be an object, got {type(body).__name__}",
            )
            continue

        if not isinstance(sig, dict):
            result.add_error(
                ErrorCode.INVALID_JSON,
                "receipt_integrity",
                Severity.FATAL,
                f"Receipt signature must be an object, got {type(sig).__name__}",
            )
            continue

        # Validate body fields
        _validate_body_fields(body, result)
        if result.receipt_integrity == LayerStatus.FAIL:
            continue

        # Validate field types
        _validate_field_types(body, result)
        if result.receipt_integrity == LayerStatus.FAIL:
            continue

        # Canonicalize and hash
        try:
            canonical_bytes = canonicalize(body)
        except CanonicalizationError as e:
            result.add_error(
                ErrorCode.CANONICALIZATION_FAILED,
                "receipt_integrity",
                Severity.FATAL,
                str(e),
            )
            continue

        receipt_hash = sha256_hex(canonical_bytes)
        seq = body["seq"]

        # Check for duplicate/forked sequences
        if seq in seen_seqs:
            if seen_seqs[seq] == receipt_hash:
                result.add_error(
                    ErrorCode.DUPLICATE_SEQUENCE,
                    "receipt_integrity",
                    Severity.FATAL,
                    f"Duplicate sequence number: {seq}",
                )
            else:
                result.add_error(
                    ErrorCode.FORKED_SEQUENCE,
                    "receipt_integrity",
                    Severity.FATAL,
                    f"Forked sequence at seq {seq}: different receipt hashes",
                )
            continue

        seen_seqs[seq] = receipt_hash
        receipt_hashes[seq] = receipt_hash

        # Key lookup and signature verification
        tenant = body["tenant"]
        kid = sig.get("kid", "")
        alg = sig.get("alg", "")

        if alg not in ("EdDSA",):
            result.add_error(
                ErrorCode.UNSUPPORTED_ALGORITHM,
                "receipt_integrity",
                Severity.FATAL,
                f"Unsupported algorithm: {alg}",
            )
            continue

        key = lookup_key(keys_data, tenant, kid, alg, result)
        if key is None:
            continue

        # Check key validity
        check_key_validity(key, body["ts"], result)
        if result.receipt_integrity == LayerStatus.FAIL:
            continue

        # Verify signature
        sig_value = sig.get("value", "")
        verify_signature(key, canonical_bytes, sig_value, result)
        if result.receipt_integrity == LayerStatus.FAIL:
            continue

    # Sequence checks (monotonic, dense, prev_receipt chain)
    if receipt_hashes and result.receipt_integrity != LayerStatus.FAIL:
        sorted_seqs = sorted(receipt_hashes.keys(), key=lambda s: int(s))

        # Check density
        for i in range(1, len(sorted_seqs)):
            prev_seq = int(sorted_seqs[i - 1])
            curr_seq = int(sorted_seqs[i])
            if curr_seq != prev_seq + 1:
                result.add_error(
                    ErrorCode.SEQUENCE_GAP,
                    "receipt_integrity",
                    Severity.FATAL,
                    f"Sequence gap between {prev_seq} and {curr_seq}",
                )

        # Check prev_receipt chain
        seq_to_body = {}
        for envelope in receipts:
            body = envelope.get("body", {})
            if "seq" in body and isinstance(body["seq"], str):
                seq_to_body[body["seq"]] = body

        for i, seq in enumerate(sorted_seqs):
            body = seq_to_body.get(seq, {})
            prev = body.get("prev_receipt", "")

            if i == 0:
                # First in segment: if genesis seq, must be genesis prev_receipt
                if int(seq) == 1 and prev != GENESIS_PREV_RECEIPT:
                    result.add_error(
                        ErrorCode.MISSING_PREVIOUS_RECEIPT,
                        "receipt_integrity",
                        Severity.FATAL,
                        f"First receipt (seq {seq}) should reference genesis but references {prev}",
                    )
                elif int(seq) != 1:
                    result.add_error(
                        ErrorCode.MISSING_PREVIOUS_RECEIPT,
                        "receipt_integrity",
                        Severity.FATAL,
                        f"First disclosed receipt seq {seq} requires previous receipt or checkpoint bridge",
                    )
            else:
                prev_seq = sorted_seqs[i - 1]
                expected_prev = receipt_hashes[prev_seq]
                if prev != expected_prev:
                    result.add_error(
                        ErrorCode.MISSING_PREVIOUS_RECEIPT,
                        "receipt_integrity",
                        Severity.FATAL,
                        f"Receipt seq {seq} prev_receipt mismatch: expected {expected_prev}, got {prev}",
                    )

    if receipt_hashes and result.receipt_integrity not in (
        LayerStatus.FAIL,
        LayerStatus.UNSUPPORTED_VERSION,
    ):
        result.receipt_integrity = LayerStatus.PASS

    return receipt_hashes


def _verify_anchor_validity(
    receipts: list[dict],
    receipt_hashes: dict[str, str],
    anchor_proof: dict | None,
    result: VerificationResult,
) -> None:
    """Verify Layer 2: anchor validity."""
    if anchor_proof is None:
        if result.anchor_validity == LayerStatus.INCONCLUSIVE:
            result.add_error(
                ErrorCode.ANCHOR_UNCHECKED,
                "anchor_validity",
                Severity.WARNING,
                "No anchor proof provided",
            )
        return

    if not isinstance(anchor_proof, dict):
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            f"Anchor proof must be an object, got {type(anchor_proof).__name__}",
        )
        return

    # Build sorted receipt hashes for Merkle root computation
    if not receipt_hashes:
        result.anchor_validity = LayerStatus.INCONCLUSIVE
        return

    # Validate root_alg
    if anchor_proof.get("root_alg") != "merkle-sha256-v1":
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            f"Unsupported anchor root_alg: {anchor_proof.get('root_alg')}",
        )
        return

    # Validate tenant matches reviewed receipts
    seq_to_tenant = {
        env["body"]["seq"]: env["body"]["tenant"]
        for env in receipts
        if isinstance(env, dict)
        and isinstance(env.get("body"), dict)
        and env["body"].get("seq") in receipt_hashes
    }
    tenants = set(seq_to_tenant.values())
    if len(tenants) != 1 or anchor_proof.get("tenant") not in tenants:
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor proof tenant does not match reviewed receipts",
        )
        return

    batch_root_hex = anchor_proof.get("batch_root", "")
    if not isinstance(batch_root_hex, str):
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "batch_root must be a string",
        )
        return

    if batch_root_hex.startswith("sha256:"):
        batch_root_hex_stripped = batch_root_hex[7:]
    else:
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Invalid batch_root format",
        )
        result.anchor_validity = LayerStatus.FAIL
        return

    commitment_value = anchor_proof.get("commitment_value", "")
    if not isinstance(commitment_value, str):
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "commitment_value must be a string",
        )
        result.anchor_validity = LayerStatus.FAIL
        return

    # Check batch_root matches commitment_value
    if batch_root_hex != commitment_value:
        result.add_error(
            ErrorCode.ANCHOR_ROOT_MISMATCH,
            "anchor_validity",
            Severity.FATAL,
            f"batch_root {batch_root_hex} does not match commitment_value {commitment_value}",
        )
        result.anchor_validity = LayerStatus.FAIL
        return

    # Recompute batch root from receipts in range
    try:
        range_start = int(anchor_proof.get("range_start", "0"))
        range_end = int(anchor_proof.get("range_end", "0"))
    except (TypeError, ValueError):
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor range fields must be decimal strings",
        )
        return

    ordered_hashes = []
    covered_seqs = []
    for seq_num in range(range_start, range_end + 1):
        seq_str = str(seq_num)
        if seq_str in receipt_hashes:
            covered_seqs.append(seq_str)
            rh = receipt_hashes[seq_str]
            if rh.startswith("sha256:"):
                ordered_hashes.append(rh[7:])
            else:
                ordered_hashes.append(rh)

    if not ordered_hashes:
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.RANGE_NOT_COVERED,
            "anchor_validity",
            Severity.FATAL,
            "Anchor range does not cover any reviewed receipt",
        )
        return

    computed_root = compute_batch_root(ordered_hashes)
    try:
        expected_root = bytes.fromhex(batch_root_hex_stripped)
    except ValueError:
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor batch_root must be lowercase hex",
        )
        return

    if computed_root != expected_root:
        result.add_error(
            ErrorCode.ANCHOR_ROOT_MISMATCH,
            "anchor_validity",
            Severity.FATAL,
            "Recomputed batch root does not match anchor batch_root",
        )
        result.anchor_validity = LayerStatus.FAIL
        return

    # Verify individual Merkle proofs
    proofs = anchor_proof.get("proofs", [])
    if not isinstance(proofs, list):
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor proofs must be an array",
        )
        return

    if not proofs:
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor proof must include at least one receipt proof",
        )
        return

    # Check that every reviewed receipt in range has a proof
    proof_hashes = {proof.get("receipt_hash") for proof in proofs if isinstance(proof, dict) and isinstance(proof.get("receipt_hash"), str)}
    missing = [receipt_hashes[seq] for seq in covered_seqs if receipt_hashes[seq] not in proof_hashes]
    if missing:
        result.anchor_validity = LayerStatus.FAIL
        result.add_error(
            ErrorCode.ANCHOR_PROOF_INVALID,
            "anchor_validity",
            Severity.FATAL,
            "Anchor proof does not include every reviewed receipt hash in range",
        )
        return

    for proof in proofs:
        if not isinstance(proof, dict):
            result.anchor_validity = LayerStatus.FAIL
            result.add_error(
                ErrorCode.ANCHOR_PROOF_INVALID,
                "anchor_validity",
                Severity.FATAL,
                "Proof must be an object",
            )
            return
        if not isinstance(proof.get("merkle_path"), list):
            result.anchor_validity = LayerStatus.FAIL
            result.add_error(
                ErrorCode.ANCHOR_PROOF_INVALID,
                "anchor_validity",
                Severity.FATAL,
                "merkle_path must be an array",
            )
            return

        rh = proof.get("receipt_hash", "")
        if not isinstance(rh, str):
            result.anchor_validity = LayerStatus.FAIL
            result.add_error(
                ErrorCode.ANCHOR_PROOF_INVALID,
                "anchor_validity",
                Severity.FATAL,
                "proof receipt_hash must be a string",
            )
            return
        if rh.startswith("sha256:"):
            rh_hex = rh[7:]
        else:
            rh_hex = rh

        try:
            leaf_idx = int(proof.get("leaf_index", "0"))
        except (TypeError, ValueError):
            result.anchor_validity = LayerStatus.FAIL
            result.add_error(
                ErrorCode.ANCHOR_PROOF_INVALID,
                "anchor_validity",
                Severity.FATAL,
                "leaf_index must be a decimal string",
            )
            return

        # Bounds-check leaf_index against batch size (#3)
        batch_size = range_end - range_start + 1
        if leaf_idx < 0 or leaf_idx >= batch_size:
            result.anchor_validity = LayerStatus.FAIL
            result.add_error(
                ErrorCode.ANCHOR_PROOF_INVALID,
                "anchor_validity",
                Severity.FATAL,
                f"leaf_index {leaf_idx} out of range for batch size {batch_size}",
            )
            return

        merkle_path = proof.get("merkle_path", [])
        # batch_root_hex_stripped was already validated by bytes.fromhex at
        # line 524; re-parsing cannot fail so we use the prior expected_root.
        if not verify_merkle_proof(rh_hex, leaf_idx, merkle_path, expected_root, batch_size):
            result.add_error(
                ErrorCode.MERKLE_PATH_INVALID,
                "anchor_validity",
                Severity.FATAL,
                f"Merkle path verification failed for receipt {rh}",
            )
            result.anchor_validity = LayerStatus.FAIL
            return

    # Anchor tx check — v0.1 does not query live chains
    tx = anchor_proof.get("tx", "")
    if tx:
        result.add_error(
            ErrorCode.ANCHOR_UNCHECKED,
            "anchor_validity",
            Severity.WARNING,
            "Anchor transaction not independently verified (v0.1 offline mode)",
        )
    result.anchor_validity = LayerStatus.INCONCLUSIVE


def _verify_completeness(
    receipts: list[dict],
    receipt_hashes: dict[str, str],
    anchor_proof: dict | None,
    result: VerificationResult,
) -> None:
    """Verify Layer 3: completeness."""
    # If receipt integrity already failed, completeness is inconclusive
    if result.receipt_integrity == LayerStatus.FAIL:
        result.completeness = LayerStatus.INCONCLUSIVE
        result.add_error(
            ErrorCode.COMPLETENESS_NOT_PROVABLE,
            "completeness",
            Severity.WARNING,
            "Completeness cannot be evaluated when receipt integrity fails",
        )
        return

    if not receipt_hashes:
        result.completeness = LayerStatus.INCONCLUSIVE
        result.add_error(
            ErrorCode.COMPLETENESS_NOT_PROVABLE,
            "completeness",
            Severity.WARNING,
            "No receipts to evaluate completeness",
        )
        return

    # Check that the provided range is dense
    sorted_seqs = sorted(receipt_hashes.keys(), key=lambda s: int(s))
    is_dense = True
    for i in range(1, len(sorted_seqs)):
        if int(sorted_seqs[i]) != int(sorted_seqs[i - 1]) + 1:
            is_dense = False
            break

    if not is_dense:
        result.completeness = LayerStatus.FAIL
        return

    if anchor_proof is None or not isinstance(anchor_proof, dict):
        result.completeness = LayerStatus.INCONCLUSIVE
        result.add_error(
            ErrorCode.COMPLETENESS_NOT_PROVABLE,
            "completeness",
            Severity.WARNING,
            "No anchor proof to support completeness claim",
        )
        return

    # Check if receipts are covered by anchor range
    try:
        range_start = int(anchor_proof.get("range_start", "0"))
        range_end = int(anchor_proof.get("range_end", "0"))
    except (TypeError, ValueError):
        result.completeness = LayerStatus.INCONCLUSIVE
        return
    min_seq = int(sorted_seqs[0])
    max_seq = int(sorted_seqs[-1])

    if min_seq < range_start or max_seq > range_end:
        result.add_error(
            ErrorCode.RANGE_NOT_COVERED,
            "completeness",
            Severity.WARNING,
            f"Receipt range [{min_seq}, {max_seq}] not fully covered by anchor range [{range_start}, {range_end}]",
        )
        result.completeness = LayerStatus.INCONCLUSIVE
        return

    result.completeness = LayerStatus.INCONCLUSIVE
    result.add_error(
        ErrorCode.COMPLETENESS_NOT_PROVABLE,
        "completeness",
        Severity.WARNING,
        "Completeness requires disclosed checkpoints or full range anchoring",
    )
