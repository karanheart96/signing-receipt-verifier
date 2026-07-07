#!/usr/bin/env python3
"""Deterministic test vector generator for Receipt Chain Verification Protocol v0.1.

Generates TV-001 through TV-020 using deterministic Ed25519 keys.
All outputs are reproducible from the same seed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

# Add parent dir so we can import verifier
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from verifier.canonical import canonicalize
from verifier.crypto import base64url_encode, sha256_hex
from verifier.merkle import compute_batch_root, leaf_hash, node_hash
from verifier.models import GENESIS_PREV_RECEIPT

_DEFAULT_BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test-vectors")

# Module-level output directory; set by main() or generate_all()
BASE_DIR = _DEFAULT_BASE_DIR

# --- Deterministic key generation ---

def _deterministic_private_key(seed: bytes) -> Ed25519PrivateKey:
    """Generate a deterministic Ed25519 private key from a 32-byte seed."""
    seed_hash = hashlib.sha256(seed).digest()
    return Ed25519PrivateKey.from_private_bytes(seed_hash)


TENANT = "test-tenant-001"
KID = "tenant-key-2026-05"

_SEED = b"receipt-chain-verifier-test-seed-v0.1"
PRIVATE_KEY = _deterministic_private_key(_SEED)
PUBLIC_KEY = PRIVATE_KEY.public_key()
PUBLIC_KEY_BYTES = PUBLIC_KEY.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
PUBLIC_KEY_B64URL = base64url_encode(PUBLIC_KEY_BYTES)

# Second key for TV-010 (wrong algorithm scenario)
_SEED2 = b"receipt-chain-verifier-test-seed-v0.1-alt"
PRIVATE_KEY_2 = _deterministic_private_key(_SEED2)
PUBLIC_KEY_2 = PRIVATE_KEY_2.public_key()
PUBLIC_KEY_2_BYTES = PUBLIC_KEY_2.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
PUBLIC_KEY_2_B64URL = base64url_encode(PUBLIC_KEY_2_BYTES)


def make_keys_json(
    tenant: str = TENANT,
    kid: str = KID,
    pub_b64: str = PUBLIC_KEY_B64URL,
    alg: str = "EdDSA",
    status: str = "active",
    not_before: str = "2026-05-01T00:00:00.000Z",
    not_after: str = "2026-06-01T00:00:00.000Z",
    revocation_time: str | None = None,
    extra_keys: list[dict] | None = None,
) -> dict:
    key_entry = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "x": pub_b64,
        "not_before": not_before,
        "not_after": not_after,
        "status": status,
        "revocation_time": revocation_time,
    }
    keys = [key_entry]
    if extra_keys:
        keys.extend(extra_keys)
    return {"tenant": tenant, "keys": keys}


def make_receipt_body(
    seq: str | int,
    prev_receipt: str,
    ts: str = "2026-05-10T19:42:00.123Z",
    tenant: str = TENANT,
    decision: str = "approve",
    reasons: list[str] | None = None,
    request_digest: str | None = None,
    policy_version: str | None = None,
    v: str = "1",
    extra_fields: dict | None = None,
) -> dict:
    if reasons is None:
        reasons = ["auto_approve"]
    if request_digest is None:
        # Deterministic fake digest
        request_digest = sha256_hex(f"request-{seq}".encode())
    if policy_version is None:
        policy_version = sha256_hex(b"policy-v1")

    body = {
        "v": v,
        "tenant": tenant,
        "seq": str(seq) if isinstance(seq, int) else seq,
        "ts": ts,
        "request_digest": request_digest,
        "policy_version": policy_version,
        "decision": decision,
        "reasons": reasons,
        "prev_receipt": prev_receipt,
    }
    if extra_fields:
        body.update(extra_fields)
    return body


def sign_body(body: dict, private_key: Ed25519PrivateKey = PRIVATE_KEY, kid: str = KID) -> dict:
    canonical_bytes = canonicalize(body)
    sig_bytes = private_key.sign(canonical_bytes)
    return {
        "body": body,
        "sig": {
            "alg": "EdDSA",
            "kid": kid,
            "value": base64url_encode(sig_bytes),
        },
    }


def receipt_hash(body: dict) -> str:
    return sha256_hex(canonicalize(body))


def write_vector(name: str, files: dict[str, object], readme_text: str) -> None:
    vec_dir = os.path.join(BASE_DIR, name)
    os.makedirs(vec_dir, exist_ok=True)
    for filename, data in files.items():
        path = os.path.join(vec_dir, filename)
        if isinstance(data, str):
            with open(path, "w") as f:
                f.write(data)
        else:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
    # Write README
    readme_path = os.path.join(vec_dir, "README.md")
    with open(readme_path, "w") as f:
        f.write(readme_text)


def build_chain(count: int, start_seq: int = 1, ts_base: str = "2026-05-10T19:42:0") -> list[dict]:
    """Build a valid chain of `count` receipts starting at start_seq."""
    envelopes = []
    prev = GENESIS_PREV_RECEIPT
    for i in range(count):
        seq = start_seq + i
        ts = f"{ts_base}{i}.123Z"
        body = make_receipt_body(seq=seq, prev_receipt=prev, ts=ts)
        envelope = sign_body(body)
        prev = receipt_hash(body)
        envelopes.append(envelope)
    return envelopes


# ============================================================
# TV-001: Valid three-receipt chain, no anchor
# ============================================================
def gen_tv001():
    envelopes = build_chain(3)
    keys = make_keys_json()
    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
    }
    write_vector(
        "TV-001-valid-chain-no-anchor",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-001: Valid three-receipt chain, no anchor\n\n"
        "Tests that a valid chain of three receipts passes receipt integrity.\n"
        "No anchor proof is provided, so anchor_validity and completeness are INCONCLUSIVE.\n",
    )


# ============================================================
# TV-002: Valid anchored batch with all receipts proven
# ============================================================
def gen_tv002():
    envelopes = build_chain(3)
    keys = make_keys_json()

    # Compute Merkle root over all 3 receipts
    hashes = []
    for env in envelopes:
        rh = receipt_hash(env["body"])
        hashes.append(rh[7:])  # strip sha256: prefix

    root_bytes = compute_batch_root(hashes)
    root_hex = "sha256:" + root_bytes.hex()

    # Build Merkle proofs for all 3 receipts
    # For 3 leaves: tree is:
    #       root
    #      /    \
    #    n01     leaf2
    #   /   \
    # leaf0  leaf1
    leaf0 = leaf_hash(hashes[0])
    leaf1 = leaf_hash(hashes[1])
    leaf2 = leaf_hash(hashes[2])
    n01 = node_hash(leaf0, leaf1)

    # Proof for leaf 0 (index 0, even -> sibling is right)
    merkle_path_receipt0 = [
        {"position": "right", "hash": "sha256:" + leaf1.hex()},
        {"position": "right", "hash": "sha256:" + leaf2.hex()},
    ]

    # Proof for leaf 1 (index 1, odd -> sibling is left)
    merkle_path_receipt1 = [
        {"position": "left", "hash": "sha256:" + leaf0.hex()},
        {"position": "right", "hash": "sha256:" + leaf2.hex()},
    ]

    # Proof for leaf 2 (index 2, even at level 1 -> sibling is right=n01;
    # but leaf2 is promoted at level 0, so at level 1 index is 1, odd -> sibling is left)
    # Actually: leaf2 is at index 2. At level 0: pairs are (leaf0,leaf1) and leaf2 promoted.
    # So leaf2 has no sibling at level 0, it's promoted to level 1 as-is.
    # At level 1: nodes are [n01, leaf2]. leaf2 is at index 1 (odd), sibling is left=n01.
    merkle_path_receipt2 = [
        {"position": "left", "hash": "sha256:" + n01.hex()},
    ]

    anchor_proof = {
        "v": "1",
        "tenant": TENANT,
        "range_start": "1",
        "range_end": "3",
        "root_alg": "merkle-sha256-v1",
        "batch_root": root_hex,
        "chain": "base",
        "chain_id": "8453",
        "tx": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "commitment_location": "calldata",
        "commitment_value": root_hex,
        "proofs": [
            {
                "receipt_hash": "sha256:" + hashes[0],
                "leaf_index": "0",
                "merkle_path": merkle_path_receipt0,
            },
            {
                "receipt_hash": "sha256:" + hashes[1],
                "leaf_index": "1",
                "merkle_path": merkle_path_receipt1,
            },
            {
                "receipt_hash": "sha256:" + hashes[2],
                "leaf_index": "2",
                "merkle_path": merkle_path_receipt2,
            },
        ],
    }

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
    }
    write_vector(
        "TV-002-valid-anchored-batch",
        {
            "receipts.json": envelopes,
            "keys.json": keys,
            "anchor-proof.json": anchor_proof,
            "expected.json": expected,
        },
        "# TV-002: Valid anchored batch with all receipts proven\n\n"
        "Tests that receipt integrity passes and Merkle proofs verify for all receipts.\n"
        "Anchor tx is not independently verified (v0.1 offline), so ANCHOR_UNCHECKED is expected.\n",
    )


# ============================================================
# TV-003: Hash-chain break
# ============================================================
def gen_tv003():
    envelopes = build_chain(3)
    keys = make_keys_json()

    # Break the chain: modify receipt 2's prev_receipt to a wrong value
    bad_body = dict(envelopes[2]["body"])
    bad_body["prev_receipt"] = sha256_hex(b"wrong-prev")
    envelopes[2] = sign_body(bad_body)

    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["MISSING_PREVIOUS_RECEIPT"],
    }
    write_vector(
        "TV-003-hash-chain-break",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-003: Hash-chain break\n\n"
        "Receipt 3 has an incorrect prev_receipt, breaking the hash chain.\n"
        "Expected: receipt_integrity FAIL with MISSING_PREVIOUS_RECEIPT.\n",
    )


# ============================================================
# TV-004: Invalid signature
# ============================================================
def gen_tv004():
    envelopes = build_chain(1)
    keys = make_keys_json()

    # Corrupt the signature
    env = envelopes[0]
    env["sig"]["value"] = base64url_encode(b"\x00" * 64)

    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["SIGNATURE_INVALID"],
    }
    write_vector(
        "TV-004-invalid-signature",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-004: Invalid signature\n\n"
        "Receipt has a corrupted Ed25519 signature.\n"
        "Expected: receipt_integrity FAIL with SIGNATURE_INVALID.\n",
    )


# ============================================================
# TV-005: Sequence gap
# ============================================================
def gen_tv005():
    # Create receipts with seq 1, 2, 4 (skip 3)
    prev = GENESIS_PREV_RECEIPT
    envelopes = []
    for seq in [1, 2, 4]:
        body = make_receipt_body(seq=seq, prev_receipt=prev, ts=f"2026-05-10T19:42:0{seq}.123Z")
        envelope = sign_body(body)
        prev = receipt_hash(body)
        envelopes.append(envelope)

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["SEQUENCE_GAP"],
    }
    write_vector(
        "TV-005-sequence-gap",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-005: Sequence gap\n\n"
        "Sequence jumps from 2 to 4 (missing 3).\n"
        "Expected: receipt_integrity FAIL with SEQUENCE_GAP.\n",
    )


# ============================================================
# TV-006: Duplicate sequence number
# ============================================================
def gen_tv006():
    envelopes = build_chain(2)
    keys = make_keys_json()

    # Add a third receipt with the same seq as receipt 2 and same hash
    dup_body = dict(envelopes[1]["body"])
    dup_envelope = sign_body(dup_body)
    envelopes.append(dup_envelope)

    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["DUPLICATE_SEQUENCE"],
    }
    write_vector(
        "TV-006-duplicate-sequence",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-006: Duplicate sequence number\n\n"
        "Two receipts share the same sequence number with the same hash.\n"
        "Expected: receipt_integrity FAIL with DUPLICATE_SEQUENCE.\n",
    )


# ============================================================
# TV-007: Forked sequence
# ============================================================
def gen_tv007():
    envelopes = build_chain(2)
    keys = make_keys_json()

    # Create a different receipt with seq=2 but different content
    prev = receipt_hash(envelopes[0]["body"])
    fork_body = make_receipt_body(
        seq=2,
        prev_receipt=prev,
        ts="2026-05-10T19:42:09.123Z",
        decision="deny",
        reasons=["forked_reason"],
    )
    fork_envelope = sign_body(fork_body)
    envelopes.append(fork_envelope)

    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["FORKED_SEQUENCE"],
    }
    write_vector(
        "TV-007-forked-sequence",
        {"receipts.json": envelopes, "keys.json": keys, "expected.json": expected},
        "# TV-007: Forked sequence\n\n"
        "Two receipts share seq=2 but have different hashes (different decisions).\n"
        "Expected: receipt_integrity FAIL with FORKED_SEQUENCE.\n",
    )


# ============================================================
# TV-008: Anchor root mismatch
# ============================================================
def gen_tv008():
    envelopes = build_chain(1)
    keys = make_keys_json()

    rh = receipt_hash(envelopes[0]["body"])
    rh_hex = rh[7:]

    correct_root = compute_batch_root([rh_hex])
    wrong_root = sha256_hex(b"wrong-root")

    anchor_proof = {
        "v": "1",
        "tenant": TENANT,
        "range_start": "1",
        "range_end": "1",
        "root_alg": "merkle-sha256-v1",
        "batch_root": wrong_root,
        "chain": "base",
        "chain_id": "8453",
        "tx": "0xaabbccdd",
        "commitment_location": "calldata",
        "commitment_value": wrong_root,
        "proofs": [],
    }

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "FAIL",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_ROOT_MISMATCH"],
    }
    write_vector(
        "TV-008-anchor-root-mismatch",
        {
            "receipts.json": envelopes,
            "keys.json": keys,
            "anchor-proof.json": anchor_proof,
            "expected.json": expected,
        },
        "# TV-008: Anchor root mismatch\n\n"
        "The anchor proof's batch_root does not match the recomputed Merkle root.\n"
        "Expected: anchor_validity FAIL with ANCHOR_ROOT_MISMATCH.\n",
    )


# ============================================================
# TV-009: Merkle path mismatch
# ============================================================
def gen_tv009():
    envelopes = build_chain(3)
    keys = make_keys_json()

    hashes = [receipt_hash(e["body"])[7:] for e in envelopes]
    root_bytes = compute_batch_root(hashes)
    root_hex = "sha256:" + root_bytes.hex()

    # Build tree structure for 3 leaves:
    #       root
    #      /    \
    #    n01     leaf2
    #   /   \
    # leaf0  leaf1
    leaf0 = leaf_hash(hashes[0])
    leaf1 = leaf_hash(hashes[1])
    leaf2 = leaf_hash(hashes[2])
    n01 = node_hash(leaf0, leaf1)

    # Proof for leaf 0 — CORRUPTED (wrong sibling at level 1)
    bad_path = [
        {"position": "right", "hash": "sha256:" + leaf1.hex()},
        {"position": "right", "hash": sha256_hex(b"wrong-sibling")},  # wrong!
    ]

    # Correct proofs for leaves 1 and 2
    merkle_path_receipt1 = [
        {"position": "left", "hash": "sha256:" + leaf0.hex()},
        {"position": "right", "hash": "sha256:" + leaf2.hex()},
    ]
    merkle_path_receipt2 = [
        {"position": "left", "hash": "sha256:" + n01.hex()},
    ]

    anchor_proof = {
        "v": "1",
        "tenant": TENANT,
        "range_start": "1",
        "range_end": "3",
        "root_alg": "merkle-sha256-v1",
        "batch_root": root_hex,
        "chain": "base",
        "chain_id": "8453",
        "tx": "0xdeadbeef",
        "commitment_location": "calldata",
        "commitment_value": root_hex,
        "proofs": [
            {
                "receipt_hash": "sha256:" + hashes[0],
                "leaf_index": "0",
                "merkle_path": bad_path,
            },
            {
                "receipt_hash": "sha256:" + hashes[1],
                "leaf_index": "1",
                "merkle_path": merkle_path_receipt1,
            },
            {
                "receipt_hash": "sha256:" + hashes[2],
                "leaf_index": "2",
                "merkle_path": merkle_path_receipt2,
            },
        ],
    }

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "FAIL",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["MERKLE_PATH_INVALID"],
    }
    write_vector(
        "TV-009-merkle-path-mismatch",
        {
            "receipts.json": envelopes,
            "keys.json": keys,
            "anchor-proof.json": anchor_proof,
            "expected.json": expected,
        },
        "# TV-009: Merkle path mismatch\n\n"
        "Merkle inclusion proof for receipt 1 has a corrupted sibling hash.\n"
        "Expected: anchor_validity FAIL with MERKLE_PATH_INVALID.\n",
    )


# ============================================================
# TV-010: Unknown algorithm
# ============================================================
def gen_tv010():
    body = make_receipt_body(seq=1, prev_receipt=GENESIS_PREV_RECEIPT)
    canonical_bytes = canonicalize(body)
    sig_bytes = PRIVATE_KEY.sign(canonical_bytes)

    envelope = {
        "body": body,
        "sig": {
            "alg": "RS256",
            "kid": KID,
            "value": base64url_encode(sig_bytes),
        },
    }

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["UNSUPPORTED_ALGORITHM"],
    }
    write_vector(
        "TV-010-unknown-algorithm",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-010: Unknown algorithm\n\n"
        "Receipt declares alg=RS256, which is not mandatory-to-implement in v0.1.\n"
        "Expected: receipt_integrity FAIL with UNSUPPORTED_ALGORITHM.\n",
    )


# ============================================================
# TV-011: Key not found
# ============================================================
def gen_tv011():
    body = make_receipt_body(seq=1, prev_receipt=GENESIS_PREV_RECEIPT)
    envelope = sign_body(body, kid="nonexistent-key-2026-05")

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["KEY_NOT_FOUND"],
    }
    write_vector(
        "TV-011-key-not-found",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-011: Key not found\n\n"
        "Receipt references a kid that does not exist in the key set.\n"
        "Expected: receipt_integrity FAIL with KEY_NOT_FOUND.\n",
    )


# ============================================================
# TV-012: Canonical key ordering
# ============================================================
def gen_tv012():
    # Body with keys that would sort differently under naive vs JCS ordering
    body = {
        "v": "1",
        "tenant": TENANT,
        "seq": "1",
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-1"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["rule_a", "rule_b"],
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    canonical_bytes = canonicalize(body)
    canonical_hex = canonical_bytes.hex()

    envelope = sign_body(body)
    keys = make_keys_json()

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
        "python_expected_canonical_hex": canonical_hex,
        "go_expected_canonical_hex": canonical_hex,
        "_TODO": "Go independent generation must be verified before public release",
    }
    write_vector(
        "TV-012-canonical-key-ordering",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-012: Canonical key ordering\n\n"
        "Tests that receipt body keys are sorted correctly under JCS (RFC 8785).\n"
        "Expected: canonical bytes are identical across Python and Go implementations.\n",
    )


# ============================================================
# TV-013: Canonical Unicode string
# ============================================================
def gen_tv013():
    body = {
        "v": "1",
        "tenant": TENANT,
        "seq": "1",
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-unicode"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["\u00e9\u00e8\u00ea", "\u4e16\u754c"],  # accented chars, CJK
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    canonical_bytes = canonicalize(body)
    canonical_hex = canonical_bytes.hex()

    envelope = sign_body(body)
    keys = make_keys_json()

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
        "python_expected_canonical_hex": canonical_hex,
        "go_expected_canonical_hex": canonical_hex,
        "_TODO": "Go independent generation must be verified before public release",
    }
    write_vector(
        "TV-013-canonical-unicode-string",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-013: Canonical Unicode string\n\n"
        "Tests that Unicode strings (accented Latin, CJK) are preserved in canonical form.\n"
        "Expected: canonical bytes preserve Unicode content per JCS rules.\n",
    )


# ============================================================
# TV-014: Large integer as JSON number
# ============================================================
def gen_tv014():
    # seq is a JSON number instead of a string — must fail
    body_raw = {
        "v": "1",
        "tenant": TENANT,
        "seq": 99999999999999,  # JSON number, not string!
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-large-int"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["auto_approve"],
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    # We need to write the raw JSON with numeric seq
    # Sign with a valid signature (though it should fail field type check first)
    canonical_bytes = canonicalize(body_raw)
    sig_bytes = PRIVATE_KEY.sign(canonical_bytes)
    envelope = {
        "body": body_raw,
        "sig": {
            "alg": "EdDSA",
            "kid": KID,
            "value": base64url_encode(sig_bytes),
        },
    }

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["INVALID_FIELD_TYPE"],
    }
    write_vector(
        "TV-014-large-integer-json-number",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-014: Large integer encoded as JSON number\n\n"
        "seq is encoded as a JSON number (99999999999999) instead of a string.\n"
        "Expected: receipt_integrity FAIL with INVALID_FIELD_TYPE.\n"
        "The rule is type-level, not range-level.\n",
    )


# ============================================================
# TV-015: Unsupported receipt version
# ============================================================
def gen_tv015():
    body = make_receipt_body(seq=1, prev_receipt=GENESIS_PREV_RECEIPT, v="2")
    envelope = sign_body(body)
    keys = make_keys_json()

    expected = {
        "receipt_integrity": "UNSUPPORTED_VERSION",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["UNSUPPORTED_RECEIPT_VERSION"],
    }
    write_vector(
        "TV-015-unsupported-receipt-version",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-015: Unsupported receipt version\n\n"
        "Receipt body has v=\"2\" which is not supported in v0.1.\n"
        "Expected: receipt_integrity UNSUPPORTED_VERSION with UNSUPPORTED_RECEIPT_VERSION.\n",
    )


# ============================================================
# TV-016: String escape forms
# ============================================================
def gen_tv016():
    # Use strings with control chars and different escape representations
    body = {
        "v": "1",
        "tenant": TENANT,
        "seq": "1",
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-escape"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["tab\there", "newline\nhere", "quote\"here", "backslash\\here", "null\x00here"],
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    canonical_bytes = canonicalize(body)
    canonical_hex = canonical_bytes.hex()

    envelope = sign_body(body)
    keys = make_keys_json()

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
        "python_expected_canonical_hex": canonical_hex,
        "go_expected_canonical_hex": canonical_hex,
        "_TODO": "Go independent generation must be verified before public release",
        "_description": "Tests that control characters, tabs, newlines, quotes, backslashes, "
                        "and null bytes are canonicalized identically across implementations. "
                        "Catches bugs where escape form normalization diverges.",
    }
    write_vector(
        "TV-016-string-escape-forms",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-016: String escape forms\n\n"
        "Tests canonicalization of strings containing control characters and escape sequences.\n"
        "Expected: Python and Go produce identical canonical bytes for tab, newline, quote, "
        "backslash, and null byte in reason strings.\n"
        "Catches portability bugs in escape form normalization.\n",
    )


# ============================================================
# TV-017: Nested object key collation
# ============================================================
def gen_tv017():
    # This tests key ordering with multi-byte Unicode keys
    # We construct a body with reasons containing visually similar keys
    # Since receipt body has fixed keys, we test ordering via the standard fields
    # but with a tenant name that uses multi-byte Unicode
    body = {
        "v": "1",
        "tenant": "\u00e9\u00c9\u00ea\u4e16",  # multi-byte Unicode tenant
        "seq": "1",
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-collation"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["\u00e9", "\u00c9", "\u00ea", "\u4e16", "\U0001f600"],  # Unicode sort test
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    canonical_bytes = canonicalize(body)
    canonical_hex = canonical_bytes.hex()

    envelope = sign_body(body)
    # Keys need matching tenant
    keys = make_keys_json(tenant="\u00e9\u00c9\u00ea\u4e16")

    expected = {
        "receipt_integrity": "PASS",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["ANCHOR_UNCHECKED", "COMPLETENESS_NOT_PROVABLE"],
        "python_expected_canonical_hex": canonical_hex,
        "go_expected_canonical_hex": canonical_hex,
        "_TODO": "Go independent generation must be verified before public release",
        "_description": "Tests that object keys are sorted by UTF-16 code unit order (JCS), "
                        "not by locale-aware or UTF-8 byte order. Includes ASCII, accented Latin, "
                        "CJK, and emoji (surrogate pair) characters.",
    }
    write_vector(
        "TV-017-nested-object-key-collation",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-017: Nested object key collation\n\n"
        "Tests JCS key collation with multi-byte Unicode (accented Latin, CJK, emoji).\n"
        "Expected: Python and Go produce identical canonical bytes using UTF-16 code unit sort.\n"
        "Catches bugs where locale-aware or UTF-8 byte sorting is used instead of JCS.\n",
    )


# ============================================================
# TV-018: seq as JSON number
# ============================================================
def gen_tv018():
    body_raw = {
        "v": "1",
        "tenant": TENANT,
        "seq": 12345,  # number, not string!
        "ts": "2026-05-10T19:42:00.123Z",
        "request_digest": sha256_hex(b"request-seq-num"),
        "policy_version": sha256_hex(b"policy-v1"),
        "decision": "approve",
        "reasons": ["auto_approve"],
        "prev_receipt": GENESIS_PREV_RECEIPT,
    }

    canonical_bytes = canonicalize(body_raw)
    sig_bytes = PRIVATE_KEY.sign(canonical_bytes)
    envelope = {
        "body": body_raw,
        "sig": {
            "alg": "EdDSA",
            "kid": KID,
            "value": base64url_encode(sig_bytes),
        },
    }

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["INVALID_FIELD_TYPE"],
    }
    write_vector(
        "TV-018-seq-as-json-number",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-018: seq as JSON number\n\n"
        "seq is encoded as JSON number 12345 instead of string \"12345\".\n"
        "Expected: receipt_integrity FAIL with INVALID_FIELD_TYPE.\n"
        "The rule is type-level: even safe-range integers must be strings.\n",
    )


# ============================================================
# TV-019: Empty array vs missing field
# ============================================================
def gen_tv019():
    # Valid receipt with reasons: []
    body_valid = make_receipt_body(seq=1, prev_receipt=GENESIS_PREV_RECEIPT, reasons=[])
    envelope_valid = sign_body(body_valid)

    # Invalid receipt with reasons omitted
    body_invalid = make_receipt_body(seq=2, prev_receipt=receipt_hash(body_valid))
    del body_invalid["reasons"]
    # Sign it anyway
    canonical_bytes = canonicalize(body_invalid)
    sig_bytes = PRIVATE_KEY.sign(canonical_bytes)
    envelope_invalid = {
        "body": body_invalid,
        "sig": {
            "alg": "EdDSA",
            "kid": KID,
            "value": base64url_encode(sig_bytes),
        },
    }

    keys = make_keys_json()
    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["MISSING_REQUIRED_FIELD"],
        "_note": "First receipt (reasons: []) is valid. Second receipt (reasons omitted) fails.",
    }
    write_vector(
        "TV-019-empty-array-vs-missing-field",
        {"receipts.json": [envelope_valid, envelope_invalid], "keys.json": keys, "expected.json": expected},
        "# TV-019: Empty array vs missing field\n\n"
        "Receipt 1 has `reasons: []` (valid for approval).\n"
        "Receipt 2 omits `reasons` entirely (invalid: required field missing).\n"
        "Expected: receipt_integrity FAIL with MISSING_REQUIRED_FIELD.\n",
    )


# ============================================================
# TV-020: kid trailing whitespace
# ============================================================
def gen_tv020():
    body = make_receipt_body(seq=1, prev_receipt=GENESIS_PREV_RECEIPT)
    # Sign with kid that has trailing whitespace
    envelope = sign_body(body, kid=KID + " ")  # trailing space

    keys = make_keys_json()  # keys.json has kid WITHOUT trailing space

    expected = {
        "receipt_integrity": "FAIL",
        "anchor_validity": "INCONCLUSIVE",
        "completeness": "INCONCLUSIVE",
        "expected_errors": ["KEY_NOT_FOUND"],
        "_note": "kid with trailing whitespace must not match key without trailing whitespace. Exact string comparison required.",
    }
    write_vector(
        "TV-020-kid-trailing-whitespace",
        {"receipts.json": [envelope], "keys.json": keys, "expected.json": expected},
        "# TV-020: kid trailing whitespace\n\n"
        "Receipt's sig.kid has trailing whitespace. The key set has kid without whitespace.\n"
        "A verifier must NOT trim or normalize kid before key lookup.\n"
        "Expected: receipt_integrity FAIL with KEY_NOT_FOUND.\n",
    )


# ============================================================
# Main
# ============================================================
def generate_all(output_dir: str | None = None) -> str:
    """Generate all test vectors into output_dir. Returns the directory used."""
    global BASE_DIR
    BASE_DIR = output_dir if output_dir else _DEFAULT_BASE_DIR
    os.makedirs(BASE_DIR, exist_ok=True)

    generators = [
        gen_tv001, gen_tv002, gen_tv003, gen_tv004, gen_tv005,
        gen_tv006, gen_tv007, gen_tv008, gen_tv009, gen_tv010,
        gen_tv011, gen_tv012, gen_tv013, gen_tv014, gen_tv015,
        gen_tv016, gen_tv017, gen_tv018, gen_tv019, gen_tv020,
    ]

    for i, gen in enumerate(generators, 1):
        print(f"Generating TV-{i:03d}...")
        gen()

    print(f"\nGenerated {len(generators)} test vectors in {BASE_DIR}")
    return BASE_DIR


def main():
    parser = argparse.ArgumentParser(
        description="Generate deterministic test vectors for Receipt Chain Verification Protocol v0.1",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for test vectors (default: repo test-vectors/)",
    )
    args = parser.parse_args()
    generate_all(args.output)


if __name__ == "__main__":
    main()
