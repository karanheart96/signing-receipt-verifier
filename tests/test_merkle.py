"""Unit tests for Merkle tree construction (merkle-sha256-v1)."""

from __future__ import annotations

import hashlib

import pytest

from verifier.merkle import (
    LEAF_DOMAIN,
    NODE_DOMAIN,
    compute_batch_root,
    leaf_hash,
    node_hash,
    verify_merkle_proof,
)


def _fake_receipt_hash(idx: int) -> str:
    """Generate a deterministic fake receipt hash (hex, no prefix)."""
    return hashlib.sha256(f"receipt-{idx}".encode()).hexdigest()


def test_leaf_hash():
    """Leaf hash = SHA256(LEAF_DOMAIN || 0x00 || receipt_hash_bytes)."""
    rh = _fake_receipt_hash(0)
    result = leaf_hash(rh)
    expected = hashlib.sha256(LEAF_DOMAIN + b"\x00" + bytes.fromhex(rh)).digest()
    assert result == expected


def test_node_hash():
    """Node hash = SHA256(NODE_DOMAIN || 0x00 || left || right)."""
    left = b"\x01" * 32
    right = b"\x02" * 32
    result = node_hash(left, right)
    expected = hashlib.sha256(NODE_DOMAIN + b"\x00" + left + right).digest()
    assert result == expected


def test_single_receipt_batch():
    """Single receipt: batch root = leaf hash."""
    rh = _fake_receipt_hash(0)
    root = compute_batch_root([rh])
    assert root == leaf_hash(rh)


def test_two_receipt_batch():
    """Two receipts: root = node_hash(leaf0, leaf1)."""
    h0 = _fake_receipt_hash(0)
    h1 = _fake_receipt_hash(1)
    root = compute_batch_root([h0, h1])
    expected = node_hash(leaf_hash(h0), leaf_hash(h1))
    assert root == expected


def test_three_receipt_batch_odd_promotion():
    """Three receipts: odd leaf promoted, not duplicated."""
    h0 = _fake_receipt_hash(0)
    h1 = _fake_receipt_hash(1)
    h2 = _fake_receipt_hash(2)

    root = compute_batch_root([h0, h1, h2])

    # Level 1: [node(leaf0, leaf1), leaf2]  (leaf2 promoted)
    # Level 2: [node(node01, leaf2)]
    l0 = leaf_hash(h0)
    l1 = leaf_hash(h1)
    l2 = leaf_hash(h2)
    n01 = node_hash(l0, l1)
    expected = node_hash(n01, l2)
    assert root == expected


def test_four_receipt_batch():
    """Four receipts: balanced tree."""
    hashes = [_fake_receipt_hash(i) for i in range(4)]
    root = compute_batch_root(hashes)

    leaves = [leaf_hash(h) for h in hashes]
    n01 = node_hash(leaves[0], leaves[1])
    n23 = node_hash(leaves[2], leaves[3])
    expected = node_hash(n01, n23)
    assert root == expected


def test_five_receipt_batch():
    """Five receipts: odd promotion at level 1."""
    hashes = [_fake_receipt_hash(i) for i in range(5)]
    root = compute_batch_root(hashes)

    leaves = [leaf_hash(h) for h in hashes]
    # Level 1: [n01, n23, leaf4]
    n01 = node_hash(leaves[0], leaves[1])
    n23 = node_hash(leaves[2], leaves[3])
    # Level 2: [node(n01, n23), leaf4]
    n0123 = node_hash(n01, n23)
    expected = node_hash(n0123, leaves[4])
    assert root == expected


def test_empty_batch_raises():
    with pytest.raises(ValueError):
        compute_batch_root([])


def test_merkle_proof_single():
    """Proof for single-receipt batch: empty path."""
    rh = _fake_receipt_hash(0)
    root = compute_batch_root([rh])
    assert verify_merkle_proof(rh, 0, [], root, batch_size=1)


def test_merkle_proof_two_receipts():
    """Proof for leaf 0 in two-receipt batch."""
    h0 = _fake_receipt_hash(0)
    h1 = _fake_receipt_hash(1)
    root = compute_batch_root([h0, h1])

    path = [{"position": "right", "hash": "sha256:" + leaf_hash(h1).hex()}]
    assert verify_merkle_proof(h0, 0, path, root, batch_size=2)


def test_merkle_proof_three_receipts_leaf0():
    """Proof for leaf 0 in three-receipt batch."""
    h0 = _fake_receipt_hash(0)
    h1 = _fake_receipt_hash(1)
    h2 = _fake_receipt_hash(2)
    root = compute_batch_root([h0, h1, h2])

    l1 = leaf_hash(h1)
    l2 = leaf_hash(h2)

    path = [
        {"position": "right", "hash": "sha256:" + l1.hex()},
        {"position": "right", "hash": "sha256:" + l2.hex()},
    ]
    assert verify_merkle_proof(h0, 0, path, root, batch_size=3)


def test_merkle_proof_wrong_sibling():
    """Proof with wrong sibling must fail."""
    h0 = _fake_receipt_hash(0)
    h1 = _fake_receipt_hash(1)
    root = compute_batch_root([h0, h1])

    wrong_hash = "sha256:" + ("aa" * 32)
    path = [{"position": "right", "hash": wrong_hash}]
    assert not verify_merkle_proof(h0, 0, path, root, batch_size=2)


class TestOddLeafPromotion:
    """Verify that odd-leaf promotion produces correct roots and
    verifiable proofs for trees where the promoted leaf's inclusion
    path depends on the promotion being correct.

    Tree shapes tested: 5 leaves (double promotion) and 7 leaves.
    """

    def test_five_leaf_root_matches_manual(self):
        hashes = [_fake_receipt_hash(i) for i in range(5)]
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n0123 = node_hash(n01, n23)
        root_expected = node_hash(n0123, leaves[4])
        assert compute_batch_root(hashes) == root_expected

    def test_five_leaf_proof_for_promoted_leaf4(self):
        hashes = [_fake_receipt_hash(i) for i in range(5)]
        root = compute_batch_root(hashes)
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n0123 = node_hash(n01, n23)
        path = [{"position": "left", "hash": "sha256:" + n0123.hex()}]
        assert verify_merkle_proof(hashes[4], 4, path, root, batch_size=5)

    def test_five_leaf_proof_for_leaf3(self):
        hashes = [_fake_receipt_hash(i) for i in range(5)]
        root = compute_batch_root(hashes)
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        path = [
            {"position": "left", "hash": "sha256:" + leaves[2].hex()},
            {"position": "left", "hash": "sha256:" + n01.hex()},
            {"position": "right", "hash": "sha256:" + leaves[4].hex()},
        ]
        assert verify_merkle_proof(hashes[3], 3, path, root, batch_size=5)

    def test_seven_leaf_root_matches_manual(self):
        hashes = [_fake_receipt_hash(i) for i in range(7)]
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n45 = node_hash(leaves[4], leaves[5])
        n0123 = node_hash(n01, n23)
        n456 = node_hash(n45, leaves[6])
        root_expected = node_hash(n0123, n456)
        assert compute_batch_root(hashes) == root_expected

    def test_seven_leaf_proof_for_promoted_leaf6(self):
        hashes = [_fake_receipt_hash(i) for i in range(7)]
        root = compute_batch_root(hashes)
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n45 = node_hash(leaves[4], leaves[5])
        n0123 = node_hash(n01, n23)
        path = [
            {"position": "left", "hash": "sha256:" + n45.hex()},
            {"position": "left", "hash": "sha256:" + n0123.hex()},
        ]
        assert verify_merkle_proof(hashes[6], 6, path, root, batch_size=7)

    def test_seven_leaf_proof_for_leaf5(self):
        hashes = [_fake_receipt_hash(i) for i in range(7)]
        root = compute_batch_root(hashes)
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n0123 = node_hash(n01, n23)
        path = [
            {"position": "left", "hash": "sha256:" + leaves[4].hex()},
            {"position": "right", "hash": "sha256:" + leaves[6].hex()},
            {"position": "left", "hash": "sha256:" + n0123.hex()},
        ]
        assert verify_merkle_proof(hashes[5], 5, path, root, batch_size=7)


class TestLeafIndexDirectionBinding:
    """Verify that wrong leaf_index is rejected when batch_size is provided,
    even when the hash-based proof would otherwise verify."""

    def test_wrong_leaf_index_rejected_3leaf(self):
        """leaf0 proof with leaf_index=1 on 3-leaf batch must FAIL."""
        h0 = _fake_receipt_hash(0)
        h1 = _fake_receipt_hash(1)
        h2 = _fake_receipt_hash(2)
        root = compute_batch_root([h0, h1, h2])
        l1 = leaf_hash(h1)
        l2 = leaf_hash(h2)
        # Correct path for leaf 0 (positions: right, right)
        path = [
            {"position": "right", "hash": "sha256:" + l1.hex()},
            {"position": "right", "hash": "sha256:" + l2.hex()},
        ]
        # Correct index passes
        assert verify_merkle_proof(h0, 0, path, root, batch_size=3)
        # Wrong index (1 expects left at level 0) must fail
        assert not verify_merkle_proof(h0, 1, path, root, batch_size=3)

    def test_wrong_leaf_index_rejected_5leaf(self):
        """leaf4 proof with leaf_index=0 on 5-leaf batch must FAIL."""
        hashes = [_fake_receipt_hash(i) for i in range(5)]
        root = compute_batch_root(hashes)
        leaves = [leaf_hash(h) for h in hashes]
        n01 = node_hash(leaves[0], leaves[1])
        n23 = node_hash(leaves[2], leaves[3])
        n0123 = node_hash(n01, n23)
        # Correct path for leaf 4 (promoted twice, sibling n0123 left)
        path = [{"position": "left", "hash": "sha256:" + n0123.hex()}]
        assert verify_merkle_proof(hashes[4], 4, path, root, batch_size=5)
        # Wrong index 0 expects right sibling at level 0, not left at level 2
        assert not verify_merkle_proof(hashes[4], 0, path, root, batch_size=5)

    def test_out_of_range_leaf_index(self):
        """leaf_index=999 on 3-leaf batch must FAIL."""
        h0 = _fake_receipt_hash(0)
        root = compute_batch_root([h0, _fake_receipt_hash(1), _fake_receipt_hash(2)])
        assert not verify_merkle_proof(h0, 999, [], root, batch_size=3)

    def test_extra_proof_steps_rejected(self):
        """Proof with more steps than needed must FAIL."""
        rh = _fake_receipt_hash(0)
        root = compute_batch_root([rh])
        extra_step = {"position": "right", "hash": "sha256:" + ("aa" * 32)}
        assert not verify_merkle_proof(rh, 0, [extra_step], root, batch_size=1)


class TestVerifyMerkleProofTypeGuards:
    """Defense-in-depth: verify_merkle_proof returns False (not raises)
    for every malformed-type input, even when the caller already validates."""

    def _valid_root(self):
        return compute_batch_root([_fake_receipt_hash(0)])

    def test_non_str_receipt_hash(self):
        assert verify_merkle_proof(12345, 0, [], self._valid_root(), batch_size=1) is False

    def test_non_int_leaf_index(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), "0", [], self._valid_root(), batch_size=1) is False

    def test_negative_leaf_index(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), -1, [], self._valid_root(), batch_size=1) is False

    def test_non_list_merkle_path(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, "bad", self._valid_root(), batch_size=1) is False

    def test_non_bytes_expected_root(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, [], "not-bytes", batch_size=1) is False

    def test_invalid_hex_receipt_hash(self):
        assert verify_merkle_proof("ZZZZ", 0, [], self._valid_root(), batch_size=1) is False

    def test_non_dict_step(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, ["bad"], self._valid_root(), batch_size=1) is False

    def test_step_missing_hash(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, [{"position": "left"}], self._valid_root(), batch_size=1) is False

    def test_step_bad_hex_hash(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, [{"position": "left", "hash": "ZZZZ"}], self._valid_root(), batch_size=1) is False

    def test_step_invalid_position(self):
        h = "sha256:" + leaf_hash(_fake_receipt_hash(0)).hex()
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, [{"position": "middle", "hash": h}], self._valid_root(), batch_size=1) is False

    def test_negative_batch_size(self):
        assert verify_merkle_proof(_fake_receipt_hash(0), 0, [], self._valid_root(), batch_size=-1) is False
