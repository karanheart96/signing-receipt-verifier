"""Merkle tree construction for merkle-sha256-v1.

Leaf: SHA256("BI_RECEIPT_LEAF_V1" || 0x00 || receipt_hash_bytes)
Node: SHA256("BI_RECEIPT_NODE_V1" || 0x00 || left || right)

Ordering: ascending seq. Odd leaf: promote unchanged (no duplication).
"""

from __future__ import annotations

import hashlib

LEAF_DOMAIN = b"BI_RECEIPT_LEAF_V1"
NODE_DOMAIN = b"BI_RECEIPT_NODE_V1"

VALID_POSITIONS = frozenset({"left", "right"})


def leaf_hash(receipt_hash_hex: str) -> bytes:
    """Compute a Merkle leaf hash from a receipt hash (hex string without prefix)."""
    receipt_bytes = bytes.fromhex(receipt_hash_hex)
    return hashlib.sha256(LEAF_DOMAIN + b"\x00" + receipt_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute a Merkle internal node hash."""
    return hashlib.sha256(NODE_DOMAIN + b"\x00" + left + right).digest()


def compute_batch_root(receipt_hashes_hex: list[str]) -> bytes:
    """Compute batch root from ordered receipt hashes (hex, no prefix).

    Leaves are ordered by ascending seq (caller must provide in order).
    Odd-count levels: promote final node unchanged.
    Single receipt: root = leaf hash.
    Empty: raises ValueError.
    """
    if not receipt_hashes_hex:
        raise ValueError("Cannot compute batch root for empty batch")

    level = [leaf_hash(h) for h in receipt_hashes_hex]

    while len(level) > 1:
        next_level = []
        i = 0
        while i < len(level):
            if i + 1 < len(level):
                next_level.append(node_hash(level[i], level[i + 1]))
                i += 2
            else:
                next_level.append(level[i])
                # i is at the last index of an odd-count level; any increment
                # >= 1 exits the while loop identically (equivalent mutant).
                i += 1
        level = next_level

    return level[0]


def verify_merkle_proof(
    receipt_hash_hex: str,
    leaf_index: int,
    merkle_path: list[dict],
    expected_root: bytes,
    batch_size: int = 0,
) -> bool:
    """Verify a Merkle inclusion proof.

    merkle_path: list of {"position": "left"|"right", "hash": "sha256:<hex>"}
    batch_size: total number of leaves in the batch.  When > 0 the proof
        direction at each level is validated against leaf_index parity and
        odd-leaf promotion is accounted for.  When 0 (legacy/direct calls)
        direction binding is skipped but hash verification still applies.
    Returns True if the path reconstructs the expected root.
    """
    if not isinstance(receipt_hash_hex, str):
        return False
    if not isinstance(leaf_index, int) or leaf_index < 0:
        return False
    if not isinstance(merkle_path, list):
        return False
    if not isinstance(expected_root, bytes):
        return False
    if not isinstance(batch_size, int) or batch_size < 0:
        return False
    if batch_size > 0 and leaf_index >= batch_size:
        return False

    try:
        current = leaf_hash(receipt_hash_hex)
    except (TypeError, ValueError):
        return False

    if batch_size > 0:
        # Direction-binding mode: walk the tree level by level, tracking
        # node_index and level_size to handle odd-leaf promotion correctly.
        node_index = leaf_index
        level_size = batch_size
        step_idx = 0

        while level_size > 1:
            # Odd-leaf promotion: last node at an odd-count level has no
            # sibling — it is promoted unchanged, consuming no proof step.
            if node_index == level_size - 1 and level_size % 2 == 1:
                node_index //= 2
                level_size = (level_size + 1) // 2
                continue

            if step_idx >= len(merkle_path):
                return False  # proof too short

            step = merkle_path[step_idx]
            step_idx += 1

            if not isinstance(step, dict):
                return False
            sibling_hex = step.get("hash")
            if not isinstance(sibling_hex, str):
                return False
            if sibling_hex.startswith("sha256:"):
                sibling_hex = sibling_hex[7:]
            try:
                sibling = bytes.fromhex(sibling_hex)
            except ValueError:
                return False

            position = step.get("position")
            expected_position = "left" if node_index % 2 == 1 else "right"
            if position != expected_position:
                return False

            if position == "left":
                current = node_hash(sibling, current)
            else:
                current = node_hash(current, sibling)

            node_index //= 2
            level_size = (level_size + 1) // 2

        # All proof steps must be consumed
        if step_idx != len(merkle_path):
            return False
    else:
        # Legacy mode (batch_size not provided): validate structure but
        # not direction binding.
        for step in merkle_path:
            if not isinstance(step, dict):
                return False

            sibling_hex = step.get("hash")
            if not isinstance(sibling_hex, str):
                return False
            if sibling_hex.startswith("sha256:"):
                sibling_hex = sibling_hex[7:]
            try:
                sibling = bytes.fromhex(sibling_hex)
            except ValueError:
                return False

            position = step.get("position")
            if position not in VALID_POSITIONS:
                return False

            if position == "left":
                current = node_hash(sibling, current)
            else:
                current = node_hash(current, sibling)

    return current == expected_root
