"""Test all 20 test vectors against the verifier."""

from __future__ import annotations

import filecmp
import json
import os
import tempfile
from pathlib import Path

import pytest

from verifier.verify import verify

VECTORS_DIR = Path(__file__).parent.parent / "test-vectors"

VECTOR_DIRS = sorted(VECTORS_DIR.iterdir())


def load_vector(vec_dir: Path) -> tuple[list, dict, dict | None, dict]:
    """Load receipts, keys, optional anchor proof, and expected results."""
    with open(vec_dir / "receipts.json") as f:
        receipts = json.load(f)
    with open(vec_dir / "keys.json") as f:
        keys = json.load(f)

    anchor_proof = None
    anchor_path = vec_dir / "anchor-proof.json"
    if anchor_path.exists():
        with open(anchor_path) as f:
            anchor_proof = json.load(f)

    with open(vec_dir / "expected.json") as f:
        expected = json.load(f)

    return receipts, keys, anchor_proof, expected


def _check_result(result, expected):
    """Check verification result against expected outcomes."""
    rd = result.to_dict()

    assert rd["receipt_integrity"] == expected["receipt_integrity"], (
        f"receipt_integrity: expected {expected['receipt_integrity']}, got {rd['receipt_integrity']}"
    )
    assert rd["anchor_validity"] == expected["anchor_validity"], (
        f"anchor_validity: expected {expected['anchor_validity']}, got {rd['anchor_validity']}"
    )
    assert rd["completeness"] == expected["completeness"], (
        f"completeness: expected {expected['completeness']}, got {rd['completeness']}"
    )

    # Check that all expected error codes appear
    actual_codes = {e["code"] for e in rd["errors"]}
    for code in expected.get("expected_errors", []):
        assert code in actual_codes, (
            f"Expected error code {code} not found. Actual codes: {actual_codes}"
        )


@pytest.mark.parametrize(
    "vec_dir",
    VECTOR_DIRS,
    ids=[d.name for d in VECTOR_DIRS],
)
def test_vector(vec_dir: Path):
    """Run each test vector through the verifier and check expected outcomes."""
    receipts, keys, anchor_proof, expected = load_vector(vec_dir)
    result = verify(receipts, keys, anchor_proof)
    _check_result(result, expected)


def test_all_vectors_present():
    """Ensure all 20 vector directories exist."""
    assert len(VECTOR_DIRS) == 20, f"Expected 20 vector dirs, found {len(VECTOR_DIRS)}"

    expected_prefixes = [f"TV-{i:03d}" for i in range(1, 21)]
    actual_prefixes = [d.name[:6] for d in VECTOR_DIRS]
    for prefix in expected_prefixes:
        assert prefix in actual_prefixes, f"Missing vector directory: {prefix}"


class TestGeneratorOutput:
    """Tests for the --output flag on generate_vectors.py."""

    def test_output_writes_to_custom_dir(self, tmp_path):
        """Running with --output <tmpdir> writes vectors into that dir."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from generate_vectors import generate_all

        out_dir = str(tmp_path / "custom-vectors")
        generate_all(out_dir)

        generated = sorted(Path(out_dir).iterdir())
        assert len(generated) == 20
        prefixes = [d.name[:6] for d in generated]
        for i in range(1, 21):
            assert f"TV-{i:03d}" in prefixes

    def test_output_does_not_modify_live_vectors(self, tmp_path):
        """Running with --output <tmpdir> must not touch repo test-vectors/."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from generate_vectors import generate_all

        # Snapshot mtimes of live test-vectors
        live_dir = Path(__file__).parent.parent / "test-vectors"
        before = {}
        for p in sorted(live_dir.rglob("*")):
            if p.is_file():
                before[str(p.relative_to(live_dir))] = p.stat().st_mtime_ns

        out_dir = str(tmp_path / "isolated-vectors")
        generate_all(out_dir)

        # Verify live dir is untouched
        after = {}
        for p in sorted(live_dir.rglob("*")):
            if p.is_file():
                after[str(p.relative_to(live_dir))] = p.stat().st_mtime_ns

        assert before == after, "Live test-vectors/ was modified by --output generation"

    def test_generated_vectors_are_deterministic(self, tmp_path):
        """Two runs produce identical output."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from generate_vectors import generate_all

        dir_a = str(tmp_path / "run-a")
        dir_b = str(tmp_path / "run-b")
        generate_all(dir_a)
        generate_all(dir_b)

        # Compare every file
        for tv_dir in sorted(Path(dir_a).iterdir()):
            for f in sorted(tv_dir.iterdir()):
                other = Path(dir_b) / tv_dir.name / f.name
                assert other.exists(), f"Missing in second run: {other}"
                assert f.read_bytes() == other.read_bytes(), (
                    f"Non-deterministic output: {tv_dir.name}/{f.name}"
                )
