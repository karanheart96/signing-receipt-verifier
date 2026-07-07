"""Test that the Go canonical check tool passes if Go is installed."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
GO_TOOL_DIR = REPO_ROOT / "tools" / "go-canonical-check"


@pytest.fixture
def go_available():
    if shutil.which("go") is None:
        pytest.skip("Go is not installed")


def test_go_canonical_check(go_available):
    """Run the Go canonical check tool and assert it passes."""
    result = subprocess.run(
        ["go", "run", ".", "--repo-root", str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(GO_TOOL_DIR),
    )
    assert result.returncode == 0, (
        f"Go canonical check failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Verify all 4 vectors reported PASS
    for vec in [
        "TV-012-canonical-key-ordering",
        "TV-013-canonical-unicode-string",
        "TV-016-string-escape-forms",
        "TV-017-nested-object-key-collation",
    ]:
        assert f"PASS {vec}" in result.stdout, f"Expected PASS for {vec}"
