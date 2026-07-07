"""Strict JSON loader that rejects duplicate object keys."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DuplicateFieldError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateFieldError(f"duplicate JSON field: {key}")
        obj[key] = value
    return obj


def load_strict_json_file(path: str | Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_reject_duplicates)
