"""Minimal CLI for the Receipt Chain Verifier."""

from __future__ import annotations

import argparse
import json
import sys

from .models import ErrorCode, LayerStatus, Severity, VerificationResult
from .strict_json import DuplicateFieldError, load_strict_json_file
from .verify import verify


def _exit_with_parse_error(code: ErrorCode, layer: str, message: str) -> None:
    result = VerificationResult()
    if layer == "anchor_validity":
        result.anchor_validity = LayerStatus.FAIL
    else:
        result.receipt_integrity = LayerStatus.FAIL
    result.add_error(code, layer, Severity.FATAL, message)
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(1)


def _load_json_arg(path: str, layer: str):
    try:
        return load_strict_json_file(path)
    except DuplicateFieldError as exc:
        _exit_with_parse_error(ErrorCode.DUPLICATE_FIELD, layer, f"{path}: {exc}")
    except json.JSONDecodeError as exc:
        _exit_with_parse_error(ErrorCode.INVALID_JSON, layer, f"{path}: {exc.msg}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="receipt-verify",
        description="Receipt Chain Verification Protocol v0.1 verifier",
    )
    sub = parser.add_subparsers(dest="command")

    verify_cmd = sub.add_parser("verify", help="Verify receipts")
    verify_cmd.add_argument("--receipts", required=True, help="Path to receipts.json")
    verify_cmd.add_argument("--keys", required=True, help="Path to keys.json")
    verify_cmd.add_argument("--anchor-proof", default=None, help="Path to anchor-proof.json")

    args = parser.parse_args()

    if args.command != "verify":
        parser.print_help()
        sys.exit(1)

    receipts_data = _load_json_arg(args.receipts, "receipt_integrity")
    keys_data = _load_json_arg(args.keys, "receipt_integrity")

    anchor_proof_data = None
    if args.anchor_proof:
        anchor_proof_data = _load_json_arg(args.anchor_proof, "anchor_validity")

    result = verify(receipts_data, keys_data, anchor_proof_data)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
