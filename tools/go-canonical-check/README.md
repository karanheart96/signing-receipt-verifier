# Go Canonical Check

Independent Go-based canonicalization verification for Receipt Chain Verification Protocol v0.1 adversarial test vectors.

## Purpose

This tool provides a cross-language check that the Python verifier's canonical byte output matches an independent Go implementation for the four adversarial canonicalization vectors:

- TV-012: Canonical key ordering
- TV-013: Canonical Unicode string
- TV-016: String escape forms
- TV-017: Nested object key collation

## Usage

```bash
# From repo root
go run ./tools/go-canonical-check --repo-root .

# Or from any directory
go run ./tools/go-canonical-check --repo-root /path/to/receipt-chain-verifier
```

## What it does

1. Reads `receipts.json` from each vector directory.
2. Extracts the first receipt's `body` object.
3. Canonicalizes the body using a JCS-subset implementation (RFC 8785 key sorting by UTF-16 code units, minimal string escaping).
4. Hex-encodes the result.
5. Compares against `python_expected_canonical_hex` and `go_expected_canonical_hex` in `expected.json`.
6. Prints PASS/FAIL per vector and exits nonzero on any failure.

## Limitations

- This is NOT a complete RFC 8785 / JCS implementation.
- It covers only the subset needed for v0.1 test vectors.
- It uses Go's `encoding/json` for parsing, which decodes numbers as `float64`. Integer values within safe range are serialized without decimal points.
- It does not handle arbitrary JSON number precision beyond float64 range.
- Do not use this as a production canonicalizer without further review.
