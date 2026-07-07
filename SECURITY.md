# Security Policy

## Status

This repository is a **private draft technical review package**. It is not production-ready.

## Reporting vulnerabilities

If you discover a security issue in the protocol specification or verifier implementation, please report it privately to the repository maintainers.

Do not open a public issue for security vulnerabilities.

## Scope

This verifier checks receipt-chain integrity properties only. It does not:

- Verify that the underlying transaction was safe.
- Verify that a policy was complete or commercially reasonable.
- Replace production security review.

## Cryptographic considerations

- The verifier uses Ed25519 (EdDSA) for signature verification.
- The canonicalizer implements a JCS-subset sufficient for test vectors but is **not a complete RFC 8785 implementation**.
- Test keys in this repository are deterministic and for testing only. They must never be used in any production context.
