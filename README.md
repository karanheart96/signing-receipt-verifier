# Receipt Chain Verification Protocol v0.1 — Starter Repository

**Status: Private draft technical review package**

## Important disclaimers

- This is a **private draft technical review package**.
- It is **not production-ready**.
- It is **not a customer deployment artifact**.
- It is **not evidence** of customer adoption, loss prevention, regulatory acceptance, or insurance acceptance.
- It verifies receipt-chain integrity properties only.
- It **does not** verify that the underlying transaction was safe.
- It **does not** verify that a policy was complete or commercially reasonable.
- It treats `request_digest` and `policy_version` as opaque commitments in v0.1.

## What this repository contains

1. `SPEC.md` — The Receipt Chain Verification Protocol v0.1 specification (normative source).
2. `test-vectors/` — Deterministic test vectors TV-001 through TV-020.
3. `verifier/` — A minimal Python verifier that passes those vectors.
4. `tests/` — pytest test suite covering all vectors, canonicalization, and Merkle construction.
5. `scripts/generate_vectors.py` — Deterministic test vector generator.

## What the verifier proves

The verifier evaluates three independent layers:

| Layer | What it proves |
|---|---|
| **Receipt integrity** | JSON structure is valid, body canonicalizes correctly, hash recomputes, signature verifies under the expected key, key was valid at signing time, sequence links are internally consistent within the disclosed segment |
| **Anchor validity** | Merkle inclusion proofs recompute the claimed batch root, batch root matches the disclosed commitment value. **The v0.1 verifier does not independently check the on-chain transaction** — if tx evidence is present but unverified, anchor validity is `INCONCLUSIVE`, not `PASS` |
| **Completeness** | Sequence density within disclosed ranges. Cannot prove global non-omission without disclosed checkpoints or full-range anchoring |

### Result model

The verifier reports each layer independently as one of:

| Status | Meaning |
|---|---|
| `PASS` | All checks for this layer succeeded |
| `FAIL` | One or more checks failed — evidence is inconsistent or malformed |
| `INCONCLUSIVE` | Checks that were performed passed, but a required external verification was not performed (e.g. on-chain anchor tx not independently confirmed in v0.1 offline mode) |
| `UNSUPPORTED_VERSION` | Receipt version is not supported by this verifier |

Results are never collapsed into a single boolean.

## What the verifier does NOT prove

- **Transaction safety:** the verifier does not prove that the underlying transaction was safe, authorized, or correct.
- **Policy adequacy:** the verifier does not prove that the policy in force was complete, reasonable, or commercially sufficient.
- **Completeness of disclosure:** the verifier does not prove that no receipts were withheld or omitted. It can only detect gaps within disclosed material.
- **On-chain anchor publication:** the v0.1 verifier operates offline and does not independently confirm that an anchor commitment was actually published on-chain. An unverified `tx` field yields `INCONCLUSIVE`, not `PASS`.
- **Customer deployment, regulatory acceptance, or loss prevention:** the verifier proves cryptographic consistency properties of disclosed evidence — nothing beyond that.
- **Request contents:** `request_digest` and `policy_version` are treated as opaque commitments unless the operator separately discloses the underlying objects.

## Requirements

- Python 3.11+
- Dependencies: `cryptography`, `pytest`

## Quick start

```bash
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Verify a test vector
python -m verifier.cli verify \
  --receipts test-vectors/TV-001-valid-chain-no-anchor/receipts.json \
  --keys test-vectors/TV-001-valid-chain-no-anchor/keys.json
```

## Limitations

**Canonicalization note:** the current Python canonicalizer is a v0.1 test-vector implementation sufficient for this draft protocol package. It should not be treated as a complete production RFC 8785/JCS implementation until independently reviewed.

**Completeness behavior:** the verifier reports `completeness: INCONCLUSIVE` unless the disclosed evidence is sufficient to prove range completeness. `INCONCLUSIVE` does not mean the receipt chain failed; it means the disclosed package does not prove global non-omission beyond the provided range and checkpoint evidence.

**Anchor validity behavior:** in v0.1 offline mode, the verifier checks Merkle proofs and batch root consistency but does not independently verify on-chain transaction publication. Even when all Merkle checks pass, `anchor_validity` is `INCONCLUSIVE` (not `PASS`) because the on-chain commitment is unconfirmed.

## CLI usage

```bash
python -m verifier.cli verify \
  --receipts <path-to-receipts.json> \
  --keys <path-to-keys.json> \
  [--anchor-proof <path-to-anchor-proof.json>]
```

The CLI prints a JSON verification result to stdout.

## Project structure

```
receipt-chain-verifier/
  README.md
  SPEC.md
  LICENSE
  SECURITY.md
  CITATION.cff
  pyproject.toml
  scripts/
    generate_vectors.py
  verifier/
    __init__.py
    canonical.py      # JCS-subset canonicalizer
    crypto.py          # Ed25519 signature verification
    merkle.py          # Merkle tree construction and proof verification
    models.py          # Data models and error codes
    verify.py          # Core verification logic
    cli.py             # Command-line interface
  tests/
    test_vectors.py    # Test vector verification
    test_canonical.py  # Canonicalization unit tests
    test_merkle.py     # Merkle construction unit tests
  test-vectors/
    TV-001-valid-chain-no-anchor/
    TV-002-valid-anchored-batch/
    ...
    TV-020-kid-trailing-whitespace/
```

## Publishing workflow

When ready to publish:

1. Start with a **private** GitHub repo.
2. Do **not** publish publicly until the spec, test vectors, and verifier have passed review.
3. Public release should happen only after tests pass, README has no overclaims, no operator-internal policy logic is disclosed, and at least one technical reviewer has reviewed the spec.

### Create private repo

```bash
cd receipt-chain-verifier
git init
git add .
git commit -m "Initial receipt chain verifier draft"
gh repo create receipt-chain-verifier --private --source=. --remote=origin --push
```

### Review checks

```bash
pytest
git status
```

### Add a reviewer

```text
Repo -> Settings -> Collaborators -> Add people
```

### Later public release (when ready)

```bash
gh repo edit receipt-chain-verifier --visibility public
```

**WARNING:** Do not run the public visibility command until:
- The protocol spec survives technical review.
- All test vectors pass.
- The README has been checked for unsupported claims.
- No operator-internal policy logic is disclosed.
- At least one technical reviewer (ideally cryptography-literate) has reviewed the spec.

## License

Apache-2.0. See [LICENSE](LICENSE).
