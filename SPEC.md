# Receipt Chain Verification Protocol v0.1

Draft spec review package  
Status: draft protocol specification
Status: internal technical review draft  
Date: May 10, 2026

## Status of this document

This document is a draft protocol specification for reviewing the minimum public verification surface of a receipt-chain system for pre-signature policy decisions in digital asset custody.

This is not a production wire format commitment. This is not an implementation commitment. This is not a publication claim, customer deployment claim, benchmark, or pilot result. The purpose of this draft is to make the verification model precise enough for technical review before any public open-source release.

The design goal is narrow: define how an independent verifier can check the integrity, signatures, sequence consistency, and external anchoring of receipt commitments without access to the operator's proprietary policy engine, receipt generator, or enforcement layer.

## Table of contents

- Scope and non-goals
- Normative language and dependencies
- Terminology
- Data model overview
- Canonicalization and encoding profile
- Immutable receipt envelope
- Request digest profile
- Policy version profile
- Key discovery, rotation, and revocation
- Hash-chain and sequence semantics
- Anchor proof object
- Merkle construction
- Verification semantics
- Error model and output format
- Threat model
- Test-vector corpus
- Review gate
- References

## Scope and non-goals

### In scope

This protocol specifies the externally reviewable verification surface for receipt chains. A conforming verifier should be able to:

- Parse receipt envelopes and anchor proofs.
- Canonicalize receipt bodies under the protocol's JSON profile.
- Recompute receipt hashes.
- Verify receipt signatures under published verification keys.
- Check hash-chain continuity within provided receipt sequences.
- Check sequence monotonicity and density within provided receipt ranges.
- Recompute Merkle batch roots.
- Verify Merkle inclusion proofs.
- Compare batch roots against disclosed anchor evidence.
- Report verification results by layer rather than returning one overloaded pass/fail result.

### Non-goals — what this protocol does NOT prove

This protocol does not prove that the underlying transaction was safe, authorized, or correct.

This protocol does not prove that the policy in force was adequate, complete, or commercially reasonable.

This protocol does not prove that no receipts were withheld or omitted. It can detect gaps only within disclosed material. Global non-omission requires disclosed checkpoints or full-range anchoring beyond what v0.1 mandates.

This protocol does not prove that an on-chain anchor commitment was actually published. The v0.1 verifier operates offline; an unverified `tx` field yields `INCONCLUSIVE`, not `PASS`.

This protocol does not verify the plaintext contents of a signing request unless the operator separately discloses the request object and its canonicalization profile.

This protocol does not define the operator's proprietary policy engine, enforcement path, transaction simulator, signer interface, or receipt-generation service.

This protocol does not generate receipts. It verifies receipt objects and related proof material.

This protocol does not prove that any customer deployment occurred, that any loss was prevented, that any insurer or regulator accepts the evidence, or that any empirical adoption threshold has been met.

### v0.1 design stance

The v0.1 protocol should prefer a small, correct, reviewable verification surface over a broad surface that accidentally exposes operator-internal policy logic or makes claims the verifier cannot actually prove.

The recommended v0.1 stance is:

- Receipts are immutable after signing.
- Anchor proofs are external to signed receipt bodies.
- Request digests are opaque commitments unless the request object is disclosed.
- Policy versions are opaque commitments unless the policy bundle is disclosed.
- Completeness claims are limited to disclosed sequence ranges, signed checkpoints, and anchored ranges.

## Normative language and dependencies

The words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL are used in their ordinary specification sense. This draft is not yet an IETF document, but it uses those terms to make implementation expectations unambiguous.

This draft references existing standards where possible:

- JSON Canonicalization Scheme, RFC 8785, for deterministic JSON canonicalization. RFC 8785 defines a canonical representation for JSON data intended for repeatable cryptographic operations such as hashing and signing ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)).
- RFC 3339 for timestamps. RFC 3339 defines an Internet date-time profile used for timestamp representation ([RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html)).
- JSON Web Signature, RFC 7515, for concepts including `alg`, `kid`, and base64url encoding without padding ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)).
- JSON Web Key, RFC 7517, for JSON representation of public verification keys and JWK sets ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)).
- RFC 8037 for EdDSA / Ed25519 representation in JOSE, if Ed25519 is selected as the mandatory-to-implement signature algorithm ([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)).
- Certificate Transparency, RFC 6962, as an architectural precedent for append-only logs and Merkle-root-based transparency systems, not as a direct dependency ([RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962)).

## Terminology

### Receipt

A receipt is an immutable signed decision record. It records that a signing request digest was evaluated against a policy version and resulted in an `approve` or `deny` decision.

### Receipt body

The receipt body is the canonicalized JSON object over which the receipt hash and signature are computed.

### Receipt envelope

The receipt envelope contains the receipt body plus signature metadata and signature value.

### Receipt hash

The receipt hash is the SHA-256 digest over the canonicalized receipt body. Unless otherwise specified, this protocol represents receipt hashes as `sha256:<lowercase_hex>`.

### Anchor proof

An anchor proof is external evidence that one or more receipt hashes were included in a batch commitment that was later anchored to an independently verifiable substrate.

### Checkpoint

A checkpoint is a signed statement over a tenant, sequence range, and batch root. Checkpoints are used to make range-level completeness claims more precise.

### Tenant

A tenant is the namespace for a receipt chain. It may represent an operator, custody environment, legal entity, or privacy-preserving tenant identifier.

### Request digest

The request digest is a cryptographic commitment to the signing request evaluated by policy. In v0.1, the verifier treats this as opaque unless the request object and request canonicalization profile are disclosed.

### Policy version

The policy version is a cryptographic commitment to the policy snapshot or policy bundle evaluated for the signing request. In v0.1, the verifier treats this as opaque unless the policy bundle and policy canonicalization profile are disclosed.

## Data model overview

The protocol separates three objects:

1. Receipt envelope.
2. Anchor proof.
3. Key set.

Receipts MUST remain immutable after signing. Anchor material MUST NOT be inserted into a signed receipt body after receipt creation. If anchor evidence is created later, it MUST live in a separate anchor proof object that references one or more receipt hashes.

This separation avoids the core mutability bug: if an `anchor_pointer` starts as `null` and is later filled in, the signed receipt hash changes unless the anchor field is excluded from the signed body. v0.1 avoids that ambiguity by keeping anchor proof material external.

## Canonicalization and encoding profile

### JSON canonicalization

Receipt bodies MUST be canonicalized before hashing and signing.

v0.1 uses RFC 8785 JCS as the baseline canonicalization scheme. JCS is useful here because it preserves JSON as the data model while providing deterministic bytes for cryptographic operations ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)).

### Additional v0.1 restrictions

The v0.1 profile is stricter than generic JSON:

- JSON objects MUST NOT contain duplicate property names.
- UTF-8 MUST be used.
- Floating-point values MUST NOT be used.
- Large integers MUST be represented as decimal strings.
- The fields `seq`, `range_start`, `range_end`, `block_number`, `leaf_index`, and `chain_id` MUST be strings if present.
- Hashes MUST be represented as `algorithm:<lowercase_hex>`.
- v0.1 supports `sha256:<lowercase_hex>` as the only required hash representation.
- Signatures SHOULD be represented as base64url without padding, following the base64url convention used in JWS ([RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)).
- Timestamps MUST use RFC 3339 UTC format with uppercase `T` and `Z`.
- v0.1 timestamps SHOULD use fixed millisecond precision, for example `2026-05-10T19:42:00.123Z`.
- Unknown fields in receipt bodies MUST cause verification failure in v0.1.

### Rationale for strict parsing

v0.1 chooses strict parsing, where unknown receipt body fields cause verification failure, over permissive parsing, where unknown fields are ignored.

This is intentional for two reasons.

First, strict parsing reduces verifier-disagreement attack surface. Permissive parsing allows an attacker who can influence receipt generation to add fields that a future verifier may interpret semantically but a v0.1 verifier ignores. That can cause two verifiers to reach different conclusions over the same receipt.

Second, strict parsing makes version changes explicit. Any change to the signed receipt body schema requires a `v` field bump. That makes schema changes visible in test vectors, version negotiation, implementation logs, and bug reports.

The cost is reduced forward compatibility. Purely additive fields cannot be introduced into the signed receipt body without a version break. v0.1 accepts that cost because cryptographic protocols benefit from change discipline more than they benefit from silent forward compatibility.

### Rationale for string integers

JCS uses ECMAScript-compatible number serialization and constrains JSON numeric data to values representable as IEEE 754 double-precision values; RFC 8785 recommends representing higher-precision or longer integer values as strings when needed ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)). v0.1 therefore encodes sequence numbers, block numbers, chain IDs, and similar values as strings to avoid cross-language precision differences.

`chain_id` MUST be a string even when a specific value would fit inside a JSON number. v0.1 intentionally avoids per-field or per-value encoding exceptions. Always-string encoding for `seq`, `range_start`, `range_end`, `block_number`, `leaf_index`, and `chain_id` gives implementers one uniform rule that survives format growth and avoids accidental narrowing by downstream parsers.

## Immutable receipt envelope

### Receipt body schema

The receipt body is the object that is canonicalized, hashed, and signed.

```json
{
  "v": "1",
  "tenant": "tenant_or_hash",
  "seq": "12345",
  "ts": "2026-05-10T19:42:00.123Z",
  "request_digest": "sha256:<hex>",
  "policy_version": "sha256:<hex>",
  "decision": "approve",
  "reasons": ["rule_id"],
  "prev_receipt": "sha256:<hex_or_genesis>"
}
```

### Field semantics

| Field | Required | Type | Semantics |
| --- | --- | --- | --- |
| `v` | Yes | string | Receipt schema version. v0.1 defines body version `"1"`. |
| `tenant` | Yes | string | Tenant namespace or privacy-preserving tenant identifier. |
| `seq` | Yes | decimal string | Monotonic per-tenant sequence number. |
| `ts` | Yes | string | RFC 3339 UTC timestamp. |
| `request_digest` | Yes | string | Opaque digest commitment to the signing request. |
| `policy_version` | Yes | string | Opaque digest commitment to the policy snapshot or bundle. |
| `decision` | Yes | string | MUST be `"approve"` or `"deny"` in v0.1. |
| `reasons` | Yes | array of strings | Stable rule IDs or reason codes. Empty array permitted for approvals. |
| `prev_receipt` | Yes | string | Previous receipt body hash or genesis marker. |

### Genesis receipt

The first receipt in a tenant chain MUST set `prev_receipt` to:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

This value is a protocol-level genesis marker, not the hash of an actual receipt body.

### Receipt envelope schema

The receipt envelope contains the immutable body and signature metadata.

```json
{
  "body": {
    "v": "1",
    "tenant": "tenant_or_hash",
    "seq": "12345",
    "ts": "2026-05-10T19:42:00.123Z",
    "request_digest": "sha256:<hex>",
    "policy_version": "sha256:<hex>",
    "decision": "approve",
    "reasons": ["rule_id"],
    "prev_receipt": "sha256:<hex_or_genesis>"
  },
  "sig": {
    "alg": "EdDSA",
    "kid": "tenant-key-2026-05",
    "value": "base64url_signature"
  }
}
```

### Signature input

The signature input MUST be the JCS-canonicalized byte representation of `body`.

The signature MUST NOT cover the `sig` object. A verifier MUST remove or ignore the `sig` object and verify only the canonicalized `body` against the declared signature algorithm and public key.

### Receipt hash

The receipt hash is:

```text
sha256(JCS(body))
```

The receipt hash representation is:

```text
sha256:<lowercase_hex_digest>
```

### Signature algorithm registry

v0.1 SHOULD define a small algorithm registry rather than hard-coding a single algorithm forever.

Recommended v0.1 registry:

| `alg` | Status | Notes |
| --- | --- | --- |
| `EdDSA` | Mandatory to implement | Ed25519 via JOSE / RFC 8037. |
| `ES256` | Optional | Useful for compatibility with existing JOSE tooling. |
| `RS256` | Optional | Familiar to enterprise systems but larger signatures and keys. |

If `EdDSA` is used, the key SHOULD be represented as an `OKP` JWK with curve `Ed25519`, consistent with RFC 8037's JOSE representation for Ed25519 ([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)).

## Request digest profile

### v0.1 stance

In v0.1, `request_digest` is an opaque commitment unless the operator discloses the signing request object and its canonicalization profile.

The verifier can verify that a receipt committed to a request digest at signing time. It cannot prove what the request meant unless the request object and schema are available.

### Optional disclosed request object

If an operator wants a verifier to recompute `request_digest`, it MAY provide a disclosed request object and a request canonicalization profile.

Minimum disclosed request fields, if used:

```json
{
  "v": "1",
  "chain_id": "8453",
  "asset": "native",
  "to": "0x...",
  "value": "1000000000000000000",
  "calldata_digest": "sha256:<hex>",
  "nonce": "123",
  "source": "internal_request_id_or_hash"
}
```

This optional object is deliberately not normative in v0.1. The review question is whether disclosing a request schema creates proprietary leakage or unnecessary scope expansion.

## Policy version profile

### v0.1 stance

In v0.1, `policy_version` is an opaque commitment.

The verifier can verify that a receipt references a specific committed policy identifier. It cannot prove the meaning, adequacy, or enforcement coverage of the policy unless the operator discloses the policy bundle and its canonicalization profile.

### Optional policy bundle

If an operator wants a verifier to recompute `policy_version`, it MAY provide a canonical policy bundle.

Potential future policy bundle shape:

```json
{
  "v": "1",
  "policy_language": "opaque|rego|cedar|custom",
  "bundle_digest": "sha256:<hex>",
  "rules": [
    {
      "id": "address_denylist",
      "digest": "sha256:<hex>"
    }
  ]
}
```

This optional policy bundle is out of scope for mandatory v0.1 verification.

## Key discovery, rotation, and revocation

### Key set

v0.1 SHOULD use a verification package that includes a static key set file. The key set SHOULD use a JWK Set shape because RFC 7517 defines JWK and JWK Set as JSON structures for representing cryptographic keys ([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)).

Example:

```json
{
  "tenant": "tenant_or_hash",
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "tenant-key-2026-05",
      "use": "sig",
      "alg": "EdDSA",
      "x": "base64url_public_key",
      "not_before": "2026-05-01T00:00:00.000Z",
      "not_after": "2026-06-01T00:00:00.000Z",
      "status": "active",
      "revocation_time": null
    }
  ]
}
```

### Key lookup

A verifier MUST map `tenant` + `kid` + `alg` to exactly one public verification key.

If no key is found, the verifier MUST return `KEY_NOT_FOUND`.

If more than one matching key is found, the verifier MUST return `AMBIGUOUS_KEY`.

If the key's algorithm is inconsistent with the receipt's declared `alg`, the verifier MUST return `KEY_ALGORITHM_MISMATCH`.

### Key rotation

Historical receipts MUST remain verifiable after rotation.

A key set SHOULD include validity windows. A receipt timestamp MUST fall within the selected key's validity window unless the verifier is operating in a mode that intentionally ignores time-window checks.

### Revocation

v0.1 distinguishes two revocation modes:

- `revoked_future_only`: historical receipts signed before revocation remain verifiable, but receipts after revocation fail.
- `revoked_all`: receipts under that key should not be trusted without additional operator explanation.

The key set SHOULD include a `status` field with one of:

- `active`
- `retired`
- `revoked_future_only`
- `revoked_all`

### Revocation timestamp semantics

Each key entry MUST include `revocation_time` if `status` is `revoked_future_only` or `revoked_all`.

If `status` is `active` or `retired`, `revocation_time` MUST be `null` or absent.

Verification order is:

1. Find the verification key by `tenant`, `kid`, and `alg`.
2. Check that the receipt timestamp falls within the key validity window, if `not_before` or `not_after` are present.
3. Apply revocation semantics.

For `revoked_future_only`, a receipt with `ts` strictly earlier than `revocation_time` MUST verify normally if all other checks pass. A receipt with `ts` greater than or equal to `revocation_time` MUST fail with `KEY_REVOKED`.

For `revoked_all`, any receipt under this key MUST fail with `KEY_REVOKED` regardless of receipt timestamp.

v0.1 does not mandate clock-skew tolerance. A verifier MAY report `INCONCLUSIVE` rather than `FAIL` for receipts within plus or minus five seconds of a revocation boundary, but it MUST disclose that behavior in its output. A verifier that does not implement clock-skew tolerance MUST apply the strict comparison rules above.

If a receipt timestamp falls outside the key's validity window, the verifier MUST fail with `KEY_NOT_VALID_AT_RECEIPT_TIME` even if the key is not revoked.

If a receipt uses a `kid` whose validity window starts after the receipt timestamp, the verifier MUST fail with `KEY_NOT_VALID_AT_RECEIPT_TIME`. This covers the case where a receipt appears to have been signed with a rotated-in key before that key became valid.

## Hash-chain and sequence semantics

### Per-tenant sequence

Each tenant chain MUST have a strictly increasing integer sequence encoded as a decimal string.

Within a disclosed continuous segment, sequence numbers MUST increase by exactly 1.

### Chain namespaces

v0.1 assumes one chain per `tenant`. If multiple chains per tenant are needed, the receipt body MUST add a `chain_id` or `stream_id` field before public release. Do not overload `tenant` to mean both legal operator and chain stream if multiple streams are expected.

### Previous receipt link

For any non-genesis receipt at sequence `n`, `prev_receipt` MUST equal the receipt hash of sequence `n - 1`.

The previous receipt link points to the previous receipt body hash, not the envelope hash. This keeps the chain commitment independent of signature encoding.

### Fork handling

If two receipts share the same `tenant` and `seq` but have different receipt hashes, the verifier MUST return `FORKED_SEQUENCE`.

If a receipt's `prev_receipt` points to a receipt not present in the provided segment and the verifier has not been given a checkpoint that bridges the gap, the verifier MUST return `MISSING_PREVIOUS_RECEIPT` or `INCOMPLETE_RANGE`.

## Anchor proof object

### Design principle

Anchor proofs are external to receipts.

Receipts are signed once and do not change. Anchor proofs may be generated later and may be stored, transmitted, or regenerated independently.

### Anchor proof schema

```json
{
  "v": "1",
  "tenant": "tenant_or_hash",
  "range_start": "12000",
  "range_end": "12999",
  "root_alg": "merkle-sha256-v1",
  "batch_root": "sha256:<hex>",
  "chain": "base",
  "chain_id": "8453",
  "tx": "0x...",
  "commitment_location": "calldata",
  "commitment_value": "sha256:<hex>",
  "proofs": [
    {
      "receipt_hash": "sha256:<hex>",
      "leaf_index": "123",
      "merkle_path": [
        {
          "position": "left",
          "hash": "sha256:<hex>"
        }
      ]
    }
  ]
}
```

### Field semantics

| Field | Required | Semantics |
| --- | --- | --- |
| `v` | Yes | Anchor proof schema version. |
| `tenant` | Yes | Tenant namespace covered by proof. |
| `range_start` | Yes | First sequence number in anchored batch. |
| `range_end` | Yes | Last sequence number in anchored batch. |
| `root_alg` | Yes | Merkle construction identifier. |
| `batch_root` | Yes | Computed Merkle root over batch leaves. |
| `chain` | Yes | Human-readable chain name. |
| `chain_id` | Yes | Chain ID as decimal string. |
| `tx` | Yes | Transaction identifier or equivalent anchor evidence pointer. |
| `commitment_location` | Yes | Where the commitment appears. |
| `commitment_value` | Yes | Root value asserted to be anchored. |
| `proofs` | Yes | One or more per-receipt inclusion proofs. |

### Offline and online verification

v0.1 SHOULD support offline verification of receipt integrity and Merkle inclusion.

Anchor transaction verification MAY be online or offline:

- Online mode: verifier queries the target chain and confirms that `commitment_value` appears in the referenced transaction.
- Offline mode: verification package includes independently obtained transaction evidence. v0.1 does not yet standardize the offline transaction evidence format.

If the verifier cannot check the referenced transaction, it MUST return `ANCHOR_UNCHECKED` for the anchor-validity layer rather than treating the entire receipt chain as invalid.

## Merkle construction

### Algorithm identifier

v0.1 defines:

```text
merkle-sha256-v1
```

### Leaf input

Each Merkle leaf commits to a receipt body hash.

Leaf hash:

```text
SHA256("BI_RECEIPT_LEAF_V1" || 0x00 || receipt_hash_bytes)
```

### Internal node hash

Internal node hash:

```text
SHA256("BI_RECEIPT_NODE_V1" || 0x00 || left_child_hash || right_child_hash)
```

### Ordering

Leaves MUST be ordered by ascending `seq`.

Leaves MUST NOT be sorted lexicographically by hash. Hash sorting would lose sequence semantics and weaken range-completeness interpretation.

### Odd leaf behavior

If a level has an odd number of nodes, the final node is promoted unchanged to the next level.

This choice MUST be reflected in test vectors. Implementers MUST NOT duplicate the final leaf unless a future version explicitly changes the construction.

### Duplicate handling

If the same receipt hash appears more than once in a batch, the verifier MUST return `DUPLICATE_RECEIPT_HASH`.

If the same sequence number appears more than once in a batch, the verifier MUST return `DUPLICATE_SEQUENCE`.

### Batch root

The final remaining node is the `batch_root`.

For a batch with exactly one receipt, the batch root is the leaf hash.

For an empty batch, no root is defined.

## Verification semantics

The verifier MUST report three layers independently:

1. Receipt integrity.
2. Anchor validity.
3. Completeness / no rollback.

The verifier MUST NOT collapse all layers into a single `valid` boolean.

### Layer 1: Receipt integrity

Layer 1 checks:

- Receipt JSON parses successfully.
- Receipt body has exactly the fields required for its version.
- Receipt body canonicalizes under the v0.1 profile.
- Receipt hash recomputes.
- Signature verifies under the declared key.
- `prev_receipt` links correctly within the provided segment.
- `seq` is monotonic and dense within the provided segment.
- `decision` is a supported value.
- `reasons` is an array of strings.

Layer 1 does not check whether the policy was good or whether the request was safe.

### Layer 2: Anchor validity

Layer 2 checks:

- Anchor proof JSON parses successfully.
- Anchor proof references the same tenant as the receipts.
- Receipt hash appears in the Merkle proof.
- Merkle path recomputes the claimed batch root.
- Batch root equals `commitment_value`.
- Referenced anchor transaction contains the commitment value, if online or offline transaction evidence is available.
- Anchor proof range covers the receipt sequence under review.

Layer 2 is `INCONCLUSIVE` when the receipt and Merkle proof are internally valid but the on-chain transaction has not been independently confirmed. In v0.1 offline mode, anchor validity is always `INCONCLUSIVE` or `FAIL` — never `PASS` — because v0.1 does not perform on-chain verification.

### Layer 3: Completeness / no rollback

Layer 3 checks:

- Provided sequence range is dense.
- Anchored ranges are internally consistent.
- Later checkpoints do not contradict earlier checkpoints.
- Overlapping ranges commit to the same receipt hashes for the same tenant and sequence numbers.

Layer 3 cannot prove global non-omission unless the protocol receives disclosed checkpoints or anchored ranges that make omission detectable.

### Completeness limitation

The phrase "no gaps" MUST be interpreted relative to disclosed material.

A verifier can verify that a provided range is dense. It cannot prove that no undisclosed receipt exists outside that range unless the operator has published range commitments, signed checkpoints, or another append-only consistency mechanism covering the relevant time interval.

## Error model and output format

### Status values

Each verification layer MUST return one of:

- `PASS`
- `FAIL`
- `INCONCLUSIVE`
- `UNSUPPORTED_VERSION`

### Error shape

```json
{
  "receipt_integrity": "PASS",
  "anchor_validity": "FAIL",
  "completeness": "INCONCLUSIVE",
  "errors": [
    {
      "code": "ANCHOR_ROOT_MISMATCH",
      "layer": "anchor_validity",
      "severity": "fatal",
      "message": "Computed batch root does not match anchored root."
    }
  ]
}
```

### Minimum error codes

| Code | Layer | Meaning |
| --- | --- | --- |
| `INVALID_JSON` | receipt_integrity | Input is not valid JSON. |
| `DUPLICATE_FIELD` | receipt_integrity | JSON object contains duplicate field names. |
| `UNSUPPORTED_RECEIPT_VERSION` | receipt_integrity | Receipt version is not supported. |
| `UNKNOWN_RECEIPT_FIELD` | receipt_integrity | Receipt body contains an unsupported field. |
| `CANONICALIZATION_FAILED` | receipt_integrity | Body cannot be canonicalized under profile. |
| `INVALID_HASH_FORMAT` | receipt_integrity | Hash does not match protocol encoding. |
| `RECEIPT_HASH_MISMATCH` | receipt_integrity | Recomputed hash differs from expected hash. |
| `KEY_NOT_FOUND` | receipt_integrity | No key matches tenant/kid/alg. |
| `AMBIGUOUS_KEY` | receipt_integrity | More than one key matches. |
| `KEY_ALGORITHM_MISMATCH` | receipt_integrity | Key is inconsistent with declared algorithm. |
| `KEY_REVOKED` | receipt_integrity | Receipt was signed under a key revoked for the receipt time. |
| `KEY_NOT_VALID_AT_RECEIPT_TIME` | receipt_integrity | Receipt timestamp falls outside the key validity window. |
| `KID_MISMATCH` | receipt_integrity | Key identifier does not exactly match any available key. |
| `SIGNATURE_INVALID` | receipt_integrity | Signature verification failed. |
| `SEQUENCE_GAP` | receipt_integrity | Provided sequence is not dense. |
| `DUPLICATE_SEQUENCE` | receipt_integrity | Duplicate sequence number appears. |
| `FORKED_SEQUENCE` | receipt_integrity | Same tenant and seq map to different receipt hashes. |
| `MISSING_PREVIOUS_RECEIPT` | receipt_integrity | Previous receipt is unavailable. |
| `INVALID_FIELD_TYPE` | receipt_integrity | Field exists but uses a prohibited JSON type. |
| `MISSING_REQUIRED_FIELD` | receipt_integrity | Required field is absent from receipt body. |
| `UNSUPPORTED_ALGORITHM` | receipt_integrity | Signature algorithm is not supported by the verifier. |
| `ANCHOR_PROOF_INVALID` | anchor_validity | Anchor proof is malformed. |
| `MERKLE_PATH_INVALID` | anchor_validity | Merkle path does not recompute root. |
| `ANCHOR_ROOT_MISMATCH` | anchor_validity | Computed root differs from commitment. |
| `ANCHOR_TX_NOT_FOUND` | anchor_validity | Referenced transaction cannot be found. |
| `ANCHOR_UNCHECKED` | anchor_validity | Transaction evidence unavailable. |
| `RANGE_NOT_COVERED` | completeness | Receipt seq is outside proof range. |
| `OVERLAPPING_RANGE_CONFLICT` | completeness | Two ranges contradict each other. |
| `COMPLETENESS_NOT_PROVABLE` | completeness | Provided evidence cannot support no-omission claim. |

## Threat model

### Verifier can provide evidence of

A conforming verifier can provide evidence that:

- Receipt bodies were not modified after signing, assuming signature keys were not compromised before signing.
- Signing keys were valid at the time indicated by the receipt timestamp, within the declared key lifecycle.
- Receipt sequence links are internally consistent within disclosed ranges.
- Receipt commitments were included in disclosed Merkle batches (Merkle binding to a provided root).
- Batch commitments match disclosed anchor evidence. Note: in v0.1 offline mode the verifier confirms internal consistency of the anchor proof but does not independently confirm on-chain publication.
- Tampering after anchoring is detectable if the tampered receipt affects a receipt hash, Merkle path, batch root, or anchored commitment.

### Verifier cannot prove by itself

A conforming verifier cannot prove:

- The underlying transaction was safe or authorized.
- The signing request displayed to a human matched the underlying transaction.
- The policy was complete, reasonable, or adequate.
- The policy engine evaluated the policy correctly.
- No undisclosed receipt exists unless range commitments or checkpoints support that claim.
- An on-chain anchor commitment was actually published (v0.1 is offline; unverified tx yields `INCONCLUSIVE`).
- A customer deployment occurred.
- A regulator, auditor, insurer, or court will accept the evidence.

### Key compromise

If a signing key is compromised, an attacker may be able to produce apparently valid receipts. Anchor timing, key validity windows, revocation status, and independent monitoring may help narrow exposure, but this protocol does not solve key compromise by itself.

### Malicious operator

A malicious operator may withhold receipts, refuse to disclose request contents, or publish incomplete verification packages. v0.1 can detect inconsistencies in disclosed material but cannot force disclosure.

### Incorrect policy

An incorrect policy can produce valid receipts for bad decisions. Receipt validity is not the same as decision correctness.

## Test-vector corpus

Phase 1.5 MUST include a minimal test-vector corpus before implementation.

Each test vector MUST include:

- Input receipt envelopes.
- Input key set.
- Anchor proof, if applicable.
- Expected layer-level output.
- Expected error codes.
- One sentence explaining the security property being tested.

### Required vectors

| ID | Name | Expected result |
| --- | --- | --- |
| TV-001 | Valid three-receipt chain, no anchor | Receipt integrity `PASS`; anchor validity `INCONCLUSIVE`; completeness `INCONCLUSIVE`. |
| TV-002 | Valid anchored batch with all receipts proven | Receipt integrity `PASS`; anchor validity `INCONCLUSIVE` (Merkle checks pass but tx is not independently verified in v0.1 offline mode); completeness depends on disclosed range. |
| TV-003 | Hash-chain break | Receipt integrity `FAIL`; `MISSING_PREVIOUS_RECEIPT` or `RECEIPT_HASH_MISMATCH`. |
| TV-004 | Invalid signature | Receipt integrity `FAIL`; `SIGNATURE_INVALID`. |
| TV-005 | Sequence gap | Receipt integrity `FAIL`; `SEQUENCE_GAP`. |
| TV-006 | Duplicate sequence number | Receipt integrity `FAIL`; `DUPLICATE_SEQUENCE`. |
| TV-007 | Forked sequence | Receipt integrity `FAIL`; `FORKED_SEQUENCE`. |
| TV-008 | Anchor root mismatch | Anchor validity `FAIL`; `ANCHOR_ROOT_MISMATCH`. |
| TV-009 | Merkle path mismatch | Anchor validity `FAIL`; `MERKLE_PATH_INVALID`. |
| TV-010 | Unknown algorithm | Receipt integrity `FAIL`; `KEY_ALGORITHM_MISMATCH` or `UNSUPPORTED_ALGORITHM`. |
| TV-011 | Key not found | Receipt integrity `FAIL`; `KEY_NOT_FOUND`. |
| TV-012 | Canonicalization edge: key ordering | Expected canonical bytes identical across languages. |
| TV-013 | Canonicalization edge: Unicode string | Expected canonical bytes preserve Unicode string content as required by JCS. |
| TV-014 | Canonicalization edge: large integer encoded as JSON number | Receipt integrity `FAIL`; `CANONICALIZATION_FAILED` or `INVALID_FIELD_TYPE`. |
| TV-015 | Unsupported receipt version | Receipt integrity `UNSUPPORTED_VERSION`. |
| TV-016 | Canonicalization adversarial: string escape forms | Python and Go expected canonical bytes match exactly for control characters, escaped characters, and equivalent JSON input forms. |
| TV-017 | Canonicalization adversarial: nested object key collation | Python and Go expected canonical bytes match exactly for nested objects with ASCII, multi-byte Unicode, and visually similar keys. |
| TV-018 | Strict field typing: `seq` encoded as JSON number | Receipt integrity `FAIL`; `INVALID_FIELD_TYPE` or `CANONICALIZATION_FAILED`. |
| TV-019 | Required empty array vs. missing field | `reasons: []` is valid for approval; omitted `reasons` fails with `MISSING_REQUIRED_FIELD`. |
| TV-020 | Key identifier trailing whitespace | `kid` with trailing whitespace MUST NOT match a key without trailing whitespace; expected `KEY_NOT_FOUND` or `KID_MISMATCH`. |

### Adversarial canonicalization vectors

TV-016 through TV-020 are required because canonical JSON protocols most often fail at language-boundary edges, not at ordinary object hashing.

TV-016 MUST include semantically equivalent JSON strings expressed with different escape forms where JSON permits more than one input representation. The expected output MUST specify the exact canonical bytes, not merely the expected parsed value.

TV-017 MUST include nested object keys that exercise Unicode collation. The expected output MUST include both Python-produced and Go-produced canonical bytes. Implementations MUST NOT rely on locale-aware sorting, UTF-8 byte sorting, or runtime-default map iteration.

TV-018 MUST encode `seq` as a JSON number, for example `"seq": 12345`, and MUST fail even if the numeric value would otherwise be representable safely. The rule is type-level, not range-level.

TV-019 MUST include one valid approval receipt with `"reasons": []` and one invalid approval receipt where `reasons` is omitted. The omitted-field case MUST fail because `reasons` is required in the signed receipt body.

TV-020 MUST include a receipt whose `sig.kid` contains trailing whitespace. A verifier MUST NOT trim or normalize `kid` before key lookup. Exact string comparison is required.

Each adversarial canonicalization vector MUST include:

- Raw JSON input.
- Expected canonical byte string as hex.
- Expected canonical byte string generated by a Python reference implementation.
- Expected canonical byte string generated by a Go reference implementation.
- Expected verification status and error code.
- One-sentence explanation of the portability bug the vector is designed to catch.

### Example test-vector directory shape

```text
test-vectors/
  TV-001-valid-chain-no-anchor/
    receipts.json
    keys.json
    expected.json
    README.md
  TV-002-valid-anchored-batch/
    receipts.json
    keys.json
    anchor-proof.json
    expected.json
    README.md
```

## Review gate

Do not proceed to a public repository or Python verifier until this draft answers the following questions cleanly:

- Is the receipt immutable after signing?
- Are anchor proofs external and reproducible?
- Can two independent engineers compute the same receipt hash from the same JSON?
- Are request-content verification and policy-content verification intentionally in or out of scope?
- Are key rotation and historical verification defined?
- Is no-gap/no-rollback phrased only as strongly as the protocol can actually prove?
- Are all test vectors understandable without access to operator-internal source code?
- Does the spec avoid implying customer deployment, customer adoption, loss prevention, or regulatory acceptance?

The go decision for implementation should require yes answers to every question above.

## Open decisions

The core v0.1 decisions are no longer parked here. EdDSA / Ed25519 is mandatory to implement, request digest verification is out of mandatory v0.1 unless the request object is disclosed, and policy bundle verification is out of mandatory v0.1 unless the policy bundle is disclosed.

### Offline chain evidence

Recommendation: mark offline transaction evidence as future work.

Reason: online verification is simpler for v0.1; standardizing offline transaction proofs can be added after the receipt and Merkle model stabilizes.

## References

- RFC 8785, JSON Canonicalization Scheme (JCS): https://www.rfc-editor.org/rfc/rfc8785
- RFC 3339, Date and Time on the Internet: Timestamps: https://www.rfc-editor.org/rfc/rfc3339.html
- RFC 7515, JSON Web Signature (JWS): https://datatracker.ietf.org/doc/html/rfc7515
- RFC 7517, JSON Web Key (JWK): https://datatracker.ietf.org/doc/html/rfc7517
- RFC 8037, CFRG ECDH and Signatures in JOSE: https://www.rfc-editor.org/rfc/rfc8037.html
- RFC 6962, Certificate Transparency: https://datatracker.ietf.org/doc/html/rfc6962
