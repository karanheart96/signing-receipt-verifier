# TV-014: Large integer encoded as JSON number

seq is encoded as a JSON number (99999999999999) instead of a string.
Expected: receipt_integrity FAIL with INVALID_FIELD_TYPE.
The rule is type-level, not range-level.
