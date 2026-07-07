# TV-019: Empty array vs missing field

Receipt 1 has `reasons: []` (valid for approval).
Receipt 2 omits `reasons` entirely (invalid: required field missing).
Expected: receipt_integrity FAIL with MISSING_REQUIRED_FIELD.
