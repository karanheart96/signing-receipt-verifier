# TV-018: seq as JSON number

seq is encoded as JSON number 12345 instead of string "12345".
Expected: receipt_integrity FAIL with INVALID_FIELD_TYPE.
The rule is type-level: even safe-range integers must be strings.
