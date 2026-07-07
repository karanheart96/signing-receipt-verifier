# TV-020: kid trailing whitespace

Receipt's sig.kid has trailing whitespace. The key set has kid without whitespace.
A verifier must NOT trim or normalize kid before key lookup.
Expected: receipt_integrity FAIL with KEY_NOT_FOUND.
