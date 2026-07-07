# TV-016: String escape forms

Tests canonicalization of strings containing control characters and escape sequences.
Expected: Python and Go produce identical canonical bytes for tab, newline, quote, backslash, and null byte in reason strings.
Catches portability bugs in escape form normalization.
