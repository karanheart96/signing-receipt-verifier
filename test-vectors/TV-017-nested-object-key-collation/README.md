# TV-017: Nested object key collation

Tests JCS key collation with multi-byte Unicode (accented Latin, CJK, emoji).
Expected: Python and Go produce identical canonical bytes using UTF-16 code unit sort.
Catches bugs where locale-aware or UTF-8 byte sorting is used instead of JCS.
