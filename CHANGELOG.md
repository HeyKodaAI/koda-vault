# Changelog

## 0.1.1 - 2026-09-07

- New records use a versioned JSON tuple for authenticated identity, so colons in names or services cannot create an identity collision. The database gains an `aad_version` column. (Review 6)
- Failed decryption/integrity checks record a sanitized failed retrieval audit event before raising. No plaintext or key material is included. (Review 15)

### Upgrade

Legacy records with colon-free name and service fields decrypt using v1 once and are upgraded to v2. A failed v2 decryption never falls back to v1. Legacy identities containing a colon are ambiguous and fail closed without modifying their ciphertext: restore those credentials under the intended identity from a trusted source. Do not bulk-rename or automatically relabel ambiguous encrypted records. Back up your encrypted database before upgrading; older package versions cannot read v2 records.

`requested_by` is audit metadata, not authentication. Scope checks validate a caller-declared required scope; hosts must authorize access to the vault object. The underlying AES-GCM and Argon2id primitives are unchanged.

### Validation

57 tests pass, including `tests/test_review_regressions.py`; main README quickstart checked. Tests use synthetic data and isolated databases. No live provider calls or service actions were used.
