# koda-vault

Encrypted credential storage for AI agents: AES-256-GCM at rest, Argon2id key derivation, scoped access, and a full audit trail.

## What & why

`koda_vault` is the credential vault extracted from [Koda AI](https://github.com/HeyKodaAI) — "the AI agent that never lies" — part of the Koda project by Mike Wandzilak / Wandzilak Web Design. Koda was built in reaction to agents that store passwords in plaintext config files; the vault is the security foundation that fixes that: every API key, token, and password an agent handles is encrypted before it touches disk, every access is logged, and decrypted values never appear in listings, logs, or error messages.

This package is the vault alone — a small, dependency-light library you can drop into any Python agent or backend. It has no FastAPI routes of its own; you wire `CredentialVault` into whatever surface you already have.

## Features

- **AES-256-GCM authenticated encryption** — 32-byte key, fresh random 96-bit IV per encryption, 128-bit auth tag. Tampered ciphertext fails to decrypt.
- **AAD binding** — ciphertext is bound to a versioned JSON tuple containing its name and service as associated data, so an encrypted blob cannot be swapped between credentials.
- **Argon2id key derivation** — master key derived from a passphrase with OWASP-recommended parameters (64 MB memory, 3 iterations, parallelism 4). Separate `hash_passphrase` / `verify_passphrase` helpers for login-style authentication.
- **Scope enforcement** — credentials declare scopes (e.g. `gmail:read`, `gmail:send`); a retrieval that declares a `required_scope` the credential lacks raises `PermissionDeniedError`.
- **Audit logging** — every store/retrieve/list/delete (success and failure) is recorded to a SQLite audit table plus the application logger, with the requesting component's name. Values are never logged.
- **Metadata-only listings** — `list()` and the Pydantic response models (`CredentialMeta`, `CredentialListItem`) intentionally have no value field.
- **SQLite storage** — WAL mode, schema auto-creates, `UNIQUE(name, service)`, thread-safe connection-per-operation. Designed to be swappable for PostgreSQL.

## Review fixes (0.1.1)

See [CHANGELOG.md](CHANGELOG.md) for fixes, compatibility changes and upgrade guidance.

## Install

Not yet on PyPI. Requires Python 3.11+.

```bash
pip install git+https://github.com/HeyKodaAI/koda-vault.git
```

Dependencies: `cryptography`, `argon2-cffi`, `pydantic`.

## Quickstart

```python
import os
import tempfile

from koda_vault import AuditLogger, CredentialVault, VaultStorage, derive_master_key

# 1. Derive a 256-bit master key from a passphrase (Argon2id).
#    Persist the salt — you need it to re-derive the same key next run.
key, salt = derive_master_key("correct horse battery staple")

# 2. Wire up storage, audit logging, and the vault.
db_path = os.path.join(tempfile.mkdtemp(), "vault.db")
storage = VaultStorage(db_path)
vault = CredentialVault(storage=storage, encryption_key=key, audit=AuditLogger(storage))

# 3. Store a credential (encrypted with AES-256-GCM before it touches disk).
vault.store(
    name="work-gmail",
    service="gmail",
    scopes=["gmail:read", "gmail:send"],
    value="ya29.example-oauth-token",
)

# 4. Retrieve it — the requested scope is checked and the caller label is audited.
token = vault.retrieve(
    name="work-gmail",
    service="gmail",
    requested_by="email-engine",
    required_scope="gmail:send",
)
print("retrieved:", token)

# 5. List returns metadata only — never values.
for meta in vault.list():
    print("stored:", meta["name"], "/", meta["service"])
```

Output:

```
retrieved: ya29.example-oauth-token
stored: work-gmail / gmail
```

## API overview

### `koda_vault.vault`
- **`CredentialVault(storage, encryption_key, audit)`** — the primary interface.
  - `store(*, name, service, scopes, value) -> str` — encrypts and stores, returns credential UUID.
  - `retrieve(*, name, service, requested_by, required_scope=None) -> str` — decrypts; raises `CredentialNotFoundError` / `PermissionDeniedError`; updates last-accessed tracking.
  - `list() -> list[dict]` — metadata only.
  - `delete(*, name, service) -> bool`

### `koda_vault.key_derivation`
- **`derive_master_key(passphrase, salt=None, ...) -> (key, salt)`** — raw 32-byte Argon2id key for AES-256.
- **`hash_passphrase(passphrase) -> str`** / **`verify_passphrase(passphrase, stored_hash) -> bool`** — Argon2id hashing for login verification (distinct from key derivation).

### `koda_vault.encryption`
- **`AESGCMEncryptor`** — stateless `encrypt(plaintext, key, associated_data)` / `decrypt(payload, key, associated_data)`.
- **`EncryptedPayload`** — frozen dataclass holding `iv` + `ciphertext` (tag appended); its `repr` shows only byte lengths.

### `koda_vault.audit` / `koda_vault.storage`
- **`AuditLogger(storage).log(...)`** — persists an audit entry and emits a structured log line.
- **`VaultStorage(db_path)`** — SQLite backend for encrypted blobs and the audit log.

### `koda_vault.models` / `koda_vault.exceptions`
- Pydantic models: `CredentialCreate`, `CredentialMeta`, `CredentialListItem`, and the `CredentialScope` enum (`gmail:read`, `github:write`, `shell:execute`, `custom:*`, ...).
- Exceptions all derive from `VaultError` and are written to never leak key material: `EncryptionError`, `DecryptionError`, `KeyDerivationError`, `CredentialNotFoundError`, `PermissionDeniedError`, `StorageError`.

## Testing

```bash
pip install -e . pytest pytest-asyncio
pytest
```

57 tests, including a dedicated no-credential-leakage suite (`tests/test_no_credential_leakage.py`).

## License

MIT — see [LICENSE](LICENSE).
