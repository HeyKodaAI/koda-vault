import sqlite3
import uuid
import pytest
from koda_vault import CredentialVault, VaultStorage, AuditLogger
from koda_vault.encryption import AESGCMEncryptor
from koda_vault.exceptions import DecryptionError


def setup(tmp_path):
    storage = VaultStorage(str(tmp_path / "vault.db"))
    return storage, CredentialVault(storage, bytes(32), AuditLogger(storage))


def test_colon_identities_cannot_be_reassigned(tmp_path):
    storage, vault = setup(tmp_path)
    vault.store(name="a:b", service="c", scopes=["read"], value="synthetic-value")
    assert vault.retrieve(name="a:b", service="c", requested_by="test") == "synthetic-value"
    with sqlite3.connect(storage.db_path) as conn:
        conn.execute("UPDATE credentials SET name='a',service='b:c'")
    with pytest.raises(DecryptionError):
        vault.retrieve(name="a", service="b:c", requested_by="test")


def legacy(storage, name, service):
    data = AESGCMEncryptor.encrypt(b"synthetic-value", bytes(32), f"{name}:{service}".encode())
    storage.insert_credential(id=str(uuid.uuid4()), name=name, service=service,
                              scopes=["read"], iv=data.iv, ciphertext=data.ciphertext)


def test_unambiguous_legacy_read_upgrades_and_reopens(tmp_path):
    storage, vault = setup(tmp_path)
    legacy(storage, "name", "service")
    assert storage.get_credential("name", "service")["aad_version"] == 1
    assert vault.retrieve(name="name", service="service", requested_by="test") == "synthetic-value"
    assert storage.get_credential("name", "service")["aad_version"] == 2
    storage = VaultStorage(storage.db_path)
    reopened = CredentialVault(storage, bytes(32), AuditLogger(storage))
    assert reopened.retrieve(name="name", service="service", requested_by="test") == "synthetic-value"


def test_ambiguous_legacy_identity_fails_closed_without_destroying_data(tmp_path):
    storage, vault = setup(tmp_path)
    legacy(storage, "a:b", "c")
    before = storage.get_credential("a:b", "c")["ciphertext"]
    with pytest.raises(DecryptionError, match="trusted source"):
        vault.retrieve(name="a:b", service="c", requested_by="test")
    assert storage.get_credential("a:b", "c")["ciphertext"] == before


@pytest.mark.parametrize("tamper", [False, True])
def test_failed_decryption_is_audited_without_secret(tmp_path, tamper):
    storage, vault = setup(tmp_path)
    vault.store(name="name", service="service", scopes=[], value="synthetic-value")
    if tamper:
        with sqlite3.connect(storage.db_path) as conn:
            conn.execute("UPDATE credentials SET ciphertext = ?", (b"corrupt",))
    else:
        vault = CredentialVault(storage, bytes([1]) * 32, AuditLogger(storage))
    before = len(storage.get_audit_entries())
    with pytest.raises(DecryptionError):
        vault.retrieve(name="name", service="service", requested_by="review")
    entries = storage.get_audit_entries()
    assert len(entries) == before + 1
    failed = [entry for entry in entries if not entry["success"]]
    assert failed[0]["accessed_by"] == "review"
    assert "synthetic-value" not in str(entries)


def test_schema_migration_adds_version_to_old_database(tmp_path):
    path = str(tmp_path / "old.db")
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE credentials (id TEXT PRIMARY KEY, name TEXT, service TEXT, scopes TEXT, iv BLOB, ciphertext BLOB, created_at TEXT, last_accessed TEXT, last_accessed_by TEXT, UNIQUE(name,service))")
    storage = VaultStorage(path)
    legacy(storage, "name", "service")
    assert storage.get_credential("name", "service")["aad_version"] == 1


def test_version_tampering_never_uses_legacy_fallback(tmp_path):
    storage, vault = setup(tmp_path)
    vault.store(name="name", service="service", scopes=[], value="synthetic-value")
    with sqlite3.connect(storage.db_path) as conn:
        conn.execute("UPDATE credentials SET aad_version=1")
    with pytest.raises(DecryptionError):
        vault.retrieve(name="name", service="service", requested_by="test")
