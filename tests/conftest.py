"""Shared test fixtures for Koda AI test suite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from koda_vault.audit import AuditLogger
from koda_vault.encryption import AESGCMEncryptor
from koda_vault.key_derivation import derive_master_key
from koda_vault.storage import VaultStorage
from koda_vault.vault import CredentialVault


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    """Temporary SQLite database path."""
    return str(tmp_path / "test_vault.db")


@pytest.fixture
def master_key() -> bytes:
    """A test master key derived from a known passphrase."""
    key, _ = derive_master_key("test-passphrase-for-unit-tests", salt=b"fixed-test-salt!")
    return key


@pytest.fixture
def storage(tmp_db: str) -> VaultStorage:
    """Fresh VaultStorage instance with a temporary database."""
    return VaultStorage(tmp_db)


@pytest.fixture
def audit(storage: VaultStorage) -> AuditLogger:
    """AuditLogger instance backed by the test storage."""
    return AuditLogger(storage)


@pytest.fixture
def vault(storage: VaultStorage, master_key: bytes, audit: AuditLogger) -> CredentialVault:
    """Fully initialized CredentialVault for testing."""
    return CredentialVault(storage=storage, encryption_key=master_key, audit=audit)


@pytest.fixture
def encryptor() -> AESGCMEncryptor:
    """AESGCMEncryptor instance."""
    return AESGCMEncryptor()
