"""Tests for the CredentialVault — the core security module."""

from __future__ import annotations

import pytest

from koda_vault.exceptions import CredentialNotFoundError, PermissionDeniedError, StorageError
from koda_vault.vault import CredentialVault


class TestVaultStore:
    """Tests for storing credentials."""

    def test_store_returns_uuid(self, vault: CredentialVault) -> None:
        """Storing a credential returns a UUID string."""
        cred_id = vault.store(
            name="test-key",
            service="gmail",
            scopes=["gmail:read"],
            value="ya29.abc123",
        )
        assert isinstance(cred_id, str)
        assert len(cred_id) == 36  # UUID format

    def test_store_duplicate_raises(self, vault: CredentialVault) -> None:
        """Storing a credential with the same name+service raises StorageError."""
        vault.store(name="api-key", service="slack", scopes=["slack:read"], value="xoxb-123")

        with pytest.raises(StorageError, match="already exists"):
            vault.store(name="api-key", service="slack", scopes=["slack:send"], value="xoxb-456")

    def test_store_same_name_different_service_ok(self, vault: CredentialVault) -> None:
        """Same name but different service is allowed."""
        id1 = vault.store(name="api-key", service="slack", scopes=["slack:read"], value="xoxb-123")
        id2 = vault.store(name="api-key", service="gmail", scopes=["gmail:read"], value="ya29-abc")
        assert id1 != id2


class TestVaultRetrieve:
    """Tests for retrieving credentials."""

    def test_retrieve_roundtrip(self, vault: CredentialVault) -> None:
        """Store and retrieve returns the original value."""
        original = "sk-ant-api03-very-secret-key"
        vault.store(name="claude", service="anthropic", scopes=["llm:query"], value=original)

        retrieved = vault.retrieve(
            name="claude",
            service="anthropic",
            requested_by="test_suite",
        )
        assert retrieved == original

    def test_retrieve_nonexistent_raises(self, vault: CredentialVault) -> None:
        """Retrieving a credential that doesn't exist raises CredentialNotFoundError."""
        with pytest.raises(CredentialNotFoundError):
            vault.retrieve(
                name="nonexistent",
                service="fake",
                requested_by="test_suite",
            )

    def test_retrieve_with_correct_scope(self, vault: CredentialVault) -> None:
        """Retrieval succeeds when required scope matches."""
        vault.store(
            name="token",
            service="gmail",
            scopes=["gmail:read", "gmail:send"],
            value="secret-token",
        )
        value = vault.retrieve(
            name="token",
            service="gmail",
            requested_by="email_sender",
            required_scope="gmail:send",
        )
        assert value == "secret-token"

    def test_retrieve_with_wrong_scope_raises(self, vault: CredentialVault) -> None:
        """Retrieval fails when required scope is not present."""
        vault.store(
            name="token",
            service="gmail",
            scopes=["gmail:read"],
            value="secret-token",
        )
        with pytest.raises(PermissionDeniedError, match="gmail:delete"):
            vault.retrieve(
                name="token",
                service="gmail",
                requested_by="email_deleter",
                required_scope="gmail:delete",
            )

    def test_retrieve_updates_last_accessed(self, vault: CredentialVault) -> None:
        """Retrieving updates the last_accessed timestamp."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")

        # Before retrieval, last_accessed should be None
        creds = vault.list()
        assert creds[0]["last_accessed"] is None

        # After retrieval, last_accessed should be set
        vault.retrieve(name="key", service="test", requested_by="checker")
        creds = vault.list()
        assert creds[0]["last_accessed"] is not None


class TestVaultList:
    """Tests for listing credentials."""

    def test_list_empty(self, vault: CredentialVault) -> None:
        """Empty vault returns empty list."""
        assert vault.list() == []

    def test_list_returns_metadata_only(self, vault: CredentialVault) -> None:
        """List returns metadata but never credential values."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="super-secret")
        creds = vault.list()

        assert len(creds) == 1
        assert creds[0]["name"] == "key"
        assert creds[0]["service"] == "test"
        # Value must NEVER be in the list response
        assert "value" not in creds[0]
        assert "ciphertext" not in creds[0]
        assert "iv" not in creds[0]
        # Scopes are also excluded from list (minimal info)
        assert "scopes" not in creds[0]

    def test_list_multiple(self, vault: CredentialVault) -> None:
        """Multiple credentials are listed."""
        vault.store(name="key1", service="s1", scopes=["custom:read"], value="v1")
        vault.store(name="key2", service="s2", scopes=["custom:read"], value="v2")
        vault.store(name="key3", service="s3", scopes=["custom:read"], value="v3")

        creds = vault.list()
        assert len(creds) == 3


class TestVaultDelete:
    """Tests for deleting credentials."""

    def test_delete_existing(self, vault: CredentialVault) -> None:
        """Deleting an existing credential returns True."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")
        assert vault.delete(name="key", service="test") is True
        assert vault.list() == []

    def test_delete_nonexistent(self, vault: CredentialVault) -> None:
        """Deleting a nonexistent credential returns False."""
        assert vault.delete(name="nope", service="fake") is False

    def test_deleted_credential_not_retrievable(self, vault: CredentialVault) -> None:
        """After deletion, the credential cannot be retrieved."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")
        vault.delete(name="key", service="test")

        with pytest.raises(CredentialNotFoundError):
            vault.retrieve(name="key", service="test", requested_by="test")


class TestVaultAudit:
    """Tests for audit trail."""

    def test_store_creates_audit_entry(self, vault: CredentialVault, storage) -> None:
        """Storing a credential creates an audit log entry."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")

        entries = storage.get_audit_entries(credential_name="key", credential_service="test")
        assert len(entries) == 1
        assert entries[0]["action"] == "store"
        assert entries[0]["success"] == 1

    def test_retrieve_creates_audit_entry(self, vault: CredentialVault, storage) -> None:
        """Retrieving a credential creates an audit log entry."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")
        vault.retrieve(name="key", service="test", requested_by="agent.email")

        entries = storage.get_audit_entries(credential_name="key", credential_service="test")
        # store + retrieve = 2 entries
        assert len(entries) == 2
        retrieve_entry = entries[0]  # Most recent first
        assert retrieve_entry["action"] == "retrieve"
        assert retrieve_entry["accessed_by"] == "agent.email"
        assert retrieve_entry["success"] == 1

    def test_failed_retrieve_creates_audit_entry(self, vault: CredentialVault, storage) -> None:
        """Failed retrieval (not found) is also audit-logged."""
        with pytest.raises(CredentialNotFoundError):
            vault.retrieve(name="missing", service="test", requested_by="agent")

        entries = storage.get_audit_entries(credential_name="missing")
        assert len(entries) == 1
        assert entries[0]["success"] == 0
        assert "not found" in entries[0]["error_message"].lower()

    def test_scope_violation_creates_audit_entry(self, vault: CredentialVault, storage) -> None:
        """Scope violation is audit-logged."""
        vault.store(name="key", service="test", scopes=["custom:read"], value="val")

        with pytest.raises(PermissionDeniedError):
            vault.retrieve(
                name="key",
                service="test",
                requested_by="attacker",
                required_scope="custom:admin",
            )

        entries = storage.get_audit_entries(credential_name="key", credential_service="test")
        failed_entries = [e for e in entries if not e["success"]]
        assert len(failed_entries) == 1
        assert "scope" in failed_entries[0]["error_message"].lower()
