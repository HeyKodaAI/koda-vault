"""Security tests: verify credentials never leak through any channel.

These tests specifically check that credential values (API keys, tokens, etc.)
never appear in:
- API responses (list, error messages)
- Log output
- Exception messages
- String representations of objects
"""

from __future__ import annotations

import logging

import pytest

from koda_vault.exceptions import CredentialNotFoundError, PermissionDeniedError
from koda_vault.vault import CredentialVault


SECRET_VALUE = "sk-ant-api03-ULTRA-SECRET-KEY-NEVER-LEAK-THIS-12345abcdef"


@pytest.fixture
def vault_with_secret(vault: CredentialVault) -> CredentialVault:
    """Vault with a credential containing a known secret value."""
    vault.store(
        name="leak-test",
        service="anthropic",
        scopes=["llm:query"],
        value=SECRET_VALUE,
    )
    return vault


class TestNoLeakInResponses:
    """Ensure credential values never appear in any vault output."""

    def test_list_does_not_contain_value(self, vault_with_secret: CredentialVault) -> None:
        """List output never contains the credential value."""
        creds = vault_with_secret.list()
        serialized = str(creds)
        assert SECRET_VALUE not in serialized
        assert "ULTRA-SECRET" not in serialized

    def test_list_has_no_value_key(self, vault_with_secret: CredentialVault) -> None:
        """List output dicts have no 'value', 'ciphertext', or 'iv' keys."""
        creds = vault_with_secret.list()
        for cred in creds:
            assert "value" not in cred
            assert "ciphertext" not in cred
            assert "iv" not in cred


class TestNoLeakInExceptions:
    """Ensure exception messages never contain credential values."""

    def test_not_found_exception_is_clean(self, vault: CredentialVault) -> None:
        """CredentialNotFoundError message doesn't contain any value."""
        with pytest.raises(CredentialNotFoundError) as exc_info:
            vault.retrieve(name="nope", service="fake", requested_by="test")

        error_msg = str(exc_info.value)
        assert SECRET_VALUE not in error_msg

    def test_scope_violation_exception_is_clean(
        self, vault_with_secret: CredentialVault
    ) -> None:
        """PermissionDeniedError message doesn't contain the credential value."""
        with pytest.raises(PermissionDeniedError) as exc_info:
            vault_with_secret.retrieve(
                name="leak-test",
                service="anthropic",
                requested_by="attacker",
                required_scope="llm:admin",
            )

        error_msg = str(exc_info.value)
        assert SECRET_VALUE not in error_msg
        assert "ULTRA-SECRET" not in error_msg


class TestNoLeakInLogs:
    """Ensure credential values never appear in log output."""

    def test_store_log_is_clean(self, vault: CredentialVault, caplog) -> None:
        """Storing a credential doesn't log the value."""
        with caplog.at_level(logging.DEBUG, logger="koda"):
            vault.store(
                name="log-test",
                service="test",
                scopes=["custom:read"],
                value=SECRET_VALUE,
            )

        log_output = caplog.text
        assert SECRET_VALUE not in log_output
        assert "ULTRA-SECRET" not in log_output

    def test_retrieve_log_is_clean(self, vault: CredentialVault, caplog) -> None:
        """Retrieving a credential doesn't log the value."""
        vault.store(name="log-test", service="test", scopes=["custom:read"], value=SECRET_VALUE)

        with caplog.at_level(logging.DEBUG, logger="koda"):
            vault.retrieve(name="log-test", service="test", requested_by="agent")

        log_output = caplog.text
        assert SECRET_VALUE not in log_output
        assert "ULTRA-SECRET" not in log_output

    def test_failed_retrieve_log_is_clean(self, vault: CredentialVault, caplog) -> None:
        """Failed retrieval log doesn't contain any credential value."""
        with caplog.at_level(logging.DEBUG, logger="koda"):
            with pytest.raises(CredentialNotFoundError):
                vault.retrieve(name="nope", service="test", requested_by="agent")

        log_output = caplog.text
        assert SECRET_VALUE not in log_output


class TestNoLeakInAuditTrail:
    """Ensure audit trail entries never contain credential values."""

    def test_audit_entries_are_clean(self, vault_with_secret: CredentialVault, storage) -> None:
        """Audit log entries contain names/services but never values."""
        # Trigger a retrieve to create more audit entries
        vault_with_secret.retrieve(
            name="leak-test", service="anthropic", requested_by="audit-checker"
        )

        entries = storage.get_audit_entries()
        serialized = str(entries)
        assert SECRET_VALUE not in serialized
        assert "ULTRA-SECRET" not in serialized

        # Entries should contain safe metadata
        for entry in entries:
            assert "credential_name" in entry
            assert "action" in entry
            # No value fields
            assert "value" not in entry
            assert "ciphertext" not in entry
