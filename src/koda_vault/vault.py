"""Credential Vault — the security foundation of Koda AI.

This is the primary interface for credential management. All other components
that need credentials go through this class.

Public API:
    vault.store(name, service, scopes, value) -> credential_id
    vault.retrieve(name, service, requested_by, required_scope?) -> decrypted_value
    vault.list() -> [metadata dicts, no values]
    vault.delete(name, service) -> bool

Security guarantees:
    - All values encrypted at rest with AES-256-GCM
    - Every access is audit-logged (success and failure)
    - Scope enforcement: must declare required scope to retrieve
    - Values never appear in logs, errors, or API responses
"""

from __future__ import annotations

import uuid
import json

from koda_vault.exceptions import CredentialNotFoundError, PermissionDeniedError, DecryptionError
from koda_vault.audit import AuditLogger
from koda_vault.encryption import AESGCMEncryptor, EncryptedPayload
from koda_vault.storage import VaultStorage


class CredentialVault:
    """Encrypted credential storage with audit logging and scope enforcement."""

    def __init__(
        self,
        storage: VaultStorage,
        encryption_key: bytes,
        audit: AuditLogger,
    ) -> None:
        """Initialize the vault.

        Args:
            storage: SQLite storage backend.
            encryption_key: 32-byte master key for AES-256-GCM.
            audit: Audit logger instance.
        """
        self._storage = storage
        self._key = encryption_key
        self._audit = audit
        self._encryptor = AESGCMEncryptor()

    def store(
        self,
        *,
        name: str,
        service: str,
        scopes: list[str],
        value: str,
    ) -> str:
        """Store an encrypted credential.

        Args:
            name: Human-readable name (e.g., "work-gmail").
            service: Service identifier (e.g., "gmail").
            scopes: Permission scopes (e.g., ["gmail:read", "gmail:send"]).
            value: The credential value to encrypt and store.

        Returns:
            Credential UUID.

        Raises:
            StorageError: If a credential with the same name+service exists.
            EncryptionError: If encryption fails.
        """
        cred_id = str(uuid.uuid4())

        # Encrypt the value — AAD binds ciphertext to this specific credential
        aad = self._identity_aad(name, service)
        payload = self._encryptor.encrypt(
            plaintext=value.encode("utf-8"),
            key=self._key,
            associated_data=aad,
        )

        # Store encrypted
        self._storage.insert_credential(
            id=cred_id,
            name=name,
            service=service,
            scopes=scopes,
            iv=payload.iv,
            ciphertext=payload.ciphertext,
            aad_version=2,
        )

        self._audit.log(
            action="store",
            credential_name=name,
            credential_service=service,
            accessed_by="vault.store",
            success=True,
        )

        return cred_id

    def retrieve(
        self,
        *,
        name: str,
        service: str,
        requested_by: str,
        required_scope: str | None = None,
    ) -> str:
        """Retrieve and decrypt a credential.

        Args:
            name: Credential name.
            service: Service identifier.
            requested_by: Name of the component/task requesting access (for audit).
            required_scope: If provided, the credential must have this scope.

        Returns:
            Decrypted credential value.

        Raises:
            CredentialNotFoundError: If the credential doesn't exist.
            PermissionDeniedError: If the required scope is missing.
            DecryptionError: If decryption or integrity check fails.
        """
        record = self._storage.get_credential(name, service)

        if record is None:
            self._audit.log(
                action="retrieve",
                credential_name=name,
                credential_service=service,
                accessed_by=requested_by,
                success=False,
                error_message="Credential not found",
            )
            raise CredentialNotFoundError(
                f"No credential found: '{name}' for service '{service}'"
            )

        # Scope enforcement
        if required_scope and required_scope not in record["scopes"]:
            self._audit.log(
                action="retrieve",
                credential_name=name,
                credential_service=service,
                accessed_by=requested_by,
                success=False,
                error_message=f"Missing required scope: {required_scope}",
            )
            raise PermissionDeniedError(
                f"Credential '{name}' lacks required scope: {required_scope}"
            )

        # No v1 fallback after a v2 authentication failure.
        try:
            version = record["aad_version"]
            if version == 1:
                if ":" in name or ":" in service:
                    raise DecryptionError(
                        "Ambiguous legacy credential identity; restore from a trusted source"
                    )
                aad = f"{name}:{service}".encode("utf-8")
            elif version == 2:
                aad = self._identity_aad(name, service)
            else:
                raise DecryptionError("Unsupported credential identity version")
            payload = EncryptedPayload(iv=record["iv"], ciphertext=record["ciphertext"])
            plaintext = self._encryptor.decrypt(payload, self._key, associated_data=aad)
            if version == 1:
                upgraded = self._encryptor.encrypt(plaintext, self._key, self._identity_aad(name, service))
                self._storage.upgrade_credential(record["id"], upgraded.iv, upgraded.ciphertext)
        except DecryptionError:
            self._audit.log(
                action="retrieve", credential_name=name, credential_service=service,
                accessed_by=requested_by, success=False,
                error_message="Credential integrity or decryption verification failed",
            )
            raise

        # Update access tracking
        self._storage.update_last_accessed(record["id"], requested_by)

        self._audit.log(
            action="retrieve",
            credential_name=name,
            credential_service=service,
            accessed_by=requested_by,
            success=True,
        )

        return plaintext.decode("utf-8")

    @staticmethod
    def _identity_aad(name: str, service: str) -> bytes:
        return json.dumps(["koda-vault", 2, name, service],
                          ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    def list(self) -> list[dict]:
        """List all credentials (metadata only, no values or scopes).

        Returns:
            List of dicts with: id, name, service, created_at, last_accessed.
        """
        self._audit.log(
            action="list",
            credential_name="*",
            credential_service="*",
            accessed_by="vault.list",
            success=True,
        )
        return self._storage.list_credentials()

    def delete(self, *, name: str, service: str) -> bool:
        """Delete a credential.

        Args:
            name: Credential name.
            service: Service identifier.

        Returns:
            True if deleted, False if not found.
        """
        success = self._storage.delete_credential(name, service)

        self._audit.log(
            action="delete",
            credential_name=name,
            credential_service=service,
            accessed_by="vault.delete",
            success=success,
            error_message=None if success else "Credential not found",
        )

        return success
