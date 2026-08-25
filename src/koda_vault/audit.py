"""Audit logging for credential vault access.

Every credential operation is logged to both the SQLite audit table and
the application logger. Credential values are NEVER included in any log output.

The audit trail records:
- What action was taken (store, retrieve, list, delete)
- Which credential was accessed (name + service, never the value)
- Who/what requested it (component name)
- Whether it succeeded
- Sanitized error message on failure
"""

from __future__ import annotations

import logging
import uuid

from koda_vault.storage import VaultStorage

logger = logging.getLogger("koda_vault.audit")


class AuditLogger:
    """Logs all credential access to persistent storage and application logger."""

    def __init__(self, storage: VaultStorage) -> None:
        self.storage = storage

    def log(
        self,
        *,
        action: str,
        credential_name: str,
        credential_service: str,
        accessed_by: str,
        success: bool,
        error_message: str | None = None,
    ) -> None:
        """Record a credential access event.

        Args:
            action: Operation type — "store", "retrieve", "list", "delete".
            credential_name: Name of the credential (safe to log).
            credential_service: Service identifier (safe to log).
            accessed_by: Component or task that requested access.
            success: Whether the operation succeeded.
            error_message: Sanitized error description (no key material).
        """
        entry_id = str(uuid.uuid4())

        # Persist to database
        self.storage.insert_audit_entry(
            id=entry_id,
            action=action,
            credential_name=credential_name,
            credential_service=credential_service,
            accessed_by=accessed_by,
            success=success,
            error_message=error_message,
        )

        # Structured application log
        log_data = {
            "audit_id": entry_id,
            "action": action,
            "credential": f"{credential_name}/{credential_service}",
            "accessed_by": accessed_by,
            "success": success,
        }

        if success:
            logger.info("Credential access: %s", log_data)
        else:
            log_data["error"] = error_message
            logger.debug("Credential access FAILED: %s", log_data)
