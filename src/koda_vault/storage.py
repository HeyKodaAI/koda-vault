"""SQLite storage backend for the credential vault.

All credential values are stored encrypted — this layer never sees plaintext.
The storage layer handles CRUD operations on encrypted blobs and audit log entries.

Design notes:
- SQLite for portability (self-hosted single-user)
- Schema auto-creates on first connection
- Thread-safe via connection-per-operation pattern
- Easily replaceable with PostgreSQL for hosted version
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from koda_vault.exceptions import StorageError


class VaultStorage:
    """SQLite backend for credential and audit storage."""

    def __init__(self, db_path: str) -> None:
        """Initialize storage, creating the database and tables if needed.

        Args:
            db_path: Path to SQLite database file. Parent directory must exist.
        """
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a new database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent read performance
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    service TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    iv BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    last_accessed TEXT,
                    last_accessed_by TEXT,
                    UNIQUE(name, service)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    credential_name TEXT NOT NULL,
                    credential_service TEXT NOT NULL,
                    accessed_by TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    error_message TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                    ON audit_log(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_credential
                    ON audit_log(credential_name, credential_service);
                CREATE INDEX IF NOT EXISTS idx_cred_service
                    ON credentials(service);
            """)

    def insert_credential(
        self,
        *,
        id: str,
        name: str,
        service: str,
        scopes: list[str],
        iv: bytes,
        ciphertext: bytes,
    ) -> None:
        """Insert a new encrypted credential.

        Args:
            id: UUID for the credential.
            name: Human-readable name.
            service: Service identifier.
            scopes: Permission scopes (stored as JSON).
            iv: Encryption IV/nonce.
            ciphertext: Encrypted credential value (includes GCM tag).

        Raises:
            StorageError: If insert fails (e.g., duplicate name+service).
        """
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """INSERT INTO credentials (id, name, service, scopes, iv, ciphertext, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        id,
                        name,
                        service,
                        json.dumps(scopes),
                        iv,
                        ciphertext,
                        _utc_now_iso(),
                    ),
                )
        except sqlite3.IntegrityError as e:
            raise StorageError(
                f"Credential '{name}' for service '{service}' already exists"
            ) from e
        except sqlite3.Error as e:
            raise StorageError("Failed to store credential") from e

    def get_credential(self, name: str, service: str) -> dict[str, Any] | None:
        """Retrieve a credential record by name and service.

        Returns:
            Dict with keys: id, name, service, scopes, iv, ciphertext,
            created_at, last_accessed, last_accessed_by. Or None if not found.
        """
        try:
            with self._get_connection() as conn:
                row = conn.execute(
                    """SELECT id, name, service, scopes, iv, ciphertext,
                              created_at, last_accessed, last_accessed_by
                    FROM credentials WHERE name = ? AND service = ?""",
                    (name, service),
                ).fetchone()

                if row is None:
                    return None

                result = dict(row)
                result["scopes"] = json.loads(result["scopes"])
                return result
        except sqlite3.Error as e:
            raise StorageError("Failed to retrieve credential") from e

    def list_credentials(self) -> list[dict[str, Any]]:
        """List all credential metadata (no encrypted data, no scopes).

        Returns:
            List of dicts with: id, name, service, created_at, last_accessed.
        """
        try:
            with self._get_connection() as conn:
                rows = conn.execute(
                    """SELECT id, name, service, created_at, last_accessed
                    FROM credentials ORDER BY created_at DESC"""
                ).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            raise StorageError("Failed to list credentials") from e

    def delete_credential(self, name: str, service: str) -> bool:
        """Delete a credential. Returns True if a row was deleted."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "DELETE FROM credentials WHERE name = ? AND service = ?",
                    (name, service),
                )
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise StorageError("Failed to delete credential") from e

    def update_last_accessed(self, credential_id: str, accessed_by: str) -> None:
        """Update the last_accessed timestamp and accessor."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """UPDATE credentials
                    SET last_accessed = ?, last_accessed_by = ?
                    WHERE id = ?""",
                    (_utc_now_iso(), accessed_by, credential_id),
                )
        except sqlite3.Error as e:
            raise StorageError("Failed to update access timestamp") from e

    def insert_audit_entry(
        self,
        *,
        id: str,
        action: str,
        credential_name: str,
        credential_service: str,
        accessed_by: str,
        success: bool,
        error_message: str | None = None,
    ) -> None:
        """Insert an audit log entry."""
        try:
            with self._get_connection() as conn:
                conn.execute(
                    """INSERT INTO audit_log
                    (id, timestamp, action, credential_name, credential_service,
                     accessed_by, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        id,
                        _utc_now_iso(),
                        action,
                        credential_name,
                        credential_service,
                        accessed_by,
                        1 if success else 0,
                        error_message,
                    ),
                )
        except sqlite3.Error:
            # Audit logging should not crash the application
            pass

    def get_audit_entries(
        self,
        *,
        credential_name: str | None = None,
        credential_service: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Retrieve audit log entries with optional filtering."""
        try:
            with self._get_connection() as conn:
                query = "SELECT * FROM audit_log"
                params: list[Any] = []
                conditions: list[str] = []

                if credential_name:
                    conditions.append("credential_name = ?")
                    params.append(credential_name)
                if credential_service:
                    conditions.append("credential_service = ?")
                    params.append(credential_service)

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)

                rows = conn.execute(query, params).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as e:
            raise StorageError("Failed to retrieve audit entries") from e


def _utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()
