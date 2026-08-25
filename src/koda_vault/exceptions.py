"""Custom exceptions for Koda AI. All exceptions are designed to never leak credential values."""


class KodaError(Exception):
    """Base exception for all Koda AI errors."""


class VaultError(KodaError):
    """Base exception for vault operations."""


class EncryptionError(VaultError):
    """Raised when encryption fails. Never includes key material in the message."""


class DecryptionError(VaultError):
    """Raised when decryption or authentication tag verification fails."""


class KeyDerivationError(VaultError):
    """Raised when master key derivation from passphrase fails."""


class CredentialNotFoundError(VaultError):
    """Raised when a requested credential does not exist."""


class PermissionDeniedError(VaultError):
    """Raised when a credential access lacks the required scope."""


class StorageError(VaultError):
    """Raised when the storage backend encounters an error."""


# ---------------------------------------------------------------------------
# Permission System Errors
# ---------------------------------------------------------------------------


class PermissionError(KodaError):
    """Base exception for permission operations."""


class ActionNotRegisteredError(PermissionError):
    """Raised when an action is not in the registry."""


class ScopeDeniedError(PermissionError):
    """Raised when the required scope is not enabled."""


class ApprovalRequiredError(PermissionError):
    """Raised when an action requires user approval before execution."""


class ApprovalDeniedError(PermissionError):
    """Raised when the user denied an approval request."""
