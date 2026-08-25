"""Koda AI Credential Vault — encrypted credential storage with audit logging."""

from .vault import CredentialVault
from .models import CredentialCreate, CredentialMeta, CredentialScope
from .encryption import AESGCMEncryptor
from .key_derivation import derive_master_key, verify_passphrase
from .audit import AuditLogger
from .storage import VaultStorage

__all__ = [
    "CredentialVault",
    "CredentialCreate",
    "CredentialMeta",
    "CredentialScope",
    "AESGCMEncryptor",
    "AuditLogger",
    "VaultStorage",
    "derive_master_key",
    "verify_passphrase",
]
