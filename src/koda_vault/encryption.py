"""AES-256-GCM authenticated encryption primitives.

This module handles all symmetric encryption for the credential vault.
AES-256-GCM provides both confidentiality and integrity — if anyone tampers
with the ciphertext, decryption will fail with an authentication error.

Security properties:
- 256-bit key (32 bytes)
- 96-bit random IV/nonce per encryption (12 bytes) — never reused
- 128-bit authentication tag (16 bytes) — detects tampering
- Associated data support for binding ciphertext to metadata
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from koda_vault.exceptions import DecryptionError, EncryptionError

# Constants
KEY_SIZE = 32  # 256 bits
IV_SIZE = 12  # 96 bits (NIST recommended for GCM)
TAG_SIZE = 16  # 128 bits


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """Immutable container for encrypted data. Never contains plaintext."""

    iv: bytes
    ciphertext: bytes  # Includes GCM tag appended by cryptography library

    def __repr__(self) -> str:
        return f"EncryptedPayload(iv={len(self.iv)}B, ciphertext={len(self.ciphertext)}B)"


class AESGCMEncryptor:
    """Stateless AES-256-GCM encryption/decryption.

    Each encrypt() call generates a fresh random IV, ensuring nonce uniqueness.
    The GCM authentication tag is automatically appended to the ciphertext by
    the cryptography library and verified on decrypt().
    """

    @staticmethod
    def encrypt(
        plaintext: bytes,
        key: bytes,
        associated_data: bytes | None = None,
    ) -> EncryptedPayload:
        """Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            key: 32-byte (256-bit) encryption key.
            associated_data: Optional AAD bound to ciphertext (e.g., credential name).
                If provided at encryption, must be provided at decryption too.

        Returns:
            EncryptedPayload containing IV and ciphertext+tag.

        Raises:
            EncryptionError: If key is wrong size or encryption fails.
        """
        if len(key) != KEY_SIZE:
            raise EncryptionError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

        try:
            iv = secrets.token_bytes(IV_SIZE)
            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(iv, plaintext, associated_data)
            return EncryptedPayload(iv=iv, ciphertext=ciphertext)
        except Exception as e:
            raise EncryptionError("Encryption failed") from e

    @staticmethod
    def decrypt(
        payload: EncryptedPayload,
        key: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt an AES-256-GCM encrypted payload.

        Args:
            payload: EncryptedPayload from encrypt().
            key: 32-byte decryption key (same key used for encryption).
            associated_data: Must match the AAD used during encryption.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            DecryptionError: If key is wrong, data is tampered, or AAD mismatch.
        """
        if len(key) != KEY_SIZE:
            raise DecryptionError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

        try:
            cipher = AESGCM(key)
            return cipher.decrypt(payload.iv, payload.ciphertext, associated_data)
        except DecryptionError:
            raise
        except Exception as e:
            raise DecryptionError("Decryption failed: authentication verification failed") from e
