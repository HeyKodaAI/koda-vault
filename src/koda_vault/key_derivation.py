"""Argon2id master key derivation from user passphrase.

Argon2id is the OWASP-recommended algorithm for password hashing and key derivation.
It combines Argon2i (memory-hard, side-channel resistant) and Argon2d (GPU-resistant)
for the strongest protection against both timing attacks and brute-force.

Parameters (OWASP recommended minimums):
- Memory: 64 MB — makes GPU/ASIC attacks expensive
- Iterations: 3 — balances security and login speed
- Parallelism: 4 — uses multiple CPU cores
- Output: 32 bytes (256-bit key for AES-256)
"""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher, Type
from argon2.exceptions import HashingError, VerifyMismatchError

from koda_vault.exceptions import KeyDerivationError

# Salt size for key derivation
SALT_SIZE = 16  # 128 bits


def derive_master_key(
    passphrase: str,
    salt: bytes | None = None,
    *,
    memory_cost: int = 65536,
    time_cost: int = 3,
    parallelism: int = 4,
    hash_len: int = 32,
) -> tuple[bytes, bytes]:
    """Derive a 256-bit master encryption key from a passphrase using Argon2id.

    Args:
        passphrase: User's master passphrase.
        salt: Optional salt bytes. If None, a random 16-byte salt is generated.
        memory_cost: Memory usage in KiB (default: 64 MB).
        time_cost: Number of iterations (default: 3).
        parallelism: Degree of parallelism (default: 4).
        hash_len: Output key length in bytes (default: 32 for AES-256).

    Returns:
        Tuple of (derived_key, salt). Save the salt for re-derivation on login.

    Raises:
        KeyDerivationError: If derivation fails.
    """
    if not passphrase:
        raise KeyDerivationError("Passphrase cannot be empty")

    if salt is None:
        salt = secrets.token_bytes(SALT_SIZE)

    try:
        # Use argon2-cffi's low-level API for raw key output
        from argon2.low_level import Type as LowType
        from argon2.low_level import hash_secret_raw

        key = hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=LowType.ID,  # Argon2id
        )
        return key, salt
    except Exception as e:
        raise KeyDerivationError("Master key derivation failed") from e


def hash_passphrase(
    passphrase: str,
    *,
    memory_cost: int = 65536,
    time_cost: int = 3,
    parallelism: int = 4,
) -> str:
    """Hash a passphrase for storage (login verification).

    This produces a full Argon2id hash string suitable for verify_passphrase().
    Different from derive_master_key — this is for authentication, not encryption.

    Args:
        passphrase: The passphrase to hash.

    Returns:
        Argon2id hash string (includes salt, params, and hash).

    Raises:
        KeyDerivationError: If hashing fails.
    """
    if not passphrase:
        raise KeyDerivationError("Passphrase cannot be empty")

    try:
        hasher = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
        return hasher.hash(passphrase)
    except HashingError as e:
        raise KeyDerivationError("Passphrase hashing failed") from e


def verify_passphrase(passphrase: str, stored_hash: str) -> bool:
    """Verify a passphrase against a stored Argon2id hash.

    Args:
        passphrase: The passphrase to verify.
        stored_hash: The hash string from hash_passphrase().

    Returns:
        True if the passphrase matches, False otherwise.
    """
    try:
        hasher = PasswordHasher()
        return hasher.verify(stored_hash, passphrase)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
