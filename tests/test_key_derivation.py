"""Tests for Argon2id key derivation."""

from __future__ import annotations

import pytest

from koda_vault.exceptions import KeyDerivationError
from koda_vault.key_derivation import derive_master_key, hash_passphrase, verify_passphrase


class TestDeriveKey:
    """Tests for master key derivation from passphrase."""

    def test_produces_32_byte_key(self) -> None:
        """Output key is exactly 32 bytes (256 bits) for AES-256."""
        key, salt = derive_master_key("test-passphrase")
        assert len(key) == 32

    def test_produces_16_byte_salt(self) -> None:
        """Auto-generated salt is 16 bytes (128 bits)."""
        key, salt = derive_master_key("test-passphrase")
        assert len(salt) == 16

    def test_same_passphrase_same_salt_same_key(self) -> None:
        """Same passphrase + salt always produces the same key (deterministic)."""
        salt = b"fixed-salt-16byt"
        key1, _ = derive_master_key("my-passphrase", salt=salt)
        key2, _ = derive_master_key("my-passphrase", salt=salt)
        assert key1 == key2

    def test_different_passphrase_different_key(self) -> None:
        """Different passphrases produce different keys."""
        salt = b"fixed-salt-16byt"
        key1, _ = derive_master_key("passphrase-one", salt=salt)
        key2, _ = derive_master_key("passphrase-two", salt=salt)
        assert key1 != key2

    def test_different_salt_different_key(self) -> None:
        """Same passphrase with different salts produces different keys."""
        key1, _ = derive_master_key("same-passphrase", salt=b"salt-one-16bytes")
        key2, _ = derive_master_key("same-passphrase", salt=b"salt-two-16bytes")
        assert key1 != key2

    def test_auto_generates_salt_when_none(self) -> None:
        """When no salt is provided, a random one is generated."""
        key1, salt1 = derive_master_key("test")
        key2, salt2 = derive_master_key("test")
        # Random salts should differ
        assert salt1 != salt2
        # Therefore keys should differ
        assert key1 != key2

    def test_empty_passphrase_raises(self) -> None:
        """Empty passphrase is rejected."""
        with pytest.raises(KeyDerivationError):
            derive_master_key("")

    def test_custom_parameters(self) -> None:
        """Custom Argon2id parameters produce a valid key."""
        key, salt = derive_master_key(
            "test",
            memory_cost=32768,  # 32 MB
            time_cost=2,
            parallelism=2,
            hash_len=32,
        )
        assert len(key) == 32


class TestPassphraseHash:
    """Tests for passphrase hashing and verification."""

    def test_hash_and_verify(self) -> None:
        """A hashed passphrase can be verified."""
        passphrase = "my-secure-passphrase"
        hashed = hash_passphrase(passphrase)
        assert verify_passphrase(passphrase, hashed) is True

    def test_wrong_passphrase_fails(self) -> None:
        """Wrong passphrase fails verification."""
        hashed = hash_passphrase("correct-passphrase")
        assert verify_passphrase("wrong-passphrase", hashed) is False

    def test_hash_contains_argon2id(self) -> None:
        """Hash string identifies as Argon2id."""
        hashed = hash_passphrase("test")
        assert "$argon2id$" in hashed

    def test_empty_passphrase_raises(self) -> None:
        """Empty passphrase is rejected."""
        with pytest.raises(KeyDerivationError):
            hash_passphrase("")
