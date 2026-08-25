"""Tests for AES-256-GCM encryption primitives."""

from __future__ import annotations

import secrets

import pytest

from koda_vault.exceptions import DecryptionError, EncryptionError
from koda_vault.encryption import AESGCMEncryptor, EncryptedPayload, KEY_SIZE, IV_SIZE


class TestAESGCMEncryptor:
    """Test suite for AES-256-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self, encryptor: AESGCMEncryptor) -> None:
        """Encrypted data can be decrypted back to the original plaintext."""
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = b"my-super-secret-api-key-12345"

        payload = encryptor.encrypt(plaintext, key)
        decrypted = encryptor.decrypt(payload, key)

        assert decrypted == plaintext

    def test_encrypt_produces_unique_iv_each_time(self, encryptor: AESGCMEncryptor) -> None:
        """Each encryption produces a different IV (nonce uniqueness)."""
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = b"same-plaintext"

        payload1 = encryptor.encrypt(plaintext, key)
        payload2 = encryptor.encrypt(plaintext, key)

        assert payload1.iv != payload2.iv
        assert payload1.ciphertext != payload2.ciphertext

    def test_iv_is_correct_size(self, encryptor: AESGCMEncryptor) -> None:
        """IV is exactly 12 bytes (96 bits) as NIST recommends for GCM."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"test", key)

        assert len(payload.iv) == IV_SIZE

    def test_wrong_key_fails_decryption(self, encryptor: AESGCMEncryptor) -> None:
        """Decryption with wrong key raises DecryptionError."""
        key1 = secrets.token_bytes(KEY_SIZE)
        key2 = secrets.token_bytes(KEY_SIZE)

        payload = encryptor.encrypt(b"secret", key1)

        with pytest.raises(DecryptionError):
            encryptor.decrypt(payload, key2)

    def test_tampered_ciphertext_fails(self, encryptor: AESGCMEncryptor) -> None:
        """Tampered ciphertext is detected by GCM authentication tag."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"secret", key)

        # Flip a byte in the ciphertext
        tampered = bytearray(payload.ciphertext)
        tampered[0] ^= 0xFF
        tampered_payload = EncryptedPayload(iv=payload.iv, ciphertext=bytes(tampered))

        with pytest.raises(DecryptionError):
            encryptor.decrypt(tampered_payload, key)

    def test_tampered_iv_fails(self, encryptor: AESGCMEncryptor) -> None:
        """Tampered IV is detected during decryption."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"secret", key)

        tampered_iv = bytearray(payload.iv)
        tampered_iv[0] ^= 0xFF
        tampered_payload = EncryptedPayload(iv=bytes(tampered_iv), ciphertext=payload.ciphertext)

        with pytest.raises(DecryptionError):
            encryptor.decrypt(tampered_payload, key)

    def test_wrong_key_size_encrypt_raises(self, encryptor: AESGCMEncryptor) -> None:
        """Keys that aren't 32 bytes are rejected."""
        bad_key = secrets.token_bytes(16)  # 128-bit instead of 256-bit

        with pytest.raises(EncryptionError):
            encryptor.encrypt(b"test", bad_key)

    def test_wrong_key_size_decrypt_raises(self, encryptor: AESGCMEncryptor) -> None:
        """Decryption rejects keys that aren't 32 bytes."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"test", key)
        bad_key = secrets.token_bytes(16)

        with pytest.raises(DecryptionError):
            encryptor.decrypt(payload, bad_key)

    def test_empty_plaintext(self, encryptor: AESGCMEncryptor) -> None:
        """Empty plaintext can be encrypted and decrypted."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"", key)
        decrypted = encryptor.decrypt(payload, key)

        assert decrypted == b""

    def test_large_plaintext(self, encryptor: AESGCMEncryptor) -> None:
        """Large payloads work correctly."""
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = secrets.token_bytes(10_000)

        payload = encryptor.encrypt(plaintext, key)
        decrypted = encryptor.decrypt(payload, key)

        assert decrypted == plaintext

    def test_associated_data_binds_ciphertext(self, encryptor: AESGCMEncryptor) -> None:
        """AAD must match between encrypt and decrypt."""
        key = secrets.token_bytes(KEY_SIZE)
        plaintext = b"secret"
        aad = b"credential:gmail"

        payload = encryptor.encrypt(plaintext, key, associated_data=aad)

        # Correct AAD works
        decrypted = encryptor.decrypt(payload, key, associated_data=aad)
        assert decrypted == plaintext

        # Wrong AAD fails
        with pytest.raises(DecryptionError):
            encryptor.decrypt(payload, key, associated_data=b"credential:slack")

        # Missing AAD fails
        with pytest.raises(DecryptionError):
            encryptor.decrypt(payload, key, associated_data=None)

    def test_payload_repr_does_not_leak_data(self, encryptor: AESGCMEncryptor) -> None:
        """EncryptedPayload repr shows sizes, not content."""
        key = secrets.token_bytes(KEY_SIZE)
        payload = encryptor.encrypt(b"super-secret-key", key)

        repr_str = repr(payload)
        assert "super-secret" not in repr_str
        assert "EncryptedPayload" in repr_str
