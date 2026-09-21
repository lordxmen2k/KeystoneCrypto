"""AES-256-GCM round-trip with associated data (AAD) for context binding."""

from __future__ import annotations

import pytest

from keystonecrypto.aead import KEY_LEN, NONCE_LEN, decrypt, encrypt
from keystonecrypto.exceptions import KeystoreDecryptionError
from keystonecrypto.secret_bytes import SecretBytes


def test_roundtrip_basic() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(key, b"hello world")
    assert decrypt(key, nonce, ct) == b"hello world"


def test_roundtrip_with_aad() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(key, b"payload", aad=b"context-v1")
    assert decrypt(key, nonce, ct, aad=b"context-v1") == b"payload"


def test_aad_mismatch_fails() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(key, b"payload", aad=b"context-v1")
    with pytest.raises(KeystoreDecryptionError):
        decrypt(key, nonce, ct, aad=b"context-v2")


def test_tampered_ciphertext_fails() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(key, b"payload")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(KeystoreDecryptionError):
        decrypt(key, nonce, bytes(tampered))


def test_wrong_key_fails() -> None:
    k1 = SecretBytes.random(KEY_LEN)
    k2 = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(k1, b"payload")
    with pytest.raises(KeystoreDecryptionError):
        decrypt(k2, nonce, ct)


def test_nonce_length_is_12_bytes() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, _ = encrypt(key, b"x")
    assert len(nonce) == NONCE_LEN


def test_key_must_be_32_bytes() -> None:
    with pytest.raises(ValueError):
        encrypt(SecretBytes(b"shortkey"), b"x")


def test_decrypt_rejects_wrong_nonce_length() -> None:
    key = SecretBytes.random(KEY_LEN)
    nonce, ct = encrypt(key, b"x")
    with pytest.raises(ValueError):
        decrypt(key, b"\x00" * 4, ct)
