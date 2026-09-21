"""Adversarial tests for the keystore envelope.

These tests target attackers who have obtained the keystore file and
try to decrypt it with modified bytes, downgrade attempts, or
malformed envelopes. Every case must fail closed.
"""

from __future__ import annotations

import pytest

from keystonecrypto.envelope import Envelope
from keystonecrypto.exceptions import (
    KeystoreDecryptionError,
    KeystoreVersionError,
    KeystoneCryptoError,
)
from keystonecrypto.kdf import (
    OWASP_MIN_MEMORY_KIB,
    OWASP_MIN_PARALLELISM,
    OWASP_MIN_TIME_COST,
    Argon2Params,
)
from keystonecrypto.keystore import Keystore
from keystonecrypto.mnemonic import Mnemonic
from keystonecrypto.secret_bytes import SecretBytes


ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _owasp_params() -> Argon2Params:
    return Argon2Params(
        time_cost=OWASP_MIN_TIME_COST,
        memory_cost=OWASP_MIN_MEMORY_KIB,
        parallelism=OWASP_MIN_PARALLELISM,
        hash_len=32,
    )


def _fast_params() -> Argon2Params:
    """Reduced Argon2 params for adversarial tests so the suite runs fast.
    These tests are about envelope integrity, not about Argon2 cost.
    Note: must be a multiple of 8 KiB to pass Argon2Params validation."""
    return Argon2Params.for_testing(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16,
    )


def _build(password: str = "right") -> bytes:
    m = Mnemonic.from_phrase(ABANDON)
    return Keystore.create(m, password, params=_fast_params()).blob


def test_truncated_blob_fails() -> None:
    blob = _build()
    with pytest.raises(KeystoneCryptoError):
        Envelope.unpack(blob[:30], SecretBytes(b"right"))


def test_flipped_magic_fails() -> None:
    blob = _build()
    bad = b"XXXX" + blob[4:]
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_version_downgrade_fails() -> None:
    blob = _build()
    bad = bytes([0x00]) + blob[1:]  # version 0
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_unknown_kdf_id_fails() -> None:
    """A modified kdf_id is caught by the AAD binding on AES-GCM."""
    blob = _build()
    bad = blob[:5] + b"\x99" + blob[6:]
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_tampered_ciphertext_fails() -> None:
    blob = _build()
    tampered = bytearray(blob)
    # Flip a byte deep in the ciphertext (just before the tag).
    tampered[-5] ^= 0xFF
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))


def test_wrong_password_fails() -> None:
    blob = _build(password="right")
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob, SecretBytes(b"wrong"))


def test_tampered_salt_fails() -> None:
    """Mutating the salt changes the derived key → decryption fails."""
    blob = _build()
    # Salt lives at offset 38..54.
    tampered = bytearray(blob)
    tampered[38] ^= 0x01
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))


def test_tampered_nonce_fails() -> None:
    """Mutating the nonce changes the AES-GCM IV → tag check fails."""
    blob = _build()
    tampered = bytearray(blob)
    tampered[55] ^= 0x01
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))


def test_tampered_kdf_params_fail() -> None:
    """Mutating kdf memory_cost (a low byte) must produce a different
    key → decryption fails. We mutate the LOW byte of memory_cost so
    the parameter stays in a small-but-valid range (avoiding infinite
    Argon2 loops from huge values).
    """
    blob = _build()
    tampered = bytearray(blob)
    # memory_cost is at offset 10..14 (big-endian uint32). Flip the
    # LOW byte (offset 13). For memory_cost=8, low byte is 0x08, flip
    # to 0x09. Argon2 runs with memory_cost=9 KiB (cheap) and produces
    # a different key, so AEAD tag check fails.
    tampered[13] ^= 0x01
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))
