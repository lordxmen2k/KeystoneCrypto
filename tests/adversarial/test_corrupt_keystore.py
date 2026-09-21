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


def _build(password: str = "right") -> bytes:
    m = Mnemonic.from_phrase(ABANDON)
    return Keystore.create(m, password, params=_owasp_params()).blob


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
    blob = _build()
    bad = blob[:5] + b"\x99" + blob[6:]
    with pytest.raises(KeystoreVersionError):
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
    """Mutating kdf time_cost must produce a different key → fail."""
    blob = _build()
    tampered = bytearray(blob)
    # time_cost is the first 4 bytes of the kdf_params block (offset 6..10).
    tampered[6] ^= 0x01
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))
