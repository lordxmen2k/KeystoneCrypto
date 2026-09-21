"""Versioned binary envelope for encrypted keystores."""

from __future__ import annotations

import pytest

from keystonecrypto.envelope import MAGIC, VERSION, Envelope, UnpackedKeystore
from keystonecrypto.exceptions import (
    KeystoreDecryptionError,
    KeystoreVersionError,
)
from keystonecrypto.kdf import (
    OWASP_MIN_MEMORY_KIB,
    OWASP_MIN_PARALLELISM,
    OWASP_MIN_TIME_COST,
    Argon2Params,
)
from keystonecrypto.secret_bytes import SecretBytes


def _owasp_params() -> Argon2Params:
    """OWASP-compliant profile so the public constructor accepts it."""
    return Argon2Params(
        time_cost=OWASP_MIN_TIME_COST,
        memory_cost=OWASP_MIN_MEMORY_KIB,
        parallelism=OWASP_MIN_PARALLELISM,
        hash_len=32,
    )


@pytest.fixture
def params() -> Argon2Params:
    return _owasp_params()


@pytest.fixture
def seed() -> SecretBytes:
    return SecretBytes(bytes(range(1, 33)))  # 32 bytes


def test_constants() -> None:
    assert MAGIC == b"KST1"
    assert VERSION == 1


def test_pack_unpack_roundtrip(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(
        seed, SecretBytes(b"correcthorsebattery"),
        params=params, has_passphrase=False, created_at=1700000000,
    )
    unpacked = Envelope.unpack(blob, SecretBytes(b"correcthorsebattery"))
    assert isinstance(unpacked, UnpackedKeystore)
    assert unpacked.seed == seed
    assert unpacked.has_passphrase is False
    assert unpacked.created_at == 1700000000


def test_unpack_wrong_password_fails(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, SecretBytes(b"right-password"), params=params)
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob, SecretBytes(b"wrong-password"))


def test_unpack_rejects_unknown_magic(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, SecretBytes(b"correcthorsebattery"), params=params)
    bad = b"XXXX" + blob[4:]
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))


def test_unpack_rejects_future_version(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, SecretBytes(b"correcthorsebattery"), params=params)
    # Bump version byte to 0x99 (offset 4).
    bad = bytes([blob[4] + 0x98]) + blob[5:]
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))


def test_unpack_rejects_truncated_blob(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, SecretBytes(b"correcthorsebattery"), params=params)
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob[:50], SecretBytes(b"correcthorsebattery"))


def test_aad_binds_kdf_id(params: Argon2Params, seed: SecretBytes) -> None:
    """Mutating the kdf_id must fail decryption (AAD check)."""
    blob = Envelope.pack(seed, SecretBytes(b"correcthorsebattery"),
                          params=params, kdf_id=1)
    # Flip kdf_id byte (offset 5) to 0x02.
    bad = blob[:5] + b"\x02" + blob[6:]
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))


def test_has_passphrase_flag_roundtrip(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, SecretBytes(b"correcthorsebattery"),
                          params=params, has_passphrase=True)
    unpacked = Envelope.unpack(blob, SecretBytes(b"correcthorsebattery"))
    assert unpacked.has_passphrase is True
