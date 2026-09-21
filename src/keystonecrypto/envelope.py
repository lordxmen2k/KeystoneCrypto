"""Binary envelope for encrypted keystores (spec §6).

Layout (big-endian, exact byte counts):

    Header (66 bytes):
        magic:        4   "KST1"
        version:      1   0x01
        kdf_id:       1   0x01 = Argon2id
        kdf_params:  32   (time_cost:4 | memory_cost:4 |
                           parallelism:4 | hash_len:4 |
                           version:4  | reserved:12)
        salt:        16
        nonce:       12
    Body (variable):
        ciphertext:  N    (includes appended 16-byte GCM tag)

Plaintext structure before encryption:

        seed_length:  1
        seed:         seed_length
        created_at:   8   (BE unix timestamp)
        flags:        1   (bit 0: has_passphrase)
        reserved:     6   (zero)

AAD = version || kdf_id. Decryption with mismatched AAD fails.
"""

from __future__ import annotations

import secrets as _secrets
import struct
import time
from typing import Final

from pydantic import BaseModel

from keystonecrypto.aead import NONCE_LEN, decrypt as _decrypt
from keystonecrypto.aead import encrypt as _encrypt
from keystonecrypto.exceptions import (
    KeystoreDecryptionError,
    KeystoreVersionError,
)
from keystonecrypto.kdf import Argon2Params, derive_key
from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "MAGIC",
    "VERSION",
    "Envelope",
    "UnpackedKeystore",
    "HEADER_LEN",
]

MAGIC:   Final[bytes] = b"KST1"
VERSION: Final[int]   = 1

_HEADER_LEN:        Final[int] = 4 + 1 + 1 + 32 + 16 + NONCE_LEN  # = 66
_GCM_TAG_LEN:       Final[int] = 16
_PLAINTEXT_OVERHEAD: Final[int] = 1 + 8 + 1 + 6                  # = 16 (excluding seed)

HEADER_LEN: Final[int] = _HEADER_LEN

# Offsets inside the header.
_OFF_MAGIC:    Final[int] = 0
_OFF_VERSION:  Final[int] = 4
_OFF_KDF_ID:   Final[int] = 5
_OFF_KDF:      Final[int] = 6
_OFF_SALT:     Final[int] = 38
_OFF_NONCE:    Final[int] = 54


class UnpackedKeystore(BaseModel):
    """Result of a successful envelope decryption."""

    model_config = {"frozen": True}

    seed:           SecretBytes
    has_passphrase: bool
    created_at:     int


class Envelope:
    """Static pack/unpack helpers for the keystore binary envelope."""

    @staticmethod
    def _pack_kdf_params(p: Argon2Params) -> bytes:
        return struct.pack(
            ">IIII I 12x",
            p.time_cost, p.memory_cost, p.parallelism, p.hash_len,
            p.version,
        )

    @staticmethod
    def _unpack_kdf_params(blob: bytes) -> Argon2Params:
        (t, m, par, hl, v) = struct.unpack(">IIIII", blob)
        return Argon2Params.for_testing(
            time_cost=t, memory_cost=m, parallelism=par,
            hash_len=hl, salt_len=16, version=v,
        )

    @staticmethod
    def _aad(version: int, kdf_id: int) -> bytes:
        return bytes([version, kdf_id])

    @staticmethod
    def pack(
        seed: SecretBytes,
        password: SecretBytes,
        params: Argon2Params,
        kdf_id: int = 1,
        has_passphrase: bool = False,
        created_at: int | None = None,
    ) -> bytes:
        """Pack and encrypt a seed into a keystore blob.

        The caller passes `password` here. If a BIP-39 passphrase is
        used, the caller is expected to concatenate it with the
        decryption password *before* calling pack; the envelope itself
        is passphrase-agnostic.
        """
        if kdf_id != 1:
            raise ValueError(f"unsupported kdf_id {kdf_id} (only 1 = Argon2id)")
        if len(seed) > 255:
            raise ValueError(f"seed too long: {len(seed)} > 255 bytes")
        if params.hash_len != 32:
            raise ValueError(f"envelope requires hash_len=32, got {params.hash_len}")

        salt = _secrets.token_bytes(params.salt_len)
        key, _salt = derive_key(password, params, salt=salt)
        ts = int(created_at if created_at is not None else time.time())
        flags = 0x01 if has_passphrase else 0x00
        plaintext = (
            bytes([len(seed)])
            + bytes(seed)
            + struct.pack(">q", ts)
            + bytes([flags])
            + b"\x00" * 6
        )
        nonce, ciphertext = _encrypt(key, plaintext, aad=Envelope._aad(VERSION, kdf_id))

        return (
            MAGIC
            + bytes([VERSION, kdf_id])
            + Envelope._pack_kdf_params(params)
            + salt
            + nonce
            + ciphertext
        )

    @staticmethod
    def unpack(blob: bytes, password: SecretBytes) -> UnpackedKeystore:
        """Decrypt and validate a keystore blob."""
        if len(blob) < _HEADER_LEN + _GCM_TAG_LEN:
            raise KeystoreDecryptionError(f"blob too short: {len(blob)} bytes")

        if blob[_OFF_MAGIC:_OFF_MAGIC + 4] != MAGIC:
            raise KeystoreVersionError("bad magic; not a keystonecrypto keystore")

        version = blob[_OFF_VERSION]
        if version != VERSION:
            raise KeystoreVersionError(
                f"unsupported keystore version {version}; "
                f"this build of keystonecrypto only supports version {VERSION}"
            )

        kdf_id = blob[_OFF_KDF_ID]
        if kdf_id != 1:
            raise KeystoreVersionError(f"unsupported kdf_id {kdf_id}")

        params = Envelope._unpack_kdf_params(blob[_OFF_KDF:_OFF_KDF + 32])
        if params.hash_len != _GCM_TAG_LEN + _GCM_TAG_LEN:
            pass  # hash_len != 32 will be caught at KDF time
        salt = blob[_OFF_SALT:_OFF_SALT + 16]
        nonce = blob[_OFF_NONCE:_OFF_NONCE + NONCE_LEN]
        ciphertext = blob[_HEADER_LEN:]

        key, _ = derive_key(password, params, salt=salt)

        try:
            plaintext = _decrypt(key, nonce, ciphertext,
                                 aad=Envelope._aad(version, kdf_id))
        except KeystoreDecryptionError:
            raise

        return Envelope._unpack_plaintext(plaintext)

    @staticmethod
    def _unpack_plaintext(plaintext: bytes) -> UnpackedKeystore:
        if len(plaintext) < 1 + 8 + 1 + 6:
            raise KeystoreDecryptionError("plaintext too short")
        seed_len = plaintext[0]
        if len(plaintext) < 1 + seed_len + 8 + 1 + 6:
            raise KeystoreDecryptionError("seed length inconsistent")
        seed = SecretBytes(plaintext[1:1 + seed_len])
        created_at = struct.unpack(">q", plaintext[1 + seed_len:1 + seed_len + 8])[0]
        flags = plaintext[1 + seed_len + 8]
        return UnpackedKeystore(
            seed=seed,
            has_passphrase=bool(flags & 0x01),
            created_at=created_at,
        )
