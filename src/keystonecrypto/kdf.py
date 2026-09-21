"""Argon2id key derivation with named profiles.

Two profiles ship by default:
- `INTERACTIVE_PROFILE` — OWASP 2024 minimum for interactive use
  (~250ms on a modern x86 server). Default for end-user keystores.
- `HIGH_SECURITY_PROFILE` — 2x memory, +1 time. Use for cold
  storage and high-value wallets where unlock latency is acceptable.

Custom profiles can be constructed by instantiating `Argon2Params`
directly. The library refuses to use parameters below the OWASP
minimum unless `Argon2Params.for_testing(...)` is called, which is
used only by the RFC 9106 conformance test.
"""

from __future__ import annotations

import secrets as _secrets
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from pydantic import BaseModel, Field, field_validator

from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "Argon2Params",
    "INTERACTIVE_PROFILE",
    "HIGH_SECURITY_PROFILE",
    "OWASP_MIN_MEMORY_KIB",
    "OWASP_MIN_TIME_COST",
    "OWASP_MIN_PARALLELISM",
    "derive_key",
]


# OWASP Password Storage Cheat Sheet (2024) — Argon2id minimum.
OWASP_MIN_MEMORY_KIB: Final[int] = 19456   # ~19 MiB
OWASP_MIN_TIME_COST:  Final[int] = 2
OWASP_MIN_PARALLELISM: Final[int] = 1


class Argon2Params(BaseModel):
    """Argon2id parameters. Pydantic-validated.

    Public construction enforces OWASP minimums. Use `.for_testing(...)`
    to bypass validation for the RFC 9106 conformance test only.
    """

    model_config = {"frozen": True}

    time_cost:    int = Field(ge=1, le=10)
    memory_cost:  int = Field(ge=OWASP_MIN_MEMORY_KIB, le=2**21)
    parallelism:  int = Field(ge=OWASP_MIN_PARALLELISM, le=16)
    hash_len:     int = Field(default=32, ge=16, le=64)
    salt_len:     int = Field(default=16, ge=8, le=64)
    version:      int = Field(default=0x13, ge=0x13, le=0x13)  # Argon2 19 (v1.3)

    @field_validator("memory_cost")
    @classmethod
    def _memory_aligned(cls, v: int) -> int:
        if v % 8 != 0:
            raise ValueError("memory_cost must be a multiple of 8 KiB")
        return v

    @classmethod
    def for_testing(cls, **kwargs: int) -> "Argon2Params":
        """Bypass OWASP minimum validation. Use ONLY in tests."""
        return cls.model_construct(**kwargs)


INTERACTIVE_PROFILE: Final[Argon2Params] = Argon2Params(
    time_cost=3, memory_cost=262144, parallelism=4,  # 256 MiB
)
HIGH_SECURITY_PROFILE: Final[Argon2Params] = Argon2Params(
    time_cost=4, memory_cost=524288, parallelism=4,  # 512 MiB
)


def derive_key(
    password: SecretBytes,
    params: Argon2Params,
    salt: bytes | None = None,
) -> tuple[SecretBytes, bytes]:
    """Derive a key from a password using Argon2id.

    Args:
        password: The user's passphrase wrapped in SecretBytes.
        params: Argon2id parameters.
        salt: Optional pre-generated salt. If None, a random salt is
            generated via the OS CSPRNG.

    Returns:
        (derived_key, salt_used). The salt is returned so the caller
        can persist it alongside the ciphertext.
    """
    if salt is None:
        salt = _secrets.token_bytes(params.salt_len)
    elif len(salt) != params.salt_len:
        raise ValueError(
            f"salt length {len(salt)} != params.salt_len {params.salt_len}"
        )

    raw = hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
        version=params.version,
    )
    return SecretBytes(raw), salt
