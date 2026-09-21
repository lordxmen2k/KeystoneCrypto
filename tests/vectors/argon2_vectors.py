"""RFC 9106 § 5 Argon2id test vector.

The canonical Argon2id test vector from RFC 9106. Password and salt
are sequences of repeated bytes for ease of reproducibility. The
expected output is the Keccak/Blake output of Argon2id under these
parameters.

Source: https://www.rfc-editor.org/rfc/rfc9106.txt § 5 (Test Vectors)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Argon2Vector:
    password: bytes
    salt: bytes
    memory_cost: int  # KiB
    time_cost: int
    parallelism: int
    hash_len: int
    expected: bytes


RFC9106_VECTORS: tuple[Argon2Vector, ...] = (
    Argon2Vector(
        password=bytes(range(1, 33)),                      # 0x01..0x20
        salt=bytes(range(1, 33)),                          # 0x01..0x20
        memory_cost=32,
        time_cost=3,
        parallelism=4,
        hash_len=32,
        expected=bytes.fromhex(
            "0d640df58d78766c08c037a34a8b53c9"
            "d01ef0452d75b65eb52520e96b01e659"
        ),
    ),
)
