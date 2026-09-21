"""Cryptographically-secure entropy generation.

Wraps `secrets.token_bytes` and returns a SecretBytes. Validates bit
lengths to match the BIP-39 allowed strengths so the same module can
feed both raw entropy generation and mnemonic generation.
"""

from __future__ import annotations

import secrets

from keystonecrypto.secret_bytes import SecretBytes

__all__ = ["STRENGTH_BITS", "generate_entropy"]

# BIP-39 § "Entropy" — allowed entropy sizes in bits.
STRENGTH_BITS: tuple[int, ...] = (128, 160, 192, 224, 256)

_MIN_BITS = min(STRENGTH_BITS)
_MAX_BITS = max(STRENGTH_BITS)


def generate_entropy(bits: int) -> SecretBytes:
    """Generate `bits` bits of cryptographically-secure random data.

    Returns: SecretBytes of length `bits // 8`.

    Raises:
        ValueError: if `bits` is not a multiple of 8 or is outside the
            BIP-39 allowed range.
    """
    if bits % 8 != 0:
        raise ValueError(f"bits must be a multiple of 8, got {bits}")
    if bits < _MIN_BITS or bits > _MAX_BITS:
        raise ValueError(
            f"bits must be in [{_MIN_BITS}, {_MAX_BITS}], got {bits}"
        )
    return SecretBytes(secrets.token_bytes(bits // 8))
