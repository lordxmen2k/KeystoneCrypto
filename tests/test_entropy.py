"""Entropy generation uses the OS CSPRNG."""

from __future__ import annotations

import pytest

from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy
from keystonecrypto.secret_bytes import SecretBytes


@pytest.mark.parametrize("bits", [128, 160, 192, 224, 256])
def test_generate_entropy_returns_correct_length(bits: int) -> None:
    s = generate_entropy(bits)
    assert isinstance(s, SecretBytes)
    assert len(s) == bits // 8


def test_generate_entropy_rejects_non_multiple_of_8() -> None:
    with pytest.raises(ValueError):
        generate_entropy(129)


def test_generate_entropy_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        generate_entropy(64)  # too low
    with pytest.raises(ValueError):
        generate_entropy(512)  # too high


def test_generate_entropy_is_random() -> None:
    a = generate_entropy(128)
    b = generate_entropy(128)
    assert bytes(a) != bytes(b)


def test_strength_bits_constants_match_bip39() -> None:
    assert STRENGTH_BITS == (128, 160, 192, 224, 256)
