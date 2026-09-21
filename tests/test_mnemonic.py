"""BIP-39 mnemonic generation, validation, and seed derivation."""

from __future__ import annotations

import pytest

from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy
from keystonecrypto.exceptions import InvalidMnemonicError, InvalidPassphraseError
from keystonecrypto.mnemonic import Mnemonic
from keystonecrypto.secret_bytes import SecretBytes
from tests.vectors.bip39_vectors import BIP39_VECTORS, Bip39Vector


@pytest.mark.parametrize("vec", BIP39_VECTORS, ids=lambda v: f"words-{len(v.mnemonic.split())}")
def test_bip39_seed_matches_official_vectors(vec: Bip39Vector) -> None:
    """Each official vector's mnemonic must yield the documented seed.

    Trezor vectors use passphrase "TREZOR" for every vector (per BIP-39
    spec convention). Empty-passphrase tests live in separate unit tests.
    """
    m = Mnemonic.from_phrase(vec.mnemonic)
    assert bytes(m.entropy).hex() == vec.entropy_hex
    seed = m.seed(passphrase=vec.passphrase)
    assert bytes(seed).hex() == vec.seed_hex


@pytest.mark.parametrize("strength", STRENGTH_BITS)
def test_generate_produces_valid_mnemonic(strength: int) -> None:
    m = Mnemonic.generate(strength=strength)
    words = m.phrase.split()
    # word count: 12 (128), 15 (160), 18 (192), 21 (224), 24 (256)
    expected_words = {128: 12, 160: 15, 192: 18, 224: 21, 256: 24}[strength]
    assert len(words) == expected_words
    # Roundtrip
    m2 = Mnemonic.from_phrase(m.phrase)
    assert bytes(m2.entropy) == bytes(m.entropy)


def test_from_phrase_rejects_bad_checksum() -> None:
    """Mutate last word → checksum must fail."""
    bad_phrase = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon"
    )
    with pytest.raises(InvalidMnemonicError):
        Mnemonic.from_phrase(bad_phrase)


def test_from_phrase_rejects_unknown_word() -> None:
    with pytest.raises(InvalidMnemonicError):
        Mnemonic.from_phrase("notaword " * 12)


def test_from_phrase_rejects_wrong_length() -> None:
    with pytest.raises(InvalidMnemonicError):
        Mnemonic.from_phrase("abandon " * 11)  # 11 words


def test_from_phrase_rejects_non_string() -> None:
    with pytest.raises((InvalidMnemonicError, TypeError)):
        Mnemonic.from_phrase(12345)  # type: ignore[arg-type]


def test_from_entropy_roundtrip() -> None:
    e = generate_entropy(128)
    m = Mnemonic.from_entropy(e)
    m2 = Mnemonic.from_phrase(m.phrase)
    assert bytes(m2.entropy) == bytes(e)


def test_different_passphrases_produce_different_seeds() -> None:
    m = Mnemonic.generate(strength=128)
    s1 = bytes(m.seed(passphrase="a"))
    s2 = bytes(m.seed(passphrase="b"))
    assert s1 != s2
    assert len(s1) == 64


def test_phrase_is_normalized_nfkd() -> None:
    """BIP-39 specifies NFKD normalization for the passphrase.

    Composed é (U+00E9) and decomposed e + combining acute (U+0065 U+0301)
    must produce the same seed.
    """
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    s1 = bytes(m.seed(passphrase="\u00e9"))
    s2 = bytes(m.seed(passphrase="e\u0301"))
    assert s1 == s2


def test_generate_invalid_strength() -> None:
    with pytest.raises(ValueError):
        Mnemonic.generate(strength=100)


def test_mnemonic_repr_redacts() -> None:
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    r = repr(m)
    assert "abandon" not in r
    assert "Mnemonic" in r


def test_phrase_roundtrip_via_from_phrase() -> None:
    """Mnemonic.phrase is the same string after from_phrase."""
    p = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    m = Mnemonic.from_phrase(p)
    assert m.phrase == p


def test_empty_passphrase_zero_entropy_seed() -> None:
    """Canonical BIP-39 zero-entropy seed with empty passphrase.

    Not in the Trezor test set (which uses 'TREZOR' for every vector).
    Independently verifiable by hand against the BIP-39 algorithm.
    """
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    s = m.seed(passphrase="")
    # Compute the expected value directly with stdlib.
    import hashlib
    import unicodedata
    salt = unicodedata.normalize("NFKD", "mnemonic").encode("utf-8")
    password = unicodedata.normalize("NFKD", m.phrase).encode("utf-8")
    expected = hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)
    assert bytes(s) == expected
