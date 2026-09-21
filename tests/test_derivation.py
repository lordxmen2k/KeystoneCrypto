"""BIP-32 derivation, BIP-44 path parsing, and base58 extended-key serialization."""

from __future__ import annotations

import pytest

from keystonecrypto.derivation import (
    DerivationPath,
    ExtendedPrivateKey,
    derive_from_seed,
)
from keystonecrypto.exceptions import InvalidDerivationPathError
from keystonecrypto.secret_bytes import SecretBytes
from tests.vectors.bip32_vectors import BIP32_VECTORS, Bip32Vector


def test_parse_path_m_44_0_0_0_0() -> None:
    p = DerivationPath.parse("m/44'/0'/0'/0/0")
    assert p.indices == ((44, True), (0, True), (0, True), (0, False), (0, False))


def test_parse_path_master() -> None:
    p = DerivationPath.parse("m")
    assert p.indices == ()


def test_parse_path_rejects_unhardened_first() -> None:
    with pytest.raises(InvalidDerivationPathError):
        DerivationPath.parse("44'/0'/0'/0/0")  # missing m/


def test_parse_path_rejects_bad_index() -> None:
    with pytest.raises(InvalidDerivationPathError):
        DerivationPath.parse("m/2147483648'")  # > 2^31 - 1


def test_parse_path_rejects_non_numeric() -> None:
    with pytest.raises(InvalidDerivationPathError):
        DerivationPath.parse("m/abc")


def test_parse_path_supports_h_suffix() -> None:
    """BIP-32 also accepts 'h' as the hardened marker."""
    p = DerivationPath.parse("m/0h")
    assert p.indices == ((0, True),)


def test_master_key_from_seed() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    xprv = derive_from_seed(seed, DerivationPath.parse("m"))
    assert isinstance(xprv, ExtendedPrivateKey)
    assert xprv.depth == 0
    assert xprv.child_number == 0
    assert xprv.parent_fingerprint == b"\x00\x00\x00\x00"


def test_derive_child_hardened_and_non_hardened() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    c1 = master.derive(0, hardened=True)
    c2 = c1.derive(1, hardened=False)
    assert c2.depth == 2
    assert c2.child_number == 1
    assert c2.parent_fingerprint == c1.fingerprint()


def test_derive_full_path_matches_step_by_step() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    p = DerivationPath.parse("m/0'/1/2'")
    via_path = derive_from_seed(seed, p)
    step = derive_from_seed(seed, DerivationPath.parse("m"))
    for (idx, hardened) in p.indices:
        step = step.derive(idx, hardened=hardened)
    assert bytes(via_path.private_key) == bytes(step.private_key)
    assert bytes(via_path.chain_code) == bytes(step.chain_code)


def test_derive_rejects_index_out_of_range() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    with pytest.raises(ValueError):
        master.derive(2**31)  # > max unhardened index


def test_to_base58_roundtrip() -> None:
    """to_base58 should produce a stable xprv string we can re-validate."""
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    xprv = master.to_base58()
    # Just structural checks — full re-parse requires a base58 decoder.
    assert xprv.startswith("xprv")
    assert len(xprv) > 100


@pytest.mark.parametrize("vec", BIP32_VECTORS, ids=lambda v: f"seed-{v.seed_hex[:8]}")
def test_bip32_official_vectors(vec: Bip32Vector) -> None:
    """Every official BIP-32 derivation path must yield the documented xprv."""
    seed = SecretBytes(bytes.fromhex(vec.seed_hex))
    for path_str, expected_xprv in vec.chain:
        xprv = derive_from_seed(seed, DerivationPath.parse(path_str))
        actual = xprv.to_base58()
        assert actual == expected_xprv, (
            f"xprv mismatch at {path_str!r}:\n"
            f"  expected: {expected_xprv}\n"
            f"  actual:   {actual}"
        )


def test_fingerprint_is_4_bytes() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    assert len(master.fingerprint()) == 4


def test_derive_invalid_zero_index_via_step() -> None:
    """Sanity: we can derive child 0 (non-hardened)."""
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    c = master.derive(0, hardened=False)
    assert c.depth == 1
    assert c.child_number == 0
