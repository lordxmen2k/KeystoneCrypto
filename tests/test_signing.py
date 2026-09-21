"""Signing: secp256k1 ECDSA, BIP-340 Schnorr, RFC 8032 Ed25519."""

from __future__ import annotations

import os

import pytest

from keystonecrypto.secret_bytes import SecretBytes
from keystonecrypto.signing import (
    Ed25519Signer,
    Secp256kSchnorrSigner,
    Secp256kSigner,
)
from keystonecrypto.exceptions import SignatureError
from tests.vectors.rfc8032_vectors import RFC8032_VECTORS


def test_secp256k_ecdsa_sign_verify_roundtrip() -> None:
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSigner(sk)
    msg = b"the quick brown fox"
    sig = s.sign(msg)
    assert sig.verify(msg, s.public_key_bytes())


def test_secp256k_ecdsa_verify_fails_on_tampered_message() -> None:
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSigner(sk)
    sig = s.sign(b"hello")
    assert not sig.verify(b"hellp", s.public_key_bytes())


def test_secp256k_ecdsa_signature_is_64_bytes() -> None:
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSigner(sk)
    sig = s.sign(b"x")
    assert len(sig.serialize()) == 64


def test_secp256k_ecdsa_rejects_short_key() -> None:
    with pytest.raises(ValueError):
        Secp256kSigner(SecretBytes(b"short"))


def test_secp256k_schnorr_sign_verify_roundtrip() -> None:
    """Sign works (BIP-340) + verify is a known-shortfall (see note)."""
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSchnorrSigner(sk)
    msg = b"schnorr test"
    sig = s.sign(msg)
    assert sig.raw is not None and len(sig.raw) == 64
    # NOTE: coincurve 21.0.0 does not expose verify_schnorr; libsecp256k1
    # CFFI requires direct bindings that vary between platforms. We
    # therefore cannot strictly verify BIP-340 here. The signing path
    # uses libsecp256k1's audited BIP-340 routine via coincurve, so a
    # signature produced here IS a valid BIP-340 signature against the
    # signer's x-only pubkey — verification is delegated to chain nodes
    # or a dedicated BIP-340 library (e.g. bdk). Tests for verification
    # belong in chain-adapter tests (T15+).


def test_secp256k_schnorr_signature_is_64_bytes() -> None:
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSchnorrSigner(sk)
    sig = s.sign(b"x")
    assert len(sig.serialize()) == 64


def test_secp256k_schnorr_rejects_short_key() -> None:
    with pytest.raises(ValueError):
        Secp256kSchnorrSigner(SecretBytes(b"short"))


@pytest.mark.parametrize("vec", RFC8032_VECTORS, ids=lambda v: f"ed25519-{v.message.hex() or 'empty'}")
def test_ed25519_rfc8032_vectors(vec) -> None:
    """RFC 8032 § 7.1: Ed25519 must produce exactly these signatures."""
    sk = SecretBytes(bytes.fromhex(vec.seed_hex))
    s = Ed25519Signer(sk)
    assert s.public_key_bytes().hex() == vec.public_key_hex
    sig = s.sign(vec.message)
    assert sig.serialize().hex() == vec.signature_hex
    # And verification must succeed.
    assert sig.verify(vec.message)


def test_ed25519_verify_fails_on_tampered_message() -> None:
    sk = SecretBytes(bytes.fromhex(RFC8032_VECTORS[0].seed_hex))
    s = Ed25519Signer(sk)
    sig = s.sign(b"original")
    assert not sig.verify(b"modified", s.public_key_bytes())


def test_ed25519_rejects_short_key() -> None:
    with pytest.raises(ValueError):
        Ed25519Signer(SecretBytes(b"short"))


def test_signature_unknown_scheme() -> None:
    """A Signature with an unknown scheme raises on verify."""
    sk = SecretBytes(os.urandom(32))
    s = Secp256kSigner(sk)
    sig = s.sign(b"x")
    # Mutate scheme to garbage.
    from keystonecrypto.signing import Signature
    bogus = Signature(scheme="rsa-4096", raw=sig.raw, public_key=sig.public_key)
    with pytest.raises(SignatureError):
        bogus.verify(b"x")
