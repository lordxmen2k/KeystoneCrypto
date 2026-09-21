"""Signing primitives: secp256k1 ECDSA + BIP-340 Schnorr + RFC 8032 Ed25519.

Layer 3. Uses coincurve (wraps libsecp256k1) for secp256k1 ops and the
`cryptography` library for Ed25519. Signature verification uses the
same libraries — no hand-rolled math.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from coincurve import PrivateKey, PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from keystonecrypto.exceptions import SignatureError
from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "Signature",
    "Signer",
    "Secp256kSigner",
    "Secp256kSchnorrSigner",
    "Ed25519Signer",
]


@dataclass(frozen=True)
class Signature:
    """A signature plus the public key needed to verify it."""

    scheme: str        # "ecdsa-secp256k1" | "schnorr-secp256k1" | "ed25519"
    raw: bytes         # 64 bytes for all schemes
    public_key: bytes  # 33 bytes (compressed secp256k1) or 32 bytes (xonly schnorr) or 32 bytes (ed25519)

    def serialize(self) -> bytes:
        return self.raw

    def verify(self, message: bytes, public_key: bytes | None = None) -> bool:
        pk = public_key if public_key is not None else self.public_key
        if self.scheme == "ecdsa-secp256k1":
            try:
                # coincurve's verify expects (signature, message, hasher)
                # By default the message is signed with sha256; we already
                # signed the raw message (no hashing), so hasher=None.
                PublicKey(pk).verify(self.raw, message, hasher=None)
                return True
            except Exception:
                return False
        if self.scheme == "schnorr-secp256k1":
            try:
                # Schnorr x-only public key (32 bytes).
                # coincurve accepts x-only sigs in verify_schnorr.
                PublicKey(b"\x02" + pk).verify(self.raw, message, hasher=None)
                return True
            except Exception:
                return False
        if self.scheme == "ed25519":
            try:
                Ed25519PublicKey.from_public_bytes(pk).verify(self.raw, message)
                return True
            except Exception:
                return False
        raise SignatureError(f"unknown scheme {self.scheme!r}")


class Signer(Protocol):
    """Common signing interface."""

    def sign(self, message: bytes) -> Signature: ...
    def public_key_bytes(self) -> bytes: ...


# ---- secp256k1 ECDSA ----

class Secp256kSigner:
    """ECDSA over secp256k1, signatures in 64-byte (r || s) compact form."""

    scheme = "ecdsa-secp256k1"

    def __init__(self, secret_key: SecretBytes) -> None:
        raw = bytes(secret_key)
        if len(raw) != 32:
            raise ValueError(f"secp256k1 secret key must be 32 bytes, got {len(raw)}")
        self._sk = PrivateKey(raw)

    def public_key_bytes(self) -> bytes:
        return self._sk.public_key.format(compressed=True)

    def sign(self, message: bytes) -> Signature:
        # coincurve's sign() with hasher=None returns a DER-encoded signature.
        der = self._sk.sign(message, hasher=None)
        r, s = _der_to_rs(der)
        return Signature(self.scheme, r + s, self.public_key_bytes())


class Secp256kSchnorrSigner:
    """BIP-340 Schnorr signatures over secp256k1 (Taproot key-path spends)."""

    scheme = "schnorr-secp256k1"

    def __init__(self, secret_key: SecretBytes) -> None:
        raw = bytes(secret_key)
        if len(raw) != 32:
            raise ValueError(f"secp256k1 secret key must be 32 bytes, got {len(raw)}")
        self._sk = PrivateKey(raw)

    def public_key_bytes(self) -> bytes:
        # Schnorr x-only pubkey (32 bytes, even-Y implied).
        xonly = self._sk.public_key.format(compressed=True)[1:]
        return xonly

    def sign(self, message: bytes) -> Signature:
        sig = self._sk.sign_schnorr(message, hasher=None)
        return Signature(self.scheme, sig, self.public_key_bytes())


# ---- Ed25519 ----

class Ed25519Signer:
    """RFC 8032 Ed25519. Used by Solana."""

    scheme = "ed25519"

    def __init__(self, secret_key: SecretBytes) -> None:
        raw = bytes(secret_key)
        if len(raw) != 32:
            raise ValueError(f"ed25519 secret key must be 32 bytes, got {len(raw)}")
        self._sk = Ed25519PrivateKey.from_private_bytes(raw)

    def public_key_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes_raw()

    def sign(self, message: bytes) -> Signature:
        sig = self._sk.sign(message)
        return Signature(self.scheme, sig, self.public_key_bytes())


# ---- helpers ----

def _der_to_rs(der: bytes) -> tuple[bytes, bytes]:
    """Extract 32-byte r and 32-byte s from a DER-encoded ECDSA signature."""
    if der[0] != 0x30:
        raise SignatureError("bad DER: expected SEQUENCE")
    if der[1] + 2 != len(der):
        raise SignatureError("bad DER: length mismatch")
    if der[2] != 0x02:
        raise SignatureError("bad DER: expected INTEGER for r")
    r_len = der[3]
    r = der[4:4 + r_len]
    s_off = 4 + r_len
    if der[s_off] != 0x02:
        raise SignatureError("bad DER: expected INTEGER for s")
    s_len = der[s_off + 1]
    s = der[s_off + 2:s_off + 2 + s_len]
    # Strip leading zero if present (DER INTEGER sign byte) and pad to 32.
    if len(r) == 33 and r[0] == 0:
        r = r[1:]
    if len(s) == 33 and s[0] == 0:
        s = s[1:]
    if len(r) > 32 or len(s) > 32:
        raise SignatureError("DER component too large for secp256k1")
    return r.rjust(32, b"\x00"), s.rjust(32, b"\x00")
