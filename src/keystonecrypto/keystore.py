"""High-level Keystore and Wallet API.

This is the user-facing entry point. It orchestrates:
- Envelope pack/unpack for the encrypted blob
- Mnemonic reconstruction from the seed
- BIP-32 derivation paths via ExtendedPrivateKey
- Signing via the chosen scheme

The `Wallet` object is short-lived: closing it (via context manager
exit or explicit `.close()`) zeroizes the in-memory seed so a memory
dump cannot recover it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from pydantic import BaseModel

from keystonecrypto.derivation import DerivationPath, ExtendedPrivateKey, derive_from_seed
from keystonecrypto.envelope import Envelope
from keystonecrypto.exceptions import KeystoreDecryptionError
from keystonecrypto.kdf import INTERACTIVE_PROFILE, Argon2Params
from keystonecrypto.mnemonic import Mnemonic
from keystonecrypto.secret_bytes import SecretBytes
from keystonecrypto.signing import (
    Ed25519Signer,
    Secp256kSchnorrSigner,
    Secp256kSigner,
    Signer,
)

__all__ = ["Keystore", "Wallet", "Account", "KeystoreContext"]


class Account(BaseModel):
    """A derived account at a specific BIP-32 path."""

    # frozen=True + arbitrary_types_allowed=True: Account is immutable,
    # and `signer` is a runtime-checkable Protocol (not a concrete type),
    # so pydantic needs the escape hatch to accept it as a field.
    model_config = {"frozen": True, "arbitrary_types_allowed": True}

    path: DerivationPath
    signer: Signer
    public_key: bytes

    def sign(self, message: bytes) -> bytes:
        return self.signer.sign(message).serialize()

    def public_key_hex(self) -> str:
        return self.public_key.hex()


class Wallet:
    """An unlocked wallet. Holds the seed in memory; zeroize on close."""

    def __init__(self, mnemonic: Mnemonic | None, seed: SecretBytes) -> None:
        self._mnemonic = mnemonic
        self._seed = seed
        self._closed = False

    @property
    def mnemonic(self) -> Mnemonic | None:
        return self._mnemonic

    @property
    def is_closed(self) -> bool:
        return self._closed

    def derive_account(
        self, path: DerivationPath, scheme: str = "ecdsa-secp256k1",
    ) -> Account:
        if self._closed:
            raise RuntimeError("wallet is closed")
        xprv = derive_from_seed(self._seed, path)
        sk = xprv.private_key
        if scheme == "ecdsa-secp256k1":
            signer: Signer = Secp256kSigner(sk)
        elif scheme == "schnorr-secp256k1":
            signer = Secp256kSchnorrSigner(sk)
        elif scheme == "ed25519":
            signer = Ed25519Signer(sk)
        else:
            raise ValueError(f"unsupported scheme: {scheme}")
        return Account(path=path, signer=signer, public_key=signer.public_key_bytes())

    def sign_message(
        self, path: DerivationPath, message: bytes,
        scheme: str = "ecdsa-secp256k1",
    ):
        if self._closed:
            raise RuntimeError("wallet is closed")
        account = self.derive_account(path, scheme=scheme)
        return account.signer.sign(message)

    def close(self) -> None:
        self._seed.zeroize()
        self._closed = True

    def __enter__(self) -> "Wallet":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class KeystoreContext:
    """A context manager wrapping an opened keystore file."""

    def __init__(self, blob: bytes) -> None:
        self._blob = blob

    def unlock(self, password: str) -> Wallet:
        if not isinstance(password, str):
            raise TypeError("password must be str")
        pw_bytes = password.encode("utf-8")
        pw_secret = SecretBytes(pw_bytes)
        unpacked = Envelope.unpack(self._blob, pw_secret)
        # Zeroize the password SecretBytes ASAP.
        pw_secret.zeroize()
        # Try to reconstruct the mnemonic. If entropy size is BIP-39-valid
        # (128/160/192/224/256 bits), we have a mnemonic; otherwise it's
        # raw seed-only.
        m: Mnemonic | None = None
        for bits in (128, 160, 192, 224, 256):
            if len(unpacked.seed) == bits // 8:
                try:
                    m = Mnemonic.from_entropy(unpacked.seed)
                except Exception:
                    m = None
                break
        return Wallet(mnemonic=m, seed=unpacked.seed)

    def __enter__(self) -> "KeystoreContext":
        return self

    def __exit__(self, *exc: object) -> None:
        # No persistent state to clean up — blob is bytes.
        pass


class Keystore(BaseModel):
    """Encrypted BIP-39 mnemonic (or raw seed) on disk.

    Use `.create(mnemonic, password)` to make a new one, `.save(path)`
    to persist, and `Keystore.open(path)` to load and unlock.
    """

    model_config = {"arbitrary_types_allowed": True}

    blob: bytes
    params: Argon2Params
    has_passphrase: bool = False
    created_at: int = 0

    @classmethod
    def create(
        cls,
        mnemonic: Mnemonic,
        password: str,
        params: Argon2Params = INTERACTIVE_PROFILE,
        has_passphrase: bool = False,
    ) -> "Keystore":
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        pw_secret = SecretBytes(password.encode("utf-8"))
        blob = Envelope.pack(
            seed=mnemonic.entropy,
            params=params,
            password=pw_secret,
            kdf_id=1,
            has_passphrase=has_passphrase,
        )
        pw_secret.zeroize()
        return cls(blob=blob, params=params, has_passphrase=has_passphrase, created_at=0)

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(self.blob)

    @classmethod
    def open(cls, path: str | Path) -> KeystoreContext:
        data = Path(path).read_bytes()
        return KeystoreContext(data)
