"""keystonecrypto — non-custodial HD wallet primitives for Python.

This is the public API. Submodules are also importable directly for
advanced users; the names below are the recommended entry points.
"""

from __future__ import annotations

__version__ = "0.1.0"

from keystonecrypto.derivation import DerivationPath, ExtendedPrivateKey, derive_from_seed
from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy
from keystonecrypto.exceptions import KeystoneCryptoError
from keystonecrypto.keystore import Keystore, Wallet
from keystonecrypto.mnemonic import Mnemonic
from keystonecrypto.secret_bytes import SecretBytes
from keystonecrypto.signing import (
    Ed25519Signer,
    Secp256kSchnorrSigner,
    Secp256kSigner,
)

__all__ = [
    "__version__",
    "KeystoneCryptoError",
    "SecretBytes",
    "Mnemonic",
    "Keystore",
    "Wallet",
    "DerivationPath",
    "ExtendedPrivateKey",
    "derive_from_seed",
    "STRENGTH_BITS",
    "generate_entropy",
    "Secp256kSigner",
    "Secp256kSchnorrSigner",
    "Ed25519Signer",
]
