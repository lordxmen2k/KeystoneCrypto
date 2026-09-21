"""Exception hierarchy for keystonecrypto."""

from __future__ import annotations

__all__ = [
    "KeystoneCryptoError",
    "InvalidMnemonicError",
    "InvalidPassphraseError",
    "InvalidDerivationPathError",
    "KeystoreVersionError",
    "KeystoreDecryptionError",
    "SignatureError",
]


class KeystoneCryptoError(Exception):
    """Base exception for all keystonecrypto errors."""


class InvalidMnemonicError(KeystoneCryptoError):
    """Mnemonic word, length, or checksum is invalid."""


class InvalidPassphraseError(KeystoneCryptoError):
    """BIP-39 passphrase is malformed (e.g. invalid UTF-8 after NFKD)."""


class InvalidDerivationPathError(KeystoneCryptoError):
    """BIP-32 derivation path cannot be parsed or is out of range."""


class KeystoreVersionError(KeystoneCryptoError):
    """Keystore envelope version is not supported by this library version."""


class KeystoreDecryptionError(KeystoneCryptoError):
    """Keystore decryption failed: wrong passphrase, tampered ciphertext, or corrupt header."""


class SignatureError(KeystoneCryptoError):
    """Signing operation failed or signature could not be verified."""
