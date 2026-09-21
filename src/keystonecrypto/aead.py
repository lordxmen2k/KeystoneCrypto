"""AES-256-GCM authenticated encryption with associated data (AAD).

AAD binds the ciphertext to a context (e.g. keystore version, chain
identifier). Decryption with mismatched AAD fails the tag check, which
prevents cross-context ciphertext replay attacks.

Returns nonce separately from ciphertext so the caller can pack them
into whatever envelope they need. The tag is appended to the
ciphertext (cryptography's default).
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keystonecrypto.exceptions import KeystoreDecryptionError
from keystonecrypto.secret_bytes import SecretBytes

__all__ = ["encrypt", "decrypt", "NONCE_LEN", "KEY_LEN"]

NONCE_LEN: int = 12
KEY_LEN:   int = 32


def _as_key(key: SecretBytes) -> bytes:
    raw = bytes(key)
    if len(raw) != KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be {KEY_LEN} bytes, got {len(raw)}")
    return raw


def encrypt(key: SecretBytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt `plaintext` under `key` with optional associated data.

    Returns (nonce, ciphertext_plus_tag). The tag is appended to the
    ciphertext per the `cryptography` library convention.
    """
    nonce = os.urandom(NONCE_LEN)
    aes = AESGCM(_as_key(key))
    ct = aes.encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt(key: SecretBytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt `ciphertext` under `key`. Raises on tag mismatch or wrong key."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    aes = AESGCM(_as_key(key))
    try:
        return aes.decrypt(nonce, ciphertext, aad)
    except Exception as e:
        # Wrap so callers get a typed exception.
        raise KeystoreDecryptionError(f"AES-GCM decryption failed: {e}") from e
