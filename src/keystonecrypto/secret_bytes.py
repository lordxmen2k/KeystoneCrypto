"""SecretBytes — a zeroizing wrapper for sensitive bytes.

Stores the value in a `bytearray` (mutable, so we can overwrite in place)
and clears it on context-manager exit, on explicit `.zeroize()`, and on
garbage collection as a last resort.

Security notes:
- This is *defense in depth*, not a guarantee. Python's GC and string
  interning can leave copies. Do not rely on this for hot-path secrecy.
- Never pass raw bytes through repr/print/log — use the SecretBytes
  wrapper so accidental logging is redacted.
"""

from __future__ import annotations

import hmac
import secrets as _secrets
from typing import Self

__all__ = ["SecretBytes"]


class SecretBytes:
    """A bytearray-backed sensitive buffer that zeroizes on close."""

    __slots__ = ("_buf",)

    def __init__(self, value: bytes | bytearray) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(
                f"SecretBytes requires bytes or bytearray, got {type(value).__name__}"
            )
        if len(value) == 0:
            raise ValueError("SecretBytes cannot be empty")
        self._buf: bytearray = bytearray(value)

    @classmethod
    def from_hex(cls, hex_str: str) -> Self:
        return cls(bytes.fromhex(hex_str))

    @classmethod
    def random(cls, length: int) -> Self:
        if length <= 0:
            raise ValueError("length must be positive")
        return cls(_secrets.token_bytes(length))

    def zeroize(self) -> None:
        """Overwrite the buffer with zeros. Idempotent."""
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def __bytes__(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def hex(self) -> str:
        """Return hex of the current (possibly zeroized) buffer."""
        return self._buf.hex()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.zeroize()

    def __del__(self) -> None:
        try:
            self.zeroize()
        except Exception:
            pass

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretBytes):
            return NotImplemented
        # Constant-time comparison via hmac.compare_digest on the raw bytes.
        a = bytes(self._buf)
        b = bytes(other._buf)
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)

    def __hash__(self) -> int:  # pragma: no cover - mutable, unhashable
        raise TypeError("SecretBytes is not hashable (contents are mutable)")

    def __repr__(self) -> str:
        return f"<SecretBytes len={len(self._buf)} redacted>"
