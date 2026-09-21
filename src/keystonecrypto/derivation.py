"""BIP-32 hierarchical key derivation + BIP-44 path parsing.

Layer 2 module. The derivation primitive uses HMAC-SHA512 and secp256k1
scalar addition via `coincurve` (so the math is libsecp256k1, not a
hand-rolled implementation).

Path syntax:
    m              -> master
    m/0            -> non-hardened child 0
    m/0'           -> hardened child 0
    m/44'/0'/0'/0  -> BIP-44 first receive address

Hardened indices are >= 2^31 in raw form. We represent them as
`(index, hardened)` pairs to keep the API unambiguous.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Final

from coincurve import PrivateKey
from pydantic import BaseModel

from keystonecrypto.exceptions import InvalidDerivationPathError
from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "DerivationPath",
    "ExtendedPrivateKey",
    "derive_from_seed",
    "HARDENED_OFFSET",
    "SECP256K1_N",
]

HARDENED_OFFSET: Final[int] = 0x80000000
_MAX_CHILD_INDEX:  Final[int] = 0xFFFFFFFF

# Order of the secp256k1 prime-order subgroup.
SECP256K1_N: Final[int] = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


class DerivationPath(BaseModel):
    """A parsed BIP-32 derivation path."""

    model_config = {"frozen": True}

    indices: tuple[tuple[int, bool], ...]  # (index, hardened) per component

    @classmethod
    def parse(cls, s: str) -> "DerivationPath":
        s = s.strip()
        if s in ("", "m"):
            return cls(indices=())
        if not s.startswith("m/"):
            raise InvalidDerivationPathError(
                f"path must start with 'm/', got {s!r}"
            )
        parts = s[2:].split("/")
        out: list[tuple[int, bool]] = []
        for part in parts:
            hardened = part.endswith("'") or part.endswith("h")
            num_str = part.rstrip("'h")
            if not num_str.isdigit():
                raise InvalidDerivationPathError(f"non-numeric component: {part!r}")
            idx = int(num_str)
            if idx < 0 or idx > 0x7FFFFFFF:
                raise InvalidDerivationPathError(f"index out of range: {idx}")
            out.append((idx, hardened))
        return cls(indices=tuple(out))


class ExtendedPrivateKey:
    """A BIP-32 extended private key (xprv): key + chain code + metadata."""

    __slots__ = ("_sk", "_cc", "_depth", "_pfp", "_child")

    def __init__(
        self,
        secret_key: SecretBytes,
        chain_code: SecretBytes,
        depth: int,
        parent_fingerprint: bytes,
        child_number: int,
    ) -> None:
        self._sk = secret_key
        self._cc = chain_code
        self._depth = depth
        self._pfp = parent_fingerprint
        self._child = child_number

    @classmethod
    def master(cls, seed: SecretBytes) -> "ExtendedPrivateKey":
        I = hmac.new(b"Bitcoin seed", bytes(seed), hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        return cls(
            secret_key=SecretBytes(IL),
            chain_code=SecretBytes(IR),
            depth=0,
            parent_fingerprint=b"\x00\x00\x00\x00",
            child_number=0,
        )

    @property
    def private_key(self) -> SecretBytes:
        return self._sk

    @property
    def chain_code(self) -> SecretBytes:
        return self._cc

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def child_number(self) -> int:
        return self._child

    def fingerprint(self) -> bytes:
        """BIP-32 key fingerprint = first 4 bytes of HASH160(pubkey)."""
        pk = PrivateKey(bytes(self._sk)).public_key.format(compressed=True)
        h160 = hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()
        return h160[:4]

    @property
    def parent_fingerprint(self) -> bytes:
        return self._pfp

    def derive(self, index: int, hardened: bool = False) -> "ExtendedPrivateKey":
        if index < 0 or index > 0x7FFFFFFF:
            raise ValueError(f"index out of range: {index}")
        if hardened:
            index += HARDENED_OFFSET
        if index < 0 or index > _MAX_CHILD_INDEX:
            raise ValueError(f"effective child index out of range: {index}")

        if index >= HARDENED_OFFSET:
            # Hardened: data = 0x00 || ser256(kpar) || ser32(i)
            data = b"\x00" + bytes(self._sk) + struct.pack(">I", index)
        else:
            # Non-hardened: data = serP(Kpar) || ser32(i)
            pub = PrivateKey(bytes(self._sk)).public_key.format(compressed=True)
            data = pub + struct.pack(">I", index)

        I = hmac.new(bytes(self._cc), data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        # child_key = (IL + kpar) mod n
        Il_int = int.from_bytes(IL, "big")
        kpar_int = int.from_bytes(bytes(self._sk), "big")
        if Il_int >= SECP256K1_N:
            raise ValueError("derivation produced invalid child key (IL >= n)")
        child_int = (Il_int + kpar_int) % SECP256K1_N
        if child_int == 0:
            raise ValueError("derivation produced zero child key")
        child_key = child_int.to_bytes(32, "big")

        return ExtendedPrivateKey(
            secret_key=SecretBytes(child_key),
            chain_code=SecretBytes(IR),
            depth=self._depth + 1,
            parent_fingerprint=self.fingerprint(),
            child_number=index,
        )

    def to_base58(self, network: str = "mainnet") -> str:
        """Serialize as a BIP-32 xprv (private key form)."""
        version = {
            "mainnet": b"\x04\x88\xad\xe4",
            "testnet": b"\x04\x35\x83\x94",
        }[network]
        raw = (
            version
            + bytes([self._depth])
            + self._pfp
            + struct.pack(">I", self._child)
            + bytes(self._cc)
            + b"\x00"
            + bytes(self._sk)
        )
        # Double-SHA256 checksum.
        checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
        return _b58encode(raw + checksum)


def derive_from_seed(seed: SecretBytes, path: DerivationPath) -> ExtendedPrivateKey:
    """Derive an extended private key from a seed and a BIP-32 path."""
    key: ExtendedPrivateKey = ExtendedPrivateKey.master(seed)
    for index, hardened in path.indices:
        key = key.derive(index, hardened=hardened)
    return key


# --- base58 (minimal; avoids an extra dep for the core) ---

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    if n == 0:
        return _B58_ALPHABET[0:1].decode()
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.append(_B58_ALPHABET[r])
    # Preserve leading zero bytes.
    for b in data:
        if b == 0:
            out.append(_B58_ALPHABET[0])
        else:
            break
    out.reverse()
    return out.decode()
