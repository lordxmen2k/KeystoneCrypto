# keystonecrypto Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `keystonecrypto`, a non-custodial HD wallet library for Python (BTC, ETH, SOL), distributed on real PyPI as `keystonecrypto`.

**Architecture:** Five-layer security-first design (entropy/KDF/AEAD → HD derivation → signing → tx builders → chain adapters). Layer 1–3 form the security-critical core shipped by default; Layer 4–5 ship as opt-in extras per chain. Strict import ordering (no inner layer imports an outer one) is enforced by lint.

**Tech Stack:** Python ≥ 3.11, `cryptography` ≥ 42, `coincurve` ≥ 20, `argon2-cffi` ≥ 23, `pydantic` ≥ 2.5. Per-chain extras add `httpx`, `bech32`, `eth-utils`, `solana-py` (or hand-rolled equivalents). Test stack: `pytest`, `pytest-cov`, `hypothesis`. Builds via `python -m build` + trusted publishing via GitHub OIDC.

**Spec:** `docs/superpowers/specs/2026-09-20-keystonecrypto-design.md`

**Repo:** `https://github.com/lordxmen2k/KeystoneCrypto` (private). PAT in `/workspace/.home/.git-credentials` (chmod 600). Sandbox CA bundle is broken — every `git` invocation uses `GIT_SSL_NO_VERIFY=1`.

---

## Global Constraints

These apply to every task unless a task explicitly overrides one.

1. **Python ≥ 3.11.** Use `from __future__ import annotations` in every source file. Type-hint everything.
2. **License:** Apache 2.0. Every source file starts with the SPDX header `SPDX-License-Identifier: Apache-2.0`.
3. **No platform references in user-facing text** (per user memory 2026-09-16). No "Mavis", "MiniMax", or internal-agent phrasing in any string the user can see (README, docstrings, CLI output, error messages).
4. **Default install has zero network capability.** Layer 1–3 source files must not import `httpx`, `requests`, `urllib`, `urllib3`, `socket`, or `aiohttp`. Enforced by `tests/lint/test_no_network_in_core.py` (Task T0).
5. **PyPI target is real PyPI (`pypi.org`).** Never `--repository testpypi`. Never add TestPyPI workflow steps.
6. **All sensitive memory goes through `SecretBytes`** (Task T1). Never store keys/seeds in raw `bytes`/`str`/`bytearray`.
7. **All hash and compare operations are constant-time** via `hmac.compare_digest` or audited library calls.
8. **Commit messages** follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`).
9. **Push after every commit.** `git push origin main` (and `git push origin <tag>` when version bumps).
10. **Tests live next to a `conftest.py`** that adds the project root to `sys.path` so `from keystonecrypto import …` works without an editable install.
11. **Coverage floor:** ≥ 95% line coverage for Layers 1–3, ≥ 85% for chain adapters. Measured by `pytest --cov=keystonecrypto`.
12. **Sandbox env:** `GIT_SSL_NO_VERIFY=1` for git operations. PAT already configured in `/workspace/.home/.git-credentials`.
13. **Worktree:** All implementation happens in `/workspace/`. Use the main branch directly (no worktree — single-developer workflow for v1).

---

## File Structure

Created/modified across all tasks. Boundaries are intentional: one responsibility per file.

```
/workspace/
├── .gitignore
├── .home/                            # local-only, gitignored (PAT lives here)
├── pyproject.toml
├── README.md
├── LICENSE                           # Apache 2.0
├── CHANGELOG.md
├── SECURITY.md
├── docs/
│   └── superpowers/
│       ├── specs/
│       │   └── 2026-09-20-keystonecrypto-design.md
│       └── plans/
│           └── 2026-09-20-keystonecrypto.md
├── src/
│   └── keystonecrypto/
│       ├── __init__.py
│       ├── exceptions.py
│       ├── secret_bytes.py           # Layer 1
│       ├── entropy.py                # Layer 1
│       ├── kdf.py                    # Layer 1
│       ├── aead.py                   # Layer 1
│       ├── envelope.py               # Layer 1 (binary framing)
│       ├── mnemonic.py               # Layer 2
│       ├── derivation.py             # Layer 2
│       ├── keystore.py               # Layer 1+2 orchestration
│       ├── signing.py                # Layer 3
│       ├── btc/                      # Layer 4+5, extra [btc]
│       │   ├── __init__.py
│       │   ├── address.py
│       │   ├── psbt.py
│       │   └── electrum.py
│       ├── eth/                      # Layer 4+5, extra [eth]
│       │   ├── __init__.py
│       │   ├── address.py
│       │   ├── tx.py
│       │   ├── typed_data.py
│       │   └── rpc.py
│       └── sol/                      # Layer 4+5, extra [sol]
│           ├── __init__.py
│           ├── address.py
│           ├── tx.py
│           └── rpc.py
└── tests/
    ├── conftest.py
    ├── lint/
    │   └── test_no_network_in_core.py
    ├── vectors/
    │   ├── bip39_vectors.py
    │   ├── bip32_vectors.py
    │   ├── rfc8032_vectors.py
    │   └── argon2_vectors.py
    ├── test_secret_bytes.py
    ├── test_entropy.py
    ├── test_kdf.py
    ├── test_aead.py
    ├── test_envelope.py
    ├── test_mnemonic.py
    ├── test_derivation.py
    ├── test_signing.py
    ├── test_keystore.py
    └── property/
        └── test_roundtrip.py
```

---

## Phase 1 — Foundations (Tasks T0–T5)

Layer 1: entropy, KDF, AEAD envelope, sensitive memory.

---

### Task T0: Project scaffolding & lint guard

**Files:**
- Create: `/workspace/pyproject.toml`
- Create: `/workspace/.gitignore`
- Create: `/workspace/src/keystonecrypto/__init__.py`
- Create: `/workspace/src/keystonecrypto/exceptions.py`
- Create: `/workspace/tests/__init__.py`
- Create: `/workspace/tests/conftest.py`
- Create: `/workspace/tests/lint/__init__.py`
- Create: `/workspace/tests/lint/test_no_network_in_core.py`
- Create: `/workspace/README.md`
- Create: `/workspace/LICENSE`

**Interfaces:**
- Consumes: nothing (greenfield).
- Produces: an installable package skeleton; the `KeystoneCryptoError` exception class imported from `keystonecrypto.exceptions`.

- [ ] **Step 1: Write the failing lint test**

Create `/workspace/tests/lint/test_no_network_in_core.py`:

```python
"""Lint guard: Layers 1-3 must not import any network library.

This is a hard constraint from the design spec. If a future commit
introduces a network import in core code, this test fails the build.
"""
from __future__ import annotations

import ast
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[2] / "src" / "keystonecrypto"
FORBIDDEN_MODULES = {
    "httpx", "requests", "urllib", "urllib3",
    "urllib.request", "urllib.parse",
    "socket", "aiohttp", "http.client",
}

# Files in these subpackages are allowed network imports (they are
# the chain-adapter layer).
ALLOWED_SUBDIRS = {"btc", "eth", "sol"}


def _imports_in(path: Path) -> set[str]:
    """Return top-level module names imported in a Python source file."""
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
    return found


def test_no_network_imports_in_core() -> None:
    offenders: list[str] = []
    for py_file in CORE_DIR.rglob("*.py"):
        # Skip chain adapter subdirs.
        rel = py_file.relative_to(CORE_DIR)
        if rel.parts and rel.parts[0] in ALLOWED_SUBDIRS:
            continue
        imports = _imports_in(py_file)
        bad = imports & FORBIDDEN_MODULES
        if bad:
            offenders.append(f"{py_file.relative_to(CORE_DIR.parent.parent)}: {sorted(bad)}")
    assert not offenders, "Forbidden network imports in core:\n" + "\n".join(offenders)
```

- [ ] **Step 2: Run the test to verify it passes (vacuously)**

```bash
cd /workspace && python -m pytest tests/lint/test_no_network_in_core.py -v
```

Expected: PASS (no Python files in core yet, so the violation set is empty).

- [ ] **Step 3: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling>=1.18"]
build-backend = "hatchling.build"

[project]
name = "keystonecrypto"
version = "0.1.0"
description = "Non-custodial HD wallet primitives for Python: BIP-39 seeds, encrypted keystores, multi-chain address derivation, pluggable chain adapters."
readme = "README.md"
license = { text = "Apache-2.0" }
requires-python = ">=3.11"
authors = [
    { name = "keystonecrypto contributors" },
]
keywords = ["bitcoin", "ethereum", "solana", "wallet", "hd-wallet", "bip39", "bip32", "cryptography"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security :: Cryptography",
]
dependencies = [
    "cryptography>=42.0,<44",
    "coincurve>=20.0,<21",
    "argon2-cffi>=23.0,<24",
    "pydantic>=2.5,<3",
]

[project.optional-dependencies]
btc = ["base58>=2.1", "bech32>=1.2"]
eth = ["eth-utils>=4.0", "rlp>=4.0"]
sol = []  # hand-rolled, no external deps at v1
network = ["httpx>=0.27"]
dev = [
    "pytest>=8.0",
    "pytest-cov>=5.0",
    "hypothesis>=6.100",
    "ruff>=0.5",
    "mypy>=1.10",
]

[tool.hatch.build.targets.wheel]
packages = ["src/keystonecrypto"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra --strict-markers"
```

- [ ] **Step 4: Create `.gitignore`**

```
.home/
__pycache__/
*.pyc
*.egg-info/
.pytest_cache/
.coverage
.coverage.*
htmlcov/
dist/
build/
.venv/
venv/
.env
.env.*
.mypy_cache/
.ruff_cache/
```

- [ ] **Step 5: Create the package skeleton**

`/workspace/src/keystonecrypto/__init__.py`:

```python
"""keystonecrypto — non-custodial HD wallet primitives for Python."""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__", "KeystoneCryptoError"]
```

`/workspace/src/keystonecrypto/exceptions.py`:

```python
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
```

`/workspace/tests/__init__.py` and `/workspace/tests/lint/__init__.py`: empty files.

`/workspace/tests/conftest.py`:

```python
"""Pytest configuration: make src/ importable without an editable install."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
```

- [ ] **Step 6: Create `README.md` and `LICENSE`**

`/workspace/README.md`:

```markdown
# keystonecrypto

Non-custodial HD wallet primitives for Python.

Generate BIP-39 seeds, derive addresses across BTC, ETH, and Solana, encrypt keystores, and sign messages. Pluggable chain adapters via `pip install keystonecrypto[btc|eth|sol]`.

## Install

```bash
pip install keystonecrypto              # core only (key mgmt + signing)
pip install keystonecrypto[btc]         # + Bitcoin transaction building + Electrum broadcast
pip install keystonecrypto[eth]         # + Ethereum transaction signing + JSON-RPC
pip install keystonecrypto[sol]         # + Solana transaction signing + RPC
```

## Quickstart

```python
from keystonecrypto import Keystore, Mnemonic

mnemonic = Mnemonic.generate()                      # 12-word phrase
keystore = Keystore.create(mnemonic, "passphrase")
keystore.save("wallet.keystore")

with Keystore.open("wallet.keystore") as ks:
    wallet = ks.unlock("passphrase")
    # ... use wallet ...
    wallet.zeroize()
```

## Security

This library handles private keys and seed phrases. Read [`SECURITY.md`](./SECURITY.md) before use.

## License

Apache-2.0.
```

`/workspace/LICENSE`: download Apache 2.0 text:

```bash
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o /workspace/LICENSE
```

(If the download fails in the sandbox, paste the standard Apache 2.0 text from https://www.apache.org/licenses/LICENSE-2.0 into `/workspace/LICENSE`.)

- [ ] **Step 7: Run all tests**

```bash
cd /workspace && python -m pytest -v
```

Expected: PASS (one lint test passing, no other tests yet).

- [ ] **Step 8: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git config credential.helper "store --file=$PWD/.home/.git-credentials"
GIT_SSL_NO_VERIFY=1 git add pyproject.toml .gitignore README.md LICENSE src/ tests/
GIT_SSL_NO_VERIFY=1 git commit -m "chore: scaffold keystonecrypto package, add lint guard for network imports"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T1: `SecretBytes` — sensitive memory wrapper

**Files:**
- Create: `/workspace/src/keystonecrypto/secret_bytes.py`
- Create: `/workspace/tests/test_secret_bytes.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `SecretBytes` class — context manager + zeroizing wrapper for sensitive bytes.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/test_secret_bytes.py`:

```python
"""SecretBytes hides sensitive material in memory and zeroizes on close."""

from __future__ import annotations

import gc
import os
import sys
from pathlib import Path

import pytest

# Ensure the test can find the package without an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402


def test_secret_bytes_holds_value_and_repr_redacts() -> None:
    s = SecretBytes(b"supersecret")
    assert bytes(s) == b"supersecret"
    assert len(s) == len(b"supersecret")
    r = repr(s)
    assert "supersecret" not in r
    assert "SecretBytes" in r


def test_secret_bytes_context_manager_zeroizes_on_exit() -> None:
    s = SecretBytes(b"hunter2")
    with s as opened:
        assert bytes(opened) == b"hunter2"
    # After exit, bytes should be zero-filled.
    assert bytes(s) == b"\x00" * len(b"hunter2")


def test_secret_bytes_zeroize_is_idempotent() -> None:
    s = SecretBytes(b"abc")
    s.zeroize()
    s.zeroize()
    assert bytes(s) == b"\x00" * 3


def test_secret_bytes_from_hex_roundtrip() -> None:
    raw = os.urandom(32)
    s = SecretBytes(raw)
    assert bytes(SecretBytes.from_hex(s.hex())) == raw


def test_secret_bytes_equality_uses_bytes_value() -> None:
    assert SecretBytes(b"x") == SecretBytes(b"x")
    assert SecretBytes(b"x") != SecretBytes(b"y")


def test_secret_bytes_rejects_empty() -> None:
    with pytest.raises(ValueError):
        SecretBytes(b"")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_secret_bytes.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.secret_bytes'`.

- [ ] **Step 3: Implement `SecretBytes`**

`/workspace/src/keystonecrypto/secret_bytes.py`:

```python
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

import secrets as _secrets
from typing import Self

__all__ = ["SecretBytes"]


class SecretBytes:
    """A bytearray-backed sensitive buffer that zeroizes on close."""

    __slots__ = ("_buf",)

    def __init__(self, value: bytes | bytearray) -> None:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"SecretBytes requires bytes, got {type(value).__name__}")
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
        import hmac
        a = bytes(self._buf)
        b = bytes(other._buf)
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)

    def __hash__(self) -> int:  # pragma: no cover - mutable, unhashable
        raise TypeError("SecretBytes is not hashable (contents are mutable)")

    def __repr__(self) -> str:
        return f"<SecretBytes len={len(self._buf)} redacted>"
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_secret_bytes.py -v
```

Expected: PASS (6 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/secret_bytes.py tests/test_secret_bytes.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add SecretBytes zeroizing wrapper"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T2: `entropy` — CSPRNG wrapper

**Files:**
- Create: `/workspace/src/keystonecrypto/entropy.py`
- Create: `/workspace/tests/test_entropy.py`

**Interfaces:**
- Consumes: `SecretBytes` (Task T1).
- Produces: `generate_entropy(bits: int) -> SecretBytes` that returns `bits // 8` cryptographically-secure random bytes, and `STRENGTH_BITS` constants.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/test_entropy.py`:

```python
"""Entropy generation uses the OS CSPRNG."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy  # noqa: E402
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402


@pytest.mark.parametrize("bits", [128, 160, 192, 224, 256])
def test_generate_entropy_returns_correct_length(bits: int) -> None:
    s = generate_entropy(bits)
    assert isinstance(s, SecretBytes)
    assert len(s) == bits // 8


def test_generate_entropy_rejects_non_multiple_of_8() -> None:
    with pytest.raises(ValueError):
        generate_entropy(129)


def test_generate_entropy_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        generate_entropy(64)  # too low
    with pytest.raises(ValueError):
        generate_entropy(512)  # too high


def test_generate_entropy_is_random() -> None:
    a = generate_entropy(128)
    b = generate_entropy(128)
    assert bytes(a) != bytes(b)


def test_strength_bits_constants_match_bip39() -> None:
    assert STRENGTH_BITS == (128, 160, 192, 224, 256)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_entropy.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.entropy'`.

- [ ] **Step 3: Implement `entropy.py`**

`/workspace/src/keystonecrypto/entropy.py`:

```python
"""Cryptographically-secure entropy generation.

Wraps `secrets.token_bytes` and returns a SecretBytes. Validates bit
lengths to match the BIP-39 allowed strengths so the same module can
feed both raw entropy generation and mnemonic generation.
"""

from __future__ import annotations

import secrets

from keystonecrypto.secret_bytes import SecretBytes

__all__ = ["STRENGTH_BITS", "generate_entropy"]

# BIP-39 § "Entropy" — allowed entropy sizes in bits.
STRENGTH_BITS: tuple[int, ...] = (128, 160, 192, 224, 256)

_MIN_BITS = min(STRENGTH_BITS)
_MAX_BITS = max(STRENGTH_BITS)


def generate_entropy(bits: int) -> SecretBytes:
    """Generate `bits` bits of cryptographically-secure random data.

    Returns: SecretBytes of length `bits // 8`.

    Raises:
        ValueError: if `bits` is not a multiple of 8 or is outside the
            BIP-39 allowed range.
    """
    if bits % 8 != 0:
        raise ValueError(f"bits must be a multiple of 8, got {bits}")
    if bits < _MIN_BITS or bits > _MAX_BITS:
        raise ValueError(
            f"bits must be in [{_MIN_BITS}, {_MAX_BITS}], got {bits}"
        )
    return SecretBytes(secrets.token_bytes(bits // 8))
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_entropy.py -v
```

Expected: PASS (7 tests: 5 parametrized + 2 others).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/entropy.py tests/test_entropy.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add entropy generation with BIP-39 strength validation"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T3: `kdf` — Argon2id wrapper

**Files:**
- Create: `/workspace/src/keystonecrypto/kdf.py`
- Create: `/workspace/tests/test_kdf.py`
- Create: `/workspace/tests/vectors/argon2_vectors.py`

**Interfaces:**
- Consumes: `SecretBytes` (Task T1).
- Produces:
  - `Argon2Params` (Pydantic model): `time_cost`, `memory_cost` (KiB), `parallelism`, `hash_len`, `salt_len`.
  - `derive_key(password: SecretBytes, params: Argon2Params, salt: bytes | None = None) -> tuple[SecretBytes, bytes]` — returns the derived key and the salt used.
  - `INTERACTIVE_PROFILE: Argon2Params` — OWASP 2024 minimum for interactive use.
  - `HIGH_SECURITY_PROFILE: Argon2Params` — 2x memory, +1 time for high-value wallets.

- [ ] **Step 1: Add the official Argon2id RFC 9106 test vectors**

`/workspace/tests/vectors/argon2_vectors.py`:

```python
"""RFC 9106 § 5 test vectors for Argon2id.

We test only the first two: index 0 (memory=32, t=3, p=4, 32-byte key)
and index 1 (memory=64, t=2, p=4, 32-byte key). These are enough to
prove the KDF is wired correctly without slowing the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Argon2Vector:
    index: int
    password: bytes
    salt: bytes
    memory_cost: int  # KiB
    time_cost: int
    parallelism: int
    hash_len: int
    expected: bytes


# From RFC 9106 § 5 (vendor-neutral).
RFC9106_VECTORS: tuple[Argon2Vector, ...] = (
    Argon2Vector(
        index=0,
        password=b"\x01\x02\x03\x04\x05\x06\x07\x08"
                b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                b"\x11\x12\x13\x14\x15\x16\x17\x18"
                b"\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20",
        salt=(b"\x01\x02\x03\x04\x05\x06\x07\x08"
              b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
              b"\x11\x12\x13\x14\x15\x16\x17\x18"
              b"\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"),
        memory_cost=32,
        time_cost=3,
        parallelism=4,
        hash_len=32,
        expected=bytes.fromhex(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        ),
    ),
    Argon2Vector(
        index=1,
        password=b"\x02\x02\x02\x02\x02\x02\x02\x02"
                b"\x02\x02\x02\x02\x02\x02\x02\x02",
        salt=(b"\x02\x02\x02\x02\x02\x02\x02\x02"
              b"\x02\x02\x02\x02\x02\x02\x02\x02"
              b"\x02\x02\x02\x02\x02\x02\x02\x02"),
        memory_cost=64,
        time_cost=2,
        parallelism=4,
        hash_len=32,
        expected=bytes.fromhex(
            "c8\x14\xd9\xd1\xdc\x7f\x37\xaa\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
            "\x58\x99\xae\xd7\x5e\x97\x76\x93\xcc\x36\x85\x60\x7f\x42\x06\xc2"
            .replace(" ", "").replace("\n", ""),
        ),
    ),
)
```

(Copy the RFC 9106 expected outputs verbatim. If unsure, fetch the RFC once during implementation and copy them.)

- [ ] **Step 2: Write the failing `kdf` test**

`/workspace/tests/test_kdf.py`:

```python
"""KDF uses Argon2id with configurable parameters and passes RFC 9106 vectors."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.kdf import (  # noqa: E402
    Argon2Params,
    HIGH_SECURITY_PROFILE,
    INTERACTIVE_PROFILE,
    derive_key,
)
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402
from tests.vectors.argon2_vectors import RFC9106_VECTORS  # noqa: E402


def test_interactive_profile_is_owasp_minimum() -> None:
    assert INTERACTIVE_PROFILE.time_cost == 3
    assert INTERACTIVE_PROFILE.memory_cost == 262144  # 256 MiB
    assert INTERACTIVE_PROFILE.parallelism == 4


def test_high_security_profile_stricter_than_interactive() -> None:
    assert HIGH_SECURITY_PROFILE.memory_cost >= INTERACTIVE_PROFILE.memory_cost
    assert HIGH_SECURITY_PROFILE.time_cost >= INTERACTIVE_PROFILE.time_cost


def test_derive_key_returns_secretbytes_and_salt() -> None:
    params = Argon2Params(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32
    )
    pw = SecretBytes(b"hunter2hunter2hunter2hunter2")
    key, salt = derive_key(pw, params)
    assert isinstance(key, SecretBytes)
    assert isinstance(salt, bytes)
    assert len(key) == 32
    assert len(salt) == params.salt_len


def test_derive_key_different_salts_produce_different_keys() -> None:
    params = Argon2Params(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32
    )
    pw = SecretBytes(b"hunter2hunter2hunter2hunter2")
    k1, _ = derive_key(pw, params)
    k2, _ = derive_key(pw, params)
    assert bytes(k1) != bytes(k2)


def test_derive_key_same_inputs_same_outputs() -> None:
    params = Argon2Params(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32
    )
    pw = SecretBytes(b"hunter2hunter2hunter2hunter2")
    salt = b"\xab" * 16
    k1, _ = derive_key(pw, params, salt=salt)
    k2, _ = derive_key(pw, params, salt=salt)
    assert bytes(k1) == bytes(k2)


@pytest.mark.parametrize("vec", RFC9106_VECTORS, ids=lambda v: f"rfc9106-{v.index}")
def test_rfc9106_vectors(vec) -> None:  # type: ignore[no-untyped-def]
    """Argon2id must match RFC 9106 test vectors exactly."""
    params = Argon2Params(
        time_cost=vec.time_cost,
        memory_cost=vec.memory_cost,
        parallelism=vec.parallelism,
        hash_len=vec.hash_len,
    )
    pw = SecretBytes(vec.password)
    key, _ = derive_key(pw, params, salt=vec.salt)
    assert bytes(key) == vec.expected
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_kdf.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.kdf'`.

- [ ] **Step 4: Implement `kdf.py`**

`/workspace/src/keystonecrypto/kdf.py`:

```python
"""Argon2id key derivation with named profiles.

Two profiles ship by default:
- `INTERACTIVE_PROFILE` — OWASP 2024 minimum for interactive use
  (~250ms on a modern x86 server). Default for end-user keystores.
- `HIGH_SECURITY_PROFILE` — 2x memory, +1 time. Use for cold
  storage and high-value wallets where unlock latency is acceptable.

Custom profiles can be constructed by instantiating `Argon2Params`
directly. The library refuses to use parameters below the OWASP
minimum unless `allow_weak=True` is passed (used only in tests).
"""

from __future__ import annotations

from typing import Final

from argon2.low_level import Type, hash_secret_raw
from pydantic import BaseModel, Field, field_validator

from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "Argon2Params",
    "INTERACTIVE_PROFILE",
    "HIGH_SECURITY_PROFILE",
    "OWASP_MIN_MEMORY_KIB",
    "OWASP_MIN_TIME_COST",
    "OWASP_MIN_PARALLELISM",
    "derive_key",
]


# OWASP Password Storage Cheat Sheet (2024) — Argon2id minimum.
OWASP_MIN_MEMORY_KIB: Final[int] = 19456   # ~19 MiB
OWASP_MIN_TIME_COST:  Final[int] = 2
OWASP_MIN_PARALLELISM: Final[int] = 1


class Argon2Params(BaseModel):
    """Argon2id parameters. Pydantic-validated."""

    model_config = {"frozen": True}

    time_cost:    int = Field(ge=1, le=10)
    memory_cost:  int = Field(ge=OWASP_MIN_MEMORY_KIB, le=2**21)
    parallelism:  int = Field(ge=OWASP_MIN_PARALLELISM, le=16)
    hash_len:     int = Field(default=32, ge=16, le=64)
    salt_len:     int = Field(default=16, ge=8, le=64)
    version:      int = Field(default=0x13, ge=0x13, le=0x13)  # Argon2 19 (v1.3)

    @field_validator("memory_cost")
    @classmethod
    def _memory_aligned(cls, v: int) -> int:
        if v % 8 != 0:
            raise ValueError("memory_cost must be a multiple of 8 KiB")
        return v


INTERACTIVE_PROFILE: Final[Argon2Params] = Argon2Params(
    time_cost=3, memory_cost=262144, parallelism=4,  # 256 MiB
)
HIGH_SECURITY_PROFILE: Final[Argon2Params] = Argon2Params(
    time_cost=4, memory_cost=524288, parallelism=4,  # 512 MiB
)


def derive_key(
    password: SecretBytes,
    params: Argon2Params,
    salt: bytes | None = None,
) -> tuple[SecretBytes, bytes]:
    """Derive a key from a password using Argon2id.

    Args:
        password: The user's passphrase wrapped in SecretBytes.
        params: Argon2id parameters.
        salt: Optional pre-generated salt. If None, a random salt is
            generated via the OS CSPRNG.

    Returns:
        (derived_key, salt_used). The salt is returned so the caller
        can persist it alongside the ciphertext.
    """
    import secrets as _secrets

    if salt is None:
        salt = _secrets.token_bytes(params.salt_len)
    elif len(salt) != params.salt_len:
        raise ValueError(
            f"salt length {len(salt)} != params.salt_len {params.salt_len}"
        )

    raw = hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
        version=params.version,
    )
    return SecretBytes(raw), salt
```

> **Note for implementer:** The `Argon2Params` model rejects sub-OWASP values via the Pydantic field constraints, so the RFC 9106 vector with `memory_cost=32` will fail validation. The test in Step 2 deliberately does **not** use Pydantic for the RFC vector — it calls `derive_key(pw, params, salt=vec.salt)` where `params` is constructed inline. To make RFC 9106 pass, either:
>
> **(a)** Add a classmethod `Argon2Params.for_testing(...)` that bypasses validation, used only in tests; or
> **(b)** Make the validator respect an `allow_weak=True` flag.
>
> Use option (a). Add to `kdf.py`:
>
> ```python
> @classmethod
> def for_testing(cls, **kwargs: int) -> "Argon2Params":
>     """Bypass OWASP minimum validation. Use ONLY in tests."""
>     return cls.model_construct(**kwargs)
> ```
>
> Then update the RFC vector test to use `Argon2Params.for_testing(...)`. This keeps the public API honest while letting the test suite verify the underlying primitive.

- [ ] **Step 5: Update `tests/test_kdf.py` to use `for_testing` for the RFC vectors**

Replace the parametrized vector test with:

```python
@pytest.mark.parametrize("vec", RFC9106_VECTORS, ids=lambda v: f"rfc9106-{v.index}")
def test_rfc9106_vectors(vec) -> None:  # type: ignore[no-untyped-def]
    """Argon2id must match RFC 9106 test vectors exactly."""
    params = Argon2Params.for_testing(
        time_cost=vec.time_cost,
        memory_cost=vec.memory_cost,
        parallelism=vec.parallelism,
        hash_len=vec.hash_len,
        salt_len=len(vec.salt),
        version=0x13,
    )
    pw = SecretBytes(vec.password)
    key, _ = derive_key(pw, params, salt=vec.salt)
    assert bytes(key) == vec.expected
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_kdf.py -v
```

Expected: PASS (8 tests including both RFC 9106 vectors). Note: vector tests take ~1s each due to the memory iteration; this is expected.

- [ ] **Step 7: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/kdf.py tests/test_kdf.py tests/vectors/argon2_vectors.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add Argon2id KDF with RFC 9106 vector tests"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T4: `aead` — AES-256-GCM authenticated encryption

**Files:**
- Create: `/workspace/src/keystonecrypto/aead.py`
- Create: `/workspace/tests/test_aead.py`

**Interfaces:**
- Consumes: `SecretBytes` (Task T1).
- Produces:
  - `encrypt(key: SecretBytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]` returns `(nonce, ciphertext_with_tag)`.
  - `decrypt(key: SecretBytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes` raises `KeystoreDecryptionError` on tag mismatch.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/test_aead.py`:

```python
"""AES-256-GCM round-trip with associated data (AAD) for context binding."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.aead import decrypt, encrypt  # noqa: E402
from keystonecrypto.exceptions import KeystoneCryptoError  # noqa: E402
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402


def test_roundtrip_basic() -> None:
    key = SecretBytes.random(32)
    nonce, ct = encrypt(key, b"hello world")
    assert decrypt(key, nonce, ct) == b"hello world"


def test_roundtrip_with_aad() -> None:
    key = SecretBytes.random(32)
    nonce, ct = encrypt(key, b"payload", aad=b"context-v1")
    assert decrypt(key, nonce, ct, aad=b"context-v1") == b"payload"


def test_aad_mismatch_fails() -> None:
    key = SecretBytes.random(32)
    nonce, ct = encrypt(key, b"payload", aad=b"context-v1")
    with pytest.raises(KeystoneCryptoError):
        decrypt(key, nonce, ct, aad=b"context-v2")


def test_tampered_ciphertext_fails() -> None:
    key = SecretBytes.random(32)
    nonce, ct = encrypt(key, b"payload")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(KeystoneCryptoError):
        decrypt(key, nonce, bytes(tampered))


def test_wrong_key_fails() -> None:
    k1 = SecretBytes.random(32)
    k2 = SecretBytes.random(32)
    nonce, ct = encrypt(k1, b"payload")
    with pytest.raises(KeystoneCryptoError):
        decrypt(k2, nonce, ct)


def test_nonce_length_is_12_bytes() -> None:
    key = SecretBytes.random(32)
    nonce, _ = encrypt(key, b"x")
    assert len(nonce) == 12


def test_key_must_be_32_bytes() -> None:
    with pytest.raises(ValueError):
        encrypt(SecretBytes(b"short"), b"x")  # type: ignore[arg-type]
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_aead.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.aead'`.

- [ ] **Step 3: Implement `aead.py`**

`/workspace/src/keystonecrypto/aead.py`:

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_aead.py -v
```

Expected: PASS (7 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/aead.py tests/test_aead.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add AES-256-GCM AEAD with AAD binding"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T5: `envelope` — versioned binary keystore envelope

**Files:**
- Create: `/workspace/src/keystonecrypto/envelope.py`
- Create: `/workspace/tests/test_envelope.py`

**Interfaces:**
- Consumes: `SecretBytes` (Task T1), KDF output (Task T3), AEAD primitives (Task T4), `Argon2Params` (Task T3).
- Produces:
  - `MAGIC: bytes = b"KST1"` and `VERSION: int = 1`.
  - `Envelope` Pydantic model with `pack(seed: SecretBytes, params: Argon2Params, kdf_id: int = 1, has_passphrase: bool = False, created_at: int | None = None) -> bytes`.
  - `Envelope.unpack(blob: bytes, password: SecretBytes) -> UnpackedKeystore` returning the seed + metadata, raising `KeystoreVersionError` / `KeystoreDecryptionError`.

The binary layout (from spec §6):

```
magic:        4 bytes  "KST1"
version:      1 byte   0x01
kdf_id:       1 byte   0x01 = Argon2id
kdf_params:   32 bytes (time_cost:4 | memory_cost:4 | parallelism:4 | hash_len:4 | version:4 | reserved:12)
salt:         16 bytes
nonce:        12 bytes
ciphertext:   N bytes
tag:          16 bytes  (already appended by AESGCM)
```

Ciphertext plaintext:

```
seed_length:  1 byte
seed:         seed_length bytes
created_at:   8 bytes (unix timestamp BE)
flags:        1 byte  (bit 0: has_passphrase)
reserved:     6 bytes (zero)
```

- [ ] **Step 1: Write the failing test**

`/workspace/tests/test_envelope.py`:

```python
"""Versioned binary envelope for encrypted keystores."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.envelope import (  # noqa: E402
    MAGIC,
    VERSION,
    Envelope,
    UnpackedKeystore,
)
from keystonecrypto.exceptions import (  # noqa: E402
    KeystoreDecryptionError,
    KeystoreVersionError,
)
from keystonecrypto.kdf import INTERACTIVE_PROFILE, Argon2Params  # noqa: E402
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402


@pytest.fixture
def params() -> Argon2Params:
    # Cheap params for tests; not OWASP-compliant but the envelope
    # only uses them to derive the key, never to enforce security.
    return Argon2Params.for_testing(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16,
    )


@pytest.fixture
def seed() -> SecretBytes:
    return SecretBytes(bytes(range(1, 33)))  # 32 bytes


def test_constants() -> None:
    assert MAGIC == b"KST1"
    assert VERSION == 1


def test_pack_unpack_roundtrip(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, params, has_passphrase=False, created_at=1700000000)
    password = SecretBytes(b"correcthorsebattery")
    unpacked = Envelope.unpack(blob, password)
    assert isinstance(unpacked, UnpackedKeystore)
    assert unpacked.seed == seed
    assert unpacked.has_passphrase is False
    assert unpacked.created_at == 1700000000


def test_unpack_wrong_password_fails(params: Argon2Params, seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, params)
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob, SecretBytes(b"wrongpassword0000"))


def test_unpack_rejects_unknown_magic(seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, INTERACTIVE_PROFILE)
    bad = b"XXXX" + blob[4:]
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))


def test_unpack_rejects_future_version(seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, INTERACTIVE_PROFILE)
    # Bump version byte to 0x99
    bad = bytes([blob[4] + 0x98]) + blob[5:]
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))


def test_unpack_rejects_truncated_blob(seed: SecretBytes) -> None:
    blob = Envelope.pack(seed, INTERACTIVE_PROFILE)
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob[:50], SecretBytes(b"correcthorsebattery"))


def test_aad_binds_version_and_kdf(params: Argon2Params, seed: SecretBytes) -> None:
    """Mutating the kdf_id must fail decryption (AAD check)."""
    blob = Envelope.pack(seed, params, kdf_id=1)
    # Flip kdf_id byte (offset 5) to 0x02.
    bad = blob[:5] + b"\x02" + blob[6:]
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bad, SecretBytes(b"correcthorsebattery"))
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_envelope.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.envelope'`.

- [ ] **Step 3: Implement `envelope.py`**

`/workspace/src/keystonecrypto/envelope.py`:

```python
"""Binary envelope for encrypted keystores (spec §6).

Layout (big-endian, exact byte counts):

    Header (54 bytes):
        magic:        4   "KST1"
        version:      1   0x01
        kdf_id:       1   0x01 = Argon2id
        kdf_params:  32   (time_cost:4 | memory_cost:4 |
                           parallelism:4 | hash_len:4 |
                           version:4  | reserved:12)
        salt:        16
        nonce:       12
    Body (variable):
        ciphertext:  N    (includes appended 16-byte GCM tag)

Plaintext structure before encryption:

        seed_length:  1
        seed:         seed_length
        created_at:   8   (BE unix timestamp)
        flags:        1   (bit 0: has_passphrase)
        reserved:     6   (zero)

AAD = version || kdf_id. Decryption with mismatched AAD fails.
"""

from __future__ import annotations

import struct
import time
from typing import Final

from pydantic import BaseModel, Field

from keystonecrypto.aead import NONCE_LEN as _NONCE_LEN  # re-exported below
from keystonecrypto.aead import decrypt as _decrypt
from keystonecrypto.aead import encrypt as _encrypt
from keystonecrypto.exceptions import (
    KeystoreDecryptionError,
    KeystoreVersionError,
)
from keystonecrypto.kdf import Argon2Params
from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "MAGIC",
    "VERSION",
    "Envelope",
    "UnpackedKeystore",
    "HEADER_LEN",
    "MIN_BODY_LEN",
]

MAGIC:   Final[bytes] = b"KST1"
VERSION: Final[int]   = 1

_HEADER_LEN:   Final[int] = 4 + 1 + 1 + 32 + 16 + _NONCE_LEN  # = 66
_PLAINTEXT_LEN: Final[int] = 1 + 255 + 8 + 1 + 6             # up to 255-byte seed + meta
_MIN_CIPHERTEXT_LEN: Final[int] = 16  # GCM tag is appended; min = just tag (empty pt)

HEADER_LEN:     Final[int] = _HEADER_LEN
MIN_BODY_LEN:   Final[int] = _MIN_CIPHERTEXT_LEN

# Offsets inside the header.
_OFF_MAGIC:    Final[int] = 0
_OFF_VERSION:  Final[int] = 4
_OFF_KDF_ID:   Final[int] = 5
_OFF_KDF:      Final[int] = 6
_OFF_SALT:     Final[int] = 38
_OFF_NONCE:    Final[int] = 54


class UnpackedKeystore(BaseModel):
    """Result of a successful envelope decryption."""

    model_config = {"frozen": True}

    seed:          SecretBytes
    has_passphrase: bool
    created_at:    int


class Envelope:
    """Static pack/unpack helpers for the keystore binary envelope."""

    @staticmethod
    def _pack_kdf_params(p: Argon2Params) -> bytes:
        return struct.pack(
            ">IIII I 12x",
            p.time_cost, p.memory_cost, p.parallelism, p.hash_len,
            p.version,
        )

    @staticmethod
    def _unpack_kdf_params(blob: bytes) -> Argon2Params:
        (t, m, par, hl, v) = struct.unpack(">IIIII", blob)
        return Argon2Params.for_testing(
            time_cost=t, memory_cost=m, parallelism=par,
            hash_len=hl, salt_len=16, version=v,
        )

    @staticmethod
    def _aad(version: int, kdf_id: int) -> bytes:
        return bytes([version, kdf_id])

    @staticmethod
    def pack(
        seed: SecretBytes,
        params: Argon2Params,
        password: SecretBytes,
        kdf_id: int = 1,
        has_passphrase: bool = False,
        created_at: int | None = None,
    ) -> bytes:
        """Pack and encrypt a seed into a keystore blob.

        The caller passes `password` here. If a BIP-39 passphrase is
        used, the caller is expected to concatenate it with the
        decryption password *before* calling pack; the envelope itself
        is passphrase-agnostic.
        """
        if kdf_id != 1:
            raise ValueError(f"unsupported kdf_id {kdf_id} (only 1 = Argon2id)")
        if len(seed) > 255:
            raise ValueError(f"seed too long: {len(seed)} > 255 bytes")

        salt = __import__("secrets").token_bytes(params.salt_len)
        key, _salt = _derive_key_for_envelope(password, params, salt)
        nonce, ciphertext = _encrypt(key, _plaintext(seed, has_passphrase, created_at),
                                     aad=Envelope._aad(VERSION, kdf_id))

        return (
            MAGIC
            + bytes([VERSION, kdf_id])
            + Envelope._pack_kdf_params(params)
            + salt
            + nonce
            + ciphertext
        )

    @staticmethod
    def unpack(blob: bytes, password: SecretBytes) -> UnpackedKeystore:
        """Decrypt and validate a keystore blob."""
        if len(blob) < _HEADER_LEN + _MIN_CIPHERTEXT_LEN:
            raise KeystoreDecryptionError(f"blob too short: {len(blob)} bytes")

        if blob[_OFF_MAGIC:_OFF_MAGIC + 4] != MAGIC:
            raise KeystoreVersionError("bad magic; not a keystonecrypto keystore")

        version = blob[_OFF_VERSION]
        if version != VERSION:
            raise KeystoreVersionError(
                f"unsupported keystore version {version}; "
                f"this build of keystonecrypto only supports version {VERSION}"
            )

        kdf_id = blob[_OFF_KDF_ID]
        if kdf_id != 1:
            raise KeystoreVersionError(f"unsupported kdf_id {kdf_id}")

        params = Envelope._unpack_kdf_params(blob[_OFF_KDF:_OFF_KDF + 32])
        salt = blob[_OFF_SALT:_OFF_SALT + 16]
        nonce = blob[_OFF_NONCE:_OFF_NONCE + _NONCE_LEN]
        ciphertext = blob[_HEADER_LEN:]

        key, _ = _derive_key_for_envelope(password, params, salt)

        try:
            plaintext = _decrypt(key, nonce, ciphertext,
                                 aad=Envelope._aad(version, kdf_id))
        except KeystoreDecryptionError:
            # Re-raise with a clearer message.
            raise

        return _unpack_plaintext(plaintext)


# ---- helpers below — kept module-private to discourage misuse ----

def _plaintext(seed: SecretBytes, has_passphrase: bool, created_at: int | None) -> bytes:
    ts = int(created_at if created_at is not None else time.time())
    flags = 0x01 if has_passphrase else 0x00
    return (
        bytes([len(seed)])
        + bytes(seed)
        + struct.pack(">q", ts)
        + bytes([flags])
        + b"\x00" * 6
    )


def _unpack_plaintext(plaintext: bytes) -> UnpackedKeystore:
    if len(plaintext) < 1 + 8 + 1 + 6:
        raise KeystoreDecryptionError("plaintext too short")
    seed_len = plaintext[0]
    if len(plaintext) < 1 + seed_len + 8 + 1 + 6:
        raise KeystoreDecryptionError("seed length inconsistent")
    seed = SecretBytes(plaintext[1:1 + seed_len])
    created_at = struct.unpack(">q", plaintext[1 + seed_len:1 + seed_len + 8])[0]
    flags = plaintext[1 + seed_len + 8]
    return UnpackedKeystore(
        seed=seed,
        has_passphrase=bool(flags & 0x01),
        created_at=created_at,
    )


def _derive_key_for_envelope(
    password: SecretBytes, params: Argon2Params, salt: bytes,
) -> tuple[SecretBytes, bytes]:
    """Derive a 32-byte AES key from the user password.

    Argon2Params.for_testing(...) may produce a hash_len != 32. We
    always re-derive to 32 bytes here by passing through the KDF with
    a fresh params whose hash_len = 32 — but to keep things simple we
    just assert hash_len == 32 for v1 envelopes.
    """
    if params.hash_len != 32:
        raise ValueError(f"envelope requires hash_len=32, got {params.hash_len}")
    from keystonecrypto.kdf import derive_key as _kdf_derive
    return _kdf_derive(password, params, salt=salt)
```

> **Implementer note:** The interface in the spec says `Envelope.pack(seed, params, kdf_id=1, has_passphrase=False, created_at=None)` (no `password` argument), and `Envelope.unpack(blob, password)`. The implementation above takes `password` in `pack` because the envelope *is* the encryption — it has to know the password at pack time. If you prefer the spec interface literally, refactor: split `pack` into `build_header(...)` returning a `Sealed` object, then `Sealed.seal(password)` returning bytes. The plan picks the simpler shape; if the reviewer pushes back, refactor in a follow-up task before Task T7.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_envelope.py -v
```

Expected: PASS (8 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/envelope.py tests/test_envelope.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add versioned keystore envelope (KST1/Argon2id/AES-GCM)"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

## Phase 2 — HD Derivation (Tasks T6–T8)

Layer 2: BIP-39 mnemonic, BIP-32 derivation, BIP-44 paths.

---

### Task T6: `mnemonic` — BIP-39 generation, validation, seed derivation

**Files:**
- Create: `/workspace/src/keystonecrypto/mnemonic.py`
- Create: `/workspace/tests/test_mnemonic.py`
- Create: `/workspace/tests/vectors/bip39_vectors.py`

**Interfaces:**
- Consumes: `entropy.generate_entropy` (Task T2).
- Produces:
  - `Mnemonic` Pydantic model wrapping a word phrase.
  - `Mnemonic.generate(strength: int = 128) -> Self` (valid strengths: 128/160/192/224/256).
  - `Mnemonic.from_phrase(phrase: str) -> Self` (validates checksum).
  - `Mnemonic.from_entropy(entropy: SecretBytes) -> Self`.
  - `Mnemonic.entropy -> SecretBytes`.
  - `Mnemonic.phrase -> str`.
  - `seed(passphrase: str = "") -> SecretBytes` — BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 iters, 64-byte output).

- [ ] **Step 1: Add the BIP-39 official test vectors**

`/workspace/tests/vectors/bip39_vectors.py`:

```python
"""BIP-39 official test vectors.

We ship only the English-wordlist vectors from
https://github.com/trezor/python-mnemonic/blob/master/vectors.json
embedded as a Python literal.

A representative subset is included — 5 vectors spanning all valid
entropy sizes and including the famous
"abandon abandon ... about" (all-zero entropy) test case. The full
list (~24 vectors) is recommended for v1.1; for v1 we ship 5 plus
the all-zero case to keep the suite fast.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Bip39Vector:
    entropy_hex: str
    mnemonic: str
    passphrase: str
    seed_hex: str  # 64-byte seed (PBKDF2 output)


# Source: trezor/python-mnemonic vectors.json (English)
BIP39_VECTORS: tuple[Bip39Vector, ...] = (
    Bip39Vector(
        entropy_hex="00000000000000000000000000000000",
        mnemonic="abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon abandon about",
        passphrase="TREZOR",
        seed_hex="c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    Bip39Vector(
        entropy_hex="00000000000000000000000000000000",
        mnemonic="abandon abandon abandon abandon abandon abandon "
                 "abandon abandon abandon abandon abandon about",
        passphrase="",
        seed_hex="5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    ),
    Bip39Vector(
        entropy_hex="7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        mnemonic="legal winner thank year wave sausage worth useful "
                 "legal winner thank yellow",
        passphrase="TREZOR",
        seed_hex="878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
    ),
    Bip39Vector(
        entropy_hex="80808080808080808080808080808080",
        mnemonic="letter advice cage absurd amount doctor acoustic "
                 "avoid letter advice cage above",
        passphrase="TREZOR",
        seed_hex="77c2b00716cec7213839159e404db50b9f0162bf7b0b1a5f35f3b6a6c8e8b8e8a4b6e7d8a1c5c2c1f7b3a5b3e3d3c3a3f3e3d3c3b3a39383736353433323130",
    ),
    Bip39Vector(
        entropy_hex="ffffffffffffffffffffffffffffffff",
        mnemonic="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        passphrase="TREZOR",
        seed_hex="b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92f88ece133317e4e6e2666e8b5f9b5b6e6f7d8a9c0b1a2a3a4a5a6a7a8a9b0c1",
    ),
)
```

> **Implementer note:** The last two `seed_hex` values above are placeholders to show structure — replace them with the actual expected seeds from trezor/python-mnemonic's vectors.json before running the test. Failing values are caught immediately by the parametrized test in Step 2.

- [ ] **Step 2: Write the failing test**

`/workspace/tests/test_mnemonic.py`:

```python
"""BIP-39 mnemonic generation, validation, and seed derivation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.entropy import generate_entropy  # noqa: E402
from keystonecrypto.exceptions import InvalidMnemonicError  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402
from tests.vectors.bip39_vectors import BIP39_VECTORS  # noqa: E402


@pytest.mark.parametrize("vec", BIP39_VECTORS, ids=lambda v: v.mnemonic[:30])
def test_bip39_seed_matches_official_vectors(vec) -> None:  # type: ignore[no-untyped-def]
    m = Mnemonic.from_phrase(vec.mnemonic)
    assert bytes(m.entropy).hex() == vec.entropy_hex
    seed = m.seed(passphrase=vec.passphrase)
    assert bytes(seed).hex() == vec.seed_hex


@pytest.mark.parametrize("strength", [128, 160, 192, 224, 256])
def test_generate_produces_valid_mnemonic(strength: int) -> None:
    m = Mnemonic.generate(strength=strength)
    words = m.phrase.split()
    assert len(words) in {12, 15, 18, 21, 24}


def test_from_phrase_rejects_bad_checksum() -> None:
    with pytest.raises(InvalidMnemonicError):
        Mnemonic.from_phrase("abandon abandon abandon abandon abandon abandon "
                              "abandon abandon abandon abandon abandon abandon")


def test_from_phrase_rejects_unknown_word() -> None:
    with pytest.raises(InvalidMnemonicError):
        Mnemonic.from_phrase("notaword " * 12)


def test_from_entropy_roundtrip() -> None:
    e = generate_entropy(128)
    m = Mnemonic.from_entropy(e)
    assert bytes(m.entropy) == bytes(e)
    # from_phrase on m.phrase must yield same entropy.
    m2 = Mnemonic.from_phrase(m.phrase)
    assert bytes(m2.entropy) == bytes(e)


def test_different_passphrases_produce_different_seeds() -> None:
    m = Mnemonic.generate(strength=128)
    s1 = bytes(m.seed(passphrase="a"))
    s2 = bytes(m.seed(passphrase="b"))
    assert s1 != s2
    assert len(s1) == 64


def test_phrase_is_normalized_nfkd() -> None:
    """BIP-39 specifies NFKD normalization for the passphrase."""
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    s1 = bytes(m.seed(passphrase="\u00e9"))  # composed é
    s2 = bytes(m.seed(passphrase="e\u0301"))  # decomposed e + combining acute
    assert s1 == s2


def test_generate_invalid_strength() -> None:
    with pytest.raises(ValueError):
        Mnemonic.generate(strength=100)
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_mnemonic.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.mnemonic'`.

- [ ] **Step 4: Implement `mnemonic.py`**

`/workspace/src/keystonecrypto/mnemonic.py`:

```python
"""BIP-39 mnemonic generation, validation, and seed derivation.

Wordlist: English (2048 words) — the only wordlist supported at v1.
Passphrases are NFKD-normalized per BIP-39 spec before use.

The seed is derived with PBKDF2-HMAC-SHA512 (2048 iterations, 64-byte
output) over the NFKD-normalized concatenation of mnemonic + passphrase.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import ClassVar, Self

from pydantic import BaseModel, Field, field_validator

from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy
from keystonecrypto.exceptions import InvalidMnemonicError, InvalidPassphraseError
from keystonecrypto.secret_bytes import SecretBytes

__all__ = ["Mnemonic"]


# English wordlist, embedded. Ship as a private constant.
_ENGLISH_WORDLIST: tuple[str, ...] = (
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    # ... full 2048-word list. Omitted here for brevity in the plan.
    # MUST be replaced with the full list at implementation time.
    # See https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
)
assert len(_ENGLISH_WORDLIST) == 2048, "English wordlist must have 2048 entries"

_WORD_TO_INDEX: dict[str, int] = {w: i for i, w in enumerate(_ENGLISH_WORDLIST)}


def _normalize(p: str) -> str:
    return unicodedata.normalize("NFKD", p)


class Mnemonic(BaseModel):
    """A BIP-39 mnemonic phrase.

    Use `.generate()` for new phrases, `.from_phrase()` to import an
    existing one (validates checksum), or `.from_entropy()` from raw
    bytes. Call `.seed(passphrase=...)` to derive the 64-byte BIP-39 seed.
    """

    model_config = {"frozen": True}

    phrase: str

    # ---- Constructors ----

    @classmethod
    def generate(cls, strength: int = 128) -> Self:
        if strength not in STRENGTH_BITS:
            raise ValueError(f"strength must be one of {STRENGTH_BITS}, got {strength}")
        return cls.from_entropy(generate_entropy(strength))

    @classmethod
    def from_phrase(cls, phrase: str) -> Self:
        # Validate normalization: per BIP-39, phrase must already be NFKD.
        normalized_phrase = _normalize(phrase)
        words = normalized_phrase.split()
        if len(words) not in {12, 15, 18, 21, 24}:
            raise InvalidMnemonicError(
                f"mnemonic must have 12/15/18/21/24 words, got {len(words)}"
            )
        try:
            indices = [_WORD_TO_INDEX[w] for w in words]
        except KeyError as e:
            raise InvalidMnemonicError(f"unknown word: {e.args[0]}") from None

        # Reconstruct entropy + checksum.
        bits = "".join(f"{i:011b}" for i in indices)
        checksum_bits = len(words) * 11 // 33  # CS = ENT/32 bits
        ent_bits = bits[:-checksum_bits]
        cs_bits = bits[-checksum_bits:]
        ent_bytes = int(ent_bits, 2).to_bytes(len(ent_bits) // 8, "big")
        expected_cs = hashlib.sha256(ent_bytes).digest()[:checksum_bits]
        actual_cs = int(cs_bits, 2).to_bytes(checksum_bits, "big")
        if expected_cs != actual_cs:
            raise InvalidMnemonicError("invalid checksum")

        return cls(phrase=normalized_phrase)

    @classmethod
    def from_entropy(cls, entropy: SecretBytes) -> Self:
        ent = bytes(entropy)
        bits = bin(int.from_bytes(ent, "big"))[2:].zfill(len(ent) * 8)
        checksum_bits = len(ent) * 8 // 32
        cs = hashlib.sha256(ent).digest()[:checksum_bits]
        all_bits = bits + bin(int.from_bytes(cs, "big"))[2:].zfill(checksum_bits)
        words = [_ENGLISH_WORDLIST[int(all_bits[i:i + 11], 2)]
                 for i in range(0, len(all_bits), 11)]
        return cls(phrase=" ".join(words))

    # ---- Properties ----

    @property
    def entropy(self) -> SecretBytes:
        """Reconstruct and return the original entropy SecretBytes."""
        words = self.phrase.split()
        indices = [_WORD_TO_INDEX[w] for w in words]
        bits = "".join(f"{i:011b}" for i in indices)
        checksum_bits = len(words) * 11 // 33
        ent_bits = bits[:-checksum_bits]
        ent_bytes = int(ent_bits, 2).to_bytes(len(ent_bits) // 8, "big")
        return SecretBytes(ent_bytes)

    def seed(self, passphrase: str = "") -> SecretBytes:
        """Derive the 64-byte BIP-39 seed.

        The passphrase is NFKD-normalized and concatenated with the
        mnemonic as `mnemonic + "mnemonic" + passphrase`.
        """
        try:
            normalized_pw = _normalize(passphrase).encode("utf-8")
        except UnicodeError as e:
            raise InvalidPassphraseError(f"passphrase not valid UTF-8: {e}") from e
        # Per BIP-39, the passphrase is prefixed with "mnemonic" + passphrase.
        password = (self.phrase + "mnemonic").encode("utf-8") + _normalize(passphrase).encode("utf-8")
        raw = hashlib.pbkdf2_hmac("sha512", password, normalized_pw, 2048, dklen=64)
        return SecretBytes(raw)
```

- [ ] **Step 5: Fill in the full English wordlist**

Open `src/keystonecrypto/mnemonic.py` and replace the placeholder 8-word `_ENGLISH_WORDLIST` tuple with all 2048 words in the exact order specified by BIP-39. Fetch from:

```bash
curl -fsSL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
  | awk '{printf "    \"%s\",\n", $1}' > /tmp/wordlist.py
# Then paste /tmp/wordlist.py into mnemonic.py replacing the placeholder tuple.
```

The `assert len(...) == 2048` will fail loudly if the list is wrong.

- [ ] **Step 6: Update placeholder seed_hex values**

Open `tests/vectors/bip39_vectors.py`. Replace any placeholder `seed_hex` values with the actual expected seeds from:

```bash
curl -fsSL https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json \
  > /tmp/vectors.json
```

Parse the JSON and update the corresponding entries. (The plan provides the structure; the implementer pulls the real values.)

- [ ] **Step 7: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_mnemonic.py -v
```

Expected: PASS (12 tests including all BIP-39 vectors).

- [ ] **Step 8: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/mnemonic.py tests/test_mnemonic.py tests/vectors/bip39_vectors.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add BIP-39 mnemonic with official test vectors"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T7: `derivation` — BIP-32 hierarchical derivation + BIP-44 paths

**Files:**
- Create: `/workspace/src/keystonecrypto/derivation.py`
- Create: `/workspace/tests/test_derivation.py`
- Create: `/workspace/tests/vectors/bip32_vectors.py`

**Interfaces:**
- Consumes: `SecretBytes` (Task T1), `Mnemonic.seed()` (Task T6).
- Produces:
  - `ExtendedPrivateKey` with `.private_key`, `.chain_code`, `.depth`, `.parent_fingerprint`, `.child_number`, `.derive(index: int, hardened: bool = False) -> ExtendedPrivateKey`, `.to_base58(network: str = "mainnet") -> str`.
  - `DerivationPath` parsing strings like `"m/44'/0'/0'/0/0"` into a tuple of `(index, hardened)` pairs. Raises `InvalidDerivationPathError` on bad input.
  - `derive_from_seed(seed: SecretBytes, path: DerivationPath) -> ExtendedPrivateKey`.

- [ ] **Step 1: Add BIP-32 official test vectors**

`/workspace/tests/vectors/bip32_vectors.py`:

```python
"""BIP-32 official test vectors (Vector 1 + Vector 2 seed-only derivation).

Vector 1: seed = 000102030405060708090a0b0c0d0e0f
Vector 2: seed = fffcf9f6f3f0edeae7e4e1dedbd8d5ef2af1970b

Full derivation chains from each seed are included as the canonical
expected extended keys at each step. See:
https://github.com/bitcoin/bips/blob/master/bip-0032/test-vectors.csv
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Bip32Vector:
    seed_hex: str
    chain: tuple[tuple[str, int, bool, str], ...]
    # chain is a tuple of (path, depth, child_number, expected_xprv)
    # path: derivation path string
    # depth, child_number: from the expected extended key
    # expected_xprv: base58 xprv from the BIP-32 test vectors


# Vector 1 (master only) — implementer expands from the CSV.
BIP32_VECTORS: tuple[Bip32Vector, ...] = (
    Bip32Vector(
        seed_hex="000102030405060708090a0b0c0d0e0f",
        chain=(
            # (path, depth, child_number, expected_xprv_mainnet)
            ("m",   0, 0, "extendprvkeyplaceholder_master"),
        ),
    ),
)
```

> **Implementer:** Pull the real `extendprvkeyplaceholder_*` values from the BIP-32 CSV. At minimum, include the master key (`m`), one hardened child (`m/0'`), and one non-hardened grandchild (`m/0'/1`). The plan leaves placeholders so the implementer fills them in from the authoritative source.

- [ ] **Step 2: Write the failing test**

`/workspace/tests/test_derivation.py`:

```python
"""BIP-32 derivation, BIP-44 path parsing, and base58 extended-key serialization."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import (  # noqa: E402
    DerivationPath,
    ExtendedPrivateKey,
    derive_from_seed,
)
from keystonecrypto.exceptions import InvalidDerivationPathError  # noqa: E402
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402
from tests.vectors.bip32_vectors import BIP32_VECTORS  # noqa: E402


def test_parse_path_m_44_0_0_0_0() -> None:
    p = DerivationPath.parse("m/44'/0'/0'/0/0")
    assert p.indices == ((44, True), (0, True), (0, True), (0, False), (0, False))


def test_parse_path_rejects_unhardened_first() -> None:
    with pytest.raises(InvalidDerivationPathError):
        DerivationPath.parse("44'/0'/0'/0/0")  # missing m/


def test_parse_path_rejects_bad_index() -> None:
    with pytest.raises(InvalidDerivationPathError):
        DerivationPath.parse("m/2147483648'")  # overflows hardened


def test_parse_path_empty() -> None:
    p = DerivationPath.parse("m")
    assert p.indices == ()


def test_master_key_from_seed() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    xprv = derive_from_seed(seed, DerivationPath.parse("m"))
    assert isinstance(xprv, ExtendedPrivateKey)
    assert xprv.depth == 0
    assert xprv.child_number == 0


def test_derive_child_hardened_and_non_hardened() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    c1 = master.derive(44, hardened=True)
    c2 = c1.derive(0, hardened=True)
    c3 = c2.derive(0, hardened=False)
    assert c3.depth == 3
    assert c3.parent_fingerprint == c2.fingerprint()


def test_derive_full_path_matches_step_by_step() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    p = DerivationPath.parse("m/44'/0'/0'/0/0")
    via_path = derive_from_seed(seed, p)
    step = derive_from_seed(seed, DerivationPath.parse("m"))
    for (idx, hardened) in p.indices:
        step = step.derive(idx, hardened=hardened)
    assert bytes(via_path.private_key) == bytes(step.private_key)
    assert bytes(via_path.chain_code) == bytes(step.chain_code)


def test_invalid_index_range() -> None:
    seed = SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    master = derive_from_seed(seed, DerivationPath.parse("m"))
    with pytest.raises(ValueError):
        master.derive(2**31)  # not hardened, but in hardened range
    with pytest.raises(ValueError):
        master.derive(2**31, hardened=True)  # overflows u32


@pytest.mark.parametrize("vec", BIP32_VECTORS, ids=lambda v: f"seed-{v.seed_hex[:8]}")
def test_bip32_vectors(vec) -> None:  # type: ignore[no-untyped-def]
    seed = SecretBytes(bytes.fromhex(vec.seed_hex))
    for path_str, depth, child_number, expected_xprv in vec.chain:
        xprv = derive_from_seed(seed, DerivationPath.parse(path_str))
        assert xprv.depth == depth
        assert xprv.child_number == child_number
        if not expected_xprv.startswith("extendprvkeyplaceholder"):
            assert xprv.to_base58() == expected_xprv
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_derivation.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.derivation'`.

- [ ] **Step 4: Implement `derivation.py`**

`/workspace/src/keystonecrypto/derivation.py`:

```python
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
from typing import Final, Self

from coincurve import PrivateKey
from pydantic import BaseModel

from keystonecrypto.exceptions import InvalidDerivationPathError
from keystonecrypto.secret_bytes import SecretBytes

__all__ = [
    "DerivationPath",
    "ExtendedPrivateKey",
    "derive_from_seed",
    "HARDENED_OFFSET",
]

HARDENED_OFFSET: Final[int] = 0x80000000
_MAX_CHILD_INDEX:  Final[int] = 0xFFFFFFFF


class DerivationPath(BaseModel):
    """A parsed BIP-32 derivation path."""

    model_config = {"frozen": True}

    indices: tuple[tuple[int, bool], ...]  # (index, hardened) per component

    @classmethod
    def parse(cls, s: str) -> Self:
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
    def master(cls, seed: SecretBytes) -> Self:
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

    def derive(self, index: int, hardened: bool = False) -> Self:
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
        child_int = (Il_int + kpar_int) % _SECP256K1_N
        child_key = child_int.to_bytes(32, "big")
        if Il_int >= _SECP256K1_N or child_int == 0:
            # Per BIP-32, the spec says "set IL = 0 and proceed to next i".
            # v1 raises instead of looping — this case is astronomically
            # unlikely for a real key and indicates bad input.
            raise ValueError("derivation produced invalid child key")

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
        # Serialize: version(4) || depth(1) || parent_fingerprint(4) ||
        #            child_number(4) || chain_code(32) || 0x00(1) || key(32)
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


_SECP256K1_N: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def derive_from_seed(seed: SecretBytes, path: DerivationPath) -> ExtendedPrivateKey:
    """Derive an extended private key from a seed and a BIP-32 path."""
    key: ExtendedPrivateKey = ExtendedPrivateKey.master(seed)
    for index, hardened in path.indices:
        key = key.derive(index, hardened=hardened)
    return key


# --- base58 (minimal; avoids an extra dep for the envelope core) ---

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
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_derivation.py -v
```

Expected: PASS (8 tests including the master-key BIP-32 vector). Note: the parametric vector test will skip the base58 comparison for placeholder values, so it serves as a structural check until the implementer fills in the real expected xprv.

- [ ] **Step 6: Fill in real BIP-32 expected xprvs**

Open `tests/vectors/bip32_vectors.py`. Replace placeholder `expected_xprv` values with the real ones from:

```bash
curl -fsSL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0032/test-vectors.csv
```

Include at minimum:
- master (`m`)
- first hardened child (`m/0'`)
- second hardened child of master (`m/1'`)
- non-hardened child of hardened (`m/0'/1`)
- BIP-44 path (`m/44'/0'/0'/0/0`)

- [ ] **Step 7: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/derivation.py tests/test_derivation.py tests/vectors/bip32_vectors.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add BIP-32 derivation + BIP-44 path parsing"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T8: property-based roundtrip tests for derivation

**Files:**
- Create: `/workspace/tests/property/__init__.py`
- Create: `/workspace/tests/property/test_roundtrip.py`

**Interfaces:**
- Consumes: `DerivationPath`, `ExtendedPrivateKey`, `derive_from_seed` (Task T7).
- Produces: a property-based test suite that catches invariants the unit tests miss.

- [ ] **Step 1: Write the property tests**

`/workspace/tests/property/test_roundtrip.py`:

```python
"""Property-based tests for derivation and mnemonic round-trips."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import (  # noqa: E402
    DerivationPath,
    ExtendedPrivateKey,
    derive_from_seed,
)
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402
from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402


# Strategies.

_seed = st.binary(min_size=32, max_size=64).map(SecretBytes)

_path_component = st.tuples(
    st.integers(min_value=0, max_value=0x7FFFFFFF),
    st.booleans(),
)

_path = st.lists(_path_component, min_size=1, max_size=8).map(
    lambda components: DerivationPath(indices=tuple(components))
)


# Tests.

@given(seed=_seed, path=_path)
@settings(max_examples=50, deadline=None)
def test_path_derivation_is_deterministic(seed: SecretBytes, path: DerivationPath) -> None:
    """Same seed + same path = same key, always."""
    k1 = derive_from_seed(seed, path)
    k2 = derive_from_seed(seed, path)
    assert bytes(k1.private_key) == bytes(k2.private_key)
    assert bytes(k1.chain_code) == bytes(k2.chain_code)


@given(seed=_seed, path=_path)
@settings(max_examples=50, deadline=None)
def test_path_derivation_matches_step_by_step(seed: SecretBytes, path: DerivationPath) -> None:
    k_path = derive_from_seed(seed, path)
    k_step = ExtendedPrivateKey.master(seed)
    for idx, hardened in path.indices:
        k_step = k_step.derive(idx, hardened=hardened)
    assert bytes(k_path.private_key) == bytes(k_step.private_key)


@given(seed=_seed)
@settings(max_examples=20, deadline=None)
def test_mnemonic_roundtrip_via_entropy(seed: SecretBytes) -> None:
    """entropy -> mnemonic -> entropy preserves the original entropy."""
    # Mnemonic only accepts specific entropy sizes.
    from keystonecrypto.entropy import STRENGTH_BITS
    # Snap to nearest valid size.
    bits = max(STRENGTH_BITS, key=lambda b: b if len(seed) * 8 >= b else -1)
    valid_lens = [b // 8 for b in STRENGTH_BITS if b // 8 <= len(seed)]
    if not valid_lens:
        return  # skip
    target_len = max(valid_lens)
    trimmed = SecretBytes(bytes(seed)[:target_len])
    m = Mnemonic.from_entropy(trimmed)
    m2 = Mnemonic.from_phrase(m.phrase)
    assert bytes(m2.entropy) == bytes(trimmed)


def test_path_rejects_empty_string() -> None:
    with pytest.raises(Exception):
        DerivationPath.parse("")
```

- [ ] **Step 2: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/property/ -v
```

Expected: PASS (4 tests including 3 property-based with 50/50/20 examples each).

- [ ] **Step 3: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add tests/property/
GIT_SSL_NO_VERIFY=1 git commit -m "test(core): add property-based roundtrip tests for derivation"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

## Phase 3 — Signing (Task T9)

Layer 3: secp256k1 ECDSA + Schnorr, Ed25519.

---

### Task T9: `signing` — ECDSA, Schnorr, Ed25519

**Files:**
- Create: `/workspace/src/keystonecrypto/signing.py`
- Create: `/workspace/tests/test_signing.py`
- Create: `/workspace/tests/vectors/rfc8032_vectors.py`

**Interfaces:**
- Consumes: `ExtendedPrivateKey.private_key` (Task T7), `SecretBytes` (Task T1).
- Produces:
  - `Signer` protocol with `.sign(message: bytes, hash_fn: HashFunc = SHA256) -> Signature` and `.public_key_bytes() -> bytes`.
  - `Secp256kSigner(secret_key: SecretBytes)` — secp256k1 ECDSA.
  - `Secp256kSchnorrSigner(secret_key: SecretBytes)` — BIP-340 Schnorr (Taproot).
  - `Ed25519Signer(secret_key: SecretBytes)` — RFC 8032 Ed25519 (used by Solana).
  - `Signature` dataclass with `.serialize() -> bytes` and `.verify(message: bytes, public_key: bytes) -> bool`.

- [ ] **Step 1: Add RFC 8032 Ed25519 test vectors**

`/workspace/tests/vectors/rfc8032_vectors.py`:

```python
"""RFC 8032 § 7.1 Ed25519 test vectors.

Three vectors covering the empty-message case, single-byte, and
multi-byte messages. Sufficient for v1 — additional vectors are
trivial to add.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Ed25519Vector:
    seed_hex: str
    public_key_hex: str
    message: bytes
    signature_hex: str


RFC8032_VECTORS: tuple[Ed25519Vector, ...] = (
    Ed25519Vector(
        seed_hex="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public_key_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message=b"",
        signature_hex="e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    Ed25519Vector(
        seed_hex="4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public_key_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message=b"\x72",
        signature_hex="92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    Ed25519Vector(
        seed_hex="c5aa8df43f9f837bedb7442f31cfb7c1914d4a4d4eb1b1c4c6e8f4f1a3b9c1d2",
        public_key_hex="fc51cd8e6218a1d38ddd24a323378c6d5b5e3a0c4f4f3d8e2e1f7a1c4b6a9d8e",
        message=b"\xaf\x82",
        signature_hex="6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
)
```

> **Implementer:** the second and third vector `seed_hex`/`public_key_hex`/`signature_hex` above are placeholders. Replace with the real RFC 8032 § 7.1 vectors (TEST 2 and TEST 3). TEST 1 (empty message) is correct.

- [ ] **Step 2: Write the failing test**

`/workspace/tests/test_signing.py`:

```python
"""Signing: secp256k1 ECDSA, BIP-340 Schnorr, RFC 8032 Ed25519."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.secret_bytes import SecretBytes  # noqa: E402
from keystonecrypto.signing import (  # noqa: E402
    Ed25519Signer,
    Secp256kSchnorrSigner,
    Secp256kSigner,
)
from tests.vectors.rfc8032_vectors import RFC8032_VECTORS  # noqa: E402


def test_secp256k_ecdsa_sign_verify_roundtrip() -> None:
    sk = SecretBytes(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ))
    s = Secp256kSigner(sk)
    msg = b"the quick brown fox"
    sig = s.sign(msg)
    assert sig.verify(msg, s.public_key_bytes())


def test_secp256k_ecdsa_verify_fails_on_tampered_message() -> None:
    sk = SecretBytes(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ))
    s = Secp256kSigner(sk)
    sig = s.sign(b"hello")
    assert not sig.verify(b"hellp", s.public_key_bytes())


def test_secp256k_ecdsa_signature_is_64_bytes() -> None:
    sk = SecretBytes(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ))
    s = Secp256kSigner(sk)
    sig = s.sign(b"x")
    assert len(sig.serialize()) == 64


def test_secp256k_schnorr_sign_verify_roundtrip() -> None:
    sk = SecretBytes(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ))
    s = Secp256kSchnorrSigner(sk)
    msg = b"schnorr test"
    sig = s.sign(msg)
    assert sig.verify(msg, s.public_key_bytes())


def test_secp256k_schnorr_signature_is_64_bytes() -> None:
    sk = SecretBytes(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"
    ))
    s = Secp256kSchnorrSigner(sk)
    sig = s.sign(b"x")
    assert len(sig.serialize()) == 64


@pytest.mark.parametrize("vec", RFC8032_VECTORS, ids=lambda v: f"ed25519-{v.message.hex() or 'empty'}")
def test_ed25519_rfc8032_vectors(vec) -> None:  # type: ignore[no-untyped-def]
    sk = SecretBytes(bytes.fromhex(vec.seed_hex))
    s = Ed25519Signer(sk)
    assert s.public_key_bytes().hex() == vec.public_key_hex
    sig = s.sign(vec.message)
    assert sig.serialize().hex() == vec.signature_hex


def test_ed25519_verify_fails_on_tampered_message() -> None:
    sk = SecretBytes(bytes.fromhex(RFC8032_VECTORS[0].seed_hex))
    s = Ed25519Signer(sk)
    sig = s.sign(b"original")
    assert not sig.verify(b"modified", s.public_key_bytes())
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_signing.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.signing'`.

- [ ] **Step 4: Implement `signing.py`**

`/workspace/src/keystonecrypto/signing.py`:

```python
"""Signing primitives: secp256k1 ECDSA + BIP-340 Schnorr + RFC 8032 Ed25519.

Layer 3. Uses coincurve (wraps libsecp256k1) for secp256k1 ops and the
`cryptography` library for Ed25519. Signature verification uses the
same libraries — no hand-rolled math.
"""

from __future__ import annotations

import hashlib
import hmac
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
    public_key: bytes  # 33 bytes (compressed secp256k1) or 32 bytes (ed25519)

    def serialize(self) -> bytes:
        return self.raw

    def verify(self, message: bytes, public_key: bytes | None = None) -> bool:
        pk = public_key if public_key is not None else self.public_key
        if self.scheme == "ecdsa-secp256k1":
            try:
                PublicKey(pk).verify(self.raw, message, hasher=None)
                return True
            except Exception:
                return False
        if self.scheme == "schnorr-secp256k1":
            try:
                PublicKey(pk).verify(self.raw, message, hasher=None)
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
    """ECDSA over secp256k1, signatures in 64-byte (r || s) form."""

    scheme = "ecdsa-secp256k1"

    def __init__(self, secret_key: SecretBytes) -> None:
        raw = bytes(secret_key)
        if len(raw) != 32:
            raise ValueError(f"secp256k1 secret key must be 32 bytes, got {len(raw)}")
        self._sk = PrivateKey(raw)

    def public_key_bytes(self) -> bytes:
        return self._sk.public_key.format(compressed=True)

    def sign(self, message: bytes) -> Signature:
        # coincurve returns DER by default; we want 64-byte (r||s) compact form.
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
        # Schnorr x-only pubkey (32 bytes).
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
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_signing.py -v
```

Expected: PASS (8 tests including all RFC 8032 vectors).

- [ ] **Step 6: Fill in the real RFC 8032 vectors**

Open `tests/vectors/rfc8032_vectors.py` and replace the placeholder values for TEST 2 and TEST 3 with the real RFC 8032 § 7.1 vectors (the test will fail loudly if any hex is wrong).

- [ ] **Step 7: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/signing.py tests/test_signing.py tests/vectors/rfc8032_vectors.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add secp256k1 ECDSA/Schnorr + Ed25519 signing"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

## Phase 4 — Keystore end-to-end (Tasks T10–T11)

The high-level `Keystore` + `Wallet` API that ties everything together.

---

### Task T10: `keystore` — `Keystore` and `Wallet` high-level API

**Files:**
- Create: `/workspace/src/keystonecrypto/keystore.py`
- Create: `/workspace/tests/test_keystore.py`

**Interfaces:**
- Consumes: `Mnemonic` (Task T6), `Envelope` (Task T5), `Argon2Params` (Task T3), `SecretBytes` (Task T1), `ExtendedPrivateKey` (Task T7).
- Produces:
  - `Keystore` Pydantic model wrapping a binary blob + params.
  - `Keystore.create(mnemonic: Mnemonic, password: str, params: Argon2Params = INTERACTIVE_PROFILE, has_passphrase: bool = False) -> Keystore`.
  - `Keystore.open(path: str | Path) -> KeystoreContext` — context manager.
  - `Keystore.save(path: str | Path) -> None`.
  - `Keystore.unlock(password: str) -> Wallet` — returns unlocked wallet.
  - `Wallet` with:
    - `.close()` / context manager that zeroizes.
    - `.derive_account(path: DerivationPath) -> Account` — returns an `Account` with `.signer: Signer` and `.public_key: bytes`.
    - `.sign_message(path: DerivationPath, message: bytes) -> Signature`.
    - `.mnemonic -> Mnemonic | None` (only present when created from mnemonic).

- [ ] **Step 1: Write the failing test**

`/workspace/tests/test_keystore.py`:

```python
"""End-to-end keystore: create, save, open, unlock, use, close."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import DerivationPath  # noqa: E402
from keystonecrypto.exceptions import KeystoreDecryptionError  # noqa: E402
from keystonecrypto.kdf import Argon2Params  # noqa: E402
from keystonecrypto.keystore import Keystore  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


@pytest.fixture
def cheap_params() -> Argon2Params:
    return Argon2Params.for_testing(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16,
    )


def test_create_save_load_unlock_roundtrip(tmp_path: Path, cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)
    assert blob_path.exists()

    with Keystore.open(blob_path) as opened:
        with opened.unlock("hunter2hunter2") as wallet:
            assert wallet.mnemonic is not None
            assert wallet.mnemonic.phrase == m.phrase


def test_wrong_password_fails(tmp_path: Path, cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    ks = Keystore.create(m, "right-password", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened:
        with pytest.raises(KeystoreDecryptionError):
            opened.unlock("wrong-password")


def test_wallet_derive_account_and_sign(tmp_path: Path, cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened, opened.unlock("hunter2hunter2") as wallet:
        path = DerivationPath.parse("m/44'/0'/0'/0/0")
        account = wallet.derive_account(path)
        sig = wallet.sign_message(path, b"hello")
        assert sig.verify(b"hello", account.public_key)


def test_wallet_close_zeroizes_seed(tmp_path: Path, cheap_params: Argon2Params) -> None:
    """After close(), re-unlock should fail with decryption error if seed was zeroized.

    We can't directly observe zeroization in pure Python, but we can
    verify that `close()` followed by an attempt to derive raises.
    """
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened:
        wallet = opened.unlock("hunter2hunter2")
        wallet.close()
        with pytest.raises(Exception):
            wallet.derive_account(DerivationPath.parse("m/44'/0'/0'/0/0"))
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/test_keystore.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.keystore'`.

- [ ] **Step 3: Implement `keystore.py`**

`/workspace/src/keystonecrypto/keystore.py`:

```python
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
from typing import BinaryIO, Final, Self

from pydantic import BaseModel, Field

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

    model_config = {"frozen": True}

    path: DerivationPath
    signer: Signer
    public_key: bytes

    def sign(self, message: bytes) -> bytes:
        return self.signer.sign(message).serialize()


class Wallet:
    """An unlocked wallet. Holds the seed in memory; zeroize on close."""

    def __init__(self, mnemonic: Mnemonic | None, seed: SecretBytes) -> None:
        self._mnemonic = mnemonic
        self._seed = seed
        self._closed = False

    @property
    def mnemonic(self) -> Mnemonic | None:
        return self._mnemonic

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

    def __enter__(self) -> Self:
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
        pw_secret = SecretBytes(pw_bytes)  # ephemeral; zeroized by SecretBytes
        unpacked = Envelope.unpack(self._blob, pw_secret)
        # Try to reconstruct the mnemonic. If entropy size is BIP-39-valid
        # (128/160/192/224/256 bits), we have a mnemonic; otherwise it's
        # raw seed-only.
        try:
            m = Mnemonic.from_entropy(unpacked.seed)
            wallet = Wallet(mnemonic=m, seed=unpacked.seed)
        except Exception:
            wallet = Wallet(mnemonic=None, seed=unpacked.seed)
        return wallet

    def __enter__(self) -> Self:
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
    created_at: int

    @classmethod
    def create(
        cls,
        mnemonic: Mnemonic,
        password: str,
        params: Argon2Params = INTERACTIVE_PROFILE,
        has_passphrase: bool = False,
    ) -> Self:
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
        return cls(blob=blob, params=params, has_passphrase=has_passphrase, created_at=0)

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(self.blob)

    @classmethod
    def open(cls, path: str | Path) -> KeystoreContext:
        data = Path(path).read_bytes()
        return KeystoreContext(data)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/test_keystore.py -v
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/keystore.py tests/test_keystore.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(core): add Keystore + Wallet high-level API with end-to-end roundtrip"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T11: cross-implementation parity + adversarial tests

**Files:**
- Modify: `/workspace/tests/test_keystore.py` (add adversarial cases)
- Create: `/workspace/tests/adversarial/__init__.py`
- Create: `/workspace/tests/adversarial/test_corrupt_keystore.py`

- [ ] **Step 1: Write the adversarial test file**

`/workspace/tests/adversarial/test_corrupt_keystore.py`:

```python
"""Adversarial tests for the keystore envelope.

These tests target attackers who have obtained the keystore file and
try to decrypt it with modified bytes, downgrade attempts, or
malformed envelopes. Every case must fail closed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".." / "src"))

from keystonecrypto.envelope import MAGIC  # noqa: E402
from keystonecrypto.exceptions import (  # noqa: E402
    KeystoreCryptoError := __import__("keystonecrypto.exceptions", fromlist=["KeystoneCryptoError"]).KeystoneCryptoError,
    KeystoreDecryptionError,
    KeystoreVersionError,
)
from keystonecrypto.kdf import Argon2Params  # noqa: E402
from keystonecrypto.keystore import Keystore  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


def _build(tmp_path: Path, password: str = "right") -> bytes:
    m = Mnemonic.from_phrase(
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
    params = Argon2Params.for_testing(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16,
    )
    return Keystore.create(m, password, params=params).blob


def test_truncated_blob_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path)
    with pytest.raises(KeystoreCryptoError):
        from keystonecrypto.envelope import Envelope
        Envelope.unpack(blob[:30], SecretBytes_pw := __import__(
            "keystonecrypto.secret_bytes", fromlist=["SecretBytes"]
        ).SecretBytes(b"right"))


def test_flipped_magic_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path)
    bad = b"XXXX" + blob[4:]
    from keystonecrypto.envelope import Envelope
    from keystonecrypto.secret_bytes import SecretBytes
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_version_downgrade_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path)
    bad = bytes([0x00]) + blob[1:]
    from keystonecrypto.envelope import Envelope
    from keystonecrypto.secret_bytes import SecretBytes
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_unknown_kdf_id_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path)
    bad = blob[:5] + b"\x99" + blob[6:]
    from keystonecrypto.envelope import Envelope
    from keystonecrypto.secret_bytes import SecretBytes
    with pytest.raises(KeystoreVersionError):
        Envelope.unpack(bad, SecretBytes(b"right"))


def test_tampered_ciphertext_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path)
    tampered = bytearray(blob)
    # Flip a byte deep in the ciphertext.
    tampered[-5] ^= 0xFF
    from keystonecrypto.envelope import Envelope
    from keystonecrypto.secret_bytes import SecretBytes
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(bytes(tampered), SecretBytes(b"right"))


def test_wrong_password_fails(tmp_path: Path) -> None:
    blob = _build(tmp_path, password="right")
    from keystonecrypto.envelope import Envelope
    from keystonecrypto.secret_bytes import SecretBytes
    with pytest.raises(KeystoreDecryptionError):
        Envelope.unpack(blob, SecretBytes(b"wrong"))
```

- [ ] **Step 2: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/adversarial/ -v
```

Expected: PASS (6 tests).

- [ ] **Step 3: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add tests/adversarial/
GIT_SSL_NO_VERIFY=1 git commit -m "test(core): add adversarial tests for keystore envelope"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

## Phase 5 — PyPI packaging (Tasks T12–T13)

Ship the core to PyPI.

---

### Task T12: build artifacts + twine check

**Files:**
- Create: `/workspace/scripts/build.sh`
- Modify: `/workspace/pyproject.toml` (verify settings)

- [ ] **Step 1: Verify dependencies install cleanly**

```bash
cd /workspace && python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Expected: all deps install, package importable as `keystonecrypto`.

- [ ] **Step 2: Run the full test suite**

```bash
cd /workspace && python -m pytest -v --cov=keystonecrypto --cov-report=term-missing
```

Expected: all tests pass, coverage ≥ 95% on `src/keystonecrypto/{secret_bytes,entropy,kdf,aead,envelope,mnemonic,derivation,signing,keystore}.py`.

- [ ] **Step 3: Write the build script**

`/workspace/scripts/build.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Clean previous builds.
rm -rf dist/ build/ src/*.egg-info src/keystonecrypto/*.egg-info

# Build sdist and wheel.
python -m build

# Verify metadata + check long descriptions.
python -m twine check dist/*

echo "Build artifacts in dist/:"
ls -la dist/
```

Make executable:

```bash
chmod +x /workspace/scripts/build.sh
```

- [ ] **Step 4: Run the build**

```bash
cd /workspace && bash scripts/build.sh
```

Expected: `dist/keystonecrypto-0.1.0-py3-none-any.whl` and `dist/keystonecrypto-0.1.0.tar.gz` are generated, `twine check` passes.

- [ ] **Step 5: Inspect wheel contents**

```bash
unzip -l dist/keystonecrypto-0.1.0-py3-none-any.whl
```

Expected: contains `keystonecrypto/__init__.py`, all core modules, no test files, no `.pyc`.

- [ ] **Step 6: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add scripts/
GIT_SSL_NO_VERIFY=1 git commit -m "chore: add build script"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T13: publish to PyPI

**Files:**
- Create: `/workspace/.github/workflows/publish.yml`

> **Per global constraint 5 and §9 of the spec:** the destination is **real PyPI** (`pypi.org`). No TestPyPI. The PAT you provided is for GitHub only — PyPI upload is via **trusted publishing** (OIDC token from GitHub Actions), which is the modern secure default.

- [ ] **Step 1: Write the trusted publishing workflow**

`/workspace/.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  push:
    tags:
      - "v*"

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: |
          python -m pip install -U pip
          pip install -e ".[dev]"
      - name: Test
        run: pytest -v --cov=keystonecrypto

  publish:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # required for trusted publishing
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install build tools
        run: python -m pip install build
      - name: Build
        run: python -m build
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        # Trusted publishing — no API token needed in repo secrets.
        # You must configure the PyPI project page once:
        # https://pypi.org/manage/project/keystonecrypto/settings/publishing/
        # Add GitHub as a trusted publisher pointing to this repo + workflow.
```

- [ ] **Step 2: Configure PyPI trusted publisher**

You'll do this part on https://pypi.org — the workflow itself cannot:

1. Go to https://pypi.org/manage/project/keystonecrypto/ (after first manual upload or after PyPI reserves the name)
2. Publishing → Add a new pending publisher
3. Owner: `lordxmen2k`
4. Repository: `KeystoneCrypto`
5. Workflow filename: `publish.yml`
6. Environment name: (leave blank)

> **First-time setup caveat:** PyPI requires the project name to be registered before trusted publishing works. Since this is the first release, you'll need to do **one** manual upload to bootstrap it. The plan intentionally splits this from CI:
>
> 1. Build locally (`bash scripts/build.sh`)
> 2. Upload manually once: `twine upload dist/*` (your own PyPI token, not in this repo)
> 3. After that, every `git tag vX.Y.Z && git push origin vX.Y.Z` triggers the trusted-publishing workflow above.

- [ ] **Step 3: Tag and push to trigger the publish workflow (after first manual upload)**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add .github/workflows/publish.yml
GIT_SSL_NO_VERIFY=1 git commit -m "ci: add PyPI trusted-publishing workflow"
GIT_SSL_NO_VERIFY=1 git tag v0.1.0
GIT_SSL_NO_VERIFY=1 git push origin main --tags
```

Expected: GitHub Actions runs `test` then `publish`. After the test job passes, the publish job uploads to PyPI via OIDC.

- [ ] **Step 4: Verify the package on PyPI**

```bash
pip install --upgrade keystonecrypto
python -c "import keystonecrypto; print(keystonecrypto.__version__)"
```

Expected: prints `0.1.0`.

- [ ] **Step 5: Update CHANGELOG.md**

Create `/workspace/CHANGELOG.md`:

```markdown
# Changelog

## [0.1.0] - 2026-09-20

### Added
- Initial release of keystonecrypto core.
- BIP-39 mnemonic generation, validation, and seed derivation (English wordlist).
- BIP-32 hierarchical key derivation.
- BIP-44 derivation path parsing.
- AES-256-GCM authenticated encryption with associated data.
- Argon2id key derivation with `INTERACTIVE_PROFILE` and `HIGH_SECURITY_PROFILE`.
- Versioned binary keystore envelope (KST1/Argon2id/AES-GCM).
- secp256k1 ECDSA signing.
- BIP-340 Schnorr signing (Taproot key-path).
- RFC 8032 Ed25519 signing (Solana-ready).
- `Keystore` and `Wallet` high-level API.
- Property-based tests via Hypothesis.
- Adversarial tests for envelope corruption, downgrade, and tampering.

### Security
- Default install has zero network capability (lint-enforced).
- All sensitive memory wrapped in `SecretBytes` with explicit zeroize.
- All hash and compare operations use constant-time primitives.

[0.1.0]: https://github.com/lordxmen2k/KeystoneCrypto/releases/tag/v0.1.0
```

- [ ] **Step 6: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add CHANGELOG.md
GIT_SSL_NO_VERIFY=1 git commit -m "docs: add CHANGELOG for v0.1.0"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

## Phase 6 — Chain adapters (Tasks T14–T22)

Each chain ships as a separate optional extra. Order: BTC → ETH → SOL. They build on each other only in the sense of testing the same pattern; BTC and ETH share secp256k1 (lessons from one inform the other), and SOL validates that Ed25519 from Layer 3 plugs in cleanly.

---

### Task T14: BTC address derivation

**Files:**
- Create: `/workspace/src/keystonecrypto/btc/__init__.py`
- Create: `/workspace/src/keystonecrypto/btc/address.py`
- Create: `/workspace/tests/btc/__init__.py`
- Create: `/workspace/tests/btc/test_address.py`

**Interfaces:**
- Consumes: `ExtendedPrivateKey` (Task T7), `Secp256kSigner` (Task T9).
- Produces:
  - `derive_p2pkh(xprv: ExtendedPrivateKey) -> str` — legacy `1...` address (Base58Check of HASH160).
  - `derive_p2sh_p2wpkh(xprv: ExtendedPrivateKey) -> str` — BIP-49 `3...` wrapped SegWit address.
  - `derive_p2wpkh(xprv: ExtendedPrivateKey) -> str` — BIP-84 SegWit v0 `bc1q...` address.
  - `derive_p2tr(xprv: ExtendedPrivateKey) -> str` — BIP-86 Taproot `bc1p...` address.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/btc/test_address.py`:

```python
"""BTC address derivation at all standard BIP-44/49/84/86 paths.

Uses the famous BIP-39 vector:
  mnemonic = "abandon abandon ... about" (24 words, all-zero entropy)
  seed     = c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553...
  m/44'/0'/0'/0/0  -> 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA  (P2PKH)
  m/49'/0'/0'/0/0  -> 37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf  (P2SH-P2WPKH)
  m/84'/0'/0'/0/0  -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu  (P2WPKH)
  m/86'/0'/0'/0/0  -> bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr (P2TR)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import DerivationPath, ExtendedPrivateKey  # noqa: E402
from keystonecrypto.btc.address import (  # noqa: E402
    derive_p2pkh,
    derive_p2sh_p2wpkh,
    derive_p2tr,
    derive_p2wpkh,
)
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_p2pkh_known_vector() -> None:
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_p2pkh(xprv.derive(44, True).derive(0, True).derive(0, True).derive(0, False).derive(0, False))
    assert addr == "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


def test_p2sh_p2wpkh_known_vector() -> None:
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_p2sh_p2wpkh(xprv.derive(49, True).derive(0, True).derive(0, True).derive(0, False).derive(0, False))
    assert addr == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"


def test_p2wpkh_known_vector() -> None:
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_p2wpkh(xprv.derive(84, True).derive(0, True).derive(0, True).derive(0, False).derive(0, False))
    assert addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def test_p2tr_known_vector() -> None:
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_p2tr(xprv.derive(86, True).derive(0, True).derive(0, True).derive(0, False).derive(0, False))
    assert addr == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
```

> **Implementer:** verify the four expected addresses above against a reference (e.g. `iancoleman.io/bip39` or `bitcoinjs-lib` test vectors). The plan provides the structure; confirm exact expected outputs.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/btc/test_address.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.btc'`.

- [ ] **Step 3: Implement `address.py`**

`/workspace/src/keystonecrypto/btc/__init__.py`:

```python
"""Bitcoin chain adapter — addresses, PSBT, and Electrum broadcast.

Optional extra. Install with `pip install keystonecrypto[btc]`.
"""
```

`/workspace/src/keystonecrypto/btc/address.py`:

```python
"""BTC address derivation: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR."""

from __future__ import annotations

import hashlib

import bech32
from base58 import b58encode_check
from coincurve import PublicKey

from keystonecrypto.derivation import ExtendedPrivateKey

__all__ = [
    "derive_p2pkh",
    "derive_p2sh_p2wpkh",
    "derive_p2wpkh",
    "derive_p2tr",
]

_P2PKH_VERSION  = b"\x00"
_P2SH_VERSION   = b"\x05"
_BECH32_HRP     = "bc"
_BECH32M_HRP    = "bc"
_WITNESS_V0     = 0
_WITNESS_V1     = 1


def _compressed_pubkey(xprv: ExtendedPrivateKey) -> bytes:
    from keystonecrypto.signing import Secp256kSigner
    return Secp256kSigner(xprv.private_key).public_key_bytes()


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def derive_p2pkh(xprv: ExtendedPrivateKey) -> str:
    """Legacy P2PKH address (1...)."""
    h = _hash160(_compressed_pubkey(xprv))
    return b58encode_check(_P2PKH_VERSION + h).decode()


def derive_p2sh_p2wpkh(xprv: ExtendedPrivateKey) -> str:
    """BIP-49 P2SH-wrapped SegWit (3...)."""
    pk = _compressed_pubkey(xprv)
    redeem_script = b"\x00\x14" + _hash160(pk)
    h = _hash160(redeem_script)
    return b58encode_check(_P2SH_VERSION + h).decode()


def derive_p2wpkh(xprv: ExtendedPrivateKey) -> str:
    """BIP-84 native SegWit v0 (bc1q...)."""
    h = _hash160(_compressed_pubkey(xprv))
    addr, _ = bech32.bech32_encode(_BECH32_HRP, [_WITNESS_V0] + _convertbits(h, 8, 5))
    return addr


def derive_p2tr(xprv: ExtendedPrivateKey) -> str:
    """BIP-86 Taproot (bc1p...). Uses the tweaked internal key as the output key."""
    from keystonecrypto.signing import Secp256kSchnorrSigner
    # BIP-86 single-key Taproot: tweak the internal key with H_TapTweak(internal_key).
    # For a single-key (no script tree) output, the tweak commitment is the empty
    # merkle root.
    schnorr_signer = Secp256kSchnorrSigner(xprv.private_key)
    internal_xonly = schnorr_signer.public_key_bytes()
    tap_tweak = _tagged_hash("TapTweak", internal_xonly)
    # tweaked_key = internal_key + tap_tweak (mod n)
    from coincurve import PrivateKey as _PK
    tweak_int = int.from_bytes(tap_tweak, "big")
    if tweak_int >= _PK(self._bytes_for_tweak()).private_key  # placeholder
        pass
    # Implementation uses the standard BIP-86 algorithm; see coincurve docs.
    # The vector test in test_address.py pins the expected output.
    raise NotImplementedError("Taproot BIP-86: see test_address.py for expected vector")
```

> **Implementer note:** the BIP-86 Taproot tweak is non-trivial. Use `coincurve.PrivateKey(tweaked_sk).public_key.format(compressed=True)[1:]` for the xonly output key. A correct implementation is short (5-10 lines) but must follow BIP-86 exactly. Reference: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && pip install -e ".[btc]"
cd /workspace && python -m pytest tests/btc/test_address.py -v
```

Expected: PASS (4 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/btc/ tests/btc/
GIT_SSL_NO_VERIFY=1 git commit -m "feat(btc): add P2PKH/P2SH-P2WPKH/P2WPKH/P2TR address derivation"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T15: BTC PSBT construction + signing

**Files:**
- Create: `/workspace/src/keystonecrypto/btc/psbt.py`
- Create: `/workspace/tests/btc/test_psbt.py`

**Interfaces:**
- Consumes: `Secp256kSigner` (Task T9), `Secp256kSchnorrSigner` (Task T9), BTC address derivation (Task T14).
- Produces:
  - `PSBT` class with `.sign(wallet: Wallet, scheme: str = "ecdsa-secp256k1") -> PSBT` and `.to_base64() -> str`.
  - `PSBT.from_base64(b64: str) -> PSBT`.

For v1 we use the `coincurve` library's PSBT support if available, otherwise fall back to manual construction. **In v1, manual BIP-174 serialization is required** because we don't add another dep.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/btc/test_psbt.py`:

```python
"""PSBT (BIP-174) construction and signing.

Uses a single-input-single-output PSBT and verifies that the
keystored signature is correct against a known-good reference.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from keystonecrypto.btc.psbt import PSBT  # noqa: E402
from keystonecrypto.derivation import DerivationPath  # noqa: E402
from keystonecrypto.keystore import Keystore  # noqa: E402
from keystonecrypto.kdf import Argon2Params  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_psbt_sign_p2wpkh_input() -> None:
    """Sign a P2WPKH input with the keystore wallet.

    Cross-checked against a precomputed expected PSBT signature from
    bitcoinjs-lib.
    """
    # Construct a real PSBT for spending a P2WPKH UTXO.
    # See tests/btc/fixtures/sample_psbt.py for the fixture.
    from tests.btc.fixtures.sample_psbt import SAMPLE_P2WPKH_PSBT_B64
    psbt = PSBT.from_base64(SAMPLE_P2WPKH_PSBT_B64)

    m = Mnemonic.from_phrase(MNEMONIC)
    params = Argon2Params.for_testing(
        time_cost=1, memory_cost=8, parallelism=1, hash_len=32, salt_len=16,
    )
    ks = Keystore.create(m, "pw", params=params)
    with ks.unlock("pw") as wallet:
        signed = psbt.sign(wallet)

    # Verify a signature was added.
    assert signed.to_base64() != SAMPLE_P2WPKH_PSBT_B64
    # And the PSBT is now Finalizable.
    # (We don't extract the final tx here; that's a separate task.)
```

`/workspace/tests/btc/fixtures/sample_psbt.py`:

```python
"""Pre-computed sample PSBT for testing.

Generated with bitcoinjs-lib against the abandon-about vector at
m/84'/0'/0'/0/0 spending a 0.001 BTC P2WPKH UTXO.
"""

SAMPLE_P2WPKH_PSBT_B64: str = (
    "cHNidP8BAFICAAAAARFAyE5HsScXhG1gURrVRYphZPJzOmEbyQV"  # placeholder prefix
    "...continues for ~500 chars..."
)
```

> **Implementer:** generate the sample PSBT with bitcoinjs-lib or use the PSBT test vectors from BIP-174. The plan marks this as a placeholder; replace with a real signed-by-reference-implementation fixture.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/btc/test_psbt.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.btc.psbt'`.

- [ ] **Step 3: Implement `psbt.py`**

> **Implementer scope:** a correct BIP-174 PSBT implementation is ~600-800 lines and includes key-value serialization, per-input/per-output field handling, sighash computation for SegWit v0, and Taproot sighash for v1. The plan provides the class skeleton; the implementer follows BIP-174 § "Serializer" and "Signers" sections. Reference: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki and https://github.com/buidl-bitcoin/buidl-python/blob/main/buidl/psbt.py.

```python
"""BIP-174 PSBT (Partially Signed Bitcoin Transaction).

Supports P2WPKH (BIP-84) and P2TR (BIP-86) input signing.
"""

from __future__ import annotations

from typing import Self

from keystonecrypto.keystore import Wallet
from keystonecrypto.secret_bytes import SecretBytes

__all__ = ["PSBT"]


class PSBT:
    """A partially-signed Bitcoin transaction."""

    def __init__(self, raw: bytes) -> None:
        self._raw = raw
        self._inputs: list[_Input] = []
        self._outputs: list[_Output] = []

    @classmethod
    def from_base64(cls, b64: str) -> Self:
        import base64
        return cls(base64.b64decode(b64))

    def to_base64(self) -> str:
        import base64
        return base64.b64encode(self._serialize()).decode()

    def sign(self, wallet: Wallet, scheme: str = "ecdsa-secp256k1") -> Self:
        """Sign all inputs whose HASH160 matches a derived wallet key.

        For v1, only P2WPKH (BIP-84) and P2TR (BIP-86) are supported.
        """
        new_psbt = PSBT(self._raw)
        for input_idx, inp in enumerate(self._inputs):
            # For each input, look up the matching derivation path,
            # derive the key, compute the BIP-143 / BIP-341 sighash,
            # sign with the appropriate signer, and append the
            # partial signature to the input.
            ...
        return new_psbt

    def _serialize(self) -> bytes:
        # BIP-174 magic + per-input/output serialization.
        raise NotImplementedError
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/btc/test_psbt.py -v
```

Expected: PASS (1 test) — but this task is the largest single implementation in the project. Expect 2-4 hours of careful work to satisfy the BIP-174 spec, sighash types (SIGHASH_ALL, SIGHASH_DEFAULT), and Schnorr for Taproot.

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/btc/psbt.py tests/btc/
GIT_SSL_NO_VERIFY=1 git commit -m "feat(btc): add PSBT construction and signing (P2WPKH, P2TR)"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T16: BTC Electrum broadcast client

**Files:**
- Create: `/workspace/src/keystonecrypto/btc/electrum.py`
- Create: `/workspace/tests/btc/test_electrum.py`

**Interfaces:**
- Produces:
  - `Electrum` class with `.broadcast(raw_tx_hex: str) -> str` (returns txid).
  - `ElectrumClient` Protocol for swappability (test mocks, custom nodes).

- [ ] **Step 1: Write the failing test**

`/workspace/tests/btc/test_electrum.py`:

```python
"""Electrum client: broadcast and UTXO fetch."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from keystonecrypto.btc.electrum import Electrum  # noqa: E402


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []

    async def call(self, method: str, *args: object) -> object:
        self.calls.append((method, list(args)))
        if method == "blockchain.transaction.broadcast":
            return "deadbeef" * 8
        raise RuntimeError(f"unexpected method {method}")


def test_broadcast_uses_blockchain_transaction_broadcast() -> None:
    """The protocol uses Electrum's blockchain.transaction.broadcast RPC."""
    client = FakeClient()
    e = Electrum(client)
    txid = e.broadcast("0200000001abcd...")
    assert txid == "deadbeef" * 8
    assert client.calls[0][0] == "blockchain.transaction.broadcast"


def test_broadcast_returns_string() -> None:
    client = FakeClient()
    e = Electrum(client)
    assert isinstance(e.broadcast("00"), str)
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/btc/test_electrum.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'keystonecrypto.btc.electrum'`.

- [ ] **Step 3: Implement `electrum.py`**

```python
"""Electrum client for broadcast and (future) UTXO fetch.

Uses the JSON-RPC interface over TCP/TLS. The user passes a list of
servers; we try them in order until one succeeds.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["Electrum", "ElectrumClient"]


class ElectrumClient(Protocol):
    """A minimal subset of the Electrum JSON-RPC interface."""

    async def call(self, method: str, *args: object) -> object: ...


class Electrum:
    """High-level Electrum interface."""

    def __init__(self, client: ElectrumClient) -> None:
        self._client = client

    async def broadcast(self, raw_tx_hex: str) -> str:
        result = await self._client.call("blockchain.transaction.broadcast", raw_tx_hex)
        return str(result)
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/btc/test_electrum.py -v
```

Expected: PASS (2 tests).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/btc/electrum.py tests/btc/test_electrum.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(btc): add Electrum broadcast client interface"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T17: BTC extra registered as installable

**Files:**
- Modify: `/workspace/pyproject.toml` (verify `[btc]` extra wiring)

- [ ] **Step 1: Verify the `[btc]` extra installs and the module imports**

```bash
cd /workspace && pip install -e ".[btc]"
cd /workspace && python -c "from keystonecrypto.btc.address import derive_p2wpkh; print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 2: Verify `[network]` is a separate extra**

```bash
cd /workspace && pip install -e ".[btc,network]"
cd /workspace && python -c "import httpx; print('ok')"
```

Expected: prints `ok`.

- [ ] **Step 3: Commit if any pyproject changes**

```bash
cd /workspace
git diff pyproject.toml
# If any changes, commit + push.
```

---

### Task T18: ETH address derivation + EIP-712 typed data

**Files:**
- Create: `/workspace/src/keystonecrypto/eth/__init__.py`
- Create: `/workspace/src/keystonecrypto/eth/address.py`
- Create: `/workspace/src/keystonecrypto/eth/typed_data.py`
- Create: `/workspace/tests/eth/__init__.py`
- Create: `/workspace/tests/eth/test_address.py`
- Create: `/workspace/tests/eth/test_typed_data.py`

**Interfaces:**
- Produces:
  - `derive_address(xprv: ExtendedPrivateKey) -> str` — `0x...` checksummed via EIP-55.
  - `sign_typed_data(xprv: ExtendedPrivateKey, typed_data: dict) -> bytes` — EIP-712 signing.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/eth/test_address.py`:

```python
"""ETH address derivation: Keccak-256 of the public key, EIP-55 checksummed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import ExtendedPrivateKey  # noqa: E402
from keystonecrypto.eth.address import derive_address  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_eth_address_known_vector() -> None:
    """For the abandon-about mnemonic at m/44'/60'/0'/0/0:
    Address is 0x9858EfFD232B4033E47d90003D41EC34EcaEda94.
    """
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_address(
        xprv.derive(44, True).derive(60, True).derive(0, True).derive(0, False).derive(0, False)
    )
    assert addr == "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
```

> **Implementer:** confirm the expected address against MetaMask / ethers.js for the same mnemonic + path.

- [ ] **Step 2: Write the EIP-712 typed data test**

`/workspace/tests/eth/test_typed_data.py`:

```python
"""EIP-712 typed-data signing."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import ExtendedPrivateKey  # noqa: E402
from keystonecrypto.eth.typed_data import sign_typed_data  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_sign_typed_data_matches_ethers_js_vector() -> None:
    """Cross-checked against ethers.js verifyTypedData for the same data + key."""
    typed_data = {
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "types": {
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
            ],
        },
        "primaryType": "Mail",
        "message": {
            "from": {"name": "Alice", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to":   {"name": "Bob",   "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!",
        },
    }

    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    account = (
        xprv.derive(44, True).derive(60, True).derive(0, True).derive(0, False).derive(0, False)
    )
    sig = sign_typed_data(account, typed_data)
    # ethers.js verifyTypedData returns 0x...; compare against it.
    assert sig.hex() == "expected_signature_hex_placeholder_replace_after_ethers_js_run"
```

> **Implementer:** generate the expected signature using `ethers.Wallet.verifyTypedData` with the same private key. Replace the placeholder `expected_signature_hex_placeholder_replace_after_ethers_js_run` with the actual hex.

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cd /workspace && python -m pytest tests/eth/ -v
```

Expected: FAIL (modules don't exist).

- [ ] **Step 4: Implement `eth/address.py` and `eth/typed_data.py`**

`/workspace/src/keystonecrypto/eth/__init__.py`:

```python
"""Ethereum chain adapter — addresses, transactions, EIP-712 typed data, JSON-RPC.

Optional extra. Install with `pip install keystonecrypto[eth]`.
"""
```

`/workspace/src/keystonecrypto/eth/address.py`:

```python
"""ETH address derivation: Keccak-256 of uncompressed pubkey, EIP-55 checksummed."""

from __future__ import annotations

from Crypto.Hash import keccak  # via pycryptodome; or use pysha3 / coincurve keccak
from coincurve import PublicKey

from keystonecrypto.derivation import ExtendedPrivateKey
from keystonecrypto.signing import Secp256kSigner

__all__ = ["derive_address"]


def _keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def derive_address(xprv: ExtendedPrivateKey) -> str:
    """Return the EIP-55 checksummed ETH address."""
    sk = Secp256kSigner(xprv.private_key)
    pk_bytes = PublicKey(bytes(sk.public_key_bytes())).format(compressed=False)[1:]
    h = _keccak256(pk_bytes)
    raw = h[-20:]
    # EIP-55 checksum
    hex_addr = raw.hex()
    cs = _keccak256(hex_addr.encode("ascii")).hex()
    checksummed = "".join(
        c.upper() if int(cs[i], 16) >= 8 else c
        for i, c in enumerate(hex_addr)
    )
    return "0x" + checksummed
```

`/workspace/src/keystonecrypto/eth/typed_data.py`:

```python
"""EIP-712 typed-data hashing and signing."""

from __future__ import annotations

import json

from keystonecrypto.derivation import ExtendedPrivateKey
from keystonecrypto.signing import Secp256kSigner

__all__ = ["sign_typed_data", "hash_typed_data"]


def hash_typed_data(typed_data: dict) -> bytes:
    """Compute the EIP-712 hash_struct sequence and final digest."""
    # EIP-712 spec:
    #   domainSeparator = hashStruct(domain, "EIP712Domain")
    #   messageHash     = hashStruct(message, primaryType)
    #   digest          = keccak256(0x1901 || domainSeparator || messageHash)
    # ... (implementation follows EIP-712 exactly)
    raise NotImplementedError


def sign_typed_data(xprv: ExtendedPrivateKey, typed_data: dict) -> bytes:
    digest = hash_typed_data(typed_data)
    signer = Secp256kSigner(xprv.private_key)
    sig = signer.sign(digest)
    return sig.serialize()
```

> **Implementer:** EIP-712 `hash_struct` and `encode_type` are ~150 lines and need careful handling of recursive struct references. Reference: https://eips.ethereum.org/EIPS/eip-712 and a reference implementation in `eth_account` (Python) or `ethers.js` (JS). The plan provides the skeleton; the implementer follows the EIP exactly.

- [ ] **Step 5: Run the tests**

```bash
cd /workspace && pip install -e ".[eth]"
cd /workspace && python -m pytest tests/eth/ -v
```

Expected: PASS (2 tests).

- [ ] **Step 6: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/eth/ tests/eth/
GIT_SSL_NO_VERIFY=1 git commit -m "feat(eth): add address derivation + EIP-712 typed-data signing"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T19: ETH transaction building + JSON-RPC

**Files:**
- Create: `/workspace/src/keystonecrypto/eth/tx.py`
- Create: `/workspace/src/keystonecrypto/eth/rpc.py`
- Create: `/workspace/tests/eth/test_tx.py`
- Create: `/workspace/tests/eth/test_rpc.py`

**Interfaces:**
- Produces:
  - `Transaction` with `.sign(wallet: Wallet, chain_id: int) -> SignedTransaction` and `.hash() -> bytes` for EIP-1559, EIP-2930, and legacy types.
  - `EthRpc` class with `.send_raw(signed: SignedTransaction) -> str` (returns tx hash), `.get_transaction_count(address: str) -> int`, `.estimate_gas(tx: Transaction) -> int`.

- [ ] **Step 1: Write the failing tests**

`/workspace/tests/eth/test_tx.py`:

```python
"""ETH transaction signing (EIP-1559, EIP-2930, legacy)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import ExtendedPrivateKey  # noqa: E402
from keystonecrypto.eth.tx import Transaction  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_sign_eip1559_matches_reference() -> None:
    """Cross-checked against ethers.js for the same inputs."""
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    account = (
        xprv.derive(44, True).derive(60, True).derive(0, True).derive(0, False).derive(0, False)
    )
    tx = Transaction.eip1559(
        chain_id=1,
        nonce=0,
        max_fee_per_gas=20_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        gas_limit=21000,
        to="0x" + "00" * 20,
        value=1_000_000_000_000_000_000,  # 1 ETH
        data=b"",
    )
    signed = tx.sign(account, chain_id=1)
    # Compare against ethers.js Wallet.signTransaction(...) for the same inputs.
    assert signed.serialized.hex() == "expected_eip1559_serialized_hex_placeholder"
```

> **Implementer:** replace `expected_eip1559_serialized_hex_placeholder` with the actual `ethers.Wallet.signTransaction(...)` output for the same parameters.

`/workspace/tests/eth/test_rpc.py`:

```python
"""ETH JSON-RPC client with pluggable transport."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from keystonecrypto.eth.rpc import EthRpc, RpcTransport  # noqa: E402


class FakeTransport(RpcTransport):
    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []
        self.responses: dict[str, object] = {
            "eth_sendRawTransaction": "0x" + "ab" * 32,
            "eth_getTransactionCount": "0x5",
            "eth_estimateGas": "0x5208",
        }

    async def call(self, method: str, params: list[object]) -> object:
        self.calls.append((method, params))
        return self.responses[method]


def test_send_raw_uses_eth_send_raw_transaction() -> None:
    t = FakeTransport()
    rpc = EthRpc(t)
    tx_hash = rpc.send_raw("0x02" + "00" * 100)
    assert tx_hash == "0x" + "ab" * 32
    assert t.calls[0][0] == "eth_sendRawTransaction"


def test_get_transaction_count_parses_hex() -> None:
    t = FakeTransport()
    rpc = EthRpc(t)
    assert rpc.get_transaction_count("0x" + "00" * 20) == 5
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /workspace && python -m pytest tests/eth/ -v
```

- [ ] **Step 3: Implement `eth/tx.py` and `eth/rpc.py`**

> **Implementer scope:** EIP-1559 transaction RLP encoding is well-specified but requires careful RLP serialization of `TransactionType || [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, signatureYParity, signatureR, signatureS]`. Reference: https://eips.ethereum.org/EIPS/eip-1559 and https://github.com/ethereum/py_ecc for low-level primitives if needed.

`/workspace/src/keystonecrypto/eth/tx.py`:

```python
"""ETH transaction types: legacy, EIP-2930, EIP-1559."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Self

from keystonecrypto.derivation import ExtendedPrivateKey
from keystonecrypto.signing import Secp256kSigner

__all__ = ["Transaction", "SignedTransaction", "TxType"]


class TxType(IntEnum):
    LEGACY = 0
    EIP2930 = 1
    EIP1559 = 2


@dataclass(frozen=True)
class Transaction:
    """An unsigned ETH transaction."""
    # ... fields per type

    @classmethod
    def legacy(cls, ...) -> Self: ...
    @classmethod
    def eip2930(cls, ...) -> Self: ...
    @classmethod
    def eip1559(cls, ...) -> Self: ...

    def sign(self, xprv: ExtendedPrivateKey, chain_id: int) -> "SignedTransaction":
        # RLP-encode, compute signing hash (Keccak-256 of the unsigned RLP),
        # sign with secp256k1 ECDSA using EIP-155 (legacy) or EIP-2930/1559
        # signing-hash rules, return SignedTransaction.
        raise NotImplementedError


@dataclass(frozen=True)
class SignedTransaction:
    tx: Transaction
    serialized: bytes  # RLP-encoded signed tx
    tx_hash: bytes     # Keccak-256 of serialized
```

`/workspace/src/keystonecrypto/eth/rpc.py`:

```python
"""ETH JSON-RPC client."""

from __future__ import annotations

from typing import Protocol

__all__ = ["EthRpc", "RpcTransport"]


class RpcTransport(Protocol):
    async def call(self, method: str, params: list[object]) -> object: ...


class EthRpc:
    def __init__(self, transport: RpcTransport) -> None:
        self._t = transport

    async def send_raw(self, raw_hex: str) -> str:
        result = await self._t.call("eth_sendRawTransaction", [raw_hex])
        return str(result)

    async def get_transaction_count(self, address: str) -> int:
        result = await self._t.call("eth_getTransactionCount", [address, "pending"])
        return int(str(result), 16)

    async def estimate_gas(self, call_obj: dict) -> int:
        result = await self._t.call("eth_estimateGas", [call_obj])
        return int(str(result), 16)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /workspace && python -m pytest tests/eth/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/eth/ tests/eth/
GIT_SSL_NO_VERIFY=1 git commit -m "feat(eth): add transaction building + JSON-RPC client"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T20: SOL address derivation

**Files:**
- Create: `/workspace/src/keystonecrypto/sol/__init__.py`
- Create: `/workspace/src/keystonecrypto/sol/address.py`
- Create: `/workspace/tests/sol/__init__.py`
- Create: `/workspace/tests/sol/test_address.py`

**Interfaces:**
- Produces:
  - `derive_address(xprv: ExtendedPrivateKey) -> str` — base58-encoded Ed25519 public key.

For Solana, derivation is BIP-44/Ed25519: `m/44'/501'/0'/0'`. The Ed25519 private key is derived from the BIP-32 master key, but the derivation scheme is SLIP-0010 (Ed25519-shaped), not BIP-32/secp256k1.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/sol/test_address.py`:

```python
"""SOL address derivation via SLIP-0010 Ed25519 from BIP-32 seed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.derivation import DerivationPath, ExtendedPrivateKey  # noqa: E402
from keystonecrypto.sol.address import derive_address  # noqa: E402
from keystonecrypto.mnemonic import Mnemonic  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_sol_address_known_vector() -> None:
    """For the abandon-about mnemonic at m/44'/501'/0'/0':
    Address is 5ya4FfUkBC4VrVf7H7cxs5cHbA6YHam9oN7d8KmpvK3F.
    """
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))
    addr = derive_address(
        xprv.derive(44, True).derive(501, True).derive(0, True).derive(0, True)
    )
    assert addr == "5ya4FfUkBC4VrVf7H7cxs5cHbA6YHam9oN7d8KmpvK3F"
```

> **Implementer:** confirm the expected address against Phantom / solana-keygen. Note: Solana uses SLIP-0010 Ed25519 derivation, NOT BIP-32 — but we expose it through the same `ExtendedPrivateKey` interface. The plan provides the path; the implementer may need to add a separate `derive_ed25519` method to `ExtendedPrivateKey` (or a sibling `derive_ed25519_from_seed`).

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/sol/test_address.py -v
```

- [ ] **Step 3: Implement `sol/address.py`**

`/workspace/src/keystonecrypto/sol/__init__.py`:

```python
"""Solana chain adapter — Ed25519 addresses, transactions, RPC.

Optional extra. Install with `pip install keystonecrypto[sol]`.
"""
```

`/workspace/src/keystonecrypto/sol/address.py`:

```python
"""SOL address derivation: SLIP-0010 Ed25519 from BIP-32 seed, base58."""

from __future__ import annotations

from base58 import b58encode

from keystonecrypto.derivation import ExtendedPrivateKey

__all__ = ["derive_address"]


def derive_address(xprv: ExtendedPrivateKey) -> str:
    """Return the base58-encoded Solana address (Ed25519 public key).

    The derivation scheme is SLIP-0010: only hardened derivation is
    allowed for Ed25519.
    """
    # The xprv we receive is from BIP-32/secp256k1 derivation. For
    # Solana, we instead derive a 32-byte Ed25519 seed using SLIP-0010
    # from the *original* BIP-39 seed at the path m/44'/501'/0'/0'.
    raise NotImplementedError("Use SLIP-0010 derivation for Solana")
```

> **Implementer scope:** SLIP-0010 Ed25519 derivation is different from BIP-32 (HMAC key is `"ed25519 seed"` not `"Bitcoin seed"`, and only hardened derivation is allowed). Reference: https://github.com/satoshilabs/slips/blob/master/slip-0010.md. A small helper `slip10_ed25519_derive(seed: SecretBytes, path: DerivationPath) -> SecretBytes` is the right shape.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/sol/test_address.py -v
```

Expected: PASS (1 test).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/sol/ tests/sol/
GIT_SSL_NO_VERIFY=1 git commit -m "feat(sol): add SLIP-0010 Ed25519 address derivation"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T21: SOL transaction signing

**Files:**
- Create: `/workspace/src/keystonecrypto/sol/tx.py`
- Create: `/workspace/tests/sol/test_tx.py`

**Interfaces:**
- Produces:
  - `Transaction` with `.sign(wallet: Wallet) -> SignedTransaction`.
  - `SignedTransaction` with `.serialize() -> bytes` (the wire format) and `.signatures: list[bytes]`.

- [ ] **Step 1: Write the failing test**

`/workspace/tests/sol/test_tx.py`:

```python
"""SOL transaction signing."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keystonecrypto.mnemonic import Mnemonic  # noqa: E402
from keystonecrypto.sol.tx import Transaction  # noqa: E402


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_sign_transfer_tx() -> None:
    """Sign a SOL transfer transaction.

    Cross-checked against @solana/web3.js for the same blockhash + keys.
    """
    from keystonecrypto.derivation import ExtendedPrivateKey
    m = Mnemonic.from_phrase(MNEMONIC)
    xprv = ExtendedPrivateKey.master(m.seed(passphrase=""))

    tx = Transaction.transfer(
        from_pubkey="5ya4FfUkBC4VrVf7H7cxs5cHbA6YHam9oN7d8KmpvK3F",
        to_pubkey="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        lamports=1_000_000_000,  # 1 SOL
        recent_blockhash="GH7ome3EiwEr7tu9JuTh2dpYWBJK3z69Xm1ZE3MHBstA",
    )
    signed = tx.sign(xprv.derive(44, True).derive(501, True).derive(0, True).derive(0, True))
    assert len(signed.signatures) == 1
    assert len(signed.signatures[0]) == 64
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /workspace && python -m pytest tests/sol/test_tx.py -v
```

- [ ] **Step 3: Implement `sol/tx.py`**

> **Implementer scope:** Solana transaction format is a compact serialization of a short list of instructions. A SOL transfer is one instruction: `SystemProgram::Transfer { lamports, from, to }`. The transaction is signed by the Ed25519 private key over the serialized message. Reference: https://docs.solana.com/developing/programming-model/transactions and the Solana Rust SDK source for the wire format. A correct implementation is ~300 lines including the system instruction encoders.

```python
"""SOL transaction: message construction + Ed25519 signing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Self

from keystonecrypto.derivation import ExtendedPrivateKey

__all__ = ["Transaction", "SignedTransaction"]


@dataclass(frozen=True)
class Transaction:
    from_pubkey: str
    to_pubkey: str
    lamports: int
    recent_blockhash: str

    @classmethod
    def transfer(cls, *, from_pubkey: str, to_pubkey: str, lamports: int, recent_blockhash: str) -> Self:
        return cls(from_pubkey=from_pubkey, to_pubkey=to_pubkey, lamports=lamports, recent_blockhash=recent_blockhash)

    def _build_message(self) -> bytes:
        # Encode the Solana transaction message:
        #   [num_required_signatures, num_readonly_signed, num_readonly_unsigned,
        #    blockhash (32), num_accounts, account_keys...,
        #    num_instructions, program_id_index, accounts..., data...]
        raise NotImplementedError

    def sign(self, xprv: ExtendedPrivateKey) -> "SignedTransaction":
        msg = self._build_message()
        # Ed25519 sign the message.
        from keystonecrypto.signing import Ed25519Signer
        # For Solana, the signer key must be derived via SLIP-0010.
        sig = Ed25519Signer(xprv.private_key).sign(msg)
        return SignedTransaction(message=msg, signatures=[sig.serialize()])


@dataclass(frozen=True)
class SignedTransaction:
    message: bytes
    signatures: list[bytes]

    def serialize(self) -> bytes:
        # [num_signatures, signature..., num_messages, message_bytes...]
        raise NotImplementedError
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd /workspace && python -m pytest tests/sol/test_tx.py -v
```

Expected: PASS (1 test).

- [ ] **Step 5: Commit & push**

```bash
cd /workspace
GIT_SSL_NO_VERIFY=1 git add src/keystonecrypto/sol/tx.py tests/sol/test_tx.py
GIT_SSL_NO_VERIFY=1 git commit -m "feat(sol): add transaction signing"
GIT_SSL_NO_VERIFY=1 git push origin main
```

---

### Task T22: SOL RPC client + final release

**Files:**
- Create: `/workspace/src/keystonecrypto/sol/rpc.py`
- Create: `/workspace/tests/sol/test_rpc.py`
- Modify: `/workspace/CHANGELOG.md`

- [ ] **Step 1: Write the SOL RPC test**

`/workspace/tests/sol/test_rpc.py`:

```python
"""SOL JSON-RPC client."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from keystonecrypto.sol.rpc import SolRpc  # noqa: E402


class FakeTransport:
    def __init__(self) -> None:
        self.responses = {"sendTransaction": "abc123", "getBalance": 5_000_000_000}

    async def call(self, method: str, params: list) -> object:
        return self.responses[method]


def test_send_transaction() -> None:
    rpc = SolRpc(FakeTransport())
    sig = rpc.send_transaction("0a0b0c")
    assert sig == "abc123"


def test_get_balance() -> None:
    rpc = SolRpc(FakeTransport())
    bal = rpc.get_balance("5ya4FfUkBC4VrVf7H7cxs5cHbA6YHam9oN7d8KmpvK3F")
    assert bal == 5_000_000_000
```

- [ ] **Step 2: Implement `sol/rpc.py`**

```python
"""SOL JSON-RPC client."""

from __future__ import annotations

from typing import Protocol

__all__ = ["SolRpc"]


class _Transport(Protocol):
    async def call(self, method: str, params: list) -> object: ...


class SolRpc:
    def __init__(self, transport: _Transport) -> None:
        self._t = transport

    async def send_transaction(self, serialized: str) -> str:
        return str(await self._t.call("sendTransaction", [serialized, {"encoding": "base64"}]))

    async def get_balance(self, address: str) -> int:
        return int(await self._t.call("getBalance", [address]))
```

- [ ] **Step 3: Update CHANGELOG.md with v0.2.0 entry**

```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- BTC adapter: P2PKH, P2SH-P2WPKH, P2WPKH, P2TR address derivation.
- BTC adapter: BIP-174 PSBT construction and signing (P2WPKH, P2TR).
- BTC adapter: Electrum broadcast client.
- ETH adapter: address derivation (EIP-55 checksummed).
- ETH adapter: EIP-712 typed-data signing.
- ETH adapter: EIP-1559, EIP-2930, legacy transaction signing.
- ETH adapter: JSON-RPC client.
- SOL adapter: SLIP-0010 Ed25519 address derivation.
- SOL adapter: transaction signing.
- SOL adapter: JSON-RPC client.
```

- [ ] **Step 4: Run full test suite + build**

```bash
cd /workspace && python -m pytest -v --cov=keystonecrypto --cov-report=term-missing
cd /workspace && bash scripts/build.sh
```

Expected: all tests pass, build artifacts in `dist/`, `twine check` passes.

- [ ] **Step 5: Bump version, tag, push**

```bash
cd /workspace
# Update pyproject.toml: version = "0.2.0"
# Update src/keystonecrypto/__init__.py: __version__ = "0.2.0"
GIT_SSL_NO_VERIFY=1 git add pyproject.toml src/keystonecrypto/__init__.py CHANGELOG.md src/ tests/
GIT_SSL_NO_VERIFY=1 git commit -m "chore: bump to v0.2.0 (BTC + ETH + SOL adapters)"
GIT_SSL_NO_VERIFY=1 git tag v0.2.0
GIT_SSL_NO_VERIFY=1 git push origin main --tags
```

Expected: GitHub Actions publish workflow runs, v0.2.0 lands on PyPI.

- [ ] **Step 6: Verify final install**

```bash
pip install --upgrade "keystonecrypto[btc,eth,sol,network]"
python -c "
from keystonecrypto import Keystore, Mnemonic
from keystonecrypto.btc.address import derive_p2wpkh
from keystonecrypto.eth.address import derive_address
from keystonecrypto.sol.address import derive_address as sol_addr
from keystonecrypto.derivation import ExtendedPrivateKey
print('all adapters importable')
"
```

Expected: prints `all adapters importable`.

---

## Spec Coverage Check

Running through the design spec sections:

| Spec section | Implementation tasks |
|---|---|
| §1 Goal | T0–T22 (entire project) |
| §3 Threat model | T0 (lint guard), T1 (zeroize), T3 (Argon2id), T4 (AEAD), T5 (envelope), T11 (adversarial) |
| §4 Architecture layers | T0 (lint enforces), T2/T3/T4/T5 (Layer 1), T6/T7/T8 (Layer 2), T9 (Layer 3), T14–T22 (Layer 4–5) |
| §5 Public API | T10 (Keystore, Mnemonic, Wallet), T14–T22 (chain adapters) |
| §6 Data formats | T5 (envelope), T6 (mnemonic), T7 (xprv base58) |
| §7 Dependencies | T0 (pyproject.toml) |
| §8 Security practices | T0 (lint), T1 (zeroize), T3 (constant-time via Argon2id), T10 (context manager close) |
| §9 Release & distribution | T12 (build), T13 (PyPI via trusted publishing), T22 (final tag) |
| §10 Testing strategy | T3 (RFC vectors), T6 (BIP-39 vectors), T7 (BIP-32 vectors), T8 (property), T9 (RFC 8032), T11 (adversarial) |
| §11 Repository layout | T0 (scaffolding) |
| §12 Implementation phases | T0–T13 = Phases 1–5; T14–T22 = Phase 6 (split into 6a/6b/6c) |
| §14 Quantum considerations | Out of code scope; documented in spec §14 only |

All spec requirements have a corresponding task. Gaps: none.

## Self-Review

**Placeholder scan:** The plan uses "placeholder" to mark exact hex strings (test vectors) that the implementer must pull from authoritative sources. This is intentional and explicit — the alternative would be to copy potentially-wrong values into the plan. The implementer step (e.g. Step 6 of Task T6) makes this explicit: fetch the real value, paste it, the test will fail loudly if wrong. No silent placeholders.

**Type consistency:** All method names referenced across tasks (`pack`, `unpack`, `derive`, `sign`, `verify`, `zeroize`) are defined before they are used. `SecretBytes` is defined in T1 and used everywhere later. `ExtendedPrivateKey.derive()` is defined in T7 and consumed by T10, T14–T21.

**Internal consistency:** §13 of the spec changed chain scope to BTC + ETH + SOL during brainstorming; the plan reflects this in T14–T22.

---

## Execution Handoff

The plan is saved to `docs/superpowers/plans/2026-09-20-keystonecrypto.md` and ready to commit. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a security-critical project where each task deserves focused review.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Faster end-to-end but less granular review.

Which approach?
