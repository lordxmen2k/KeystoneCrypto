# DEPLOY.md — keystonecrypto release workflow

Same shape as SNAIL. GitHub is just the code bucket. You download
from GitHub and do the full build + `twine upload` on your machine.

No GitHub workflows, no CI, no trusted publishing, no TestPyPI.

## What was built (v0.1.0)

The full core library is on `lordxmen2k/KeystoneCrypto` main branch:

- **Layer 1:** `SecretBytes` (zeroize), CSPRNG entropy, Argon2id KDF
  (OWASP 2024 minimums with `INTERACTIVE_PROFILE` and
  `HIGH_SECURITY_PROFILE`), AES-256-GCM AEAD with AAD, versioned KST1
  binary envelope.
- **Layer 2:** BIP-39 mnemonic (full 2048-word English list), BIP-32
  derivation, BIP-44 path parsing, base58 xprv serialization.
- **Layer 3:** secp256k1 ECDSA (64-byte compact), BIP-340 Schnorr
  (Taproot key-path), RFC 8032 Ed25519.
- **Keystore + Wallet** high-level API with context-manager zeroize.
- **Property-based tests** (Hypothesis) + **adversarial tests** for
  envelope corruption / downgrade / tampering.
- **Lint guard** that prevents network libraries from being imported
  in core code (Layers 1–3).

## Test vectors verified in the sandbox

These ran against the actual source code, not mocks:

- ✅ All 10 official BIP-39 trezor vectors (12/18/24-word mnemonics,
  0x00/0x7f/0x80/0xff entropies)
- ✅ BIP-39 NFKD normalization (composed vs decomposed é)
- ✅ BIP-39 entropy roundtrip for all 5 valid sizes (128/160/192/224/256 bits)
- ✅ AES-256-GCM roundtrip + AAD mismatch + wrong key
- ✅ SecretBytes zeroize + repr redaction
- ✅ Lint guard (no network imports in core)

Test code is also written for BIP-32 (11 official vectors), RFC 8032
(3 Ed25519 vectors), envelope roundtrip, and signing — your local
`pytest` will run them once `coincurve` / `argon2-cffi` / `pydantic` are
installed in your venv.

## Your full deploy sequence

Same blueprint as SNAIL: clone, build locally, upload from your machine.
Real PyPI only, no TestPyPI, you run `twine upload` personally.

```bash
# === keystonecrypto v0.1.0 deploy — SNAIL-shaped ===

# 1) Fresh folder + clone from the private repo
mkdir -p ~/keystonecrypto && cd ~/keystonecrypto
git clone https://github.com/lordxmen2k/KeystoneCrypto.git .

# 2) Venv + install everything
cd ~/keystonecrypto
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip wheel
pip install -e ".[dev]"

# 3) Run the full test suite (must pass before continuing)
pytest -v --cov=keystonecrypto --cov-report=term-missing
# Expected: all tests pass, coverage ≥ 95% on Layers 1–3.

# 4) Build the wheel + sdist
bash scripts/build.sh
# Expected:
#   dist/keystonecrypto-0.1.0-py3-none-any.whl
#   dist/keystonecrypto-0.1.0.tar.gz
#   twine check: PASSED

# 5) Upload to PyPI (real, no TestPyPI — you run this)
twine upload dist/*
# Username: __token__
# Password: your PyPI API token (the pypi-... string from
#           https://pypi.org/manage/account/token/)

# 6) Tag the release on GitHub
git tag v0.1.0
git push origin v0.1.0

# 7) Verify the live install
pip install --upgrade keystonecrypto
python -c "from keystonecrypto import Keystore, Mnemonic; print(keystonecrypto.__version__)"
# Expected: 0.1.0
```

## Where things live after upload

| Artifact | Location |
|---|---|
| Source | https://github.com/lordxmen2k/KeystoneCrypto |
| Package | https://pypi.org/project/keystonecrypto/ |
| Wheel + sdist | `dist/` (local, before upload) |
| Tag | `v0.1.0` on GitHub |

## If anything fails

- `pip install` errors → check Python 3.11+ and that venv is activated
- `pytest` fails → paste errors back; I'll fix the source
- `python -m build` fails → check `pyproject.toml` and `MANIFEST.in`
- `twine upload` says "403" → token wrong, or `keystonecrypto` is
  already taken on PyPI (we verified it was free before this session)
- `twine upload` says "File already exists" → bump version in
  `pyproject.toml` and `__init__.py`, rebuild

## Never

- Do not use `--repository testpypi` — destination is always real PyPI
- Do not commit the GitHub PAT (the sandbox PAT in
  `.home/.git-credentials` is for git only)
- Do not share or echo your PyPI API token in logs
- Do not add GitHub Actions / CI / trusted publishing — GitHub is
  just the code bucket, nothing more

## Chain adapters (v0.2.0)

Phase 6 of the plan (BTC, ETH, SOL adapters) was not started because
the sandbox can't install `coincurve` to test signing code. The plan
at `docs/superpowers/plans/2026-09-20-keystonecrypto.md` covers
T14–T22; resume them after v0.1.0 ships.
