# DEPLOY.md — keystonecrypto release workflow

This file is the human handoff for shipping keystonecrypto to PyPI.
The build never runs in the sandbox — it runs on your machine.

## What I do on my side (already in /workspace)

- Source code lives in `/workspace/src/keystonecrypto/`
- Tests live in `/workspace/tests/`
- Spec + plan in `/workspace/docs/superpowers/`
- Every commit pushed to `https://github.com/lordxmen2k/KeystoneCrypto.git` (private)

## What you do on your side (commands below)

Set up a fresh folder for keystonecrypto, clone the repo, build the
wheel, run `twine check`, then `twine upload`.

**All commands run as you, on your local machine. No TestPyPI.**

### 1. Create the folder + clone

```bash
mkdir -p ~/keystonecrypto && cd ~/keystonecrypto
git clone https://github.com/lordxmen2k/KeystoneCrypto.git .
```

### 2. Set up the venv + install deps

```bash
cd ~/keystonecrypto
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
pip install -e ".[dev]"   # installs everything we need to test + build
```

### 3. Run the test suite (must pass before shipping)

```bash
cd ~/keystonecrypto
source .venv/bin/activate
pytest -v --cov=keystonecrypto --cov-report=term-missing
```

Expected:
- All tests pass
- Coverage ≥ 95% on Layers 1–3 (`secret_bytes`, `entropy`, `kdf`,
  `aead`, `envelope`, `mnemonic`, `derivation`, `signing`, `keystore`)

### 4. Build the distribution artifacts

```bash
cd ~/keystonecrypto
source .venv/bin/activate
rm -rf dist/ build/ src/*.egg-info src/keystonecrypto/*.egg-info
python -m build
twine check dist/*
ls -la dist/
```

Expected output:
- `dist/keystonecrypto-0.1.0-py3-none-any.whl`
- `dist/keystonecrypto-0.1.0.tar.gz`
- `twine check` prints "PASSED"

### 5. Upload to PyPI (real PyPI, no TestPyPI)

You run this yourself with your own PyPI API token.

```bash
cd ~/keystonecrypto
source .venv/bin/activate
twine upload dist/*
```

When prompted:
- Username: `__token__`
- Password: your PyPI API token (the `pypi-...` string from
  https://pypi.org/manage/account/token/)

After upload completes:
- Verify at https://pypi.org/project/keystonecrypto/
- Run `pip install --upgrade keystonecrypto` somewhere clean to
  confirm the install works

### 6. Tag the release on GitHub

```bash
cd ~/keystonecrypto
git tag v0.1.0
git push origin v0.1.0
```

### 7. (optional) Zip for archival

```bash
cd ~
zip -r keystonecrypto-v0.1.0.zip keystonecrypto -x "keystonecrypto/.venv/*" "keystonecrypto/.git/*" "keystonecrypto/dist/*" "keystonecrypto/build/*"
```

## Where things live after upload

| Artifact | Location |
|---|---|
| Source | https://github.com/lordxmen2k/KeystoneCrypto |
| Package | https://pypi.org/project/keystonecrypto/ |
| Wheel + sdist | `dist/` (local) before upload |
| Tag | `v0.1.0` on GitHub |

## If anything fails

- `pip install` errors → check you're on Python 3.11+ and the venv is activated
- `pytest` fails → check the output, paste errors back to me; I'll fix the source
- `python -m build` fails → paste errors back; usually means a missing
  file in `MANIFEST.in` or a typo in `pyproject.toml`
- `twine upload` says "403 Forbidden" → your token is wrong, or
  the package name is already taken (we verified `keystonecrypto`
  is available earlier in this session)
- `twine upload` says "File already exists" → you tried to upload
  the same version twice; bump version in `pyproject.toml` +
  `__init__.py` and rebuild

## Never

- Do not use `--repository testpypi` — destination is always real PyPI
- Do not commit the PAT to git (the sandbox PAT in
  `.home/.git-credentials` is for git operations only)
- Do not share or echo your PyPI API token in logs
