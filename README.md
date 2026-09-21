# keystonecrypto

[![PyPI](https://img.shields.io/pypi/v/keystonecrypto)](https://pypi.org/project/keystonecrypto/)
[![Python](https://img.shields.io/pypi/pyversions/keystonecrypto)](https://pypi.org/project/keystonecrypto/)
[![License](https://img.shields.io/pypi/l/keystonecrypto)](https://github.com/lordxmen2k/KeystoneCrypto/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-yellow)](https://github.com/lordxmen2k/KeystoneCrypto)
[![Tests](https://img.shields.io/badge/tests-101%20passed-blue)](https://github.com/lordxmen2k/KeystoneCrypto)
[![Coverage](https://img.shields.io/badge/coverage-95%25%2B-brightgreen)](https://github.com/lordxmen2k/KeystoneCrypto)
[![Conformance](https://img.shields.io/badge/BIP--39%20%2F%20BIP--32%20%2F%20RFC8032%20%2F%20RFC9106-passing-success)](https://github.com/lordxmen2k/KeystoneCrypto)
[![Repo](https://img.shields.io/badge/github-lordxmen2k%2FKeystoneCrypto-blue)](https://github.com/lordxmen2k/KeystoneCrypto)

> **Note on badge values:** the `Tests`, `Coverage`, and `Conformance`
> badges reflect the test suite at v0.1.0 (101 test functions across 12
> files; coverage ≥ 95% on Layers 1–3; 10 BIP-39 + 11 BIP-32 + 3 RFC 8032
> + 1 RFC 9106 vector). Run `pytest --cov=keystonecrypto` locally for
> the actual current measurement.

Non-custodial hierarchical deterministic (HD) wallet primitives for Python.

Generate BIP-39 seeds, derive addresses across Bitcoin, Ethereum, and
Solana, encrypt keystores with Argon2id + AES-256-GCM, and sign messages
with secp256k1 ECDSA, BIP-340 Schnorr, or RFC 8032 Ed25519. Pluggable
chain adapters ship as optional extras.

The security-critical core (key management + signing) is the default
install. Optional `[btc]`, `[eth]`, `[sol]` extras add per-chain
transaction building and broadcast. **No chain extras means no network
calls** — the core is offline by default.

## Install

```bash
pip install keystonecrypto              # core only (key mgmt + signing)
pip install keystonecrypto[btc]         # + Bitcoin (PSBT, Electrum)
pip install keystonecrypto[eth]         # + Ethereum (tx + JSON-RPC)
pip install keystonecrypto[sol]         # + Solana (tx + RPC)
pip install keystonecrypto[network]     # + httpx for chain RPC clients
```

Python 3.11+ required. Tested on 3.12 and 3.13. Python 3.14 is not yet
supported because some C-extension dependencies do not publish
prebuilt wheels for it.

## Five-minute tour

### 1. Generate a new mnemonic and persist it

```python
from keystonecrypto import Keystore, Mnemonic

# 12-word phrase from 128 bits of OS entropy.
# Use strength=256 for a 24-word phrase.
mnemonic = Mnemonic.generate()
print(mnemonic.phrase)   # NEVER log this in production code

# Encrypt it under a user passphrase using Argon2id + AES-256-GCM.
keystore = Keystore.create(mnemonic, "correct horse battery staple")
keystore.save("wallet.keystore")  # ~200 bytes, opaque binary
```

### 2. Open the keystore, unlock it, derive keys

```python
from keystonecrypto import Keystore, DerivationPath

with Keystore.open("wallet.keystore") as ctx:
    with ctx.unlock("correct horse battery staple") as wallet:
        # The wallet holds the seed in memory. close() zeroizes it.

        # BIP-44 first receive address for Bitcoin (m/44'/0'/0'/0/0).
        path = DerivationPath.parse("m/44'/0'/0'/0/0")
        account = wallet.derive_account(path)   # default: ECDSA over secp256k1
        print(account.public_key_hex())

        # Ethereum uses coin type 60, not 0.
        eth_path = DerivationPath.parse("m/44'/60'/0'/0/0")
        eth_account = wallet.derive_account(eth_path)
        # (Address derivation itself is in the [eth] extra.)
```

### 3. Sign and verify messages

```python
from keystonecrypto import (
    Keystore, Mnemonic, DerivationPath,
    Secp256kSigner, Secp256kSchnorrSigner, Ed25519Signer,
)

with Keystore.open("wallet.keystore") as ctx, \
     ctx.unlock("correct horse battery staple") as wallet:

    path = DerivationPath.parse("m/44'/0'/0'/0/0")

    # ECDSA over secp256k1 (Bitcoin, Ethereum) — 64-byte compact signature.
    sig = wallet.sign_message(path, b"hello world", scheme="ecdsa-secp256k1")
    assert sig.verify(b"hello world", wallet.derive_account(path).public_key)

    # BIP-340 Schnorr (Taproot key-path spends).
    sig = wallet.sign_message(path, b"hello world", scheme="schnorr-secp256k1")
    assert sig.verify(b"hello world", wallet.derive_account(path).public_key)

    # RFC 8032 Ed25519 (Solana).
    sol_path = DerivationPath.parse("m/44'/501'/0'/0'")
    sig = wallet.sign_message(sol_path, b"hello world", scheme="ed25519")
    assert sig.verify(b"hello world", wallet.derive_account(sol_path).public_key)
```

### 4. Sign without a keystore (lower-level API)

```python
from keystonecrypto import (
    Mnemonic, ExtendedPrivateKey, derive_from_seed,
    Secp256kSigner, Ed25519Signer,
)
from keystonecrypto.secret_bytes import SecretBytes

seed_bytes = Mnemonic.from_phrase(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
).seed(passphrase="")  # 64-byte SecretBytes

xprv = derive_from_seed(seed_bytes, DerivationPath.parse("m/44'/0'/0'/0/0"))
signer = Secp256kSigner(xprv.private_key)
sig = signer.sign(b"raw message")
assert sig.verify(b"raw message", signer.public_key_bytes())
```

## BIP-39 passphrase ("25th word")

A BIP-39 passphrase is appended to the mnemonic before seed derivation.
It is **not** recoverable — losing the passphrase means losing the
wallet, even with the correct mnemonic.

```python
from keystonecrypto import Mnemonic

m = Mnemonic.from_phrase(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Same mnemonic + different passphrase = different wallet.
seed_no_pp    = m.seed(passphrase="")             # default
seed_with_pp  = m.seed(passphrase="my-secret-25th")
assert bytes(seed_no_pp) != bytes(seed_with_pp)
```

`Mnemonic.generate()` returns a phrase; the passphrase is supplied at
seed-derivation time and stored in the keystore envelope's
`has_passphrase` flag.

## Keystore envelope (binary format)

The keystore is an opaque binary blob, ~200 bytes for a 32-byte seed.
Layout (big-endian, version 1 = "KST1"):

```
Header (66 bytes):
    magic        4   "KST1"
    version      1   0x01
    kdf_id       1   0x01 = Argon2id
    kdf_params  32   (time_cost | memory_cost | parallelism |
                       hash_len | version | reserved)
    salt        16
    nonce       12
Body (variable):
    ciphertext   N   (AES-256-GCM with 16-byte appended tag)
```

Decryption binds the ciphertext to the (version, kdf_id) via GCM
associated data, so downgrades and cross-context replay fail closed.
See [`SECURITY.md`](./SECURITY.md) for the threat model and a list of
known adversarial behaviors that fail correctly.

## Argon2id profiles

```python
from keystonecrypto import Keystore
from keystonecrypto.kdf import (
    INTERACTIVE_PROFILE, HIGH_SECURITY_PROFILE, Argon2Params,
)

# Default: OWASP 2024 minimum for interactive use.
ks = Keystore.create(mnemonic, "pw", params=INTERACTIVE_PROFILE)

# Cold storage / high-value wallets: 2x memory, +1 time.
ks = Keystore.create(mnemonic, "pw", params=HIGH_SECURITY_PROFILE)

# Custom profile — must meet OWASP minimums (~19 MiB, time_cost ≥ 2,
# parallelism ≥ 1). Tests bypass this with Argon2Params.for_testing(...).
```

## Chain adapters (optional extras)

The `[btc]`, `[eth]`, and `[sol]` extras each ship in v0.2.0. They
provide per-chain address derivation, transaction construction, and
broadcast clients. Until then, the core covers key generation and
signing — you bring your own chain logic.

Example after v0.2.0:

```python
# pip install "keystonecrypto[btc]"   (planned for v0.2.0)
from keystonecrypto.btc.address import derive_p2wpkh_from_path
from keystonecrypto.btc.psbt import PSBT
from keystonecrypto.btc.electrum import Electrum

# Native SegWit address at m/84'/0'/0'/0/0.
addr = derive_p2wpkh_from_path(wallet, "m/84'/0'/0'/0/0")

# Sign a PSBT and broadcast via Electrum.
psbt = PSBT.from_base64(raw_psbt)
signed = psbt.sign(wallet)
txid = await Electrum(client).broadcast(signed.to_base64())
```

> **Status note:** chain adapters (`keystonecrypto[btc]`, `[eth]`, `[sol]`)
> ship in v0.2.0 and are not yet part of v0.1.0. The function names above
> show the intended API and may change before release. The plan at
> [`docs/superpowers/plans/2026-09-20-keystonecrypto.md`](docs/superpowers/plans/2026-09-20-keystonecrypto.md)
> tasks T14–T22 covers what will land.

## API reference

Top-level exports (`from keystonecrypto import ...`):

| Name | Purpose |
|---|---|
| `Keystore` | Encrypted mnemonic on disk; `create`, `save`, `open` |
| `KeystoreContext` | Context manager; `.unlock(password) -> Wallet` |
| `Wallet` | Unlocked wallet; `.derive_account(path)`, `.sign_message(...)`, `.close()` |
| `Mnemonic` | BIP-39 phrase; `.generate()`, `.from_phrase()`, `.from_entropy()`, `.seed()` |
| `DerivationPath` | BIP-32 path; `parse("m/44'/0'/0'/0/0")` |
| `ExtendedPrivateKey` | BIP-32 xprv; `.derive(i, hardened=...)`, `.to_base58()` |
| `derive_from_seed` | One-shot derivation from seed + path |
| `SecretBytes` | Zeroizing wrapper; `random(length)`, `.zeroize()`, `.hex()` |
| `Secp256kSigner` | secp256k1 ECDSA, 64-byte compact signature |
| `Secp256kSchnorrSigner` | BIP-340 Schnorr (Taproot key-path) |
| `Ed25519Signer` | RFC 8032 Ed25519 (Solana) |
| `STRENGTH_BITS`, `generate_entropy` | BIP-39 entropy sizes |

## Security

Read [`SECURITY.md`](./SECURITY.md) before using this library in
production. Highlights:

- The default install has **zero network capability**. A lint guard
  prevents network libraries (`httpx`, `requests`, `socket`, etc.)
  from being imported in core code.
- All sensitive memory lives in `SecretBytes`, which zeroizes on
  context-manager exit and on garbage collection.
- All hash and compare operations use constant-time primitives.
- Public keystore construction enforces OWASP 2024 Argon2id minimums
  (`Argon2Params.for_testing(...)` is the only escape hatch, used by
  the RFC 9106 conformance test).
- Conformance: BIP-39 (10 official trezor vectors), BIP-32 (11
  official spec vectors), RFC 8032 (3 Ed25519 vectors), RFC 9106
  (Argon2id § 5).

This library is **not** a hosted service, **not** a custodial wallet,
**not** a UI. It is a building block. The user is responsible for
securing the host process, the passphrase, and the keystore file.

## Glossary

Every term used in this README and the public API.

### Cryptography

| Term | Definition |
|---|---|
| **AEAD (Authenticated Encryption with Associated Data)** | Encryption mode that produces both ciphertext and an authentication tag, binding the ciphertext to a context string so tampering or cross-context replay is detectable. We use AES-256-GCM. |
| **AES-256-GCM** | The Advanced Encryption Standard with 256-bit keys, in Galois/Counter Mode. Symmetric encryption (same key for encrypt and decrypt) producing a 12-byte nonce, ciphertext, and 16-byte authentication tag. |
| **Argon2id** | A memory-hard password hashing function. The recommended KDF for password-based key derivation because it resists both GPU and side-channel attacks. Winner of the 2015 Password Hashing Competition. |
| **Authentication tag** | The 16-byte value AES-GCM appends to the ciphertext. Decryption verifies the tag matches; mismatch raises `KeystoreDecryptionError`. |
| **Constant-time** | An operation whose execution time does not depend on secret data, preventing timing side-channel attacks. We use `hmac.compare_digest` for byte comparison and audited `libsecp256k1` for scalar arithmetic. |
| **CSPRNG** | A Cryptographically Secure Pseudo-Random Number Generator. We use `secrets.token_bytes`, which draws from the OS entropy source (`/dev/urandom` on Unix, `BCryptGenRandom` on Windows). |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm. We use it over secp256k1 for Bitcoin and Ethereum. Produces a 64-byte compact signature `(r, s)`. |
| **Ed25519** | A signature scheme using the Edwards-curve `Curve25519`. RFC 8032 standard. Used by Solana. |
| **KDF (Key Derivation Function)** | A slow, memory-hard function that turns a password into a cryptographic key. |
| **libsecp256k1** | The reference C implementation of secp256k1 elliptic-curve operations, written by Bitcoin Core contributors and audited. Used via the `coincurve` Python wrapper. |
| **Schnorr signature (BIP-340)** | A signature scheme over secp256k1 with provable security under standard assumptions and native multi-sig aggregation. Taproot (BIP-341) uses BIP-340 Schnorr for key-path spends. |
| **secp256k1** | The elliptic curve used by Bitcoin and Ethereum. Parameters: y² = x³ + 7 over the finite field of order `2^256 - 2^32 - 977`. |
| **Zeroize** | To overwrite memory containing a secret with zeros, ideally before it can be read by an attacker. `SecretBytes.zeroize()` overwrites the bytearray in place. |

### BIP standards

| Term | Definition |
|---|---|
| **BIP-32** | Hierarchical Deterministic Wallets. Defines how to derive a tree of keypairs from a single seed using HMAC-SHA512 and secp256k1 scalar addition. |
| **BIP-39** | Mnemonic code for generating deterministic keys. Defines the wordlist, the entropy-to-mnemonic mapping, and the PBKDF2-HMAC-SHA512 seed derivation (2048 iterations). |
| **BIP-44** | Multi-account hierarchy for HD wallets. Defines the 5-level path structure `m / purpose' / coin_type' / account' / change / address_index`. |
| **BIP-49** | Derivation scheme for P2SH-wrapped SegWit (`3...` addresses). Path: `m/49'/coin_type'/account'/change/address_index`. |
| **BIP-84** | Derivation scheme for native SegWit v0 (`bc1q...` addresses). Path: `m/84'/coin_type'/account'/change/address_index`. |
| **BIP-86** | Derivation scheme for single-key Taproot (`bc1p...` addresses). Path: `m/86'/coin_type'/account'/change/address_index`. |
| **Chain code** | The 32-byte auxiliary value in a BIP-32 extended key, used to derive children. |
| **Extended key (xprv/xpub)** | A BIP-32 serialized private (`xprv`) or public (`xpub`) key, containing the key, chain code, depth, parent fingerprint, and child number. 78 bytes, base58check-encoded. |
| **Hardened derivation** | A BIP-32 derivation mode in which the parent private key is required. Indices `>= 2^31`. Indicated by the apostrophe in `m/44'`. |
| **Master key** | The BIP-32 key derived directly from a seed via HMAC-SHA512. The root of the derivation tree. |
| **Mnemonic** | A BIP-39 phrase: 12, 15, 18, 21, or 24 words from a 2048-word list. Encodes 128, 160, 192, 224, or 256 bits of entropy plus a checksum. |
| **Mnemonic passphrase (25th word)** | An optional user-supplied string combined with the mnemonic to produce a different seed. Not stored anywhere; losing it = losing the wallet. |
| **Non-hardened derivation** | A BIP-32 derivation mode using only the parent public key. Indices `< 2^31`. Indicated by the lack of apostrophe in `m/0`. |
| **Seed** | The 512-bit output of BIP-39 seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations). Used as the input to BIP-32 master key generation. |
| **Wordlist** | The 2048 English words defined by BIP-39, in alphabetical order. Index 0 = "abandon", index 2047 = "zoo". |

### Wallet concepts

| Term | Definition |
|---|---|
| **Account (BIP-44)** | The third level of a BIP-44 path (`account'`), allowing multiple wallets under the same seed (e.g. personal vs. business funds). |
| **Address** | A public, human-shareable identifier derived from a public key. Different chains use different address formats (Base58 for legacy BTC, Bech32 for SegWit, hex with EIP-55 checksum for ETH, base58 for SOL). |
| **Air-gapped wallet** | A wallet whose keys never touch an internet-connected device. Generate keys offline, sign transactions on the offline device, broadcast from an online device. |
| **BIP-44 path** | A 5-level derivation path: `m / purpose' / coin_type' / account' / change / address_index`. `change` is 0 for receive, 1 for change outputs. |
| **Change output** | In Bitcoin, the "leftover" amount from a transaction that's sent back to the spender. Uses `change = 1` in the derivation path. |
| **Coin type** | The second level of a BIP-44 path, identifying the blockchain. 0 = Bitcoin, 60 = Ethereum, 501 = Solana. |
| **Custodial wallet** | A wallet where a third party holds the keys on the user's behalf. **This library is NOT custodial.** |
| **Derivation path** | The string used to derive a specific key from a master seed. Examples: `m`, `m/44'/0'/0'/0/0`, `m/0'/1`. |
| **HD wallet (Hierarchical Deterministic)** | A wallet where a single seed generates a tree of keypairs. Contrast with non-deterministic (random) wallets. |
| **Keystore** | In this library, an encrypted BIP-39 mnemonic persisted to disk. ~200 bytes, KST1 binary format, Argon2id + AES-256-GCM. |
| **Non-custodial wallet** | A wallet where the user holds the keys. **This library is non-custodial.** |
| **PSBT (Partially Signed Bitcoin Transaction, BIP-174)** | A binary interchange format for partially-signed Bitcoin transactions, used to pass transactions between wallets and signers. |
| **Purpose** | The first level of a BIP-44 path, identifying the derivation scheme. 44 = BIP-44, 49 = BIP-49, 84 = BIP-84, 86 = BIP-86. |
| **Receive address** | An address given to others to send funds to. Uses `change = 0` in the BIP-44 path. Should be used exactly once for privacy. |
| **Seed phrase** | Synonym for mnemonic. A BIP-39 phrase. |
| **Sighash** | The hash a signer commits to when signing a transaction input. Different per-input types: BIP-143 (SegWit v0), BIP-341 (Taproot). |
| **Signer** | In this library, an object with `.sign(message) -> Signature` and `.public_key_bytes() -> bytes`. Three implementations: secp256k1 ECDSA, BIP-340 Schnorr, Ed25519. |
| **Wallet (this library)** | An in-memory object holding the seed, returned by `KeystoreContext.unlock(...)`. Closed via context-manager exit or `.close()`. |
| **xprv** | See Extended key. |

### Encryption envelope (this library)

| Term | Definition |
|---|---|
| **KST1** | The magic bytes marking a keystonecrypto v1 keystore file. Any blob not starting with these four bytes is rejected. |
| **kdf_id** | The 1-byte identifier for the key derivation function used to wrap the seed. 0x01 = Argon2id. Future versions may add scrypt, PBKDF2, etc. |
| **magic** | Four bytes at the start of a binary file identifying its format. We use `KST1`. |
| **OWASP minimums** | The Password Storage Cheat Sheet's Argon2id recommendations as of 2024: memory_cost ≥ 19 MiB, time_cost ≥ 2, parallelism ≥ 1. We enforce these for public `Argon2Params(...)` construction. |
| **Salt** | Random bytes mixed into the KDF to prevent rainbow-table attacks. We use 16 bytes from the OS CSPRNG. |
| **Version byte** | The 1-byte field after `KST1` indicating the envelope version. We currently support version 0x01 only. Unknown versions are rejected with `KeystoreVersionError`. |

### Threat model

| Term | Definition |
|---|---|
| **AEAD failure** | The exception raised when AES-GCM authentication fails. We use `KeystoreDecryptionError`. Never leaks which byte was wrong. |
| **Downgrade attack** | An attempt to use a weaker version of a primitive (e.g. lower Argon2id cost) than the current default. Defended by binding the ciphertext to the (version, kdf_id) via GCM associated data. |
| **Fail closed** | A failure mode where any unexpected condition results in the secure default (deny access, refuse to decrypt, reject the request). Every keystore error path fails closed. |
| **Harvest now, decrypt later** | An adversary records today's encrypted traffic or public keys, then decrypts them later when cryptographically relevant quantum computers exist. HD wallets are narrow targets: seeds live in keystores, not on-chain. |
| **Side-channel attack** | An attack that uses physical effects of computation (timing, power consumption, cache patterns) rather than direct cryptanalysis. Mitigated via constant-time primitives and audited libraries. |

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
