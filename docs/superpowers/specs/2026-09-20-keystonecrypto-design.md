# keystonecrypto — Design Spec

**Status:** Draft for review
**Date:** 2026-09-20
**Repo:** https://github.com/lordxmen2k/KeystoneCrypto (private)
**PyPI:** `keystonecrypto` (real PyPI, NOT TestPyPI)

---

## 1. Goal

A non-custodial hierarchical deterministic (HD) wallet **library** for Python, distributed via PyPI as `keystonecrypto`. The library handles the security-critical primitives (seed generation, encryption, derivation, signing) in a small, audited core, with optional per-chain adapters that add transaction building and broadcast.

It is **not** a hosted service, **not** a custodial wallet, **not** a CLI application — those are out of scope. It is a building block other developers use to add self-custodial wallet functionality to their software.

## 2. Non-Goals

- Hosting user funds or keys on behalf of users
- Mobile / desktop / web UI (this library, not an app)
- Web-based key generation in the browser (Python only)
- Fiat on/off-ramps
- Exchange functionality
- Custodial account management
- Cloud key storage / sync

## 3. Threat Model

The library must hold up under these adversarial conditions:

| Threat | Mitigation |
|---|---|
| Memory dump while unlocked | Sensitive material zeroized after use; constant-time operations; `secrets`-grade RNG |
| Weak user passphrase | Argon2id KDF with conservative parameters; configurable work factor |
| Keystore file theft | Authenticated encryption (AES-GCM or XChaCha20-Poly1305); Argon2id-derived key; versioned format |
| Replay of old ciphertexts | AEAD nonce + version field; reject on version mismatch |
| Side-channel timing leaks | Constant-time comparisons; constant-time scalar ops via audited library |
| Downgrade attacks | Strict version negotiation; refuse to decrypt with weaker params than current default |
| Supply-chain attack | Minimal dependencies; pinned lockfile; reproducible builds (cibuildwheel + hash check); SLSA-style provenance noted in README |
| Malicious BIP-39 wordlist | Validate wordlist checksum at load; reject unknown lists |
| Invalid curve points | Strict validation against secp256k1; reject points not on curve, at infinity, or of unknown order |
| Network-based key exfiltration | Default install has zero network capability; chain adapter opt-in only |

### Out of threat model

- Physical access to a running, unlocked process (assumed game-over)
- Compromised Python interpreter
- Side-channel on host CPU (Spectre, etc.) — we use audited primitive libraries; we do not write our own field arithmetic

## 4. Architecture

Five layers, strictly import-ordered from inner to outer. Lower layers must not import higher ones.

```
                    ┌────────────────────────────────┐
   Layer 5 (opt-in) │  chain adapters                │  keystonecrypto[btc], [eth], ...
                    ├────────────────────────────────┤
   Layer 4 (opt-in) │  transaction builder           │  PSBT, EIP-1559, ...
                    ├────────────────────────────────┤
   Layer 3          │  signing primitives            │  ECDSA, Schnorr, Ed25519
                    ├────────────────────────────────┤
   Layer 2          │  HD derivation + serialization │  BIP-32/39/44
                    ├────────────────────────────────┤
   Layer 1          │  entropy + KDF + AEAD          │  CSPRNG, Argon2id, AES-GCM
                    └────────────────────────────────┘
```

**Layer 1 — entropy, KDF, AEAD:**
- `secrets` module for entropy
- Argon2id (via `argon2-cffi`) for KDF
- AES-256-GCM (via `cryptography`) for symmetric encryption
- Strict, versioned binary envelope: `[magic:4][version:1][kdf_id:1][kdf_params:32][salt:16][nonce:12][ciphertext:N][tag:16]`

**Layer 2 — HD derivation + serialization:**
- BIP-39 mnemonic generation (12/15/18/21/24 words) and validation
- BIP-39 passphrase support (the "25th word")
- BIP-32 hierarchical derivation (master → child keys, hardened + non-hardened)
- BIP-44/49/84/86 purpose paths for BTC, EIP-44 for ETH, SLIP-10 for Ed25519 chains
- Serialization: extended keys (xprv/xpub), addresses (per chain adapter)
- Wordlist: English only at v1 (single wordlist reduces supply-chain surface; non-English is a v2 feature)

**Layer 3 — signing primitives:**
- secp256k1 ECDSA + Schnorr (via `coincurve`, which wraps libsecp256k1)
- Ed25519 (via `cryptography` for Ed25519, or `PyNaCl` for compatibility)
- Constant-time comparison helpers
- Signature format converters (DER, compact, raw)

**Layer 4 — transaction builders (per chain, in extras):**
- BTC: PSBT (BIP-174) construction, SegWit v0/v1 (Taproot) signing inputs
- ETH: EIP-1559 + EIP-2930 + legacy tx, EIP-712 typed data
- More chains in v2

**Layer 5 — chain adapters (in extras):**
- BTC: Electrum client for broadcast + UTXO fetch, OR user-provided node URL
- ETH: JSON-RPC client (Infura/Alchemy/custom) for broadcast + nonce + gas estimation
- All network code behind a `Network` protocol the user can substitute (test mocks, custom nodes, Tor proxies)

**Keystore model:**
- `Keystore` is an opaque, encrypted blob. Library never holds an unlocked key in a long-lived process unless the user explicitly asks.
- `Wallet` object is short-lived: `unlock(keystore, passphrase) → wallet; use; wallet.close()` zeroizes memory.
- Context manager API: `with Keystore.from_file(...) as ks: ...`

## 5. Public API

```python
from keystonecrypto import Keystore, Mnemonic, Wallet, Network
from keystonecrypto.derivation import BIP44, Purpose
from keystonecrypto.exceptions import InvalidMnemonic, InvalidPassphrase

# 1. Generate a new mnemonic
mnemonic = Mnemonic.generate(strength=128)  # 12 words; 256 → 24 words
print(mnemonic.phrase)                      # human-readable, never log this

# 2. Restore from mnemonic
mnemonic = Mnemonic.from_phrase("abandon abandon ...")

# 3. Create an encrypted keystore
keystore = Keystore.create(
    mnemonic=mnemonic,
    passphrase="correct horse battery staple",
    kdf_params=Argon2Params(time_cost=3, memory_cost=262144, parallelism=4),
)

# 4. Persist keystore (user's responsibility — file, db, etc.)
keystore.save("/path/to/wallet.keystore")

# 5. Load and unlock
with Keystore.open("/path/to/wallet.keystore") as ks:
    wallet = ks.unlock(passphrase="correct horse battery staple")
    try:
        # Derive addresses
        btc_account = wallet.derive_account(BIP44.bitcoin(0))
        addr = btc_account.address(0)         # first receive address

        # Sign a message
        sig = wallet.sign_message(addr, b"hello")
    finally:
        wallet.zeroize()

# 6. Optional: build + broadcast a BTC tx
# pip install keystonecrypto[btc]
from keystonecrypto.btc import PSBT, Electrum
psbt = PSBT.from_base64("...")
signed = psbt.sign(wallet)
Electrum.broadcast(signed, servers=["electrum.example.com"])
```

## 6. Data Formats

**Keystore envelope (binary, big-endian):**
```
magic:        4 bytes  "KST1"
version:      1 byte   0x01
kdf_id:       1 byte   0x01 = Argon2id
kdf_params:   32 bytes (time_cost:4, memory_cost:4, parallelism:4, version:4, hash_len:4, reserved:12)
salt:         16 bytes
nonce:        12 bytes
ciphertext:   N bytes  (variable, includes seed + metadata)
tag:          16 bytes (AES-GCM auth tag)
```

Ciphertext decrypts to:
```
seed_length:  1 byte
seed:         seed_length bytes  (BIP-39 entropy)
created_at:   8 bytes  (unix timestamp, big-endian)
flags:        1 byte   (bit 0: has_passphrase, bit 1: unused, ...)
reserved:     6 bytes  (zero)
```

Version 0x01 is the only supported version. Future versions append; we never silently downgrade.

**Mnemonic:** BIP-39 standard. 12/15/18/21/24 words from English wordlist.

**Extended keys:** BIP-32 standard serialization (78 bytes base58, version-prefixed).

## 7. Dependencies

**Core (Layer 1–3):**
- `cryptography >= 42.0` — AES-GCM, Ed25519, secure compare
- `coincurve >= 20.0` — secp256k1 ECDSA + Schnorr, wraps libsecp256k1
- `argon2-cffi >= 23.0` — Argon2id KDF
- `pydantic >= 2.5` — typed models, validation

**Optional extras:**
- `keystonecrypto[btc]`: adds `base58`, `bech32`, `ripemd-kernel` or similar
- `keystonecrypto[eth]`: adds `eth-utils`, `rlp` (or hand-rolled minimal encoder)
- `keystonecrypto[network]`: adds `httpx` + `websockets` for chain RPC clients

**Dev:**
- `pytest`, `pytest-cov`, `hypothesis`, `ruff`, `mypy`, `cibuildwheel`

All deps pinned in `pyproject.toml` with upper bounds; lockfile generated via `uv pip compile` or `pip-tools`.

## 8. Security Practices

- **Zero-by-default network access.** Layer 1–3 must not import `httpx`, `requests`, `urllib`, `socket` (lint-enforced).
- **Memory zeroization.** All sensitive byte buffers wrapped in a `SecretBytes` type that zeroizes in `__del__` and via explicit `.zeroize()`. Tests verify zeroization.
- **Constant-time operations.** All signature comparisons, KDF verifications, and similar go through `hmac.compare_digest` or audited library calls.
- **Test vectors.** Every cryptographic primitive must pass the official test vectors from the relevant BIP/RFC:
  - BIP-39 official vectors
  - BIP-32 official vectors (all 4 cases × multiple chains)
  - secp256k1 test vectors
  - Argon2id RFC 9106 vectors
- **Property-based tests.** `hypothesis` strategies for mnemonic round-trip, derivation paths, KDF envelopes.
- **Adversarial tests.** Garbage input, oversized inputs, edge cases, malformed envelopes, version downgrades.
- **Fuzzing.** Layer 1–3 inputs fuzzed with `atheris` (or `hypofuzz`); seed corpus from official vectors.
- **Audit-ready.** Public API surface kept small. No global state. No implicit I/O. No background threads.

## 9. Release & Distribution

- **PyPI target:** real PyPI (`pypi.org`), NOT TestPyPI. No separate test deployment step.
- **Versioning:** SemVer. Pre-1.0 we use 0.y.z; breaking changes bump minor.
- **Source dist + wheel** built via `python -m build`, verified with `twine check`.
- **Reproducible builds** for wheels via `SOURCE_DATE_EPOCH` and sorted inputs; hashes published in release notes.
- **Signing:** release artifacts signed via `sigstore` (or minisign); signature verification instructions in README.
- **Deprecation:** any API removal goes through one minor version of deprecation warnings first.
- **GitHub workflow:** every commit pushed to `main`; tags trigger PyPI publish via trusted publishing (OIDC); PAT in `~/.git-credentials` is for `git push` only — never used for PyPI uploads from the sandbox.

## 10. Testing Strategy

Five test categories, run on every push:

1. **Unit tests** — every public function, every error path.
2. **BIP/RFC vector conformance** — every official vector passes.
3. **Property-based** — round-trip mnemonic, round-trip keystore, derivation invariants.
4. **Adversarial** — malformed input, downgrade attempts, garbage ciphertext, version mismatch.
5. **Cross-implementation parity** — for each chain adapter, sign the same tx as a reference impl (`bitcoinjs-lib`, `ethers.js`) and compare signatures.

Coverage floor: ≥ 95% line coverage for Layer 1–3. Layer 4–5: ≥ 85%.

## 11. Repository Layout

```
KeystoneCrypto/
├── pyproject.toml
├── README.md
├── LICENSE                       # MIT
├── CHANGELOG.md
├── SECURITY.md
├── docs/
│   └── superpowers/
│       ├── specs/
│       └── plans/
├── src/
│   └── keystonecrypto/
│       ├── __init__.py
│       ├── exceptions.py
│       ├── entropy.py
│       ├── kdf.py
│       ├── aead.py
│       ├── mnemonic.py
│       ├── derivation.py
│       ├── keystore.py
│       ├── signing.py
│       ├── secret_bytes.py       # Sensitive memory wrapper
│       ├── btc/                  # extra: keystonecrypto[btc]
│       └── eth/                  # extra: keystonecrypto[eth]
└── tests/
    ├── test_entropy.py
    ├── test_kdf.py
    ├── test_aead.py
    ├── test_mnemonic.py
    ├── test_derivation.py
    ├── test_keystore.py
    ├── test_signing.py
    ├── test_vectors_bip39.py
    ├── test_vectors_bip32.py
    ├── test_vectors_argon2.py
    └── property/
        └── test_roundtrip.py
```

## 12. Implementation Phases

The implementation plan will respect this order. Earlier phases unlock testing of later phases.

1. **Phase 1 — Foundations:** `SecretBytes`, entropy, KDF, AEAD envelope. Includes BIP-39 official vector tests.
2. **Phase 2 — Mnemonic + HD derivation:** BIP-39, BIP-32, BIP-44 paths. Includes BIP-32 vector tests.
3. **Phase 3 — Signing:** secp256k1 ECDSA + Schnorr, Ed25519. Includes RFC 8032 + secp256k1 test vectors.
4. **Phase 4 — Keystore end-to-end:** round-trip create → save → unlock → use → close. Includes adversarial tests.
5. **Phase 5 — PyPI packaging:** build, twine check, publish workflow, signing.
6. **Phase 6 — Chain adapters (extras):** BTC PSBT + Electrum, ETH typed data + RPC. Shipped as optional extras only.

## 13. Open Questions for Reviewer

1. **Wordlist scope at v1** — English only, or include all BIP-39 wordlists? My recommendation: English only at v1 (smaller attack surface, less supply-chain risk). Add others in v2 if there's demand.

2. **Argon2id parameters** — `time_cost=3, memory_cost=262144 (256 MiB), parallelism=4` is OWASP 2024 minimum for interactive use. Mobile users may want lower. My recommendation: ship a "interactive" profile and a "high-security" profile; let the user pick.

3. **Passphrase support** — BIP-39 "25th word" passphrases are powerful but a foot-gun (lose the passphrase = lose the wallet, no recovery). My recommendation: support them, but log a clear warning when a user creates a keystore with one.

4. **Hardware-wallet integration** — out of v1. Probably a v3 feature if there's demand. Keep the signing layer clean enough that a Ledger adapter could slot in later.

5. **License** — MIT, Apache 2.0, or BSL? My recommendation: MIT for max adoption; audit firm will want source-available long-term, but that's an org decision.

6. **Initial chain scope** — BTC + ETH, or just BTC for v1? My recommendation: BTC only in the core plan; ETH as a second chain adapter to validate the adapter pattern. Don't ship both at the same time.

7. **Documentation site** — Read the Docs / MkDocs / GitHub Pages? My recommendation: keep docs in `docs/` with MkDocs Material; defer a custom site until after v1.

8. **Post-quantum / lattice signatures** — confirm: v1 stays on ECDSA/secp256k1 + Ed25519 (current ecosystem standard). Post-quantum migration deferred until BIP/IETF standards for PQ HD wallets exist and chains accept PQ signatures. See §14.

---

## 14. Quantum Considerations

**v1 is not quantum-safe against a cryptographically-relevant quantum computer (CRQC).** This is deliberate and matches every other HD wallet library shipping today.

### Why v1 stays on ECDSA/secp256k1 + Ed25519

- No finalized BIP or IETF standard exists for HD wallets over post-quantum signature schemes (CRYSTALS-Dilithium, FALCON-512, SPHINCS+).
- No major chain (BTC, ETH, SOL, etc.) verifies PQ signatures today. Even if `keystonecrypto` could generate Dilithium keys, no UTXO could be spent with them.
- BIP-32 derivation (HMAC-SHA512 chain code, CKDpriv/CKDpub) and BIP-39 entropy encoding are ECDSA-shaped; reusing them for PQ schemes without a standard would produce non-interoperable wallets.
- "Quantum-resistant wallet" product marketing is generally a placeholder for "we'll migrate you when standards land," not actual PQ cryptography.

### Real quantum-era threats v1 users should understand

1. **Public-key exposure after first spend.** Once a BTC address is spent from, its public key is on-chain. A future CRQC could derive the private key from that public key. **Mitigation: address rotation.** Never reuse addresses; treat every receive address as single-use. This is standard BIP-44 hygiene and is built into our derivation API.
2. **Harvest-now, decrypt-later.** Adversaries can record today's encrypted traffic and public keys. For HD wallets this is narrow: seeds are derived from your BIP-39 entropy and never appear on-chain until broadcast. As long as the seed lives only in your keystore and you rotate addresses, exposure is bounded.
3. **Symmetric primitives are already safe.** AES-256 (Grover's halves effective key strength to 128 bits — still infeasible), Argon2id (Grover's doesn't help against memory-hard KDFs), and SHA-2/SHA-3 are not meaningfully weakened by quantum computers at security levels we use.

### Migration plan when the ecosystem catches up

- **Signer abstraction in Layer 3** means new signature schemes slot in without rewriting derivation, mnemonic, or keystore code.
- We will track the IETF CFRG work on PQ HD wallets and the BIP editor's queue for any "BIP-39-style" PQ mnemonic proposals.
- When chains ship PQ address types (analogous to how SegWit/Taprot rolled out), we will add chain adapters that derive PQ keys from existing seeds where possible, or from parallel PQ mnemonics where not.
- Until then, the security-critical advice for users is unchanged: **rotate addresses, keep your keystore offline, use a strong passphrase.**

---

**Reviewer:** please flag any section that needs more detail, any decision in §13 you want changed, or any missing requirement. Once approved, I'll write the implementation plan under `docs/superpowers/plans/`.
