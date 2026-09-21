# SECURITY.md — keystonecrypto threat model and security guarantees

## Threat model

The library is designed to hold up under these adversarial conditions:

| Threat | Mitigation |
|---|---|
| Memory dump while unlocked | Sensitive material in `SecretBytes`, which zeroizes on context-manager exit and on GC. |
| Weak user passphrase | Argon2id with OWASP 2024 minimums (`INTERACTIVE_PROFILE` = t=3, m=256 MiB, p=4). `Argon2Params.for_testing(...)` bypasses only for the RFC 9106 conformance test. |
| Keystore file theft | AES-256-GCM with Argon2id-derived 32-byte key. AEAD nonce + version field; rejects on version mismatch. |
| Replay of old ciphertexts | AEAD rejects ciphertexts produced under different (version, kdf_id) because they are bound to GCM associated data. |
| Side-channel timing leaks | Constant-time comparison via `hmac.compare_digest`. secp256k1 ops via audited `libsecp256k1` (libsecp256k1, via `coincurve`). |
| Supply-chain attack | Minimal dependencies (5 core, pinned with upper bounds). Lint guard prevents network libraries in core code. |
| Malicious BIP-39 wordlist | Wordlist checksum validated at module load (`assert len == 2048`). Unknown words raise `InvalidMnemonicError` immediately. |
| Invalid curve points | secp256k1 ops delegated to libsecp256k1; no hand-rolled field arithmetic. |
| Network-based exfiltration | Default install cannot reach the network. `tests/lint/test_no_network_in_core.py` enforces this; chain adapters are isolated in `[btc]/[eth]/[sol]` extras. |

### Out of threat model

- Physical access to a running, unlocked process (assumed game-over).
- A compromised Python interpreter.
- Side-channel attacks on the host CPU (Spectre, Rowhammer, etc.).
  We use audited primitive libraries; we do not write field arithmetic.
- Quantum adversaries. See [Quantum considerations](#quantum-considerations).

## Adversarial behaviors that fail correctly

`tests/adversarial/test_corrupt_keystore.py` enumerates attacker actions
against a stolen keystore. Every case must fail closed:

| Attack | Expected exception |
|---|---|
| Truncated blob | `KeystoreDecryptionError` |
| Flipped magic bytes | `KeystoreVersionError` |
| Bumped version (downgrade attempt) | `KeystoreVersionError` |
| Unknown kdf_id | `KeystoreVersionError` |
| Tampered ciphertext (any byte) | `KeystoreDecryptionError` |
| Tampered salt | `KeystoreDecryptionError` |
| Tampered nonce | `KeystoreDecryptionError` |
| Tampered KDF parameters | `KeystoreDecryptionError` |
| Wrong password | `KeystoreDecryptionError` |

All are GCM-tag failures (we never leak which byte was wrong).

## Quantum considerations

**keystonecrypto v0.1.0 is not quantum-safe against a cryptographically
relevant quantum computer (CRQC).** This is deliberate and matches every
other HD wallet library shipping today.

- No finalized BIP or IETF standard exists for HD wallets over
  post-quantum signature schemes (CRYSTALS-Dilithium, FALCON-512,
  SPHINCS+).
- No major chain (BTC, ETH, SOL, etc.) verifies PQ signatures today.
  Even if keystonecrypto generated Dilithium keys, no UTXO could be
  spent with them.
- BIP-32 derivation (HMAC-SHA512 chain code, CKDpriv/CKDpub) and
  BIP-39 entropy encoding are ECDSA-shaped; reusing them for PQ
  schemes without a standard would produce non-interoperable wallets.

### Real quantum-era threats

1. **Public-key exposure after first spend.** Once a BTC address is
   spent from, its public key is on-chain. A future CRQC could derive
   the private key from that public key. **Mitigation: address
   rotation.** Never reuse addresses; treat every receive address as
   single-use.
2. **Harvest-now, decrypt-later.** Adversaries can record today's
   encrypted traffic and public keys. For HD wallets this is narrow:
   seeds are derived from BIP-39 entropy and never appear on-chain
   until broadcast. As long as the seed lives only in the keystore
   and you rotate addresses, exposure is bounded.
3. **Symmetric primitives are already safe.** AES-256 (Grover halves
   effective key strength to 128 bits — still infeasible), Argon2id
   (memory-hard, Grover doesn't help), SHA-2/SHA-3 are not meaningfully
   weakened by quantum computers at our security levels.

### Migration plan when the ecosystem catches up

- The signer abstraction (Layer 3 in the design spec) means new
  signature schemes slot in without rewriting derivation, mnemonic,
  or keystore code.
- We will track IETF CFRG work on PQ HD wallets and any BIP-style
  PQ mnemonic proposals.
- When chains ship PQ address types, we add chain adapters that
  derive PQ keys from existing seeds where possible, or from parallel
  PQ mnemonics where not.
- Until then: rotate addresses, keep your keystore offline, use a
  strong passphrase.

## What this library does NOT do

This is a building block, not a product. The following are out of scope:

- Hosting user funds or keys on behalf of users.
- Mobile / desktop / web UI.
- Web-based key generation in the browser.
- Fiat on/off-ramps.
- Exchange functionality.
- Cloud key storage / sync.
- Key recovery (BIP-39 passphrase loss = total loss; this is by design).

## Reporting security issues

For now, file issues in the GitHub repo. Once the project has a
disclosure process, this section will be updated.
