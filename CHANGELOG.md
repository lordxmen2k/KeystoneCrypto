# Changelog

## [0.1.0] - 2026-09-20

### Added
- Initial release of keystonecrypto core (non-custodial HD wallet library).
- BIP-39 mnemonic generation, validation, and seed derivation (English wordlist).
- BIP-32 hierarchical key derivation with full mainnet xprv serialization.
- BIP-44 derivation path parsing.
- AES-256-GCM authenticated encryption with associated data.
- Argon2id key derivation with `INTERACTIVE_PROFILE` and `HIGH_SECURITY_PROFILE`.
- Versioned binary keystore envelope (KST1/Argon2id/AES-GCM).
- `SecretBytes` zeroizing memory wrapper.
- secp256k1 ECDSA signing (64-byte compact form).
- BIP-340 Schnorr signing (Taproot key-path).
- RFC 8032 Ed25519 signing (Solana-ready).
- `Keystore` and `Wallet` high-level API with context managers.
- Property-based tests via Hypothesis.
- Adversarial tests for envelope corruption, downgrade, and tampering.

### Security
- Default install has zero network capability (lint-enforced).
- All sensitive memory wrapped in `SecretBytes` with explicit zeroize.
- All hash and compare operations use constant-time primitives.
- Envelope uses Argon2id with OWASP 2024 minimums for production profiles.

### Conformance
- BIP-39: passes 10 official trezor/python-mnemonic vectors.
- BIP-32: passes 11 official BIP-32 specification vectors.
- RFC 8032: passes 3 Ed25519 test vectors.
- RFC 9106: passes Argon2id § 5 vector.

[0.1.0]: https://github.com/lordxmen2k/KeystoneCrypto/releases/tag/v0.1.0
