"""End-to-end keystore: create, save, open, unlock, use, close."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystonecrypto.derivation import DerivationPath
from keystonecrypto.exceptions import KeystoreDecryptionError
from keystonecrypto.kdf import (
    OWASP_MIN_MEMORY_KIB,
    OWASP_MIN_PARALLELISM,
    OWASP_MIN_TIME_COST,
    Argon2Params,
)
from keystonecrypto.keystore import Account, Keystore, Wallet
from keystonecrypto.mnemonic import Mnemonic


ABANDON_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


@pytest.fixture
def cheap_params() -> Argon2Params:
    """OWASP-minimum profile; safe to use in tests since we have a real KDF."""
    return Argon2Params(
        time_cost=OWASP_MIN_TIME_COST,
        memory_cost=OWASP_MIN_MEMORY_KIB,
        parallelism=OWASP_MIN_PARALLELISM,
        hash_len=32,
    )


def test_create_save_load_unlock_roundtrip(
    tmp_path: Path, cheap_params: Argon2Params,
) -> None:
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)
    assert blob_path.exists()

    with Keystore.open(blob_path) as opened:
        with opened.unlock("hunter2hunter2") as wallet:
            assert isinstance(wallet, Wallet)
            assert wallet.mnemonic is not None
            assert wallet.mnemonic.phrase == m.phrase


def test_wrong_password_fails(tmp_path: Path, cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "right-password", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened:
        with pytest.raises(KeystoreDecryptionError):
            opened.unlock("wrong-password")


def test_wallet_derive_account_and_sign(
    tmp_path: Path, cheap_params: Argon2Params,
) -> None:
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened, opened.unlock("hunter2hunter2") as wallet:
        path = DerivationPath.parse("m/44'/0'/0'/0/0")
        account = wallet.derive_account(path)
        assert isinstance(account, Account)
        assert len(account.public_key) > 0
        sig = wallet.sign_message(path, b"hello")
        assert sig.verify(b"hello", account.public_key)


def test_wallet_close_zeroizes_seed(
    tmp_path: Path, cheap_params: Argon2Params,
) -> None:
    """After close(), the wallet refuses to derive accounts."""
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened:
        wallet = opened.unlock("hunter2hunter2")
        assert wallet.is_closed is False
        wallet.close()
        assert wallet.is_closed is True
        with pytest.raises(RuntimeError):
            wallet.derive_account(DerivationPath.parse("m/44'/0'/0'/0/0"))


def test_wallet_context_manager_closes(
    tmp_path: Path, cheap_params: Argon2Params,
) -> None:
    """Using `with wallet as w:` triggers close() on exit."""
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened:
        with opened.unlock("hunter2hunter2") as wallet:
            assert wallet.is_closed is False
        # wallet context exited; wallet is now closed.
        assert wallet.is_closed is True


def test_keystore_create_rejects_empty_password(cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    with pytest.raises(ValueError):
        Keystore.create(m, "", params=cheap_params)


def test_keystore_create_rejects_non_string_password(cheap_params: Argon2Params) -> None:
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    with pytest.raises(ValueError):
        Keystore.create(m, 12345, params=cheap_params)  # type: ignore[arg-type]


def test_wallet_supports_ed25519_scheme(
    tmp_path: Path, cheap_params: Argon2Params,
) -> None:
    """Solana-style derivation uses ed25519."""
    m = Mnemonic.from_phrase(ABANDON_MNEMONIC)
    ks = Keystore.create(m, "hunter2hunter2", params=cheap_params)
    blob_path = tmp_path / "wallet.keystore"
    ks.save(blob_path)

    with Keystore.open(blob_path) as opened, opened.unlock("hunter2hunter2") as wallet:
        account = wallet.derive_account(DerivationPath.parse("m/44'/501'/0'/0'"),
                                        scheme="ed25519")
        # Ed25519 public key is 32 bytes.
        assert len(account.public_key) == 32
