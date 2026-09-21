"""SecretBytes hides sensitive material in memory and zeroizes on close."""

from __future__ import annotations

import pytest

from keystonecrypto.secret_bytes import SecretBytes


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
    import os
    raw = os.urandom(32)
    s = SecretBytes(raw)
    assert bytes(SecretBytes.from_hex(s.hex())) == raw


def test_secret_bytes_equality_uses_bytes_value() -> None:
    assert SecretBytes(b"x") == SecretBytes(b"x")
    assert SecretBytes(b"x") != SecretBytes(b"y")


def test_secret_bytes_rejects_empty() -> None:
    with pytest.raises(ValueError):
        SecretBytes(b"")


def test_secret_bytes_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        SecretBytes("string")  # type: ignore[arg-type]


def test_secret_bytes_random_returns_distinct_values() -> None:
    a = SecretBytes.random(32)
    b = SecretBytes.random(32)
    assert bytes(a) != bytes(b)
    assert len(a) == 32


def test_secret_bytes_random_rejects_non_positive_length() -> None:
    with pytest.raises(ValueError):
        SecretBytes.random(0)
    with pytest.raises(ValueError):
        SecretBytes.random(-1)
