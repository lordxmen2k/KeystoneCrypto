"""Property-based tests for derivation and mnemonic round-trips."""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from keystonecrypto.derivation import (
    DerivationPath,
    ExtendedPrivateKey,
    derive_from_seed,
)
from keystonecrypto.entropy import STRENGTH_BITS, generate_entropy
from keystonecrypto.mnemonic import Mnemonic


_seed = st.binary(min_size=32, max_size=64).map(lambda b: __import__("keystonecrypto.secret_bytes", fromlist=["SecretBytes"]).SecretBytes(b))

_path_component = st.tuples(
    st.integers(min_value=0, max_value=0x7FFFFFFF),
    st.booleans(),
)

_path = st.lists(_path_component, min_size=1, max_size=8).map(
    lambda components: DerivationPath(indices=tuple(components))
)


@given(seed=_seed, path=_path)
@settings(max_examples=50, deadline=None)
def test_path_derivation_is_deterministic(seed, path) -> None:  # type: ignore[no-untyped-def]
    """Same seed + same path = same key, always."""
    k1 = derive_from_seed(seed, path)
    k2 = derive_from_seed(seed, path)
    assert bytes(k1.private_key) == bytes(k2.private_key)
    assert bytes(k1.chain_code) == bytes(k2.chain_code)


@given(seed=_seed, path=_path)
@settings(max_examples=50, deadline=None)
def test_path_derivation_matches_step_by_step(seed, path) -> None:  # type: ignore[no-untyped-def]
    """derive_from_seed and step-by-step .derive() must agree."""
    k_path = derive_from_seed(seed, path)
    k_step = ExtendedPrivateKey.master(seed)
    for idx, hardened in path.indices:
        k_step = k_step.derive(idx, hardened=hardened)
    assert bytes(k_path.private_key) == bytes(k_step.private_key)
    assert bytes(k_path.chain_code) == bytes(k_step.chain_code)


@given(seed=_seed)
@settings(max_examples=20, deadline=None)
def test_mnemonic_roundtrip_via_entropy(seed) -> None:  # type: ignore[no-untyped-def]
    """entropy -> mnemonic -> entropy preserves the original entropy (within BIP-39 sizes)."""
    valid_lens = [b // 8 for b in STRENGTH_BITS if b // 8 <= len(seed)]
    if not valid_lens:
        return  # skip — seed too small for any BIP-39 size
    target_len = max(valid_lens)
    trimmed = __import__("keystonecrypto.secret_bytes", fromlist=["SecretBytes"]).SecretBytes(bytes(seed)[:target_len])
    m = Mnemonic.from_entropy(trimmed)
    m2 = Mnemonic.from_phrase(m.phrase)
    assert bytes(m2.entropy) == bytes(trimmed)


def test_path_rejects_empty_string() -> None:
    with pytest.raises(Exception):
        DerivationPath.parse("")


def test_path_rejects_non_m_prefix() -> None:
    with pytest.raises(Exception):
        DerivationPath.parse("/0/1")


def test_derivation_depth_increases() -> None:
    """Each derive() call increments depth by 1."""
    seed = __import__("keystonecrypto.secret_bytes", fromlist=["SecretBytes"]).SecretBytes(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    k = ExtendedPrivateKey.master(seed)
    for d in range(1, 6):
        k = k.derive(0, hardened=False)
        assert k.depth == d
