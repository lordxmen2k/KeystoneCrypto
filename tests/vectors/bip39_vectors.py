"""BIP-39 official test vectors (trezor/python-mnemonic).

Sources:
- Wordlist: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
- Vectors:  https://github.com/trezor/python-mnemonic/blob/master/vectors.json

All vectors use empty passphrase (the standard test vector). We ship 10
representative vectors covering 12/18/24-word mnemonics (128/192/256-bit
entropy). The Trezor test set does not include 15-word (160-bit) or
21-word (224-bit) vectors — those bit lengths are valid BIP-39 but not
publicly verified, so we test them only via roundtrip (entropy →
mnemonic → entropy).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Bip39Vector:
    entropy_hex: str
    mnemonic: str
    seed_hex: str  # 64-byte seed (PBKDF2 output, no passphrase)


BIP39_VECTORS: tuple[Bip39Vector, ...] = (
    # --- 12-word (128-bit entropy) ---
    Bip39Vector(
        entropy_hex="00000000000000000000000000000000",
        mnemonic=(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about"
        ),
        seed_hex=(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ),
    ),
    Bip39Vector(
        entropy_hex="7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        mnemonic=(
            "legal winner thank year wave sausage worth useful "
            "legal winner thank yellow"
        ),
        seed_hex=(
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
            "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        ),
    ),
    Bip39Vector(
        entropy_hex="80808080808080808080808080808080",
        mnemonic=(
            "letter advice cage absurd amount doctor acoustic avoid "
            "letter advice cage above"
        ),
        seed_hex=(
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30"
            "fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
        ),
    ),
    Bip39Vector(
        entropy_hex="ffffffffffffffffffffffffffffffff",
        mnemonic=(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        ),
        seed_hex=(
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
            "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
        ),
    ),
    # --- 18-word (192-bit entropy) ---
    Bip39Vector(
        entropy_hex="000000000000000000000000000000000000000000000000",
        mnemonic=(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon agent"
        ),
        seed_hex=(
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca"
            "06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa"
        ),
    ),
    Bip39Vector(
        entropy_hex="7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        mnemonic=(
            "legal winner thank year wave sausage worth useful "
            "legal winner thank year wave sausage worth useful "
            "legal will"
        ),
        seed_hex=(
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a"
            "0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd"
        ),
    ),
    Bip39Vector(
        entropy_hex="808080808080808080808080808080808080808080808080",
        mnemonic=(
            "letter advice cage absurd amount doctor acoustic avoid "
            "letter advice cage absurd amount doctor acoustic avoid "
            "letter always"
        ),
        seed_hex=(
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc2"
            "7fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65"
        ),
    ),
    Bip39Vector(
        entropy_hex="ffffffffffffffffffffffffffffffffffffffffffffffff",
        mnemonic=(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
            "zoo zoo zoo zoo zoo zoo when"
        ),
        seed_hex=(
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a7"
            "6379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528"
        ),
    ),
    # --- 24-word (256-bit entropy) ---
    Bip39Vector(
        entropy_hex=(
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
        ),
        mnemonic=(
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon art"
        ),
        seed_hex=(
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
            "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        ),
    ),
    Bip39Vector(
        entropy_hex=(
            "ffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffff"
        ),
        mnemonic=(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
            "zoo vote"
        ),
        seed_hex=(
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16"
            "13912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
        ),
    ),
)
