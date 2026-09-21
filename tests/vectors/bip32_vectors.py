"""BIP-32 official test vectors.

Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
Section "Test vectors".

We ship the full chains for Vector 1 (5 paths) and Vector 2 (6 paths),
covering master derivation, hardened, non-hardened, mixed paths, and
the maximum index (2^31, 2^31-1, 1,000,000,000). All xprv values are
copied verbatim from the official BIP-0032 specification.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Bip32Vector:
    seed_hex: str
    chain: tuple[tuple[str, str], ...]
    # chain is (path, expected_xprv_mainnet) pairs.


# Vector 1: seed = 000102030405060708090a0b0c0d0e0f
BIP32_VECTORS: tuple[Bip32Vector, ...] = (
    Bip32Vector(
        seed_hex="000102030405060708090a0b0c0d0e0f",
        chain=(
            ("m",                            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
            ("m/0'",                         "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"),
            ("m/0'/1",                       "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"),
            ("m/0'/1/2'",                    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"),
            ("m/0'/1/2'/2",                  "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"),
            ("m/0'/1/2'/2/1000000000",       "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
        ),
    ),
    # Vector 2: long seed (64 bytes)
    Bip32Vector(
        seed_hex=(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2"
            "cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
            "9f9c999693908d8a8784817e7b787572"
            "6f6c696663605d5a5754514e4b484542"
        ),
        chain=(
            ("m",                            "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"),
            ("m/0",                          "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"),
            ("m/0/2147483647'",              "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"),
            ("m/0/2147483647'/1",            "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"),
            ("m/0/2147483647'/1/2147483646'","xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"),
            ("m/0/2147483647'/1/2147483646'/2","xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"),
        ),
    ),
)
