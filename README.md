# keystonecrypto

Non-custodial HD wallet primitives for Python.

Generate BIP-39 seeds, derive addresses across BTC, ETH, and Solana, encrypt keystores, and sign messages. Pluggable chain adapters via `pip install keystonecrypto[btc|eth|sol]`.

## Install

```bash
pip install keystonecrypto              # core only (key mgmt + signing)
pip install keystonecrypto[btc]         # + Bitcoin transaction building + Electrum broadcast
pip install keystonecrypto[eth]         # + Ethereum transaction signing + JSON-RPC
pip install keystonecrypto[sol]         # + Solana transaction signing + RPC
```

## Quickstart

```python
from keystonecrypto import Keystore, Mnemonic

mnemonic = Mnemonic.generate()                      # 12-word phrase
keystore = Keystore.create(mnemonic, "passphrase")
keystore.save("wallet.keystore")

with Keystore.open("wallet.keystore") as ks:
    wallet = ks.unlock("passphrase")
    # ... use wallet ...
    wallet.zeroize()
```

## Security

This library handles private keys and seed phrases. Read [`SECURITY.md`](./SECURITY.md) before use.

## License

Apache-2.0.
