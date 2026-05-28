# bitcoin_core_sv2

A Rust library that integrates [Bitcoin Core](https://bitcoin.org/en/bitcoin-core/) with the [Stratum V2 Template Distribution Protocol](https://github.com/stratum-mining/sv2-spec/blob/main/07-Template-Distribution-Protocol.md) via IPC over a UNIX socket.

## Overview

`bitcoin_core_sv2` allows for the official Bitcoin Core distribution to be leveraged for the following use-cases:
- building Sv2 applications that act as a Client under the Template Distribution Protocol (e.g.: Pool or JDC) while connecting directly to the Bitcoin Core node.
- building a Sv2 Template Provider application that acts as a Template Distribution Protocol Server while creating templates from a Bitcoin Core node.

The crate exposes three module families:

- `bitcoin_core_sv2::common` - version-agnostic enum-dispatch runtime handles and factories based only on Sv2 protocol IO primitives.
- `bitcoin_core_sv2::unix_capnp::v30x` - Bitcoin Core v30.x IPC implementation.
- `bitcoin_core_sv2::unix_capnp::v31x` - Bitcoin Core v31.x IPC implementation.

Downstream applications should integrate through `bitcoin_core_sv2::common` and choose the Bitcoin Core major version at runtime.

## Requirements

In order to build this, crate you need `capnproto` on your system.

For example, on Ubuntu/Debian:
```
apt-get install capnproto libcapnp-dev
```

Or macOS:
```
brew install capnproto
```

## Important Notes

### `LocalSet` Requirement

Due to limitations in the `capnp-rpc` dependency (where some abstractions do not implement the `Send` trait), `BitcoinCoreSv2TDP` and `BitcoinCoreSv2JDP` must be run within a [`tokio::task::LocalSet`](https://docs.rs/tokio/latest/tokio/task/struct.LocalSet.html). The crate examples demonstrate the proper setup pattern.

### Fee Threshold

The `fee_threshold` parameter (in satoshis) determines when a new template is distributed due to mempool changes. When the mempool fee delta exceeds this threshold, a new `NewTemplate` message is sent.

## Minimum Interval

The `min_interval` parameter (in seconds) determines the minimum amount of time between two consecutive `NewTemplate` messages (with exception to Chain Tip updates, which are always sent immediately, followed by `SetNewPrevHash`).

## Examples

- `tdp_logger_v30x` - Template Distribution Protocol logger wired to `bitcoin_core_sv2::unix_capnp::v30x`.
- `tdp_logger_v31x` - Template Distribution Protocol logger wired to `bitcoin_core_sv2::unix_capnp::v31x`.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
