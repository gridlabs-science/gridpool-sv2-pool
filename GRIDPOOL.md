# GridPool SV2 Pool

This repository is a minimal fork of the SRI Pool role from `sv2-apps` v0.6.0. It replaces the
earlier GridPool JDC/JDS sidecar experiment with a direct architecture:

```text
SV2 miner/proxy -> gridpool-sv2-pool -> Bitcoin Core IPC
                         |
                         +-> local GridPool node HTTP API
```

The SRI Pool remains responsible for SV2 channels, vardiff, job construction, share validation,
and direct Bitcoin block submission. The isolated `pool/src/lib/gridpool.rs` module adds:

- active payout suffix retrieval from `GET /api/mining/sv2-work-selection`;
- per-Standard/Extended-channel slot-0 attribution from `user_identity`;
- a global fallback payout address for worker-only identities;
- fail-closed handling for malformed or wrong-network address-like identities;
- deterministic optional operator-fee work slices, disabled with a zero percent setting;
- batched authenticated vardiff telemetry;
- full proof reconstruction for blocks, reserve candidates, and cadence-limited pulse proofs;
- an on-disk proof spool with automatic retry.

GridPool payout changes and fee-boundary changes generate channel-specific replacement jobs. The
stock SRI Template Provider solution path remains independent of GridPool HTTP availability, so a
Bitcoin block is still submitted directly to the operator's Bitcoin Core node.

Start with
`pool-apps/pool/config-examples/mainnet/gridpool-bitcoin-core-ipc-example.toml`. The GridPool node
and this process must share the generated local adapter token file. This fork requires Bitcoin Core
30.2+ IPC in the same way as current SRI Pool.

The public-beta example uses a 2% operator fee implemented as deterministic, staggered work slices.
It does not alter GridPool consensus payouts. Operators may set `operator_fee_percent = 0` for a
fee-free sovereign deployment.

## Upstream Strategy

Keep changes limited to the Pool role and the standalone GridPool module. Periodically merge SRI
upstream tags, run the upstream Pool tests, then run GridPool integration tests. Generic hooks that
would reduce this diff, especially safe accepted-share observers and per-channel payout providers,
are candidates for narrowly scoped upstream PRs.
