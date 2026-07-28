# GridPool SV2 Pool

This repository is a minimal fork of the SRI Pool role from `sv2-apps` v0.6.0. It replaces the
earlier GridPool JDC/JDS sidecar experiment with a direct architecture:

```text
SV2 miner/proxy -> gridpool-sv2-pool -> Bitcoin Core IPC (preferred)
                         |             -> Bitcoin JSON-RPC (compatible fallback)
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

The GridPool node and this process must share the generated local adapter token file. Select one
template backend:

- `gridpool-bitcoin-core-ipc-example.toml` uses the lowest-latency Bitcoin Core 30/31 IPC path.
- `gridpool-bitcoin-rpc-example.toml` uses standard `getblocktemplate` and `submitblock`, supporting
  Bitcoin Knots, older Bitcoin Core, Docker networks, Umbrel, and StartOS.
- `gridpool-bitcoin-auto-example.toml` probes the configured IPC socket at startup and falls back
  to RPC when IPC is unavailable.

The RPC path uses GBT long polling for prompt template refreshes. Because the standard RPC does not
offer Core IPC's dynamic coinbase-weight reservation, it reserves room for the GridPool payout
suffix by removing only a low-priority transaction suffix when required, then recomputes the
coinbase merkle path and BIP141 witness commitment. A solved block is reconstructed and submitted
directly to the attached node with `submitblock`.

The RPC path was exercised against Bitcoin Core 31 using a live mainnet
`getblocktemplate` response and followed a subsequent chain-tip transition.
Bitcoin Knots and older Core releases use the same standard mining RPC
contract. Appliance packages therefore use RPC by default; native operators
may select `BitcoinAuto` to prefer Core 31 IPC and fall back to RPC when the
socket is unavailable.

The public-beta example uses a 2% operator fee implemented as deterministic, staggered work slices.
It does not alter GridPool consensus payouts. Operators may set `operator_fee_percent = 0` for a
fee-free sovereign deployment.

## Upstream Strategy

Keep changes limited to the Pool role and the standalone GridPool module. Periodically merge SRI
upstream tags, run the upstream Pool tests, then run GridPool integration tests. Generic hooks that
would reduce this diff, especially safe accepted-share observers and per-channel payout providers,
are candidates for narrowly scoped upstream PRs.
