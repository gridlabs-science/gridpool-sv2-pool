# GridPool SV2 Pool Agent Guide

This is the active SRI-derived GridPool SV2 integration. Keep the fork delta
minimal, modular, and suitable for upstreaming when behavior is generally
useful.

Read:

- `../gridpool-handbook/AGENTS.md`
- `../gridpool-handbook/handbook/mining-integrations.md`
- `../gridpool-handbook/decisions/0008-sv2-pool-fork.md`
- Upstream SRI documentation and this repository's GridPool-specific docs

## Rules

- The GridPool node remains the consensus validator.
- Construct actual per-channel slot-0 attribution when supplied; use the
  configured operator fallback only when no miner address is provided.
- Keep ordinary vardiff shares local for cadence/telemetry while forwarding
  bounded pulse proofs and reserve-qualifying full proofs.
- A found Bitcoin block must have a direct trusted submission path.
- Never advertise public multi-user behavior that has not been tested end to
  end for attribution, fees, reconnects, and full-proof reconstruction.
- Preserve upstream formatting, MSRV, and dual MIT/Apache licensing.

Run the relevant Cargo unit and integration tests from the owning workspace
before updating the deployed fork.

