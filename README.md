# covenant-poc

Proof-of-concept that a Kaspa **Covenant++** (KIP-17 / SilverScript) **Vault** —
a time-delayed withdrawal with a clawback path — can be built from a **fixed
script template** whose only varying inputs are `{owner pubkey, recovery
address, delay}`.

## What it proves

- **ADR-005 seed-completeness invariant**: the vault is recoverable from the
  seed phrase **alone** — no backend, no indexer. Every template input is either
  seed-derivable (owner pubkey, recovery address) or enumerable (delay), so a
  cold re-derivation from the seed reproduces the exact same P2SH address.
- **Fixed-template rule**: the script is constant; only `{owner, recovery,
  delay}` vary. Determinism (same inputs → same bytes → same address) is the
  invariant later tickets must not break.

## Layers (both modules in one crate)

- `template` — builds the redeem script from `VaultParams` and computes its
  P2SH address.
- `derive` — derives owner key + recovery address from a BIP-32 seed
  (path `m/44'/111111'/<account>'/0/<index>`) and enumerates the fixed delay
  set `[1d, 3d, 7d, 30d, 90d]`.

Both are **deterministic stubs** right now (std-only). The real
KIP-17/SilverScript logic and BIP-32 derivation arrive in later tickets.

On-chain **TN10** steps are performed **manually** in later tickets — this
scaffold builds and passes CI with no network or chain access.

**Status: scaffold**
