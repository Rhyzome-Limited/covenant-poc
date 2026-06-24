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

## Toolchain

The real KIP-17/SilverScript logic compiles `.sil` templates with the
**SilverScript compiler** and computes Kaspa P2SH with **rusty-kaspa**. Both are
git-only deps (no crates.io), pinned in `tools/sil-compile-check/Cargo.toml`:

| Tool | Repo | Compiler binary | Pinned version |
|------|------|-----------------|----------------|
| SilverScript | [kaspanet/silverscript](https://github.com/kaspanet/silverscript) | `silverc` (crate `silverscript-lang`) | commit `faaa074` (2026-06-16) |
| rusty-kaspa | [kaspanet/rusty-kaspa](https://github.com/kaspanet/rusty-kaspa) | — (library) | tag `v2.0.1` (2026-06-15) |

`tools/sil-compile-check` is a probe crate: its test compiles a trivial `.sil`
(`examples/trivial.sil`) via `silverscript-lang` and asserts the redeem script is
non-empty and yields a 32-byte Kaspa P2SH script hash (`blake2b-256`, computed
with rusty-kaspa v2.0.1). It keeps the root crate zero-dep and runs in CI with no
secrets, no TN10, and no RPC access.

**Status: scaffold**
