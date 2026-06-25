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

- `template` — **REAL** now. `build_redeem_script` compiles the fixed
  SilverScript vault template (`fixtures/kastle-vault-v1.sil`) with the three
  params bound as constructor args, and `p2sh_address` bech32-encodes the
  canonical Kaspa P2SH (`blake2b-256(redeem)`, 32-byte script hash) as a
  Testnet `ScriptHash` address.
- `derive` — derives owner key + recovery address from a BIP-32 seed
  (path `m/44'/111111'/<account>'/0/<index>`) and enumerates the fixed delay
  set `[1d, 3d, 7d, 30d, 90d]`. Still a **deterministic stub** (std-only);
  real BIP-32 derivation arrives in a later ticket.

### The vault template (`fixtures/kastle-vault-v1.sil`)

A P2SH redeem script with two spend paths, constructor params
`(pubkey owner, byte[] recoverySpk, int delay)`:

- **clawback** `(sig ownerSig)` — owner-signed, valid at any time; the
  pre-delay escape hatch (`require(checkSig(ownerSig, owner))`).
- **withdraw** `()` — no signature, valid only once the UTXO has aged past
  `delay` *and* `tx.outputs[0].scriptPubKey == recoverySpk`; the time-delayed
  move-to-recovery path.

`Delay` is the fixed enumerable set; `Delay::relative_units()` maps each variant
to the timelock count committed into the script
(`D1→86, D3→259, D7→604, D30→2592, D90→7776`).

Two notes on how the three params reach the compiler:

- **Owner pubkey** — the compiler requires a 32-byte `pubkey`. Real derivation
  yields a 32-byte x-only key (passed through as-is); the current derive stub is
  shorter, so it's normalized to 32 bytes via `blake2b-256` first. Drop the
  normalization once `derive.rs` returns real keys.
- **`recoverySpk`** — committed as the recovery address's own opaque bytes, so
  no valid-bech32 round-trip is required (the derive stub doesn't emit one yet)
  and every committed byte is still derivable from `recovery_address`.

On-chain **TN10** steps are performed **manually** in later tickets — this
scaffold builds and passes CI with no network or chain access.

### Version duality (intentional)

`silverscript-lang` (rev `faaa074`) pulls its own rusty-kaspa pin (branch
`tn12`) transitively, while the root pins rusty-kaspa **v2.0.1** directly for
P2SH + address encoding. Cargo treats the two git sources as distinct packages,
so the pins never have to agree — the only boundary crossed is plain bytes
(`Vec<u8>` / `Expr`), never a shared rusty-kaspa type.

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
secrets, no TN10, and no RPC access. The same SilverScript + rusty-kaspa pins
now back the root `template` module (see above).

## Determinism tests

`tests/determinism.rs` guards the invariant from four angles: identical bytes on
recompile, cold seed re-derivation, a vary-one-input check (owner / recovery /
delay each change the script), and a **cross-process** subprocess run
(`covenant-poc --seed <s>` twice → identical stdout) that proves no time/RNG/env
byte leaks into the script.

**Status: template real (T2); derive still stubbed**
