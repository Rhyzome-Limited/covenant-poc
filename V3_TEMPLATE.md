# kastle-vault-v3 template (ADR-007)

**Naming:** this is the PRODUCT template `kastle-vault-v3`
(`fixtures/kastle-vault-v3.sil`). It is NOT the "V3" row of the README findings
table — that row is an on-chain validation run of the **v2** template.

## What v3 changes

v2 committed TWO external destinations: withdraw paid `recoverySpk`, clawback
paid `clawbackSpk`. v3 commits ONE, `destinationSpk`, and BOTH branches assert
`tx.outputs[0].scriptPubKey == destinationSpk`:

| Branch | v2 | v3 |
|--------|----|----|
| clawback | owner sig + output[0] == `clawbackSpk` | owner sig + output[0] == `destinationSpk` |
| withdraw | `this.age >= delay` + output[0] == `recoverySpk` | `this.age >= delay` + output[0] == `destinationSpk` |

Constructor: `KastleVaultV3(pubkey owner, byte[] destinationSpk, int delay)`.
Rust: `template::build_redeem_script_v3(&VaultParamsV3 { owner_pubkey,
destination_address, delay })`. v1 and v2 builders are unchanged.

## Why one destination

**Invariant:** a stolen owner key cannot move vault funds to any address the
creator did not commit. With one committed destination there is no second
address to choose, no arbitrary withdraw, and no input slot where a caller can
put a different address for one branch.

## Bytes vs v2

SilverScript inlines constructor args and drops names. So v3 compiles to the
**same bytes** as v2 with `recoverySpk == clawbackSpk == destinationSpk`: same
opcodes, same P2SH address. The v3 opcode sequence is the one V4 validated
on-chain for v2. A v2 vault with two distinct destinations differs from v3 only
in the clawback branch's 36-byte SPK push (redeem offsets 46..82 for a P2PK
destination). Guarded by `v3_bytes_equal_v2_with_one_destination`.

Consequence: a v3 vault and a v2 vault with equal destinations have the same
address. The script cannot tell them apart; only off-script metadata can.

## v2 receipts stay valid for v2

v3 adds a fixture and a builder. It does not edit `kastle-vault-v2.sil` or the
v1/v2 builders. The V3/V4 TN10 receipts in
[`V2_SEEDTHEFT_FINDINGS.md`](V2_SEEDTHEFT_FINDINGS.md) are for v2 and stay
valid. `v1_v2_outputs_unchanged` pins v1/v2 P2SH literals recorded on main,
including the `cross-process!00` v2 receipt.

## Validation (local engine, no network)

`tests/vault_v3.rs` runs real P2SH spends through the rusty-kaspa v2.0.1
`TxScriptEngine`, with real schnorr signatures:

| Test | Result |
|------|--------|
| `v3_seed_only_discovery_rebuilds_same_p2sh` | seed + delay enum rebuild exactly one P2SH == vault |
| `v3_attacker_clawback_to_foreign_address_rejected` | valid owner sig, foreign output: REJECTED |
| `v3_pre_delay_withdraw_rejected` | sequence = delay − 1: REJECTED (`UnsatisfiedLockTime`) |
| `v3_withdraw_to_destination_after_delay_accepted` | sequence = delay, committed output: ACCEPTED |
| `v3_clawback_to_destination_before_delay_accepted` | owner sig, sequence 0: ACCEPTED |
| `v3_determinism_identical_script_bytes` | same inputs, same bytes; each input committed |

**Timelock boundary:** the engine checks `input.sequence >= delay`. Consensus
(`check_sequence_lock`) checks that the UTXO age covers the sequence. The
consensus half is not in `kaspa-txscript`; V4.2 proved it on-chain for the same
opcodes.

## Out of scope

- Sealed creation-tx payload and the backup file (separate ticket).
- Marker-chain address derivation.
- Client, mobile and extension code.
