# V2 Seed-Theft Findings — kastle-vault-v2

Tracks how each vault version constrains a **stolen-owner-key** attacker. The
threat: an attacker who recovers the owner's signing key from the seed. What can
they do with the vault UTXO?

---

## V1 (baseline) — clawback UNCONSTRAINED

`fixtures/kastle-vault-v1.sil` clawback branch:

```
entrypoint function clawback(sig ownerSig) {
    require(checkSig(ownerSig, owner));   // <-- only constraint
}
```

**Finding:** the clawback path pins nothing about the output. A stolen owner key
sweeps the entire vault to **any** attacker address, instantly, bypassing the
delay. The time-delayed `withdraw` → recovery path is irrelevant to the attacker
because they never need it. This is the gap V2 closes.

(Recorded in commit `b22e02c`: "clawback unconstrained finding — gates v2 design".)

## V2 — destination-locked clawback + recovery

`fixtures/kastle-vault-v2.sil` adds a `byte[] clawbackSpk` constructor param and
pins output[0] in the clawback branch, mirroring withdraw:

```
entrypoint function clawback(sig ownerSig) {
    require(checkSig(ownerSig, owner));
    require(tx.outputs[0].scriptPubKey == clawbackSpk);   // <-- destination lock
}
entrypoint function withdraw() {
    require(this.age >= delay);
    require(tx.outputs[0].scriptPubKey == recoverySpk);
}
```

**Result:** a stolen owner key can clawback ONLY to the fixed, seed-derivable
`clawbackSpk` destination — never to an attacker address. Theft of the signing
key no longer means theft of funds; it means at worst a forced early move to a
destination the legitimate owner controls.

### Seed-completeness (ADR-005) preserved

The four — and only four — varying inputs are
`{owner_pubkey, recovery_address, clawback_address, delay}`. All are
seed-derivable or enumerable; no nonce, salt, timestamp, or RNG enters the
script. `spk_bytes()` is a pure address→SPK function, so the destinations stay
fully determined by the seed.

### Evidence

- **Determinism (in-process + cross-process):**
  `v2_external_clawback_is_deterministic` (byte-identical redeem + stable P2SH),
  and the binary — which now builds v2 with clawback derived at index 1 — yields
  the same P2SH across two independent processes:

  ```
  $ cargo run -q -- --seed cross-process!00   (x2)
  kaspatest:pzf3tct0jkx06j4xqw986e8yetvz28ynwhd3lsujryc4g7u9pnrtcft3kzvc6
  ```

- **SPK-encoding guard (T6-bug signature):**
  `spk_bytes_is_real_encoding_not_address_string` asserts
  `spk_bytes(addr).len() != addr.len()` for BOTH recovery and clawback — proving
  the committed bytes are the real `version || script` ScriptPublicKey, not the
  address STRING (which a real output never carries, so the equality would never
  hold).

- **Delay BPS-derivation:** `delay_daa_units_derives_per_day_from_bps` asserts
  `delay_daa_units(1, 10) == 864_000` AND `delay_daa_units(1, 1) == 86_400` —
  literal oracles proving the per-day count is derived from BPS, not hardcoded.

- **v1 not stranded:** `v1_still_builds` confirms the 3-input v1 builder still
  compiles to a nonempty script + valid Testnet P2SH.

- Full suite: `cargo test` → all pass; `cargo clippy --all-targets -- -D warnings`
  clean.

### "Three branches" clarification

The redeem script has TWO script entrypoints (withdraw, clawback). The often-cited
"three branches" counts the creation transaction's own FEE output as the third —
that output carries no covenant and is just the miner fee paid when the vault UTXO
is created. There is no third `entrypoint` in the `.sil`.

---

## V2 — Marker output + creation payload (root-key-only reconstruction)

### Problem

A v2 vault can lock funds to recovery/clawback destinations that are **external** —
not derivable from the owner root key. Seed-completeness (ADR-005) breaks here: a
root-key-only scan enumerates only its own derived addresses, so it can never find
a contract whose destinations live under different seeds. Without a server or
indexer, the externally-addressed contract is unrecoverable.

### Design

The creation transaction leaves two breadcrumbs the root key can follow:

1. **Marker output** → a root-key-derived address at `MARKER_INDEX = 49` (owner is
   index 0, clawback index 1, marker index 49). A scan of root-key addresses finds
   this output; its outpoint names the creation tx.
2. **Data payload** → encodes `{version, delay_disc, rec_spk, claw_spk}`. The
   external SPKs are stored RAW (version‖script), so reconstruction needs no
   address strings.

Creation tx (`build_creation_tx`) has three outputs: `[0]` contract P2SH (the vault
UTXO), `[1]` marker (10_000 sompi to the root-key address), `[2]` fee (1_000_000 to
recovery). Its id is a blake2b-256 commitment over all outputs + payload.

Reconstruction (`reconstruct`): derive marker addr → scan node for its UTXO → fetch
creation tx → require nonempty, parseable payload → decode params → re-derive owner
(index 0) → rebuild redeem via `build_redeem_script_v2_from_parts` → **ASSERT** its
`p2sh_spk_bytes` equals the on-chain contract output[0]. Both create and reconstruct
compute the contract SPK through the SAME path (`p2sh_spk_bytes(build_redeem_script_v2*)`),
so the committed SPK can never diverge.

### Results

- **E2E (external case):** owner, recovery, clawback derived from THREE different
  seeds. `reconstructs_external_contract_from_root_key` builds the creation tx,
  stores it in `MockNode`, recovers from the owner seed alone, and asserts the
  rebuilt redeem script is byte-identical to `build_redeem_script_v2(&params)` and
  the amount matches the funding.
- **v1-compat / no-payload:** `v1_contract_with_empty_payload_is_not_recovered` —
  a creation tx with an empty payload parses to `None` and `reconstruct` returns
  `None` (no panic). Older contracts predate the payload scheme and are skipped, not
  crashed on.
- **Codec guards:** `payload_roundtrips_and_rejects_foreign_version` (round-trip +
  foreign version → `None`), `truncated_payload_is_none` (bounds-checked cursor).
- **Refactor equivalence:** `from_parts_matches_build_redeem_script_v2` and
  `p2sh_address_unchanged_after_refactor` prove the delegation refactors are
  behaviour-preserving; `delay_discriminant_roundtrips` covers the 1..=5 tag map
  and rejects 0/6 (T6Test is deliberately unmapped).
- **No new deps:** payload codec is hand-rolled length-prefix (no serde). Full
  suite: `cargo test` → 20 pass; `cargo clippy --all-targets` (and `--features
  test-delay`) clean.

---

## V3 — TODO

> Future work. Not implemented in this ticket.

- _Threat / design TBD._

## V4 — TODO

> Future work. Not implemented in this ticket.

- _Threat / design TBD._
