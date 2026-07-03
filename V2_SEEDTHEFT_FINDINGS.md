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

## V3 — on-chain seed-only recovery (TESTNET-10)

On-chain acceptance run, 2026-07-03. First real confirmed-block exercise (prior
runs proved the mempool path only).

### Environment
- **Endpoint:** `wss://testnet10-wrpc.kasia.fyi` (public wRPC, Borsh, NetworkId
  Testnet-10). No local node. All four rothschild harness bins
  (`create_vault_v2`, `fetch_tx_payload`, `spend_vault`, `vault_utxos`) ported
  gRPC→wRPC — only the client-construction block changed; `RpcApi` trait calls
  are identical, so the harness is transport-agnostic. No new crate deps
  (`kaspa-wrpc-client` already in the workspace).
- **utxoindex:** ON (confirmed — `get_utxos_by_addresses` returns the UTXO set).
- **Block production:** live, ~10 BPS; virtual DAA advancing ~507.0M during the run.
  Broadcasts confirmed by the public network (no local miner).

### Results
- **CREATION_TXID:** `7a64ee8e9cf260e808077b611caa3e3c6a84d0578bea51813dc2025139c097cf`
  - vault P2SH output[0] `7a64ee8e…:0` = 5.0 TKAS; marker output[1] `7a64ee8e…:1`
    = 0.5 TKAS; fee output[2] = 0.5 TKAS; VAULT_P2SH
    `kaspatest:pze96w97nkryutp0jv7glxt5qup7nap0wev2mmd2en9vmu6vrjhngrs232uys`.
- **Marker index:** 49 (root-key `(0, 49)`). Re-derived from the test seed alone;
  MARKER_ADDR reproduced byte-exact → seed-only discovery.
- **marker.outpoint.tx_id == CREATION_TXID:** **yes** (`7a64ee8e…` == `7a64ee8e…`).
- **Confirmed-block payload round-trip byte-exact:** **yes.** `fetch_tx_payload`
  found the tx via `get_blocks` block-scan (confirmed-block path, not mempool —
  found at round 0 from the pre-broadcast sink cursor), payload == committed
  (194 hex chars, discriminant 1 = D1, recovery/clawback SPKs exact).
- **Rebuilt P2SH == output[0]:** **yes.** `--reconstruct-from-payload` on the
  node-fetched payload + seed-derived owner (idx 0) → RECON_VAULT_SPK
  `0000aa20b25d38be9d864e2c2f933c8f99740703e9f42f7658adedaacccacdf34c1caf3487`
  == on-chain output[0] SPK (spendability proof).

**V3 = PASS** (all five steps green).

> Prior vault `4fddcc27…` (first creation) confirmed on-chain but its block was
> **pruned** (public node retains ~1.5 days of block bodies; the vault was ~2.2
> days old — utxoindex still served its UTXOs). Block-scan payload fetch is
> impossible against a pruned block, so a fresh vault (same seed/params →
> identical VAULT_P2SH) was rebuilt to exercise the confirmed-block path.

## V4 — on-chain seed-theft simulation (TESTNET-10)

Rejects run first, against the unspent vault `7a64ee8e…:0`.

- **Attacker address (seed-holder, non-destination):**
  `kaspatest:qqkqrkprs5qvxs9xvxv67qwtve97rlgh2vdz3yk8eweravx65d29uwx8pddhn`.

- **V4.1 — attacker clawback → attacker address: REJECTED.** Owner-signed with the
  test seed, valid sig, adequate fee; only output[0] destination differs from
  `clawback_spk`. Verbatim reason:
  > Rejected transaction f74038ed…: **failed to verify the signature script:
  > script ran, but verification failed**

  This is a script/covenant-level failure — not fee, mempool policy, or malformed
  sig (each of which surfaces a distinct error). Isolated as the **destination
  constraint** by V4.3: same owner-key, redeem, and fee, differing **only** in the
  sink address → V4.1 rejects, V4.3 accepts. The signature path therefore works;
  the sole cause of the V4.1 rejection is the wrong destination.

- **V4.2 — pre-delay withdraw → attacker address: REJECTED.** Withdraw branch, CSV
  sequence = D1 (`002f0d` LE = 864000) vs UTXO age ~5.9k. Verbatim reason:
  > Rejected transaction 75db3ce1…: **one of the transaction sequence locks
  > conditions was not met**

  (Relative-timelock rejection; destination is also wrong but consensus enforces
  the sequence lock first.)

- **V4.3 — legitimate clawback → real clawback address: ACCEPTED.**
  - **CONTROL_TXID:** `36ea3d000bc1f35f8a616fe08980373dbac283a03e17bdd91a88b5d31b8bcf9e`
  - Funds confirmed at clawback address
    `kaspatest:qqr2k8jl0zrhwdgz7x7n6g8ljhdehlume7es2mk9649mw43myr9cktwm5vfdd`:
    UTXO `36ea3d…:0` = 4.99 TKAS (5.0 − 0.01 fee), block_daa 507076737.
  - Vault UTXO `7a64ee8e…:0` consumed (no longer in the P2SH UTXO set).

**V4 = PASS** (V4.1 REJECTED for the destination constraint + V4.3 ACCEPTED).

### Environment caveats
- wRPC public endpoint `kasia.fyi` (no self-hosted node); TN10 **post-Toccata**
  (non-empty native-subnetwork payload allowed, payload-aware sighash).
- **KIP-9 storage mass:** every output must be ≳ 0.5 TKAS. A 0.01-TKAS output
  gives mass 1e12/1e6 = 1.02M > the 500k limit (hard reject); creation used
  `--fee-amount 50000000`.
- **No txindex** on kaspad 2.0.1 → no get-tx-by-id for a confirmed tx. The
  confirmed-block payload is fetched by `get_blocks` block-scan from the
  pre-broadcast selected-chain sink; requires an **unpruned** block, so the fetch
  must run within the node's retention window (~1.5 days here).
- **D1 delay** (discriminant 1, 864000 DAA ≈ 1 day). T6Test (discriminant 0) is
  codec-unmapped by design, so test-delay vaults are not payload-reconstructable;
  V3/V4 use the production delay. Reconstruction uses the **default** build (not
  `--features test-delay`).

### Verdict

**PASS** — seed-only discovery + confirmed-block reconstruction rebuild the
spendable vault byte-exact, and the destination-locked clawback rejects theft to
an attacker address while accepting recovery to the committed clawback
destination. ADR-006 on-chain receipts above.
