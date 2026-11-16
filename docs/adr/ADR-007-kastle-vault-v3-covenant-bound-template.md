# ADR-007 — kastle-vault-v3: covenant-bound (KIP-20) vault template and mandatory re-validation

## 1. Status

- **Status:** Proposed
- **Date:** 2026-11-16
- **Deciders:** Leo (maintainer of Notion "ADR-007 — kastle-vault-v3: covenant-bound (KIP-20) with three-layer recovery")

## 2. Context

A vault P2SH commits only a script hash, so an unspent vault reveals no parameters on-chain (Notion "ADR-005 — Vault recovery…"). ADR-005 made seed re-derivation load-bearing.

- **v1.** The clawback branch checks only the owner signature (`fixtures/kastle-vault-v1.sil:20-22`). A seed holder can send funds anywhere (`V0_CLAWBACK_FINDING.md:3-6`).
- **v2 / ADR-006.** Both branches are destination-locked (`fixtures/kastle-vault-v2.sil:29-37`). ADR-006 accepted two presets, Standard (v1) and Cold Recovery (v2) (Notion "ADR-006 — Seed-theft-resistant Vault…"). TN10 receipts: V3 PASS, V4.1 and V4.2 REJECTED, V4.3 ACCEPTED (`V2_SEEDTHEFT_FINDINGS.md:181-223`).
- **What changed.** Toccata activated on mainnet on 2026-06-30. KIP-20 binding became the ecosystem pattern, and no vault engine code existed yet (Notion ADR-007, Context). The Standard preset cannot support the claim that a stolen seed cannot reach the funds (Notion ADR-007, Decision 5).

## 3. Decision

Kastle adopts `kastle-vault-v3`, a covenant-bound (KIP-20) template in SilverScript (Notion ADR-007, Decision 1).

**What binds it:**
- One committed `destinationSpk`. Both branches require `tx.outputs[0].scriptPubKey == destinationSpk` (`fixtures/kastle-vault-v3.sil:30-39`).
- The withdraw branch also requires `this.age >= delay` (`fixtures/kastle-vault-v3.sil:37`). The clawback branch requires the owner signature (`fixtures/kastle-vault-v3.sil:32`).
- `covenant_id` lineage tracks post-genesis state (Notion ADR-007, Decision 4).

**What it refuses:**
- Any spend whose `output[0]` is not `destinationSpk`, on both branches (`V3_TEMPLATE.md:24-27`).
- A withdraw before the delay (`tests/vault_v3.rs:242`).
- At creation: a seed-derived or wallet-internal destination, non-mnemonic wallets, and a plaintext args payload (Notion ADR-007, Decision 5).

**Scope of this checkout.** The fixture in this checkout is a plain P2SH (`src/template.rs:288-305`). With equal destinations it is byte-identical to v2 (`tests/vault_v3.rs:334-346`, `V3_TEMPLATE.md:29-34`). The KIP-20 binding, the sealed payload and the marker chain are not in this checkout (`V3_TEMPLATE.md:68-72`).

## 4. Alternatives considered

- **ADR-006 destination-locked design (two destinations, two presets).** Superseded. v3 keeps its security model with one destination and one preset (Notion ADR-007, Decision 5). ADR-006 is superseded, not deleted. Its authority-vs-destination model, findings, INV set and receipts stay binding (Notion ADR-006, supersession callout).
- **Keep the v1 Standard preset for creation.** Rejected: a seed thief can claw back instantly (Notion ADR-007, Consequences). v1 recovery code stays for existing vaults.
- **Argent as the authoring language.** Rejected as prototype-stage (Notion ADR-007, Decision 1).
- **Funding-address history scan as primary recovery.** Rejected as strictly dominated (Notion ADR-007, Decision 3).

## 5. Consequences

- **Receipts are void by design.** "Template recompilation voids ADR-006's on-chain receipts" (Notion ADR-007, Consequences). Today the receipts carry over only because the P2SH fixture is byte-equal to v2 (Notion session "2026-11-10 — Vault v3 template…"). The KIP-20 binding changes the compiled template, so that byte-equality ends.
- **Re-validation is mandatory, not optional.** Offline tests passed through both v1 bugs (`VAULT_POC_FINDINGS.md:46-48`). The local engine does not check the consensus sequence lock (`V3_TEMPLATE.md:63-66`).
- **One destination is a deliberate downgrade.** If the user loses that address, no other exit exists (Notion ADR-007, Consequences).
- **Recovery scope.** Seed re-derivation stays load-bearing for the owner key and K_vault, not for v3 args (Notion ADR-005, forward pointer).

## 6. Validation matrix

Run this matrix after the KIP-20 recompilation. The cases come from Notion ADR-007, Consequences. None of them has run against the covenant-bound template.

**Precondition (no network):** `tests/vault_v3.rs` passes against the recompiled template.

| Network | Source | Cases | Pass condition |
|---|---|---|---|
| TN10 | A non-Kastle wRPC source (Notion ADR-007, release gate) | 1. Seed-only discovery. 2. Attacker clawback. 3. Pre-delay withdraw. 4. Legitimate clawback. 5. Marker-swept recovery via Layer 2. | 1: the rebuilt script hash equals the genesis `output[0]`. 2: REJECTED by the destination assertion, isolated against case 4 (method: `V2_SEEDTHEFT_FINDINGS.md:202-206`). 3: REJECTED by the sequence lock. 4: ACCEPTED and funds reach `destinationSpk`. 5: the vault is recovered with the marker swept. Every case records its txid. |
| Mainnet | — | No first v3 vault until the TN10 row passes. | All release gates hold: scanner persistence live, the K_vault test vector passes in extension and mobile, the enumeration endpoint is live, and no plaintext-payload vault exists (Notion ADR-007, Decision 5). |

## 7. Open questions

1. Does the KIP-20 binding change the delay or SPK encoding? `Delay` hardcodes 10 BPS (`src/template.rs:79`).
2. Does TN12 need its own row? INV-4 accepts "TN10 or TN12" (Notion "Covenant++ (KIP-17) — Technical Reference for kastle-vault-v1").
3. Does gRPC expose `covenant_id`? The reference marks this as unconfirmed (same page, Caveats).
4. The sealed payload and kvbackup file are a separate ticket (Notion session "2026-11-10 — Vault v3 template…"). Does case 5 wait for that ticket?

## 8. Sources

**Repository:** `fixtures/kastle-vault-v1.sil`, `fixtures/kastle-vault-v2.sil`, `fixtures/kastle-vault-v3.sil`, `src/template.rs`, `tests/vault_v3.rs`, `V3_TEMPLATE.md`, `V2_SEEDTHEFT_FINDINGS.md`, `V0_CLAWBACK_FINDING.md`, `VAULT_POC_FINDINGS.md`.

**Notion:**
- 📖 Kastle Wiki; Index; Decisions
- ADR-005 — Vault recovery: seed re-derivation is load-bearing; backend & scanner are non-load-bearing accelerators
- ADR-006 — Seed-theft-resistant Vault: destination-locked clawback + external recovery via marker/payload (kastle-vault-v2)
- ADR-007 — kastle-vault-v3: covenant-bound (KIP-20) with three-layer recovery
- 2026-11-10 — Vault v3 template, the INS fix on both surfaces, and NACHO turned out to be L1-only
- Covenant++ (KIP-17) — Technical Reference for kastle-vault-v1
