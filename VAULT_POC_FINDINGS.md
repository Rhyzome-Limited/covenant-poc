# VAULT_POC_FINDINGS

Acceptance deliverable for the kastle-vault-v1 covenant PoC. Closes the [Research] task.
Evidence-led; every on-chain claim carries its txid. Open items are recorded as open, not resolved.

---

## 1. VERDICT

Timelock and clawback **compose in a single fixed, seed-complete template** (`kastle-vault-v1`),
proven end-to-end on TN10. A vault address is recomputed from the seed alone — no backend, no
scanner, no stored state — and both spend paths enforce correctly on-chain: the time-locked
withdraw is rejected before the delay and accepted after, while the owner-signed clawback exits at
any time. Seed-only recovery works.

---

## 2. WHAT WAS PROVEN (on-chain, TN10)

| Step | Claim | Evidence |
|------|-------|----------|
| Vault address | P2SH computed from seed | `kaspatest:pz7hflwz...jt476kfj` |
| **T4** fund | Funded address == computed address; canonical P2SH output | txid `cc0a69e9...` |
| **T5** discovery | P2SH recomputed from seed alone (no stored state) == funded address; `getUtxosByAddresses` located the UTXO | (seed-only, no txid) |
| **T6a** pre-delay withdraw | **REJECTED** on `OpCheckSequenceVerify` — correct reason, timelock not met | rejected (no txid) |
| **T6b** clawback | Owner-signed, pre-delay — **ACCEPTED** | txid `503fa595...` |
| **T6c** post-delay withdraw | age ≥ 600 — **ACCEPTED**; `output[0]` paid the recovery address's real SPK; recovery address received **4.99 TKAS** | txid `e6cda8f8...` |

T6c is the make-or-break gate: it proves the time-locked path both unlocks at the right time **and**
pays the right script.

**Node:** kaspad v2.0.1, TN10, utxoindex on, wRPC `ws://127.0.0.1:17110`.

---

## 3. BUGS CAUGHT & FIXED

The PoC's real payoff — **neither bug was catchable offline.**

- **Delay-unit error.** Magnitudes were ~10,000× too small (`days × 86.4`); D1 would have enforced
  ~8.6 s instead of 24 h. Root cause: DAA-block unit confusion. Fixed to `days × 864,000` (10 BPS).
- **recoverySpk encoding.** Committed the recovery **address-string bytes** instead of the real
  `scriptPublicKey` → withdraw-to-recovery was unspendable. Fixed via `pay_to_address_script` then
  `version.to_be_bytes() ++ script()`. Commit `ed62972`.

**Offline determinism tests passed through BOTH bugs.** They prove only *reproducible* bytes, not
*correct* bytes. On-chain validation is therefore mandatory for any covenant template — it is not
optional hardening.

---

## 4. ARCHITECTURE CONFIRMED

Feeds ADR-005 and the engine design.

- **Seed-completeness.** Only `{owner pubkey, recovery address, delay}` vary, and all three are
  seed-derivable or enumerable. No nonce, no salt. Confirmed preserved through **both** fixes above.
- **`this.age` = relative timelock** (`OpCheckSequenceVerify`), measured in DAA-blocks from UTXO
  creation.

---

## 5. CARRY-FORWARD for the covenant engine

Non-blocking, but the engine **must** handle each.

- **Delay constant is BPS-dependent.** `days × 864,000` holds at 10 BPS. Derive it from the target
  network's BPS — never hardcode — or labels enforce the wrong windows.
- **address → SPK encoding is a general correctness trap.** The SPK the VM compares is
  `version.to_be_bytes() ++ script()`, not the address-string bytes.
- **BIP-39 phrase → seed layer is ABSENT.** The PoC proves recovery from the BIP-32 seed *down*,
  not from the 24-word mnemonic. The mnemonic → seed link is untested.
- **Two distinct rusty-kaspa packages in the tree** (pinned v2.0.1 vs `silverscript-lang` tn12
  branch). The boundary is crossed as plain bytes — flag for the engine.

---

## 6. OPEN DECISIONS

Recorded, not resolved.

- **Creation-tx payload.** Emit an ecosystem-standard payload (`covenant_id` + args, as KaspaCom /
  Manyfest indexers expect) vs. stay P2SH-only / private. Current lean: **private**. The PoC commits
  only the P2SH.
- **Recovery-address UI/UX.** Default to a seed-derived address (recoverable) vs. allow an external
  address (requires backup, or breaks seed recovery).

---

## 7. REPRODUCIBILITY

- **Branches:** `fix/recovery-spk-encoding`, `onchain/t6-harness`.
- **Spend binaries** live in the nested `work/rk` (a separate repo — **not vendored** into
  covenant-poc).
- **T4–T6 invocation:** `--features test-delay --delay test`. The spend harness is **test-delay-gated**.

---

## VERDICT (restated)

**GO** for the covenant engine design — conditional on the §5 carry-forward items being handled.
