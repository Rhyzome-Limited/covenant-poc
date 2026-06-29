# V0 Clawback Finding — kastle-vault-v1

## Verdict: (b) UNCONSTRAINED

The clawback branch in `kastle-vault-v1` authorizes the owner key with **no output-destination
assertion**. The owner can send clawback funds to any address.

---

## Quoted Script Lines

### Clawback branch — `fixtures/kastle-vault-v1.sil:20-22`

```silverscript
entrypoint function clawback(sig ownerSig) {
    require(checkSig(ownerSig, owner));
}
```

One constraint only: a valid Schnorr signature from the `owner` pubkey.
No `tx.outputs[*].scriptPubKey` check. No introspection of any kind.
Owner → anywhere.

### Withdraw branch (for contrast) — `fixtures/kastle-vault-v1.sil:24-27`

```silverscript
entrypoint function withdraw() {
    require(this.age >= delay);
    require(tx.outputs[0].scriptPubKey == recoverySpk);
}
```

The destination constraint (`tx.outputs[0].scriptPubKey == recoverySpk`) lives exclusively in
the **withdraw** branch, not in clawback.

---

## Template builder — `src/template.rs`

The Rust builder (`build_redeem_script`, `src/template.rs:77-124`) passes three constructor
args to the SilverScript compiler in the order `(owner, recoverySpk, delay)`. `recoverySpk`
is a real P2SH/P2PKH scriptPubKey derived from `recovery_address` (lines 108-112). It is
wired into the compiled script only as the target for the `withdraw` path; the clawback
branch receives no reference to it.

---

## Parameter-vs-hardcoded (moot for unconstrained, recorded for completeness)

`recoverySpk` IS a parameter — it flows in through `VaultParams.recovery_address`
(`src/template.rs:68`) and is seed-derivable. If a future v2 template were to add a
destination constraint to the clawback branch, passing a *different* `clawback_spk`
parameter would be structurally possible without changing the template shape. But in v1 the
clawback branch references no destination at all, so the parameter/hardcoded question does
not apply.

---

## Implication

Seed-theft resistance (clawback → recovery address only, not arbitrary) is **not a config of
v1**. It requires a new `kastle-vault-v2` template that adds an output-destination assertion
to the clawback branch.
