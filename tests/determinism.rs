//! ADR-005 seed-completeness invariant at the stub level.
//!
//! Two things must hold so later tickets can't silently break recovery:
//!   1. build_redeem_script + p2sh_address are pure functions of their inputs.
//!   2. an INDEPENDENT cold re-derivation from the same seed yields the same
//!      P2SH address (no hidden state, no backend).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{
    build_redeem_script, build_redeem_script_v2, p2sh_address, Delay, VaultParams, VaultParamsV2,
};
use std::process::Command;

fn vault_from_seed(seed: &[u8]) -> String {
    let params = VaultParams {
        owner_pubkey: derive_owner_pubkey(seed, 0, 0).unwrap(),
        recovery_address: derive_recovery_address(seed, 0, 0).unwrap(),
        delay: Delay::D7,
    };
    p2sh_address(&build_redeem_script(&params))
}

#[test]
fn script_and_address_are_deterministic() {
    // Real recovery address: the fix derives recoverySpk via pay_to_address_script,
    // which requires a valid kaspa address (a fake "kaspatest:rec" string no longer
    // decodes).
    let rec = derive_recovery_address(b"det-test-seed!01", 0, 0).unwrap();
    let mk = || VaultParams {
        owner_pubkey: vec![1, 2, 3],
        recovery_address: rec.clone(),
        delay: Delay::D30,
    };
    let s1 = build_redeem_script(&mk());
    let s2 = build_redeem_script(&mk());
    assert_eq!(s1, s2, "redeem script must be deterministic");
    assert_eq!(
        p2sh_address(&s1),
        p2sh_address(&s2),
        "P2SH address must be deterministic"
    );
}

#[test]
fn cold_rederivation_matches() {
    let seed = b"seed-complete!00";
    assert_eq!(
        vault_from_seed(seed),
        vault_from_seed(seed),
        "cold re-derivation from the same seed must reproduce the same vault"
    );

    // Real BIP-32 outputs: a 32-byte x-only owner key and a Testnet address.
    let owner = derive_owner_pubkey(seed, 0, 0).unwrap();
    assert_eq!(owner.len(), 32, "owner pubkey must be a 32-byte x-only key");
    let recovery = derive_recovery_address(seed, 0, 0).unwrap();
    assert!(
        recovery.starts_with("kaspatest:"),
        "recovery must be a Testnet address, got: {recovery:?}"
    );
}

#[test]
fn varying_one_input_changes_the_script() {
    // Real, distinct recovery addresses (see note in the deterministic test):
    // recoverySpk is now derived from the address, so each must be valid.
    let rec_a = derive_recovery_address(b"vary-test-seed!a", 0, 0).unwrap();
    let rec_b = derive_recovery_address(b"vary-test-seed!b", 0, 0).unwrap();
    let base = || VaultParams {
        owner_pubkey: vec![1, 2, 3],
        recovery_address: rec_a.clone(),
        delay: Delay::D7,
    };
    let baseline = build_redeem_script(&base());

    let other_owner = VaultParams {
        owner_pubkey: vec![9, 9, 9],
        ..base()
    };
    assert_ne!(
        baseline,
        build_redeem_script(&other_owner),
        "changing the owner pubkey must change the script"
    );

    let other_recovery = VaultParams {
        recovery_address: rec_b.clone(),
        ..base()
    };
    assert_ne!(
        baseline,
        build_redeem_script(&other_recovery),
        "changing the recovery address must change the script"
    );

    let other_delay = VaultParams {
        delay: Delay::D30,
        ..base()
    };
    assert_ne!(
        baseline,
        build_redeem_script(&other_delay),
        "changing the delay must change the script"
    );
}

/// Determinism must hold ACROSS processes, not just within one — no hidden
/// per-run state (env, time, RNG) may leak into the redeem bytes. The binary now
/// builds the v2 vault (four inputs: owner + recoverySpk + clawbackSpk + delay,
/// clawback derived at index 1), so this proves cross-process determinism for the
/// full v2 input set. Run the binary twice with the same seed and assert
/// identical stdout.
#[test]
fn subprocess_address_is_deterministic() {
    let bin = env!("CARGO_BIN_EXE_covenant-poc");
    let run = || {
        let out = Command::new(bin)
            .args(["--seed", "cross-process!00"])
            .output()
            .expect("binary must run");
        assert!(out.status.success(), "binary must exit 0");
        String::from_utf8(out.stdout).expect("stdout is utf8")
    };
    let first = run();
    assert!(
        first.starts_with("kaspatest:"),
        "expected a testnet P2SH address, got: {first:?}"
    );
    assert_eq!(
        first,
        run(),
        "same seed must yield the same P2SH address across processes"
    );
}

/// v1-regression: the v2 ticket must not strand kastle-vault-v1. The 3-input v1
/// builder must still compile to a nonempty redeem script and a valid Testnet
/// P2SH address.
#[test]
fn v1_still_builds() {
    let rec = derive_recovery_address(b"v1-regress-seed!", 0, 0).unwrap();
    let script = build_redeem_script(&VaultParams {
        owner_pubkey: vec![1, 2, 3],
        recovery_address: rec,
        delay: Delay::D7,
    });
    assert!(!script.is_empty(), "v1 redeem script must be nonempty");
    let addr = p2sh_address(&script);
    assert!(
        addr.starts_with("kaspatest:"),
        "v1 must still produce a valid Testnet P2SH, got: {addr:?}"
    );
}

/// External recovery+clawback determinism: owner, recovery, and clawback all come
/// from DIFFERENT seeds (the "external" recovery/clawback case — destinations not
/// tied to the owner key). Same four inputs must reproduce byte-identical redeem
/// bytes AND a stable P2SH hash across independent builds.
#[test]
fn v2_external_clawback_is_deterministic() {
    let owner = derive_owner_pubkey(b"v2-owner-seed!00", 0, 0).unwrap();
    let recovery = derive_recovery_address(b"v2-recovery-seed", 0, 0).unwrap();
    let clawback = derive_recovery_address(b"v2-clawback-seed", 0, 0).unwrap();
    assert_ne!(recovery, clawback, "recovery and clawback must be distinct");

    let mk = || VaultParamsV2 {
        owner_pubkey: owner.clone(),
        recovery_address: recovery.clone(),
        clawback_address: clawback.clone(),
        delay: Delay::D30,
    };
    let s1 = build_redeem_script_v2(&mk());
    let s2 = build_redeem_script_v2(&mk());
    assert_eq!(s1, s2, "v2 redeem script must be byte-identical");
    assert_eq!(
        p2sh_address(&s1),
        p2sh_address(&s2),
        "v2 P2SH hash must be stable across builds"
    );

    // Varying the clawback destination alone must change the script — proves
    // clawbackSpk is actually committed, not dropped.
    let other_clawback = derive_recovery_address(b"v2-clawback-altr", 0, 0).unwrap();
    let s3 = build_redeem_script_v2(&VaultParamsV2 {
        clawback_address: other_clawback,
        ..mk()
    });
    assert_ne!(
        s1, s3,
        "changing the clawback destination must change the v2 script"
    );
}
