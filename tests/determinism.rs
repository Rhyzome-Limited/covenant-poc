//! ADR-005 seed-completeness invariant at the stub level.
//!
//! Two things must hold so later tickets can't silently break recovery:
//!   1. build_redeem_script + p2sh_address are pure functions of their inputs.
//!   2. an INDEPENDENT cold re-derivation from the same seed yields the same
//!      P2SH address (no hidden state, no backend).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{build_redeem_script, p2sh_address, Delay, VaultParams};
use std::process::Command;

fn vault_from_seed(seed: &[u8]) -> String {
    let params = VaultParams {
        owner_pubkey: derive_owner_pubkey(seed, 0, 0),
        recovery_address: derive_recovery_address(seed, 0),
        delay: Delay::D7,
    };
    p2sh_address(&build_redeem_script(&params))
}

#[test]
fn script_and_address_are_deterministic() {
    let mk = || VaultParams {
        owner_pubkey: vec![1, 2, 3],
        recovery_address: "kaspatest:rec".to_string(),
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
    let seed = b"seed-completeness";
    assert_eq!(
        vault_from_seed(seed),
        vault_from_seed(seed),
        "cold re-derivation from the same seed must reproduce the same vault"
    );
}

#[test]
fn varying_one_input_changes_the_script() {
    let base = || VaultParams {
        owner_pubkey: vec![1, 2, 3],
        recovery_address: "kaspatest:rec".to_string(),
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
        recovery_address: "kaspatest:other".to_string(),
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
/// per-run state (env, time, RNG) may leak into the redeem bytes. Run the
/// binary twice with the same seed and assert identical stdout.
#[test]
fn subprocess_address_is_deterministic() {
    let bin = env!("CARGO_BIN_EXE_covenant-poc");
    let run = || {
        let out = Command::new(bin)
            .args(["--seed", "cross-process"])
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
