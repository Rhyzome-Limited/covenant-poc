//! ADR-005 seed-completeness invariant at the stub level.
//!
//! Two things must hold so later tickets can't silently break recovery:
//!   1. build_redeem_script + p2sh_address are pure functions of their inputs.
//!   2. an INDEPENDENT cold re-derivation from the same seed yields the same
//!      P2SH address (no hidden state, no backend).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{build_redeem_script, p2sh_address, Delay, VaultParams};

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
