//! Trivial runnable binary: derive a vault from a hardcoded seed, print its
//! P2SH address. Proves the layers wire together end to end.

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{build_redeem_script, p2sh_address, Delay, VaultParams};

fn main() {
    let seed = b"covenant-poc-test-seed";
    let params = VaultParams {
        owner_pubkey: derive_owner_pubkey(seed, 0, 0),
        recovery_address: derive_recovery_address(seed, 0),
        delay: Delay::D7,
    };
    let script = build_redeem_script(&params);
    println!("vault P2SH address: {}", p2sh_address(&script));
}
