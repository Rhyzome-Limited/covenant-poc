//! Trivial runnable binary: derive a vault from a seed, print its P2SH address.
//! Proves the layers wire together end to end and gives the determinism test a
//! subprocess to run.
//!
//! Usage: `covenant-poc [--seed <bytes>]` (defaults to a fixed test seed).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{build_redeem_script, p2sh_address, Delay, VaultParams};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed: Vec<u8> = b"covenant-poc-test-seed".to_vec();
    while let Some(arg) = args.next() {
        if arg == "--seed" {
            seed = args.next().expect("--seed requires a value").into_bytes();
        }
    }

    let params = VaultParams {
        owner_pubkey: derive_owner_pubkey(&seed, 0, 0),
        recovery_address: derive_recovery_address(&seed, 0),
        delay: Delay::D7,
    };
    let script = build_redeem_script(&params);
    // Address only, on its own line, so the subprocess test can compare stdout.
    println!("{}", p2sh_address(&script));
}
