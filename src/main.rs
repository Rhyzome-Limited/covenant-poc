//! Trivial runnable binary: derive a vault from a seed, print its P2SH address.
//! Proves the layers wire together end to end and gives the determinism test a
//! subprocess to run.
//!
//! Usage: `covenant-poc [--seed <bytes>]` (defaults to a fixed test seed).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::template::{build_redeem_script, p2sh_address, Delay, VaultParams};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed: Vec<u8> = b"covenant-poc-test-seed-000000000".to_vec();
    let mut delay = Delay::D7;
    // TEST/HARNESS ONLY — emit the material the on-chain T6 spend harness needs
    // (redeem bytes, owner privkey, recovery address) instead of just the P2SH.
    let mut emit_spend_material = false;
    while let Some(arg) = args.next() {
        if arg == "--seed" {
            seed = args.next().expect("--seed requires a value").into_bytes();
        } else if arg == "--emit-spend-material" {
            emit_spend_material = true;
        } else if arg == "--delay" {
            let v = args.next().expect("--delay requires a value");
            delay = match v.as_str() {
                "d1" => Delay::D1,
                "d3" => Delay::D3,
                "d7" => Delay::D7,
                "d30" => Delay::D30,
                "d90" => Delay::D90,
                // TEST ONLY — 60 s window for on-chain T6; only exists under the
                // test-delay feature, never in a shipped build.
                #[cfg(feature = "test-delay")]
                "test" => Delay::T6Test,
                other => panic!("unknown --delay {other:?}"),
            };
        }
    }

    let params = VaultParams {
        owner_pubkey: derive_owner_pubkey(&seed, 0, 0).expect("owner key derives from seed"),
        recovery_address: derive_recovery_address(&seed, 0, 0)
            .expect("recovery addr derives from seed"),
        delay,
    };
    let script = build_redeem_script(&params);

    if emit_spend_material {
        // TEST/HARNESS ONLY — drive the on-chain T6 spend harness. Owner privkey
        // is derived from the seed at the same path as the owner pubkey.
        let owner_sk = covenant_poc::derive::derive_owner_privkey(&seed, 0, 0)
            .expect("owner privkey derives from seed");
        println!("REDEEM_HEX {}", hex(&script));
        println!("OWNER_PRIVKEY {}", hex(&owner_sk));
        println!("RECOVERY_ADDRESS {}", params.recovery_address);
        println!("VAULT_P2SH {}", p2sh_address(&script));
        return;
    }

    // Address only, on its own line, so the subprocess test can compare stdout.
    println!("{}", p2sh_address(&script));
}

/// Lowercase hex, no deps — the harness only needs to read it back as bytes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
