//! Trivial runnable binary: derive a vault from a seed, print its P2SH address.
//! Proves the layers wire together end to end and gives the determinism test a
//! subprocess to run.
//!
//! Usage: `covenant-poc [--seed <bytes>]` (defaults to a fixed test seed).

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address, MARKER_INDEX};
use covenant_poc::recovery::{build_creation_tx, parse};
use covenant_poc::template::{
    build_redeem_script_v2, build_redeem_script_v2_from_parts, p2sh_address, p2sh_spk_bytes,
    spk_bytes, Delay, VaultParamsV2,
};
use kaspa_addresses::{Address, Prefix, Version};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed: Vec<u8> = b"covenant-poc-test-seed-000000000".to_vec();
    let mut delay = Delay::D7;
    // TEST/HARNESS ONLY — emit the material the on-chain T6 spend harness needs
    // (redeem bytes, owner privkey, recovery address) instead of just the P2SH.
    let mut emit_spend_material = false;
    // V3 TEST/HARNESS ONLY — emit the full creation-tx material (external
    // destinations + marker + payload) for the seed-only-discovery exercise.
    let mut emit_creation = false;
    let mut derive_dest = false;
    let mut recon_payload: Option<String> = None;
    let mut recovery_addr: Option<String> = None;
    let mut clawback_addr: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--seed" {
            seed = args.next().expect("--seed requires a value").into_bytes();
        } else if arg == "--seed-hex" {
            // External-destination seeds are random bytes, not UTF-8 — take hex.
            let h = args.next().expect("--seed-hex requires a value");
            seed = (0..h.len() / 2)
                .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("seed hex"))
                .collect();
        } else if arg == "--emit-spend-material" {
            emit_spend_material = true;
        } else if arg == "--emit-creation" {
            emit_creation = true;
        } else if arg == "--recovery-addr" {
            recovery_addr = Some(args.next().expect("--recovery-addr requires a value"));
        } else if arg == "--clawback-addr" {
            clawback_addr = Some(args.next().expect("--clawback-addr requires a value"));
        } else if arg == "--reconstruct-from-payload" {
            recon_payload = Some(args.next().expect("--reconstruct-from-payload needs hex"));
        } else if arg == "--derive-dest" {
            // V3 prep — print the EXTERNAL recovery/clawback addresses derived from
            // THIS seed (use a DIFFERENT seed than the test seed → provably
            // non-derivable destinations). idx 0 = recovery, idx 1 = clawback.
            derive_dest = true;
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

    // V3.4 step 5 — feed the NODE-FETCHED payload back in, rebuild the redeem from
    // its raw SPKs + the re-derived owner (idx 0), and print the recomputed contract
    // SPK/P2SH. The caller asserts this equals the on-chain vault output[0] SPK —
    // the real-node codec round-trip + rebuild proof (the only thing that proves the
    // discovered vault is actually spendable).
    if let Some(ph) = recon_payload {
        let payload_bytes: Vec<u8> = (0..ph.len() / 2)
            .map(|i| u8::from_str_radix(&ph[i * 2..i * 2 + 2], 16).expect("payload hex"))
            .collect();
        let p = parse(&payload_bytes).expect("node payload must parse (real-node round-trip)");
        let delay = Delay::from_discriminant(p.delay_discriminant).expect("delay tag valid");
        let owner = derive_owner_pubkey(&seed, 0, 0).expect("owner key derives");
        let redeem = build_redeem_script_v2_from_parts(&owner, &p.rec_spk, &p.claw_spk, delay);
        println!("PARSED_VERSION {}", p.version);
        println!("PARSED_DELAY_DISC {}", p.delay_discriminant);
        println!("PARSED_RECOVERY_SPK_HEX {}", hex(&p.rec_spk));
        println!("PARSED_CLAWBACK_SPK_HEX {}", hex(&p.claw_spk));
        println!("RECON_VAULT_SPK_HEX {}", hex(&p2sh_spk_bytes(&redeem)));
        println!("RECON_VAULT_P2SH {}", p2sh_address(&redeem));
        return;
    }

    // V3 prep — derive external destination addresses from this (external) seed.
    if derive_dest {
        println!(
            "RECOVERY_ADDR {}",
            derive_recovery_address(&seed, 0, 0).expect("recovery addr derives")
        );
        println!(
            "CLAWBACK_ADDR {}",
            derive_recovery_address(&seed, 0, 1).expect("clawback addr derives")
        );
        return;
    }

    // V3 creation material — owner from THIS seed at (0,0) (reconstruct hardcodes
    // index 0), recovery/clawback are EXTERNAL addresses passed in. Emits every
    // byte the on-chain creation broadcaster + the seed-only reconstruct need.
    if emit_creation {
        let rec = recovery_addr.expect("--emit-creation needs --recovery-addr");
        let claw = clawback_addr.expect("--emit-creation needs --clawback-addr");
        let params = VaultParamsV2 {
            owner_pubkey: derive_owner_pubkey(&seed, 0, 0).expect("owner key derives"),
            recovery_address: rec.clone(),
            clawback_address: claw.clone(),
            delay,
        };
        let redeem = build_redeem_script_v2(&params);
        // build_creation_tx is the SAME path reconstruct re-walks: out[0]=vault
        // P2SH, out[1]=marker, out[2]=fee, plus the authoritative payload bytes.
        let ctx = build_creation_tx(&seed, &params, 500_000_000);
        let marker_xonly = derive_owner_pubkey(&seed, 0, MARKER_INDEX).expect("marker key derives");
        let marker_addr = Address::new(Prefix::Testnet, Version::PubKey, &marker_xonly).to_string();
        let owner_sk = covenant_poc::derive::derive_owner_privkey(&seed, 0, 0).expect("owner sk");
        println!("OWNER_PRIVKEY {}", hex(&owner_sk));
        println!("VAULT_P2SH {}", p2sh_address(&redeem));
        println!("VAULT_SPK_HEX {}", hex(&p2sh_spk_bytes(&redeem)));
        println!("MARKER_ADDR {marker_addr}");
        println!("MARKER_SPK_HEX {}", hex(&ctx.outputs[1].spk));
        println!("FEE_ADDR {rec}");
        println!("RECOVERY_ADDR {rec}");
        println!("CLAWBACK_ADDR {claw}");
        println!("RECOVERY_SPK_HEX {}", hex(&spk_bytes(&rec)));
        println!("CLAWBACK_SPK_HEX {}", hex(&spk_bytes(&claw)));
        println!("PAYLOAD_HEX {}", hex(&ctx.payload));
        println!("REDEEM_HEX {}", hex(&redeem));
        return;
    }

    // v2 vault: clawback destination is the seed-derivable address at index 1,
    // distinct from the recovery address at index 0, so the subprocess
    // determinism test exercises all four v2 inputs.
    let params = VaultParamsV2 {
        owner_pubkey: derive_owner_pubkey(&seed, 0, 0).expect("owner key derives from seed"),
        recovery_address: derive_recovery_address(&seed, 0, 0)
            .expect("recovery addr derives from seed"),
        clawback_address: derive_recovery_address(&seed, 0, 1)
            .expect("clawback addr derives from seed"),
        delay,
    };
    let script = build_redeem_script_v2(&params);

    if emit_spend_material {
        // TEST/HARNESS ONLY — drive the on-chain T6 spend harness. Owner privkey
        // is derived from the seed at the same path as the owner pubkey.
        let owner_sk = covenant_poc::derive::derive_owner_privkey(&seed, 0, 0)
            .expect("owner privkey derives from seed");
        println!("REDEEM_HEX {}", hex(&script));
        println!("OWNER_PRIVKEY {}", hex(&owner_sk));
        println!("RECOVERY_ADDRESS {}", params.recovery_address);
        println!("CLAWBACK_ADDRESS {}", params.clawback_address);
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
