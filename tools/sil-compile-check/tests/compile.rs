//! T1 acceptance: a trivial `.sil` compiles and yields a non-empty redeem
//! script plus a real Kaspa P2SH script hash — no network, no secrets, no RPC.

use blake2b_simd::Params;
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

// Loaded at compile time per the ticket — no runtime path resolution.
const TRIVIAL_SIL: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/trivial.sil"));

#[test]
fn trivial_sil_compiles_to_nonempty_script_and_p2sh() {
    // SilverScript (faaa074): compile the template to redeem-script bytes.
    let compiled = compile_contract(TRIVIAL_SIL, &[], CompileOptions::default())
        .expect("trivial.sil must compile");
    let redeem = &compiled.script;
    assert!(!redeem.is_empty(), "redeem script must be non-empty");

    // rusty-kaspa v2.0.1: build the canonical P2SH scriptPublicKey, which is
    // `OP_BLAKE2B OP_DATA_32 <32-byte script hash> OP_EQUAL`.
    let spk = pay_to_script_hash_script(redeem);
    let spk_bytes = spk.script();
    let p2sh_hash = &spk_bytes[2..34];
    // Kaspa P2SH commits with blake2b-256 (32 bytes), not Bitcoin's HASH160 (20).
    assert_eq!(p2sh_hash.len(), 32, "Kaspa P2SH script hash is 32 bytes");

    // Independently recompute blake2b-256(redeem) and confirm the P2SH commits
    // to exactly our compiled script. This is the determinism anchor: the same
    // redeem bytes must always yield the same P2SH hash, with no hidden inputs.
    let recomputed = Params::new()
        .hash_length(32)
        .to_state()
        .update(redeem)
        .finalize();
    assert_eq!(
        p2sh_hash,
        recomputed.as_bytes(),
        "P2SH must commit to blake2b-256(redeem)"
    );
}
