//! End-to-end: build a creation tx for an EXTERNALLY-addressed contract, store
//! it in the mock node, and recover it from the owner root key alone.

use covenant_poc::derive::{derive_owner_pubkey, derive_recovery_address};
use covenant_poc::recovery::{
    build_creation_tx, creation_tx_id, parse, reconstruct, CreationTx, MockNode,
};
use covenant_poc::template::{build_redeem_script_v2, Delay, VaultParamsV2};

// Three distinct 32-byte root keys: owner, recovery, clawback. Recovery and
// clawback come from DIFFERENT seeds than the owner — the external case where a
// root-key-only scan can't find them, so the marker+payload is the only path.
const OWNER_SEED: &[u8] = b"rec-owner-seed!0";
const RECOVERY_SEED: &[u8] = b"rec-recovery-s!0";
const CLAWBACK_SEED: &[u8] = b"rec-clawback-s!0";

const CONTRACT_FUNDING: u64 = 42_000_000;

fn external_params() -> VaultParamsV2 {
    VaultParamsV2 {
        owner_pubkey: derive_owner_pubkey(OWNER_SEED, 0, 0).unwrap(),
        recovery_address: derive_recovery_address(RECOVERY_SEED, 0, 0).unwrap(),
        clawback_address: derive_recovery_address(CLAWBACK_SEED, 0, 0).unwrap(),
        delay: Delay::D7,
    }
}

#[test]
fn reconstructs_external_contract_from_root_key() {
    let params = external_params();

    let tx = build_creation_tx(OWNER_SEED, &params, CONTRACT_FUNDING);
    let mut node = MockNode::new();
    node.add_creation_tx(tx);

    let recovered = reconstruct(&node, OWNER_SEED).expect("contract recoverable from root key");

    // The rebuilt redeem script must be byte-identical to the original.
    assert_eq!(recovered.redeem_script, build_redeem_script_v2(&params));
    assert_eq!(recovered.amount, CONTRACT_FUNDING);
}

#[test]
fn v1_contract_with_empty_payload_is_not_recovered() {
    // A pre-payload (v1) creation tx: marker output present, but empty payload.
    // reconstruct must return None — no panic — because parse() yields None.
    let params = external_params();
    let full = build_creation_tx(OWNER_SEED, &params, CONTRACT_FUNDING);
    // Same outputs, empty payload, id recomputed so the marker outpoint resolves.
    let v1 = CreationTx {
        id: creation_tx_id(&full.outputs, &[]),
        outputs: full.outputs,
        payload: Vec::new(),
    };
    assert_eq!(parse(&v1.payload), None);

    let mut node = MockNode::new();
    node.add_creation_tx(v1);

    assert!(reconstruct(&node, OWNER_SEED).is_none());
}
