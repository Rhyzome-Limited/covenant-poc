//! BIP-32 Test Vector 1 — proves our derivation matches the spec, not just
//! itself. Seed `000102030405060708090a0b0c0d0e0f`; expected private/public/
//! chain-code bytes are the published values from BIP-0032.
//!
//! This pins the derivation primitive directly (master + one hardened child),
//! independent of the Kaspa coin-type path that `derive.rs` layers on top.

use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, SecretKey};
use std::str::FromStr;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// (private key, compressed public key, chain code) as hex for an xprv.
fn parts(xprv: &ExtendedPrivateKey<SecretKey>) -> (String, String, String) {
    (
        hex(&xprv.to_bytes()),
        hex(&xprv.public_key().to_bytes()),
        hex(&xprv.attrs().chain_code),
    )
}

#[test]
fn vector1_master_and_first_hardened_child() {
    // Seed = 000102030405060708090a0b0c0d0e0f.
    let seed: Vec<u8> = (0u8..=15).collect();
    let master = ExtendedPrivateKey::<SecretKey>::new(&seed[..]).unwrap();

    // Chain m.
    assert_eq!(
        parts(&master),
        (
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35".into(),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2".into(),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508".into(),
        ),
        "BIP-32 vector 1, chain m"
    );

    // Chain m/0'.
    let path = DerivationPath::from_str("m/0'").unwrap();
    let child = master.derive_path(&path).unwrap();
    assert_eq!(
        parts(&child),
        (
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea".into(),
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56".into(),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141".into(),
        ),
        "BIP-32 vector 1, chain m/0'"
    );
}
