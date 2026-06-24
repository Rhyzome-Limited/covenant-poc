//! Seed-derivation layer.
//!
//! Layer 2 of the POC. Derives the owner key + recovery address from a BIP-32
//! seed and enumerates the candidate delays. Because all three template inputs
//! come from the seed (or a fixed enum), the vault is recoverable from the seed
//! phrase ALONE — no backend, no indexer (ADR-005 seed-completeness).

use crate::template::Delay;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Derive the owner pubkey from a seed.
///
/// PLACEHOLDER. Real impl: BIP-32 on path m/44'/111111'/<account>'/0/<index>.
/// Deterministic stub so the cold re-derivation test can exist now.
pub fn derive_owner_pubkey(seed: &[u8], account: u32, index: u32) -> Vec<u8> {
    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    account.hash(&mut h);
    index.hash(&mut h);
    h.finish().to_le_bytes().to_vec()
}

/// Derive the recovery address from a seed.
///
/// PLACEHOLDER. Real impl: BIP-32 on path m/44'/111111'/<account>'/0/<index>,
/// then encode as a TN10 address. Deterministic stub for now.
pub fn derive_recovery_address(seed: &[u8], index: u32) -> String {
    let mut h = DefaultHasher::new();
    seed.hash(&mut h);
    index.hash(&mut h);
    format!("kaspatest:recstub{:016x}", h.finish())
}

/// The fixed, enumerable delay set.
pub fn enumerate_delays() -> Vec<Delay> {
    vec![Delay::D1, Delay::D3, Delay::D7, Delay::D30, Delay::D90]
}
