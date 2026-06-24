//! Vault redeem-script template + P2SH address.
//!
//! Layer 1 of the POC. Builds the Covenant++ "Vault" redeem script from a
//! FIXED template whose only varying inputs are {owner pubkey, recovery
//! address, delay}. Those three are seed-derivable or enumerable, which is what
//! makes the vault recoverable from the seed phrase ALONE (ADR-005).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Enumerable, fixed set of withdrawal delays.
///
/// TODO: real impl converts each variant to a concrete block/DAA count on TN10.
/// For now the variant identity is all the stub needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delay {
    D1,
    D3,
    D7,
    D30,
    D90,
}

/// The three varying inputs to the otherwise-fixed vault script template.
pub struct VaultParams {
    pub owner_pubkey: Vec<u8>,
    pub recovery_address: String,
    pub delay: Delay,
}

/// Build the vault redeem script from params.
///
/// PLACEHOLDER. The real implementation will emit the KIP-17 / SilverScript
/// Covenant++ template (time-delayed withdrawal + clawback path). The invariant
/// the POC must preserve — and that this stub already satisfies — is
/// determinism: same {owner, recovery, delay} -> same bytes. Later tickets
/// replace the body but MUST keep that invariant.
pub fn build_redeem_script(p: &VaultParams) -> Vec<u8> {
    let mut h = DefaultHasher::new();
    p.owner_pubkey.hash(&mut h);
    p.recovery_address.hash(&mut h);
    p.delay.hash(&mut h);
    h.finish().to_le_bytes().to_vec()
}

/// Compute the P2SH address for a redeem script.
///
/// PLACEHOLDER. The real implementation will hash the script per Kaspa's P2SH
/// rules and bech32-encode the TN10 address. This stub is a deterministic
/// hash -> hex string so the seed-completeness round-trip test can exist now.
pub fn p2sh_address(redeem_script: &[u8]) -> String {
    let mut h = DefaultHasher::new();
    redeem_script.hash(&mut h);
    format!("kaspatest:stub{:016x}", h.finish())
}
