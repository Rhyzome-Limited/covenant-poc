//! Seed-derivation layer.
//!
//! Layer 2 of the POC. Derives the owner key + recovery address from a BIP-32
//! seed and enumerates the candidate delays. Because all three template inputs
//! come from the seed (or a fixed enum), the vault is recoverable from the seed
//! phrase ALONE — no backend, no indexer (ADR-005 seed-completeness).

use crate::template::Delay;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, SecretKey};
use std::str::FromStr;

/// Coin type 111111 is the Kaspa BIP-44 registration; chain 0 is the external
/// branch (BIP-44 `change`), per the seed-completeness path convention.
const COIN_TYPE: u32 = 111111;

/// What can go wrong turning a seed into key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The seed bytes could not seed a BIP-32 master key.
    InvalidSeed,
    /// Building or walking the derivation path failed.
    DerivationFailed,
}

/// Derive the BIP-32 child key at `m/44'/111111'/<account>'/0/<index>`.
fn derive_child(seed: &[u8], account: u32, index: u32) -> Result<SecretKey, Error> {
    let master = ExtendedPrivateKey::<SecretKey>::new(seed).map_err(|_| Error::InvalidSeed)?;
    let path = DerivationPath::from_str(&format!("m/44'/{COIN_TYPE}'/{account}'/0/{index}"))
        .map_err(|_| Error::DerivationFailed)?;
    let child = master
        .derive_path(&path)
        .map_err(|_| Error::DerivationFailed)?;
    Ok(*child.private_key())
}

/// The 32-byte x-only schnorr public key for a derived child.
fn xonly(secret: &SecretKey) -> [u8; 32] {
    // UFCS: the BIP-32 `PrivateKey::public_key` (no secp context) is shadowed by
    // secp256k1's inherent `public_key(&secp)`, so name the trait explicitly.
    let pubkey = <SecretKey as kaspa_bip32::PrivateKey>::public_key(secret);
    pubkey.x_only_public_key().0.serialize()
}

/// Derive the owner pubkey on path `m/44'/111111'/<account>'/0/<index>`.
///
/// Returns the 32-byte x-only schnorr key the vault template binds as `owner`.
pub fn derive_owner_pubkey(seed: &[u8], account: u32, index: u32) -> Result<Vec<u8>, Error> {
    Ok(xonly(&derive_child(seed, account, index)?).to_vec())
}

/// Derive the recovery address on path `m/44'/111111'/<account>'/0/<index>`.
///
/// Returns a Testnet bech32 `PubKey` address over the same x-only key.
pub fn derive_recovery_address(seed: &[u8], account: u32, index: u32) -> Result<String, Error> {
    let xonly = xonly(&derive_child(seed, account, index)?);
    Ok(Address::new(Prefix::Testnet, Version::PubKey, &xonly).to_string())
}

/// The fixed, enumerable delay set.
pub fn enumerate_delays() -> Vec<Delay> {
    vec![Delay::D1, Delay::D3, Delay::D7, Delay::D30, Delay::D90]
}
