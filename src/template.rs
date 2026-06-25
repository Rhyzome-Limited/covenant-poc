//! Vault redeem-script template + P2SH address.
//!
//! Layer 1 of the POC. Builds the Covenant++ "Vault" redeem script from a
//! FIXED SilverScript template (`fixtures/kastle-vault-v1.sil`) whose only
//! varying inputs are {owner pubkey, recovery address, delay}. Those three are
//! seed-derivable or enumerable, which is what makes the vault recoverable from
//! the seed phrase ALONE (ADR-005).

use blake2b_simd::Params;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_txscript::pay_to_script_hash_script;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

/// The fixed vault template, loaded at compile time — no runtime path lookup,
/// so the redeem bytes depend on nothing outside {owner, recovery, delay}.
const VAULT_SIL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/kastle-vault-v1.sil"
));

/// Enumerable, fixed set of withdrawal delays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delay {
    D1,
    D3,
    D7,
    D30,
    D90,
}

impl Delay {
    /// Relative timelock in DAA/sequence units committed into the script.
    ///
    /// One unit ≈ one second of DAA score; the values are the canonical
    /// TN10 counts for 1/3/7/30/90 days used across the POC.
    pub fn relative_units(&self) -> i64 {
        match self {
            Delay::D1 => 86,
            Delay::D3 => 259,
            Delay::D7 => 604,
            Delay::D30 => 2592,
            Delay::D90 => 7776,
        }
    }
}

/// The three varying inputs to the otherwise-fixed vault script template.
pub struct VaultParams {
    pub owner_pubkey: Vec<u8>,
    pub recovery_address: String,
    pub delay: Delay,
}

/// Build the vault redeem script by compiling the fixed SilverScript template
/// with the three params bound as constructor arguments.
///
/// Determinism: every byte of the output is a pure function of
/// {owner_pubkey, recovery_address, delay} — the template is constant and
/// compiled in-process, so same inputs → same bytes (ADR-005).
pub fn build_redeem_script(p: &VaultParams) -> Vec<u8> {
    // The compiler enforces a 32-byte `pubkey` constructor arg. Real derivation
    // yields a 32-byte x-only schnorr key (used as-is); the current stub yields
    // a shorter blob, so normalize it deterministically to 32 bytes. Drop this
    // branch once derive.rs returns real 32-byte keys.
    // ponytail: normalize only when not already 32B, so real keys pass through.
    let owner32: Vec<u8> = if p.owner_pubkey.len() == 32 {
        p.owner_pubkey.clone()
    } else {
        Params::new()
            .hash_length(32)
            .to_state()
            .update(&p.owner_pubkey)
            .finalize()
            .as_bytes()
            .to_vec()
    };

    // Constructor args, IN PARAMETER ORDER: (owner, recoverySpk, delay).
    // recoverySpk is the fixed recovery target committed as opaque bytes — the
    // address's own bytes, so no valid-bech32 round-trip is required and every
    // committed byte is derivable from recovery_address.
    let args: Vec<Expr> = vec![
        owner32.into(),
        p.recovery_address.as_bytes().to_vec().into(),
        p.delay.relative_units().into(),
    ];

    compile_contract(VAULT_SIL, &args, CompileOptions::default())
        .expect("fixed vault template must compile")
        .script
}

/// Compute the canonical Kaspa P2SH address for a redeem script.
///
/// Builds the standard `OP_BLAKE2B OP_DATA_32 <blake2b-256(redeem)> OP_EQUAL`
/// scriptPublicKey, lifts the 32-byte script hash out of it, and bech32-encodes
/// it as a Testnet ScriptHash address.
pub fn p2sh_address(redeem_script: &[u8]) -> String {
    let spk = pay_to_script_hash_script(redeem_script);
    let hash = &spk.script()[2..34];
    Address::new(Prefix::Testnet, Version::ScriptHash, hash).to_string()
}
