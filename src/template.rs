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
    /// TEST ONLY — 60 s window for on-chain T6; never expose in production enum/UI.
    /// Gated behind the `test-delay` feature so it cannot exist in a shipped build,
    /// and deliberately excluded from `enumerate_delays()`.
    #[cfg(feature = "test-delay")]
    T6Test,
}

impl Delay {
    /// Relative timelock committed into the script, in DAA-score units.
    ///
    /// `this.age` lowers to `OpCheckSequenceVerify`, whose operand consensus
    /// reads as a relative lock "expressed in blocks" against the input's
    /// `block_daa_score` (rusty-kaspa v2.0.1
    /// consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:143-155).
    /// One unit = one DAA-score increment ≈ one block. On the target network
    /// TN10 the block rate is 10 BPS post-Crescendo (params.rs:716
    /// `BlockrateParams::new::<10>()`), so 1 block ≈ 0.1 s and
    /// 1 day = 86_400 s × 10 = 864_000 units. Magnitudes below are
    /// days × 864_000.
    pub fn relative_units(&self) -> i64 {
        const PER_DAY: i64 = 864_000; // 86_400 s/day × 10 BPS (TN10 post-Crescendo)
        match self {
            Delay::D1 => PER_DAY,
            Delay::D3 => 3 * PER_DAY,
            Delay::D7 => 7 * PER_DAY,
            Delay::D30 => 30 * PER_DAY,
            Delay::D90 => 90 * PER_DAY,
            // TEST ONLY — 60 s at 10 BPS; never reachable in a shipped build.
            #[cfg(feature = "test-delay")]
            Delay::T6Test => 600,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each preset must enforce its true day window. Expected values are LITERAL
    /// hardcoded DAA-unit counts (days × 864_000 at 10 BPS) — deliberately NOT
    /// recomputed from relative_units() or re-derived as days×864_000 inline. A
    /// test that recomputes the code's own formula proves nothing; these literals
    /// are the independent oracle.
    #[test]
    fn delay_units_are_real_day_windows() {
        assert_eq!(Delay::D1.relative_units(), 864_000);
        assert_eq!(Delay::D3.relative_units(), 2_592_000);
        assert_eq!(Delay::D7.relative_units(), 6_048_000);
        assert_eq!(Delay::D30.relative_units(), 25_920_000);
        assert_eq!(Delay::D90.relative_units(), 77_760_000);
    }

    /// TEST ONLY delay enforces a 60 s on-chain window (600 units at 10 BPS).
    /// Literal expected value, same oracle rule as above.
    #[cfg(feature = "test-delay")]
    #[test]
    fn test_only_delay_is_sixty_seconds() {
        assert_eq!(Delay::T6Test.relative_units(), 600);
    }
}
