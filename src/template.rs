//! Vault redeem-script template + P2SH address.
//!
//! Layer 1 of the POC. Builds the Covenant++ "Vault" redeem script from a
//! FIXED SilverScript template (`fixtures/kastle-vault-v1.sil`) whose only
//! varying inputs are {owner pubkey, recovery address, delay}. Those three are
//! seed-derivable or enumerable, which is what makes the vault recoverable from
//! the seed phrase ALONE (ADR-005).

use blake2b_simd::Params;
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_txscript::{pay_to_address_script, pay_to_script_hash_script};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

/// The fixed vault template, loaded at compile time — no runtime path lookup,
/// so the redeem bytes depend on nothing outside {owner, recovery, delay}.
const VAULT_SIL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/kastle-vault-v1.sil"
));

/// The fixed v2 vault template — adds a destination-locked clawback. Only
/// varying inputs are {owner, recoverySpk, clawbackSpk, delay}; everything else
/// is constant, so the four still fully determine the redeem bytes (ADR-005).
const VAULT_V2_SIL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/kastle-vault-v2.sil"
));

/// Relative timelock in DAA-score units for a `days`-long window at `bps`
/// blocks/second.
///
/// One unit = one DAA-score increment ≈ one block; on a `bps`-BPS network
/// 1 day = 86_400 s × bps blocks. The 86_400 here is seconds-per-day (a real
/// physical constant), NOT the per-day unit count — that count is DERIVED from
/// bps, so retargeting the BPS retargets every delay. Never hardcode the
/// composed `864_000` constant inside a delay body; pass the BPS in.
pub fn delay_daa_units(days: u32, bps: u32) -> i64 {
    days as i64 * bps as i64 * 86_400
}

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
        // TN10 post-Crescendo BPS; the per-day unit count is delay_daa_units's to
        // derive, never a hardcoded 864_000 here.
        const BPS: u32 = 10;
        match self {
            Delay::D1 => delay_daa_units(1, BPS),
            Delay::D3 => delay_daa_units(3, BPS),
            Delay::D7 => delay_daa_units(7, BPS),
            Delay::D30 => delay_daa_units(30, BPS),
            Delay::D90 => delay_daa_units(90, BPS),
            // TEST ONLY — 60 s at 10 BPS; never reachable in a shipped build.
            #[cfg(feature = "test-delay")]
            Delay::T6Test => 600,
        }
    }

    /// Stable 1-byte tag for the creation-tx payload. Only the five production
    /// presets are mapped; T6Test is deliberately unmapped so a test delay can
    /// never be serialized into (or recovered from) a payload.
    pub fn discriminant(&self) -> u8 {
        match self {
            Delay::D1 => 1,
            Delay::D3 => 2,
            Delay::D7 => 3,
            Delay::D30 => 4,
            Delay::D90 => 5,
            #[cfg(feature = "test-delay")]
            Delay::T6Test => 0,
        }
    }

    /// Inverse of `discriminant`: 1..=5 → preset, anything else → None.
    pub fn from_discriminant(disc: u8) -> Option<Delay> {
        match disc {
            1 => Some(Delay::D1),
            2 => Some(Delay::D3),
            3 => Some(Delay::D7),
            4 => Some(Delay::D30),
            5 => Some(Delay::D90),
            _ => None,
        }
    }
}

/// Encode a kaspa address as the FULL ScriptPublicKey bytes a real tx output
/// carries: version as big-endian u16 followed by the locking script
/// (work/rk/crypto/txscript/src/lib.rs:945-951). A script branch comparing
/// `tx.outputs[i].scriptPubKey == someSpk` (OpTxOutputSpk) pushes exactly this,
/// so any *_spk committed into the redeem script MUST be built this way — via
/// the consensus conversion `pay_to_address_script` (rusty-kaspa v2.0.1
/// crypto/txscript/src/standard.rs:41), NEVER the address-STRING bytes (which a
/// real output never carries, so the equality could never hold — the T6 bug).
///
/// Deterministic: address→SPK is a pure function, so each address stays the ONLY
/// varying input it represents and seed-completeness is preserved (ADR-005).
pub fn spk_bytes(addr: &str) -> Vec<u8> {
    let address = Address::try_from(addr).expect("spk address must be a valid kaspa address");
    let spk = pay_to_address_script(&address);
    let mut bytes = spk.version.to_be_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    bytes
}

/// The three varying inputs to the otherwise-fixed vault script template.
pub struct VaultParams {
    pub owner_pubkey: Vec<u8>,
    pub recovery_address: String,
    pub delay: Delay,
}

/// Normalize a candidate owner pubkey to the 32-byte x-only schnorr width the
/// SilverScript compiler's `pubkey` constructor arg requires. Real derivation
/// already yields 32 bytes (passed through); a shorter stub blob is hashed to 32
/// deterministically. Drop once derive.rs always returns real 32-byte keys.
// ponytail: normalize only when not already 32B, so real keys pass through.
fn owner32(owner_pubkey: &[u8]) -> Vec<u8> {
    if owner_pubkey.len() == 32 {
        owner_pubkey.to_vec()
    } else {
        Params::new()
            .hash_length(32)
            .to_state()
            .update(owner_pubkey)
            .finalize()
            .as_bytes()
            .to_vec()
    }
}

/// Build the vault redeem script by compiling the fixed SilverScript template
/// with the three params bound as constructor arguments.
///
/// Determinism: every byte of the output is a pure function of
/// {owner_pubkey, recovery_address, delay} — the template is constant and
/// compiled in-process, so same inputs → same bytes (ADR-005).
pub fn build_redeem_script(p: &VaultParams) -> Vec<u8> {
    // Constructor args, IN PARAMETER ORDER: (owner, recoverySpk, delay).
    // recoverySpk is the real version||script SPK (see spk_bytes) so the withdraw
    // branch's `tx.outputs[0].scriptPubKey == recoverySpk` can actually hold.
    let args: Vec<Expr> = vec![
        owner32(&p.owner_pubkey).into(),
        spk_bytes(&p.recovery_address).into(),
        p.delay.relative_units().into(),
    ];

    compile_contract(VAULT_SIL, &args, CompileOptions::default())
        .expect("fixed vault template must compile")
        .script
}

/// The four varying inputs to the otherwise-fixed v2 vault script template.
///
/// v2 adds `clawback_address`: the clawback branch is now destination-locked,
/// pinning output[0] to this address's SPK just as withdraw pins recovery. So a
/// stolen owner key can only sweep funds back to the seed-derivable clawback
/// destination, not to an attacker address.
pub struct VaultParamsV2 {
    pub owner_pubkey: Vec<u8>,
    pub recovery_address: String,
    pub clawback_address: String,
    pub delay: Delay,
}

/// Build the v2 vault redeem script — destination-locked external clawback +
/// recovery — by compiling the fixed v2 template with the four params bound as
/// constructor arguments.
///
/// THREE BRANCHES: the script itself has TWO entrypoints (withdraw, clawback),
/// each pinning output[0] to a fixed SPK. The "third branch" is NOT a script
/// path — it's the creation transaction's own FEE output, which carries no
/// covenant and is just the miner fee paid when the vault UTXO is created. Don't
/// look for a third `entrypoint` in the .sil; there are only two.
///
/// Determinism: every byte is a pure function of {owner_pubkey,
/// recovery_address, clawback_address, delay} — template is constant, compiled
/// in-process, same inputs → same bytes (ADR-005).
pub fn build_redeem_script_v2(p: &VaultParamsV2) -> Vec<u8> {
    // Delegate to _from_parts after resolving both addresses to real SPK bytes —
    // single compile path so the create and reconstruct flows can never diverge.
    build_redeem_script_v2_from_parts(
        &p.owner_pubkey,
        &spk_bytes(&p.recovery_address),
        &spk_bytes(&p.clawback_address),
        p.delay,
    )
}

/// Build the v2 redeem script from raw SPK bytes, no address round-trip.
///
/// Same compile as `build_redeem_script_v2` but takes the recovery/clawback
/// destinations as already-encoded version||script SPK bytes. The reconstruction
/// path uses this: payload carries the raw SPKs, so re-deriving the script needs
/// no address strings (which the payload never stores).
pub fn build_redeem_script_v2_from_parts(
    owner_pubkey: &[u8],
    rec_spk_raw: &[u8],
    claw_spk_raw: &[u8],
    delay: Delay,
) -> Vec<u8> {
    // Constructor args, IN PARAMETER ORDER: (owner, recoverySpk, clawbackSpk,
    // delay). Both SPKs are real version||script bytes (see spk_bytes) so each
    // `tx.outputs[0].scriptPubKey == *Spk` equality can actually hold.
    let args: Vec<Expr> = vec![
        owner32(owner_pubkey).into(),
        rec_spk_raw.to_vec().into(),
        claw_spk_raw.to_vec().into(),
        delay.relative_units().into(),
    ];

    compile_contract(VAULT_V2_SIL, &args, CompileOptions::default())
        .expect("fixed v2 vault template must compile")
        .script
}

/// Compute the canonical Kaspa P2SH address for a redeem script.
///
/// Builds the standard `OP_BLAKE2B OP_DATA_32 <blake2b-256(redeem)> OP_EQUAL`
/// scriptPublicKey, lifts the 32-byte script hash out of it, and bech32-encodes
/// it as a Testnet ScriptHash address.
pub fn p2sh_address(redeem_script: &[u8]) -> String {
    let spk = p2sh_spk_bytes(redeem_script);
    // spk = version:u16BE || script; the 32-byte script hash sits at script[2..34].
    let hash = &spk[2 + 2..2 + 34];
    Address::new(Prefix::Testnet, Version::ScriptHash, hash).to_string()
}

/// The FULL ScriptPublicKey bytes (version:u16BE || locking script) a real
/// creation-tx output carries to lock funds under a P2SH redeem script. Same
/// version||script shape as `spk_bytes`, but for the P2SH path. Both the create
/// and reconstruct flows compute the contract output SPK through this, so the
/// committed SPK is byte-identical on both sides.
pub fn p2sh_spk_bytes(redeem_script: &[u8]) -> Vec<u8> {
    let spk = pay_to_script_hash_script(redeem_script);
    let mut bytes = spk.version.to_be_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    bytes
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

    /// delay_daa_units derives the per-day count from BPS — it is NOT the
    /// hardcoded 864_000 constant. Two literal oracles prove the derivation:
    /// at 10 BPS one day = 864_000 units, at 1 BPS one day = 86_400 units. If the
    /// body ever reverted to a hardcoded per-day constant the 1-BPS case fails.
    #[test]
    fn delay_daa_units_derives_per_day_from_bps() {
        assert_eq!(delay_daa_units(1, 10), 864_000);
        assert_eq!(delay_daa_units(1, 1), 86_400);
    }

    /// SPK-encoding guard (the T6 bug signature): spk_bytes must return the real
    /// version||script ScriptPublicKey, whose length differs from the raw address
    /// STRING. If the encoding ever regressed to address.as_bytes() these lengths
    /// would match. Checked for BOTH the recovery and clawback destinations.
    #[test]
    fn spk_bytes_is_real_encoding_not_address_string() {
        let rec = test_address(&[7u8; 32]);
        let claw = test_address(&[9u8; 32]);
        assert_ne!(
            spk_bytes(&rec).len(),
            rec.len(),
            "recovery spk must be real version||script bytes, not the address string"
        );
        assert_ne!(
            spk_bytes(&claw).len(),
            claw.len(),
            "clawback spk must be real version||script bytes, not the address string"
        );
    }

    /// A valid Testnet PubKey address over a fixed 32-byte x-only key — gives the
    /// SPK guard real, decodable addresses with no seed/derivation dependency.
    #[cfg(test)]
    fn test_address(xonly: &[u8; 32]) -> String {
        Address::new(Prefix::Testnet, Version::PubKey, xonly).to_string()
    }

    /// _from_parts must produce byte-identical script to the address-taking
    /// build_redeem_script_v2 — the two paths only differ in how they obtain the
    /// SPK bytes, so feeding spk_bytes() of the same addresses must converge.
    #[test]
    fn from_parts_matches_build_redeem_script_v2() {
        let params = VaultParamsV2 {
            owner_pubkey: vec![3u8; 32],
            recovery_address: test_address(&[7u8; 32]),
            clawback_address: test_address(&[9u8; 32]),
            delay: Delay::D7,
        };
        let via_addr = build_redeem_script_v2(&params);
        let via_parts = build_redeem_script_v2_from_parts(
            &params.owner_pubkey,
            &spk_bytes(&params.recovery_address),
            &spk_bytes(&params.clawback_address),
            params.delay,
        );
        assert_eq!(via_addr, via_parts);
    }

    /// p2sh_address must be unchanged by the p2sh_spk_bytes refactor. Literal
    /// oracle: a fixed redeem script always hashes to the same Testnet P2SH addr.
    #[test]
    fn p2sh_address_unchanged_after_refactor() {
        let redeem = build_redeem_script_v2(&VaultParamsV2 {
            owner_pubkey: vec![1u8; 32],
            recovery_address: test_address(&[2u8; 32]),
            clawback_address: test_address(&[3u8; 32]),
            delay: Delay::D1,
        });
        // Independent recomputation via the pre-refactor path (extract hash
        // straight from pay_to_script_hash_script) must equal p2sh_address.
        let spk = pay_to_script_hash_script(&redeem);
        let expected =
            Address::new(Prefix::Testnet, Version::ScriptHash, &spk.script()[2..34]).to_string();
        assert_eq!(p2sh_address(&redeem), expected);
    }

    /// discriminant ↔ from_discriminant round-trips for all five presets, and
    /// out-of-range tags decode to None (older/invalid payloads rejected).
    #[test]
    fn delay_discriminant_roundtrips() {
        for d in [Delay::D1, Delay::D3, Delay::D7, Delay::D30, Delay::D90] {
            assert_eq!(Delay::from_discriminant(d.discriminant()), Some(d));
        }
        assert_eq!(Delay::from_discriminant(0), None);
        assert_eq!(Delay::from_discriminant(6), None);
    }
}
