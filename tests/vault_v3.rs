//! kastle-vault-v3 validation matrix (ADR-007), run against the LOCAL rusty-kaspa
//! v2.0.1 TxScriptEngine — no node, no RPC, no testnet.
//!
//! Each spend is a real P2SH spend: the UTXO is locked to `p2sh(redeem)`, the
//! signature script carries the entrypoint args + selector + the redeem script,
//! and the clawback signature is a real schnorr signature over the SIG_HASH_ALL
//! sighash of the exact spend tx.

use covenant_poc::derive::{
    derive_owner_privkey, derive_owner_pubkey, derive_recovery_address, enumerate_delays,
};
use covenant_poc::template::{
    build_redeem_script, build_redeem_script_v2, build_redeem_script_v3, p2sh_address, spk_bytes,
    Delay, VaultParams, VaultParamsV2, VaultParamsV3,
};
use kaspa_addresses::Address;
use kaspa_bip32::secp256k1::{schnorr, Keypair, Message, Secp256k1, XOnlyPublicKey};
use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{
    pay_to_address_script, pay_to_script_hash_script, EngineCtx, EngineFlags, TxScriptEngine,
};
use kaspa_txscript_errors::TxScriptError;
use silverscript_lang::compiler::{compile_contract, CompileOptions};

const V3_SIL: &str = include_str!("../fixtures/kastle-vault-v3.sil");

// Owner seed; the attacker holds this seed too (the seed-theft threat model).
const OWNER_SEED: &[u8] = b"v3-owner-seed!00";
// An address the creator never committed.
const ATTACKER_SEED: &[u8] = b"v3-attacker-s!00";

const DELAY: Delay = Delay::D1;
const VAULT_AMOUNT: u64 = 500_000_000;
const FEE: u64 = 1_000_000;
const VAULT_BLOCK_DAA: u64 = 507_000_000;

/// The committed destination. Test placement only: the existing index-1 slot
/// (derive.rs) of the owner seed, so seed-only discovery has everything it needs.
fn destination() -> String {
    derive_recovery_address(OWNER_SEED, 0, 1).unwrap()
}

fn attacker() -> String {
    derive_recovery_address(ATTACKER_SEED, 0, 0).unwrap()
}

fn params() -> VaultParamsV3 {
    VaultParamsV3 {
        owner_pubkey: derive_owner_pubkey(OWNER_SEED, 0, 0).unwrap(),
        destination_address: destination(),
        delay: DELAY,
    }
}

enum Branch {
    /// Owner-signed with this 32-byte secret.
    Clawback([u8; 32]),
    Withdraw,
}

/// Spend the v3 vault UTXO to `pay_to` with input `sequence`, through the local
/// engine. Returns the engine verdict and, for clawback, the schnorr signature
/// with the sighash message it signs.
fn spend(
    branch: Branch,
    pay_to: &str,
    sequence: u64,
) -> (
    Result<(), TxScriptError>,
    Option<(schnorr::Signature, Message)>,
) {
    let p = params();
    let redeem = build_redeem_script_v3(&p);

    // Independent oracle for the arg order in template.rs: the test compiles the
    // fixture itself and must get the same bytes. It also gives the ABI that
    // builds the signature script.
    let compiled = compile_contract(
        V3_SIL,
        &[
            p.owner_pubkey.clone().into(),
            spk_bytes(&p.destination_address).into(),
            p.delay.relative_units().into(),
        ],
        CompileOptions::default(),
    )
    .expect("v3 fixture compiles");
    assert_eq!(
        compiled.script, redeem,
        "template.rs must bind args in order"
    );

    let utxo = UtxoEntry::new(
        VAULT_AMOUNT,
        pay_to_script_hash_script(&redeem),
        VAULT_BLOCK_DAA,
        false,
        None,
    );
    let input = TransactionInput::new(
        TransactionOutpoint::new(TransactionId::from_bytes([7u8; 32]), 0),
        vec![],
        sequence,
        1,
    );
    let output = TransactionOutput::new(
        VAULT_AMOUNT - FEE,
        pay_to_address_script(&Address::try_from(pay_to).unwrap()),
    );
    let tx = Transaction::new(
        0,
        vec![input],
        vec![output],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut tx = MutableTransaction::with_entries(tx, vec![utxo.clone()]);
    let reused = SigHashReusedValuesUnsync::new();

    let (entrypoint, args, proof) = match branch {
        Branch::Clawback(secret) => {
            let sig_hash =
                calc_schnorr_signature_hash(&tx.as_verifiable(), 0, SIG_HASH_ALL, &reused);
            let msg = Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
            let keypair = Keypair::from_seckey_slice(&Secp256k1::new(), &secret).unwrap();
            let sig = keypair.sign_schnorr(msg);
            let mut bytes = sig.as_ref().to_vec();
            bytes.push(SIG_HASH_ALL.to_u8());
            ("clawback", vec![bytes.into()], Some((sig, msg)))
        }
        Branch::Withdraw => ("withdraw", vec![], None),
    };
    let mut sigscript = compiled
        .build_sig_script(entrypoint, args)
        .expect("sigscript builds");
    sigscript.extend(ScriptBuilder::new().add_data(&redeem).unwrap().drain());
    tx.tx.inputs[0].signature_script = sigscript;

    let tx = tx.as_verifiable();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        &tx,
        &tx.inputs()[0],
        0,
        &utxo,
        EngineCtx::new(&sig_cache).with_reused(&reused),
        EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        },
    );
    (vm.execute(), proof)
}

fn owner_secret() -> [u8; 32] {
    derive_owner_privkey(OWNER_SEED, 0, 0).unwrap()
}

/// A failed `require(...)` in the redeem script.
fn is_require_failure(err: &TxScriptError) -> bool {
    matches!(err, TxScriptError::VerifyError | TxScriptError::EvalFalse)
}

/// Seed-only discovery: from the seed alone (owner at index 0, destination at
/// index 1) plus the fixed delay enum, a cold scan rebuilds exactly ONE P2SH, and
/// it equals the vault address the creator funded.
#[test]
fn v3_seed_only_discovery_rebuilds_same_p2sh() {
    let vault_p2sh = p2sh_address(&build_redeem_script_v3(&params()));

    let matches: Vec<Delay> = enumerate_delays()
        .into_iter()
        .filter(|&delay| {
            let cold = VaultParamsV3 {
                owner_pubkey: derive_owner_pubkey(OWNER_SEED, 0, 0).unwrap(),
                destination_address: derive_recovery_address(OWNER_SEED, 0, 1).unwrap(),
                delay,
            };
            p2sh_address(&build_redeem_script_v3(&cold)) == vault_p2sh
        })
        .collect();
    assert_eq!(
        matches,
        vec![DELAY],
        "exactly one delay must rebuild the vault"
    );
}

/// Seed theft, clawback branch: the attacker has the owner key and signs a
/// clawback to a foreign address. The signature is VALID (checked with secp256k1
/// outside the script), yet the engine REJECTS the spend. The control spend is
/// identical except for output[0]: it pays the committed destination and is
/// ACCEPTED. So the destination constraint is the only cause of the rejection.
#[test]
fn v3_attacker_clawback_to_foreign_address_rejected() {
    assert_ne!(destination(), attacker());
    let (verdict, proof) = spend(Branch::Clawback(owner_secret()), &attacker(), 0);
    let err = verdict.expect_err("clawback to a foreign address must be rejected");
    assert!(
        is_require_failure(&err),
        "expected require failure, got {err:?}"
    );

    // The attacker signature verifies against the owner key on its own.
    let (sig, msg) = proof.unwrap();
    let owner = derive_owner_pubkey(OWNER_SEED, 0, 0).unwrap();
    let owner = XOnlyPublicKey::from_slice(&owner).unwrap();
    assert_eq!(
        Secp256k1::verification_only().verify_schnorr(&sig, &msg, &owner),
        Ok(()),
        "attacker holds a VALID owner signature over the spend"
    );

    let (control, _) = spend(Branch::Clawback(owner_secret()), &destination(), 0);
    assert_eq!(
        control,
        Ok(()),
        "same sig path to the committed destination"
    );
}

/// Pre-delay withdraw: the input sequence is one unit short of `delay`. The
/// script's `this.age >= delay` (OpCheckSequenceVerify) REJECTS it.
///
/// Boundary: the engine checks `sequence >= delay`; consensus
/// (`check_sequence_lock`, kaspa-consensus) checks that the UTXO age covers the
/// sequence. Together they force age >= delay. The consensus half is not in
/// kaspa-txscript; it was proven on-chain in V4.2 (V2_SEEDTHEFT_FINDINGS.md).
#[test]
fn v3_pre_delay_withdraw_rejected() {
    let short = DELAY.relative_units() as u64 - 1;
    let (verdict, _) = spend(Branch::Withdraw, &destination(), short);
    let err = verdict.expect_err("pre-delay withdraw must be rejected");
    assert!(
        matches!(err, TxScriptError::UnsatisfiedLockTime(_)),
        "expected relative-timelock failure, got {err:?}"
    );
}

/// Legitimate withdraw after the delay to the committed destination: ACCEPTED.
/// Negative control on the same branch and sequence: a foreign output is
/// REJECTED, so withdraw carries the same destination constraint as clawback.
#[test]
fn v3_withdraw_to_destination_after_delay_accepted() {
    let full = DELAY.relative_units() as u64;
    let (verdict, _) = spend(Branch::Withdraw, &destination(), full);
    assert_eq!(verdict, Ok(()), "withdraw after delay must be accepted");

    let (foreign, _) = spend(Branch::Withdraw, &attacker(), full);
    let err = foreign.expect_err("withdraw to a foreign address must be rejected");
    assert!(
        is_require_failure(&err),
        "expected require failure, got {err:?}"
    );
}

/// Legitimate clawback before the delay (sequence 0) to the committed
/// destination: ACCEPTED. A wrong key on the same tx is REJECTED, so the owner
/// signature check is still live.
#[test]
fn v3_clawback_to_destination_before_delay_accepted() {
    let (verdict, _) = spend(Branch::Clawback(owner_secret()), &destination(), 0);
    assert_eq!(
        verdict,
        Ok(()),
        "owner clawback to destination must be accepted"
    );

    let wrong_key = derive_owner_privkey(ATTACKER_SEED, 0, 0).unwrap();
    let (verdict, _) = spend(Branch::Clawback(wrong_key), &destination(), 0);
    assert!(
        verdict.is_err(),
        "clawback signed by a non-owner key must fail"
    );
}

/// Determinism: same inputs give identical script bytes and P2SH address; each
/// of the three inputs is committed (changing one changes the script).
#[test]
fn v3_determinism_identical_script_bytes() {
    let s1 = build_redeem_script_v3(&params());
    let s2 = build_redeem_script_v3(&params());
    assert_eq!(s1, s2, "v3 redeem script must be byte-identical");
    assert_eq!(p2sh_address(&s1), p2sh_address(&s2));
    // Change detector, recorded from this branch: any template or compiler-pin
    // change that moves a byte moves this address.
    assert_eq!(
        p2sh_address(&s1),
        "kaspatest:pq48d3asmp9ysdr3r7kscwdusmhznkvtu8ak5gar9nhkxlhtc6sd5qju0we8g"
    );

    let other_owner = VaultParamsV3 {
        owner_pubkey: derive_owner_pubkey(ATTACKER_SEED, 0, 0).unwrap(),
        ..params()
    };
    let other_dest = VaultParamsV3 {
        destination_address: attacker(),
        ..params()
    };
    let other_delay = VaultParamsV3 {
        delay: Delay::D7,
        ..params()
    };
    for (what, p) in [
        ("owner", other_owner),
        ("destination", other_dest),
        ("delay", other_delay),
    ] {
        assert_ne!(
            s1,
            build_redeem_script_v3(&p),
            "{what} must change the script"
        );
    }
}

/// v3 changes the template interface, not the opcodes. SilverScript inlines
/// constructor args and drops names, so v2 with BOTH destinations set to the v3
/// destination compiles to the SAME bytes: v3 runs the opcode sequence that V4
/// validated on-chain for v2. A v2 vault with two DISTINCT destinations differs
/// from v3 only inside the clawback branch's 36-byte SPK push.
#[test]
fn v3_bytes_equal_v2_with_one_destination() {
    let p = params();
    let v3 = build_redeem_script_v3(&p);
    let v2 = |clawback_address: String| {
        build_redeem_script_v2(&VaultParamsV2 {
            owner_pubkey: p.owner_pubkey.clone(),
            recovery_address: p.destination_address.clone(),
            clawback_address,
            delay: p.delay,
        })
    };
    assert_eq!(v3, v2(p.destination_address.clone()));

    let split = v2(attacker());
    assert_eq!(
        split.len(),
        v3.len(),
        "both destinations are 36-byte P2PK SPKs"
    );
    // First occurrence of the destination SPK is the clawback branch push.
    let dest = spk_bytes(&p.destination_address);
    let claw = v3.windows(dest.len()).position(|w| w == dest).unwrap();
    let diff: Vec<usize> = (0..v3.len()).filter(|&i| v3[i] != split[i]).collect();
    assert!(!diff.is_empty());
    assert!(diff.iter().all(|i| (claw..claw + dest.len()).contains(i)));
}

/// v1 and v2 output is unchanged by the v3 work. Literal oracles, recorded on
/// main (3f532a7) BEFORE this branch touched template.rs. The `cross-process!00`
/// address is the v2 receipt in V2_SEEDTHEFT_FINDINGS.md.
#[test]
fn v1_v2_outputs_unchanged() {
    let owner = derive_owner_pubkey(b"golden-owner-s!0", 0, 0).unwrap();
    let rec = derive_recovery_address(b"golden-recov-s!0", 0, 0).unwrap();
    let claw = derive_recovery_address(b"golden-clawb-s!0", 0, 0).unwrap();
    let v1 = build_redeem_script(&VaultParams {
        owner_pubkey: owner.clone(),
        recovery_address: rec.clone(),
        delay: Delay::D7,
    });
    let v2 = build_redeem_script_v2(&VaultParamsV2 {
        owner_pubkey: owner,
        recovery_address: rec,
        clawback_address: claw,
        delay: Delay::D7,
    });
    assert_eq!(
        p2sh_address(&v1),
        "kaspatest:pqy3wf35fa4jpcgewpmmrx2crzussg6fu67zwvt6xzgft2y7m6n9vjcxkq2uh"
    );
    assert_eq!(
        p2sh_address(&v2),
        "kaspatest:pqkjjldt89lrr3u7whwzxqakj03fplljuznxckgpwmlqce98qemuuhlvfz7u0"
    );

    let seed = b"cross-process!00";
    let receipt = build_redeem_script_v2(&VaultParamsV2 {
        owner_pubkey: derive_owner_pubkey(seed, 0, 0).unwrap(),
        recovery_address: derive_recovery_address(seed, 0, 0).unwrap(),
        clawback_address: derive_recovery_address(seed, 0, 1).unwrap(),
        delay: Delay::D7,
    });
    assert_eq!(
        p2sh_address(&receipt),
        "kaspatest:pzf3tct0jkx06j4xqw986e8yetvz28ynwhd3lsujryc4g7u9pnrtcft3kzvc6"
    );
}
