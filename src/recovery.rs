//! Marker-output + creation-payload recovery.
//!
//! Layer 3 of the POC. A v2 vault can lock funds to EXTERNAL recovery/clawback
//! addresses that are not derivable from the owner root key — so a root-key-only
//! scan can't find the contract by enumerating its own addresses. The fix: the
//! creation tx pays a small MARKER output to a root-key-derived address
//! (`MARKER_INDEX`) and carries a data PAYLOAD encoding the reconstruction
//! params. Scanning root-key addresses finds the marker → its outpoint names the
//! creation tx → parsing the payload rebuilds the exact redeem script. No server,
//! no indexer: the seed alone still recovers the vault (ADR-005).

use std::collections::HashMap;

use blake2b_simd::Params;
use kaspa_addresses::{Address, Prefix, Version};

use crate::derive::{derive_owner_pubkey, MARKER_INDEX};
use crate::template::{
    build_redeem_script_v2, build_redeem_script_v2_from_parts, p2sh_spk_bytes, spk_bytes, Delay,
    VaultParamsV2,
};

/// The payload version tag. Older contracts predate the payload scheme and carry
/// an empty payload, so a mismatch here means "no recoverable payload".
const PAYLOAD_VERSION: &str = "kastle-contract-v2";

/// A reference to one transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outpoint {
    pub tx_id: [u8; 32],
    pub index: u32,
}

/// A transaction output: full SPK bytes (version||script) + amount in sompi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub spk: Vec<u8>,
    pub amount: u64,
}

/// An unspent output the node hands back, with the standard "do not spend" flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub outpoint: Outpoint,
    pub output: TxOutput,
    pub do_not_spend: bool,
}

/// A creation transaction: three outputs (contract, marker, fee) + payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreationTx {
    pub id: [u8; 32],
    pub outputs: [TxOutput; 3],
    pub payload: Vec<u8>,
}

/// The reconstruction params decoded from a creation-tx payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub version: String,
    pub delay_discriminant: u8,
    pub rec_spk: Vec<u8>,
    pub claw_spk: Vec<u8>,
}

/// A fully recovered contract: where it lives, how to spend it, how much it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredContract {
    pub outpoint: Outpoint,
    pub redeem_script: Vec<u8>,
    pub amount: u64,
}

/// Deterministic id for a creation tx: a blake2b-256 commitment over all three
/// outputs (each `spk_len:u16LE || spk || amount:u64LE`) followed by
/// `payload_len:u16LE || payload`. Pure function of (outputs, payload) so the id
/// is reproducible cross-process (ADR-005); only the create path computes it,
/// reconstruct just reads `tx.id`.
pub fn creation_tx_id(outputs: &[TxOutput; 3], payload: &[u8]) -> [u8; 32] {
    let mut buf = Vec::new();
    for out in outputs {
        buf.extend_from_slice(&(out.spk.len() as u16).to_le_bytes());
        buf.extend_from_slice(&out.spk);
        buf.extend_from_slice(&out.amount.to_le_bytes());
    }
    buf.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(payload);

    let hash = Params::new()
        .hash_length(32)
        .to_state()
        .update(&buf)
        .finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(hash.as_bytes());
    id
}

/// Encode the reconstruction params into the creation-tx payload:
/// `[version_len:u16LE][version][delay_disc:u8][rec_spk_len:u16LE][rec_spk][claw_spk_len:u16LE][claw_spk]`.
pub fn encode(version: &str, delay: Delay, rec_spk: &[u8], claw_spk: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(version.len() as u16).to_le_bytes());
    buf.extend_from_slice(version.as_bytes());
    buf.push(delay.discriminant());
    buf.extend_from_slice(&(rec_spk.len() as u16).to_le_bytes());
    buf.extend_from_slice(rec_spk);
    buf.extend_from_slice(&(claw_spk.len() as u16).to_le_bytes());
    buf.extend_from_slice(claw_spk);
    buf
}

/// Parse a creation-tx payload. Returns None on any of: wrong/absent version
/// (older contracts have no payload), an unmapped delay discriminant, or
/// truncation. None is the v1-compat / corruption signal — never panics.
pub fn parse(data: &[u8]) -> Option<Payload> {
    let mut cur = Reader { data, pos: 0 };

    let version_len = cur.u16()? as usize;
    let version_bytes = cur.take(version_len)?;
    let version = String::from_utf8(version_bytes.to_vec()).ok()?;
    if version != PAYLOAD_VERSION {
        return None;
    }

    let delay_discriminant = cur.u8()?;
    // Validate the tag maps to a real delay; reject unknown/test discriminants.
    Delay::from_discriminant(delay_discriminant)?;

    let rec_len = cur.u16()? as usize;
    let rec_spk = cur.take(rec_len)?.to_vec();
    let claw_len = cur.u16()? as usize;
    let claw_spk = cur.take(claw_len)?.to_vec();

    Some(Payload {
        version,
        delay_discriminant,
        rec_spk,
        claw_spk,
    })
}

/// Minimal bounds-checked cursor — every read returns None past the end, so a
/// truncated payload parses to None instead of panicking.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
}

/// The root-key-derived marker address (Testnet PubKey over the x-only key at
/// account 0, `MARKER_INDEX`). Single source of truth for both create and
/// reconstruct so the marker output and the scan target can't drift.
fn marker_address(root_key: &[u8]) -> String {
    let xonly =
        derive_owner_pubkey(root_key, 0, MARKER_INDEX).expect("marker key derives from root");
    Address::new(Prefix::Testnet, Version::PubKey, &xonly).to_string()
}

/// Build a creation tx for `params`, funded with `contract_funding` sompi.
///
/// out[0] = contract P2SH (the vault UTXO), out[1] = marker to the root-key
/// address, out[2] = fee to the recovery address. The payload encodes the
/// external recovery/clawback SPKs + delay so the contract is reconstructable
/// from the root key alone. The contract SPK is computed via
/// `p2sh_spk_bytes(build_redeem_script_v2(..))` — the SAME path reconstruct uses.
pub fn build_creation_tx(
    root_key: &[u8],
    params: &VaultParamsV2,
    contract_funding: u64,
) -> CreationTx {
    let contract_spk = p2sh_spk_bytes(&build_redeem_script_v2(params));

    let marker_spk = spk_bytes(&marker_address(root_key));
    let fee_spk = spk_bytes(&params.recovery_address);

    let outputs = [
        TxOutput {
            spk: contract_spk,
            amount: contract_funding,
        },
        TxOutput {
            spk: marker_spk,
            amount: 10_000,
        },
        TxOutput {
            spk: fee_spk,
            amount: 1_000_000,
        },
    ];

    let payload = encode(
        PAYLOAD_VERSION,
        params.delay,
        &spk_bytes(&params.recovery_address),
        &spk_bytes(&params.clawback_address),
    );
    let id = creation_tx_id(&outputs, &payload);

    CreationTx {
        id,
        outputs,
        payload,
    }
}

/// In-memory stand-in for a node: stores creation txs by id and answers
/// utxo-by-address queries. No network, so CI stays deterministic and offline.
#[derive(Default)]
pub struct MockNode {
    txs: HashMap<[u8; 32], CreationTx>,
}

impl MockNode {
    pub fn new() -> Self {
        MockNode::default()
    }

    pub fn add_creation_tx(&mut self, tx: CreationTx) {
        self.txs.insert(tx.id, tx);
    }

    pub fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<&CreationTx> {
        self.txs.get(tx_id)
    }

    /// Every UTXO whose output SPK matches `spk_bytes(addr)` — the same encoding
    /// the outputs were built with, so a marker scan finds the marker output.
    pub fn utxos_by_address(&self, addr: &str) -> Vec<Utxo> {
        let target = spk_bytes(addr);
        let mut found = Vec::new();
        for tx in self.txs.values() {
            for (i, out) in tx.outputs.iter().enumerate() {
                if out.spk == target {
                    found.push(Utxo {
                        outpoint: Outpoint {
                            tx_id: tx.id,
                            index: i as u32,
                        },
                        output: out.clone(),
                        do_not_spend: false,
                    });
                }
            }
        }
        found
    }
}

/// Reconstruct an externally-addressed contract from the root key alone.
///
/// Steps: derive the marker address and scan for its UTXO; fetch its creation tx
/// and require a parseable payload; decode the params; re-derive the owner key;
/// rebuild the redeem script and ASSERT its P2SH SPK equals the on-chain contract
/// output; return where it lives + how to spend it. None if no marker is found or
/// the tx carries no recoverable payload.
pub fn reconstruct(node: &MockNode, root_key: &[u8]) -> Option<RecoveredContract> {
    // 1. Find the marker UTXO at the root-key-derived marker address.
    let addr = marker_address(root_key);
    let marker_utxo = node.utxos_by_address(&addr).into_iter().next()?;

    // 2. Locate the creation tx; it must exist and carry a parseable payload.
    //    Empty/unparseable payload → None (v1 contracts predate the scheme); the
    //    SPK mismatch in step 5 is the only hard invariant that panics.
    let tx = node.get_transaction(&marker_utxo.outpoint.tx_id)?;
    if tx.payload.is_empty() {
        return None;
    }
    let payload = parse(&tx.payload)?;

    // 3. Decode params (delay tag was already validated by parse()).
    let delay = Delay::from_discriminant(payload.delay_discriminant)?;

    // 4. Re-derive the owner key (account 0, index 0).
    let owner = derive_owner_pubkey(root_key, 0, 0).expect("owner key derives from root");

    // 5. Rebuild the redeem script from the raw payload SPKs; its P2SH SPK must
    //    match the on-chain contract output[0] byte-for-byte.
    let redeem =
        build_redeem_script_v2_from_parts(&owner, &payload.rec_spk, &payload.claw_spk, delay);
    let expected_spk = p2sh_spk_bytes(&redeem);
    assert_eq!(
        expected_spk, tx.outputs[0].spk,
        "rebuilt contract SPK must match the on-chain contract output"
    );

    // 6. Return the recovered contract.
    Some(RecoveredContract {
        outpoint: Outpoint {
            tx_id: tx.id,
            index: 0,
        },
        redeem_script: redeem,
        amount: tx.outputs[0].amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// encode → parse round-trips the params; an unknown version decodes to None.
    #[test]
    fn payload_roundtrips_and_rejects_foreign_version() {
        let rec = vec![0u8, 1, 2, 3];
        let claw = vec![9u8, 8, 7];
        let data = encode(PAYLOAD_VERSION, Delay::D30, &rec, &claw);
        let p = parse(&data).expect("valid payload parses");
        assert_eq!(p.delay_discriminant, Delay::D30.discriminant());
        assert_eq!(p.rec_spk, rec);
        assert_eq!(p.claw_spk, claw);

        let foreign = encode("some-other-version", Delay::D30, &rec, &claw);
        assert_eq!(parse(&foreign), None);
    }

    /// A truncated payload parses to None rather than panicking.
    #[test]
    fn truncated_payload_is_none() {
        let data = encode(PAYLOAD_VERSION, Delay::D1, &[1, 2, 3], &[4, 5, 6]);
        assert_eq!(parse(&data[..data.len() - 2]), None);
    }
}
