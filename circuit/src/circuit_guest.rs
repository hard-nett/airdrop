//! Guest-only circuit surface for CosmWasm wasm32 builds (no host-crypto).
//!
//! Provides [`Instance`] (and byte serde) used by `cw-headstash` without pulling
//! halo2-base / libsecp C-sys / multicore prove machinery.

use alloc::vec::Vec;

use ff::PrimeField;
use pasta_curves::pallas;

use crate::{
    address::RecpAddr,
    note::{ExtractedNoteCommitment, Nullifier},
    tree::Anchor,
    value::{NoteDenom, NoteValue},
};

/// Public inputs to the Headstash Action circuit (guest-compatible).
#[derive(Clone, Debug)]
pub struct Instance {
    pub(crate) anchor: Anchor,
    pub(crate) nd: NoteDenom,
    pub(crate) v: NoteValue,
    pub(crate) nf: Nullifier,
    pub(crate) recp: RecpAddr,
    pub(crate) cmx: ExtractedNoteCommitment,
}

impl Instance {
    /// Constructs an [`Instance`] from its constituent parts.
    pub fn from_parts(
        anchor: Anchor,
        nd: NoteDenom,
        v: NoteValue,
        recp: RecpAddr,
        nf: Nullifier,
        cmx: ExtractedNoteCommitment,
    ) -> Self {
        Instance {
            anchor,
            nd,
            v,
            recp,
            nf,
            cmx,
        }
    }

    /// Byte layout matches host `circuit::Instance::to_bytes` (168 bytes).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        const THREETWO: usize = 32;
        const EIGHT: usize = 8;
        let mut offset = 0;

        let anchor: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("anchor");
        offset += THREETWO;

        let nd: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("nd");
        offset += THREETWO;

        let v_bytes = &bytes[offset..offset + EIGHT];
        let v = u64::from_le_bytes(v_bytes.try_into().expect("v"));
        offset += EIGHT;

        let nf: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("nf");
        offset += THREETWO;

        let recp = &bytes[offset..offset + THREETWO];
        offset += THREETWO;
        let cmx: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("cmx");

        Instance {
            anchor: Anchor::from_bytes(*anchor).expect("anchor"),
            nd: NoteDenom::from(*nd),
            v: NoteValue::from(v),
            nf: Nullifier::from_bytes(nf).expect("nf"),
            recp: RecpAddr::try_from(recp).expect("recp"),
            cmx: ExtractedNoteCommitment::from_bytes(cmx).expect("cmx"),
        }
    }

    /// Serialize for CosmWasm proof_instance_verify / storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(168);
        bytes.extend_from_slice(&self.anchor.to_bytes());
        bytes.extend_from_slice(&self.nd.to_fp().to_repr());
        bytes.extend_from_slice(&self.v.inner().to_le_bytes());
        bytes.extend_from_slice(&self.nf.to_bytes());
        bytes.extend_from_slice(&self.recp.to_canonical_bytes());
        bytes.extend_from_slice(&self.cmx.to_bytes());
        bytes
    }
}

// Silence unused import if pallas only needed via to_repr on Base
#[allow(dead_code)]
fn _pallas_link() -> pallas::Base {
    pallas::Base::zero()
}
