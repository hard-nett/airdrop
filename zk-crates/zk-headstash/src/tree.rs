use crate::constants::MERKLE_DEPTH_HEADSTASH;
use crate::note::ExtractedNoteCommitment;
use ff::PrimeField;
use lazy_static::lazy_static;
use pasta_curves::pallas;
use subtle::CtOption;

// The uncommitted leaf is defined as pallas::Base(2).
// <https://zips.z.cash/protocol/protocol.pdf#thmuncommittedorchard>
lazy_static! {
    static ref UNCOMMITTED_ORCHARD: pallas::Base = pallas::Base::from(2);
}

/// A newtype wrapper for leaves and internal nodes in the Headstash
/// incremental note commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MerkleHashHeadstash(pallas::Base);
impl MerkleHashHeadstash {
    /// Creates an incremental tree leaf digest from a suspected [ExtractedNoteCommitment].
    pub fn from_cmx(value: &ExtractedNoteCommitment) -> Self {
        MerkleHashHeadstash(value.inner())
    }

    /// Only used in the circuit.
    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }
}

/// The root of an Headstash commitment tree. This must be a value
/// in the range {0..=q_ℙ-1}
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Anchor(pallas::Base);

impl From<pallas::Base> for Anchor {
    fn from(anchor_field: pallas::Base) -> Anchor {
        Anchor(anchor_field)
    }
}

impl From<MerkleHashHeadstash> for Anchor {
    fn from(anchor: MerkleHashHeadstash) -> Anchor {
        Anchor(anchor.0)
    }
}

impl Anchor {
    /// The anchor of the empty Orchard note commitment tree.
    ///
    /// This anchor does not correspond to any valid anchor for a spend, so it
    /// may only be used for coinbase bundles or in circumstances where Orchard
    /// functionality is not active.

    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }

    /// Parses an Orchard anchor from a byte encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Anchor> {
        pallas::Base::from_repr(bytes).map(Anchor)
    }

    /// Returns the byte encoding of this anchor.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

// impl Hashable for MerkleHashHeadstash {
//     fn empty_leaf() -> Self {
//         MerkleHashOrchard(*U)
//     }
// }
