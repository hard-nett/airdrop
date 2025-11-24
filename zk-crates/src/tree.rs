use pasta_curves::pallas;

use crate::note::ExtractedNoteCommitment;

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
