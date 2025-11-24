use pasta_curves::pallas;

use crate::note::ExtractedNoteCommitment;

/// A newtype wrapper for leaves and internal nodes in the Orchard
/// incremental note commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MerkleHashHeadstash(pallas::Base);
impl MerkleHashHeadstash {
    /// Creates an incremental tree leaf digest from the specified
    /// Orchard extracted note commitment.
    pub fn from_cmx(value: &ExtractedNoteCommitment) -> Self {
        MerkleHashHeadstash(value.inner())
    }

    /// Only used in the circuit.
    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }
}
