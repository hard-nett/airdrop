use pasta_curves::pallas;

/// A newtype wrapper for leaves and internal nodes in the Orchard
/// incremental note commitment tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MerkleHashHeadstash(pallas::Base);
