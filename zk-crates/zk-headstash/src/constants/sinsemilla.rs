use ff::PrimeField;
use halo2_gadgets::sinsemilla::{CommitDomains, HashDomains};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;

use crate::constants::fixed_bases::{HeadstashFixedBases, HeadstashFixedBasesFull};

/// SWU hash-to-curve personalization for the Merkle CRH generator
pub const MERKLE_CRH_PERSONALIZATION: &str = "t.network:Headstash-MerkleCRH";
pub const LEAF_PERSONALIZATION: &str = "t.network:Headstash-Sinsemilla-leaf";
pub const DST_ND: &str = "t.network:Headstash-Sinsemilla-nd";

/// Generator used in SinsemillaHashToPoint for note commitment
pub const Q_NOTE_COMMITMENT_M_GENERATOR: ([u8; 32], [u8; 32]) = (
    [
        93, 116, 168, 64, 9, 186, 14, 50, 42, 221, 70, 253, 90, 15, 150, 197, 93, 237, 176, 121,
        180, 242, 159, 247, 13, 205, 251, 86, 160, 7, 128, 23,
    ],
    [
        99, 172, 73, 115, 90, 10, 39, 135, 158, 94, 219, 129, 136, 18, 34, 136, 44, 201, 244, 110,
        217, 194, 190, 78, 131, 112, 198, 138, 147, 88, 160, 50,
    ],
);

/// Generator used in SinsemillaHashToPoint for Merkle collision-resistant hash
pub const Q_MERKLE_CRH: ([u8; 32], [u8; 32]) = (
    [
        160, 198, 41, 127, 249, 199, 185, 248, 112, 16, 141, 192, 85, 185, 190, 201, 153, 14, 137,
        239, 90, 54, 15, 160, 185, 24, 168, 99, 150, 210, 22, 22,
    ],
    [
        98, 234, 242, 37, 206, 174, 233, 134, 150, 21, 116, 5, 234, 150, 28, 226, 121, 89, 163, 79,
        62, 242, 196, 45, 153, 32, 175, 227, 163, 66, 134, 53,
    ],
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadstashHashDomains {
    // CommitIvk,
    NoteCommit,
    MerkleCrh,
}

// #[cfg(feature = "circuit")]
#[allow(non_snake_case)]
impl HashDomains<pallas::Affine> for HeadstashHashDomains {
    fn Q(&self) -> pallas::Affine {
        match self {
            // HeadstashHashDomains::CommitIvk => pallas::Affine::from_xy(
            //     pallas::Base::from_repr(Q_COMMIT_IVK_M_GENERATOR.0).unwrap(),
            //     pallas::Base::from_repr(Q_COMMIT_IVK_M_GENERATOR.1).unwrap(),
            // )
            // .unwrap(),
            HeadstashHashDomains::NoteCommit => pallas::Affine::from_xy(
                pallas::Base::from_repr(Q_NOTE_COMMITMENT_M_GENERATOR.0).unwrap(),
                pallas::Base::from_repr(Q_NOTE_COMMITMENT_M_GENERATOR.1).unwrap(),
            )
            .unwrap(),
            HeadstashHashDomains::MerkleCrh => pallas::Affine::from_xy(
                pallas::Base::from_repr(Q_MERKLE_CRH.0).unwrap(),
                pallas::Base::from_repr(Q_MERKLE_CRH.1).unwrap(),
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadstashCommitDomains {
    NoteCommit,
    // CommitIvk,
}

// #[cfg(feature = "circuit")]
impl CommitDomains<pallas::Affine, HeadstashFixedBases, HeadstashHashDomains>
    for HeadstashCommitDomains
{
    fn r(&self) -> HeadstashFixedBasesFull {
        match self {
            Self::NoteCommit => HeadstashFixedBasesFull::NoteCommitR,
            // Self::CommitIvk => HeadstashFixedBasesFull::CommitIvkR,
        }
    }

    fn hash_domain(&self) -> HeadstashHashDomains {
        match self {
            Self::NoteCommit => HeadstashHashDomains::NoteCommit,
            // Self::CommitIvk => HeadstashHashDomains::CommitIvk,
        }
    }
}
