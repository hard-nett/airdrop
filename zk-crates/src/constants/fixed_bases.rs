use halo2_gadgets::ecc::FixedPoints;
use pasta_curves::pallas;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// A sum type for both full-width and short bases. This enables us to use the
// shared functionality of full-width and short fixed-base scalar multiplication.
pub enum HeadstashFixedBases {
    Full(HeadstashFixedBasesFull),
    NullifierK,
    ValueCommitV,
}

/// The Orchard fixed bases used in scalar mul with full-width scalars.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeadstashFixedBasesFull {
    CommitIvkR,
    NoteCommitR,
    ValueCommitR,
    SpendAuthG,
}

/// NullifierK is used in scalar mul with a base field element.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NullifierK;

/// ValueCommitV is used in scalar mul with a short signed scalar.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ValueCommitV;

// #[cfg(feature = "circuit")]
impl FixedPoints<pallas::Affine> for HeadstashFixedBases {
    type FullScalar = HeadstashFixedBasesFull;
    type Base = NullifierK;
    type ShortScalar = ValueCommitV;
}

pub const FIXED_AMOUNTS: [u64; 10] = [
    1_000_000_000,
    100_000_000,
    10_000_000,
    1_000_000,
    100_000,
    10_000,
    1_000,
    100,
    10,
    1,
];
