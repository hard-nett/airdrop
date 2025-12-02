use super::{L_ORCHARD_SCALAR, L_VALUE};
use halo2_gadgets::ecc::chip::{BaseFieldElem, FixedPoint, FullScalar, ShortScalar, H};
use halo2_gadgets::ecc::FixedPoints;
use pasta_curves::pallas;

pub mod note_commit_r;
pub mod nullifier_k;
pub mod value_commit_r;
pub mod value_commit_v;

/// Window size for fixed-base scalar multiplication
pub const FIXED_BASE_WINDOW_SIZE: usize = 3;

/// Number of windows for a full-width scalar
pub const NUM_WINDOWS: usize =
    (L_ORCHARD_SCALAR + FIXED_BASE_WINDOW_SIZE - 1) / FIXED_BASE_WINDOW_SIZE;

/// Number of windows for a short signed scalar
pub const NUM_WINDOWS_SHORT: usize =
    (L_VALUE + FIXED_BASE_WINDOW_SIZE - 1) / FIXED_BASE_WINDOW_SIZE;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// A sum type for both full-width and short bases. This enables us to use the
// shared functionality of full-width and short fixed-base scalar multiplication.
pub enum HeadstashFixedBases {
    Full(HeadstashFixedBasesFull),
    NullifierK,
    ValueCommitV,
}

impl From<HeadstashFixedBasesFull> for HeadstashFixedBases {
    fn from(full_width_base: HeadstashFixedBasesFull) -> Self {
        Self::Full(full_width_base)
    }
}

impl From<ValueCommitV> for HeadstashFixedBases {
    fn from(_value_commit_v: ValueCommitV) -> Self {
        Self::ValueCommitV
    }
}
impl From<NullifierK> for HeadstashFixedBases {
    fn from(_nullifier_k: NullifierK) -> Self {
        Self::NullifierK
    }
}

/// The Orchard fixed bases used in scalar mul with full-width scalars.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HeadstashFixedBasesFull {
    // CommitIvkR,
    NoteCommitR,
    ValueCommitR,
    // SpendAuthG,
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

// #[cfg(feature = "circuit")]
impl FixedPoint<pallas::Affine> for HeadstashFixedBasesFull {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        match self {
            // Self::CommitIvkR => commit_ivk_r::generator(),
            Self::NoteCommitR => note_commit_r::generator(),
            Self::ValueCommitR => value_commit_r::generator(),
            // Self::SpendAuthG => spend_auth_g::generator(),
        }
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        match self {
            // Self::CommitIvkR => commit_ivk_r::U.to_vec(),
            Self::NoteCommitR => note_commit_r::U.to_vec(),
            Self::ValueCommitR => value_commit_r::U.to_vec(),
            // Self::SpendAuthG => spend_auth_g::U.to_vec(),
        }
    }

    fn z(&self) -> Vec<u64> {
        match self {
            // Self::CommitIvkR => commit_ivk_r::Z.to_vec(),
            Self::NoteCommitR => note_commit_r::Z.to_vec(),
            Self::ValueCommitR => value_commit_r::Z.to_vec(),
            // Self::SpendAuthG => spend_auth_g::Z.to_vec(),
        }
    }
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

// #[cfg(feature = "circuit")]
impl FixedPoint<pallas::Affine> for NullifierK {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        nullifier_k::generator()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        nullifier_k::U.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        nullifier_k::Z.to_vec()
    }
}

// #[cfg(feature = "circuit")]
impl FixedPoint<pallas::Affine> for ValueCommitV {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        value_commit_v::generator()
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        value_commit_v::U_SHORT.to_vec()
    }

    fn z(&self) -> Vec<u64> {
        value_commit_v::Z_SHORT.to_vec()
    }
}
