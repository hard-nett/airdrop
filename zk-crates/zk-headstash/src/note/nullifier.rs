use ff::PrimeField;
use group::Group;
use memuse::DynamicUsage;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::CtOption;

use crate::keys::{EligiblePk, EligibleSk, NullifierDerivingKey};
use crate::spec::{esk_to_base, extract_p, mod_r_p};
use crate::value::{NoteDenom, NoteValue};

use super::NoteCommitment;

/// A unique nullifier for a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nullifier(pub(crate) pallas::Base);

// We know that `pallas::Base` doesn't allocate internally.
memuse::impl_no_dynamic_usage!(Nullifier);

impl Nullifier {
    /// Deserialize the nullifier from a byte array.
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(Nullifier)
    }
    /// Serialize the nullifier to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
    /// ```math
    /// DeriveNullifier
    /// ```
    ///
    /// Defined in Headstash Protocol Spec: TODO-map to defintion in spec
    pub fn derive(
        nk: NullifierDerivingKey,
        rho: pallas::Base,
        psi: pallas::Base,
        cm: NoteCommitment,
    ) -> Self {
        let k = pallas::Point::hash_to_curve("terp.network:headstash")(b"K");
        // TODO: derive nullifier by deriving nullifier key from correct inputs & hash dst, then use the
        Nullifier(extract_p(&(k * mod_r_p(nk.prf_nf(rho)))))
    }
    /// Generates a dummy nullifier for use as $\rho$ in dummy spent notes.
    ///
    /// Nullifiers are required by consensus to be unique. For dummy output notes, we get
    /// this restriction as intended: the note's $\rho$ value is set to the nullifier of
    /// the accompanying spent note within the action, which is constrained by consensus
    /// to be unique. In the case of dummy spent notes, we get this restriction by
    /// following the chain backwards: the nullifier of the dummy spent note will be
    /// constrained by consensus to be unique, and the nullifier's uniqueness is derived
    /// from the uniqueness of $\rho$.
    ///
    /// Instead of explicitly sampling for a unique nullifier, we rely here on the size of
    /// the base field to make the chance of sampling a colliding nullifier negligible.
    pub(crate) fn dummy(rng: &mut impl RngCore) -> Self {
        Nullifier(extract_p(&pallas::Point::random(rng)))
    }
}
