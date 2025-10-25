use ff::PrimeField;
use memuse::DynamicUsage;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use subtle::CtOption;

use crate::keys::NullifierDerivingKey;
use crate::spec::{extract_p, mod_r_p};

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
    /// $DeriveNullifier$.
    ///
    /// Defined in [Zcash Protocol Spec § 4.16: Note Commitments and Nullifiers][commitmentsandnullifiers].
    ///
    /// [commitmentsandnullifiers]: https://zips.z.cash/protocol/nu5.pdf#commitmentsandnullifiers
    pub fn derive(
        nk: &NullifierDerivingKey,
        rho: pallas::Base,
        psi: pallas::Base,
        cm: NoteCommitment,
    ) -> Self {
        let k = pallas::Point::hash_to_curve("terp.network:headstash")(b"K");

        Nullifier(extract_p(&(k * mod_r_p(nk.prf_nf(rho) + psi) + cm.0)))
    }
}
