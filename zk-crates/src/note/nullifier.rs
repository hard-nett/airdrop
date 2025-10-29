use ff::PrimeField;
use memuse::DynamicUsage;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use subtle::CtOption;

use crate::keys::{EligibleSk, NullifierDerivingKey};
use crate::spec::{denom_to_base, elig_sk_to_base, extract_p, mod_r_p, prf_jubjub_m};
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
    /// $DeriveNullifier$.
    ///
    /// Defined in [Zcash Protocol Spec § 4.16: Note Commitments and Nullifiers][commitmentsandnullifiers].
    ///
    /// [commitmentsandnullifiers]: https://zips.z.cash/protocol/nu5.pdf#commitmentsandnullifiers
    pub fn derive(fdi: u64, v: NoteValue, nd: NoteDenom, elig_sk: EligibleSk) -> Self {
        let m = prf_jubjub_m(
            fdi.into(),
            v.inner().into(),
            denom_to_base(&nd),
            elig_sk_to_base(&elig_sk),
        );
        let k = pallas::Point::hash_to_curve("terp.network:headstash")(b"K");

        Nullifier(extract_p(&(k * mod_r_p(m))))
    }
}
