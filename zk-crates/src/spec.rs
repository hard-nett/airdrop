use std::ops::Deref;

use ff::{Field, FromUniformBytes, PrimeField};
use group::{Curve, Group, GroupEncoding, WnafBase, WnafScalar};
use halo2_ecc::bigint::FixedOverflowInteger;
use halo2_gadgets::{poseidon::primitives as poseidon, sinsemilla::primitives as sinsemilla};
use num_bigint::BigUint;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use subtle::{ConditionallySelectable, CtOption};

use crate::constants::DST_HKDF;
use crate::keys::EligibleSk;
use crate::note::Rho;
use crate::value::{NoteDenom, MAX_DENOM_LEN};

const PREPARED_WINDOW_SIZE: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct PreparedNonIdentityBase(WnafBase<pallas::Point, PREPARED_WINDOW_SIZE>);

impl PreparedNonIdentityBase {
    pub(crate) fn new(base: NonIdentityPallasPoint) -> Self {
        PreparedNonIdentityBase(WnafBase::new(base.0))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedNonZeroScalar(WnafScalar<pallas::Scalar, PREPARED_WINDOW_SIZE>);

impl PreparedNonZeroScalar {
    pub(crate) fn new(scalar: &NonZeroPallasScalar) -> Self {
        PreparedNonZeroScalar(WnafScalar::new(scalar))
    }
}

/// A Pallas point that is guaranteed to not be the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NonIdentityPallasPoint(pallas::Point);

impl Default for NonIdentityPallasPoint {
    fn default() -> Self {
        NonIdentityPallasPoint(pallas::Point::generator())
    }
}

impl ConditionallySelectable for NonIdentityPallasPoint {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        NonIdentityPallasPoint(pallas::Point::conditional_select(&a.0, &b.0, choice))
    }
}

impl NonIdentityPallasPoint {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Point::from_bytes(bytes)
            .and_then(|p| CtOption::new(NonIdentityPallasPoint(p), !p.is_identity()))
    }
}

impl Deref for NonIdentityPallasPoint {
    type Target = pallas::Point;

    fn deref(&self) -> &pallas::Point {
        &self.0
    }
}
/// Decompose a BigUint into limbs without requiring BigPrimeField trait.
///
/// This is our own implementation to avoid dependency on halo2-base traits.
pub fn decompose_biguint_simple(
    value: &BigUint,
    num_limbs: usize,
    limb_bits: usize,
) -> Vec<pallas::Base> {
    use ff::PrimeField;
    let mask = (BigUint::from(1u64) << limb_bits) - 1u64;
    let mut limbs = Vec::with_capacity(num_limbs);
    let mut remaining = value.clone();

    for _ in 0..num_limbs {
        let limb_big = &remaining & &mask;
        // Convert limb to field element
        let limb_bytes = limb_big.to_bytes_le();
        let mut limb_bytes_32 = [0u8; 32];
        limb_bytes_32[..limb_bytes.len().min(32)]
            .copy_from_slice(&limb_bytes[..limb_bytes.len().min(32)]);
        let limb_fe = pallas::Base::from_repr(limb_bytes_32).unwrap_or(pallas::Base::ZERO);
        limbs.push(limb_fe);
        remaining >>= limb_bits;
    }

    limbs
}

/// Coordinate extractor for Pallas.
pub(crate) fn extract_p(point: &pallas::Point) -> pallas::Base {
    point
        .to_affine()
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(pallas::Base::zero)
}

/// Converts from pallas::Base to pallas::Scalar (aka $x \pmod{r_\mathbb{P}}$).
///
/// This requires no modular reduction because Pallas' base field is smaller than its
/// scalar field.
pub(crate) fn mod_r_p(x: pallas::Base) -> pallas::Scalar {
    pallas::Scalar::from_repr(x.to_repr()).unwrap()
}

/// # Pseudo-Random-Function DST: Nullifier
pub(crate) fn prf_nf(nk: pallas::Base, rho: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([nk, rho])
}

// /// convert e_sk into 3 88 bit pallas curve values
// /// // TODO: implement the derivation of 3 limbs on pallas curve bytes of secp256k1 curve
// pub(crate) fn elig_sk_to_limbs(e_sk: [u8; 32]) -> [pallas::Base; 3] {
//     let mut acc = [pallas::Base::ZERO; 3];
//     FixedOverflowInteger::from_native(BigUint, 3, 88);
//     for &byte in &e_sk {
//         acc = acc * pallas::Base::from(256u64).add(&pallas::Base::from(byte as u64));
//         acc[i]
//     }
// }
// s
/// # hdkf_pallas
/// Derives nk from the Pallas base field representation for `e_sk`\
/// *(via modular big-endian byte-to-field-element conversion)*\
/// using the posiedon hashing algorithm with a domain-separation-tag in the order (`DST`,`esk_fp`,`rho`).
pub fn hdkf_pallas(elig_sk_pallas_fp: pallas::Base, rho: pallas::Base) -> pallas::Base {
    let mut dst_bytes = [0u8; 32];
    let copy_len = DST_HKDF.len().min(32);
    dst_bytes[..copy_len].copy_from_slice(&DST_HKDF[..copy_len]);
    let dst_fe = pallas::Base::from_repr(dst_bytes).expect("invalid DST bytes");
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<3>, 3, 2>::init().hash([
        dst_fe,
        elig_sk_pallas_fp,
        rho,
    ])
}

// Derives the hash of the expected_dst used for the hash deriving step. is multiplied by rho an provided to the function.
pub(crate) fn prf_pallas_m(
    fdi: pallas::Base,
    v: pallas::Base,
    nd: pallas::Base,
    e_sk: pallas::Base,
) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<4>, 3, 2>::init()
        .hash([fdi, v, nd, e_sk])
}

/// Convert a `NoteDenom` into a field element by hashing its byte payload.
pub(crate) fn denom_to_base(nd: &NoteDenom) -> pallas::Base {
    let mut inputs = [pallas::Base::zero(); MAX_DENOM_LEN];
    for (i, &b) in nd.as_bytes()[..nd.len_inner() as usize].iter().enumerate() {
        // Simple conversion: a byte → the scalar `b` in the field.
        // `Base::from` is available via the `From<u64>` impl.
        inputs[i] = pallas::Base::from(b as u64);
    }

    poseidon::Hash::<
        _,                    // the circuit (unused here)
        poseidon::P128Pow5T3, // the permutation parameters
        poseidon::ConstantLength<MAX_DENOM_LEN>,
        3, // width = 3 (t = 3)
        2, // rounds = 2 (full rounds per the spec)
    >::init()
    .hash(inputs)
}

/// Convert e_sk (`EligibleSk`) into a `pallas::Base` scalar
/// using the Poseidon hash.
/// Used to prepare an input into a circuit hashing function
pub(crate) fn elig_sk_to_base(esk: &EligibleSk) -> pallas::Base {
    let mut tag_inputs = [pallas::Base::zero(); MAX_DENOM_LEN];
    for (i, &b) in DST_HKDF.iter().enumerate() {
        tag_inputs[i] = pallas::Base::from(b as u64);
    }

    // One `Base` per byte – this mirrors the handling in `denom_to_base`.
    let mut key_inputs = [pallas::Base::zero(); MAX_DENOM_LEN];
    for (i, &b) in esk.0.secret_bytes().iter().enumerate() {
        key_inputs[i] = pallas::Base::from(b as u64);
    }

    let mut poseidon_inputs = [pallas::Base::zero(); MAX_DENOM_LEN];
    let tag_len = DST_HKDF.len();
    poseidon_inputs[..tag_len].copy_from_slice(&tag_inputs[..tag_len]);
    poseidon_inputs[tag_len..tag_len + 32].copy_from_slice(&key_inputs[..32]);

    poseidon::Hash::<
        _, // circuit placeholder (unused here)
        poseidon::P128Pow5T3,
        poseidon::ConstantLength<MAX_DENOM_LEN>,
        3, // width = 3 (t = 3)
        2, // full rounds per spec
    >::init()
    .hash(poseidon_inputs)
}

/// An integer in [1..q_P].
#[derive(Clone, Copy, Debug)]
pub(crate) struct NonZeroPallasBase(pallas::Base);

impl Default for NonZeroPallasBase {
    fn default() -> Self {
        NonZeroPallasBase(pallas::Base::one())
    }
}
impl ConditionallySelectable for NonZeroPallasBase {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        NonZeroPallasBase(pallas::Base::conditional_select(&a.0, &b.0, choice))
    }
}

impl NonZeroPallasBase {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).and_then(NonZeroPallasBase::from_base)
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }

    pub(crate) fn from_base(b: pallas::Base) -> CtOption<Self> {
        CtOption::new(NonZeroPallasBase(b), !b.is_zero())
    }

    /// Constructs a wrapper for a base field element that is guaranteed to be non-zero.
    ///
    /// # Panics
    ///
    /// Panics if `s.is_zero()`.
    fn guaranteed(s: pallas::Base) -> Self {
        assert!(!bool::from(s.is_zero()));
        NonZeroPallasBase(s)
    }
}

/// An integer in [1..r_P].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NonZeroPallasScalar(pallas::Scalar);

impl Default for NonZeroPallasScalar {
    fn default() -> Self {
        NonZeroPallasScalar(pallas::Scalar::one())
    }
}

impl From<NonZeroPallasBase> for NonZeroPallasScalar {
    fn from(s: NonZeroPallasBase) -> Self {
        NonZeroPallasScalar::guaranteed(mod_r_p(s.0))
    }
}

impl NonZeroPallasScalar {
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Scalar::from_repr(*bytes).and_then(NonZeroPallasScalar::from_scalar)
    }

    pub(crate) fn from_scalar(s: pallas::Scalar) -> CtOption<Self> {
        CtOption::new(NonZeroPallasScalar(s), !s.is_zero())
    }

    /// Constructs a wrapper for a scalar field element that is guaranteed to be non-zero.
    ///
    /// # Panics
    ///
    /// Panics if `s.is_zero()`.
    fn guaranteed(s: pallas::Scalar) -> Self {
        assert!(!bool::from(s.is_zero()));
        NonZeroPallasScalar(s)
    }
}

impl Deref for NonZeroPallasScalar {
    type Target = pallas::Scalar;

    fn deref(&self) -> &pallas::Scalar {
        &self.0
    }
}
/// $\mathsf{ToBase}^\mathsf{Orchard}(x) := LEOS2IP_{\ell_\mathsf{PRFexpand}}(x) (mod q_P)$
///
/// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
pub(crate) fn to_base(x: [u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(&x)
}

/// $\mathsf{ToScalar}^\mathsf{Orchard}(x) := LEOS2IP_{\ell_\mathsf{PRFexpand}}(x) (mod r_P)$
///
/// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
pub(crate) fn to_scalar(x: [u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(&x)
}

/// Defined in [Zcash Protocol Spec § 5.4.1.6: DiversifyHash^Sapling and DiversifyHash^Orchard Hash Functions][concretediversifyhash].
///
/// [concretediversifyhash]: https://zips.z.cash/protocol/nu5.pdf#concretediversifyhash
// pub(crate) fn diversify_hash(d: &[u8; 32]) -> NonIdentityPallasPoint {
//     let hasher = pallas::Point::hash_to_curve(KEY_DIVERSIFICATION_PERSONALIZATION);
//     let g_d = hasher(d);
//     // If the identity occurs, we replace it with a different fixed point.
//     // TODO: Replace the unwrap_or_else with a cached fixed point.
//     NonIdentityPallasPoint(CtOption::new(g_d, !g_d.is_identity()).unwrap_or_else(|| hasher(&[])))
// }

/// Defined in [Zcash Protocol Spec § 5.4.5.5: Orchard Key Agreement][concreteorchardkeyagreement].
///
/// [concreteorchardkeyagreement]: https://zips.z.cash/protocol/nu5.pdf#concreteorchardkeyagreement
pub(crate) fn ka_orchard(
    sk: &NonZeroPallasScalar,
    b: &NonIdentityPallasPoint,
) -> NonIdentityPallasPoint {
    ka_orchard_prepared(
        &PreparedNonZeroScalar::new(sk),
        &PreparedNonIdentityBase::new(*b),
    )
}

/// Defined in [Zcash Protocol Spec § 5.4.5.5: Orchard Key Agreement][concreteorchardkeyagreement].
///
/// [concreteorchardkeyagreement]: https://zips.z.cash/protocol/nu5.pdf#concreteorchardkeyagreement
pub(crate) fn ka_orchard_prepared(
    sk: &PreparedNonZeroScalar,
    b: &PreparedNonIdentityBase,
) -> NonIdentityPallasPoint {
    NonIdentityPallasPoint(&b.0 * &sk.0)
}

/// modular big-endian byte-to-field-element conversion
pub fn mbe_btfe(e_sk: [u8; 32]) -> pallas::Base {
    let mut acc = pallas::Base::ZERO;
    for &byte in &e_sk {
        acc = acc * pallas::Base::from(256u64) + pallas::Base::from(byte as u64);
    }
    acc
}
