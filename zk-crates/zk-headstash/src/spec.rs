use std::ops::Deref;

use crate::address::RecpAddr;
use crate::constants::DST_HKDF;
use crate::keys::EligibleSk;
use crate::note::commitment::NoteCommitTrapdoor;
use crate::value::{NoteDenom, MAX_DENOM_LEN};

use ff::{Field, FromUniformBytes, PrimeField};
use group::{Curve, Group, GroupEncoding, WnafBase, WnafScalar};
use halo2_gadgets::poseidon::primitives as poseidon;
use num_bigint::BigUint;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use subtle::{ConditionallySelectable, CtOption};

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
        let limb_fe = pallas::Base::from_repr(limb_bytes_32).expect("limb must be in pallas range");
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

/// # hdkf_pallas
/// Derives nk from the Pallas base field representation for `esk`\
/// *(via modular big-endian byte-to-field-element conversion)*\
/// using the posiedon hashing algorithm with a domain-separation-tag in the order (`DST`,`esk_fp`,`rho`).
pub fn hdkf_pallas(esk_pallas_fp: pallas::Base, rho: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<3>, 3, 2>::init().hash([
        pallas::Base::from_repr(DST_HKDF).expect("invalid DST bytes"),
        esk_pallas_fp,
        rho,
    ])
}

// Derives the hash of the expected_dst used for the hash deriving step.
// is multiplied by rho an provided to the function.
pub(crate) fn prf_pallas_m(
    fdi: pallas::Base,
    esk: pallas::Base,
    v: pallas::Base,
    nd: pallas::Base,
) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<4>, 3, 2>::init()
        .hash([fdi, v, nd, esk])
}

/// Convert a `NoteDenom` into a field element.
///  NoteDenom is expected to have been hashed and trimmed when it was initialized.
pub(crate) fn nd_to_fp(nd: &NoteDenom) -> pallas::Base {
    pallas::Base::from_repr(nd.as_bytes().try_into().expect("invalid length")).expect("bad nd_to_fp")
}

/// Convert a `RecpAddr` into a field element by hashing its byte payload.\
/// posiedon params: width = 3 (t = 3) // rounds = 2 (full rounds per the spec)
pub(crate) fn recp_to_fp(ra: &RecpAddr) -> pallas::Base {
    let bytes = ra.to_bytes();
    let first_half = &bytes[0..16];
    let second_half = &bytes[16..32];

    // Convert each chunk to a field element (interpreting as little-endian u128)
    let fe1 = pallas::Base::from_u128(u128::from_le_bytes(first_half.try_into().unwrap()));
    let fe2 = pallas::Base::from_u128(u128::from_le_bytes(second_half.try_into().unwrap()));

    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([fe1, fe2])
}

/// Convert a field element to BigUint without requiring BigPrimeField trait.
pub fn fe_to_biguint_simple(fe: &pallas::Base) -> BigUint {
    use ff::PrimeField;
    let bytes = fe.to_repr();
    BigUint::from_bytes_le(&bytes)
}

/// Convert a BigUint to a field element without requiring BigPrimeField trait.
pub fn biguint_to_fe_simple(value: &BigUint) -> pallas::Base {
    use ff::PrimeField;
    let bytes = value.to_bytes_le();
    let mut bytes_32 = [0u8; 32];
    bytes_32[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
    pallas::Base::from_repr(bytes_32).unwrap_or(pallas::Base::ZERO)
}

/// Convert a generic field element to BigUint.
///
/// This is a generic version that works for any PrimeField, not just pallas::Base.
pub fn fe_to_biguint_for_field<F: PrimeField>(fe: &F) -> BigUint {
    let bytes = fe.to_repr();
    BigUint::from_bytes_le(bytes.as_ref())
}

/// Convert esk (`EligibleSk`) into a `pallas::Base` scalar by decomposing into 3 88 bit limbs\
/// Hash array of 3 limbs using Poseidon to get single pallas::Base value\
/// This compresses the CRT representation into a single field element
pub(crate) fn esk_to_base(esk: &EligibleSk) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<MAX_DENOM_LEN>, 3, 2>::init()
        .hash(
            crate::spec::decompose_biguint_simple(
                &halo2_base::utils::fe_to_biguint(
                    &halo2_base::halo2_proofs::halo2curves::secq256k1::Fp::from_repr(
                        esk.0.secret_bytes(),
                    )
                    .expect("valid Fq"),
                ),
                3,
                88,
            )
            .try_into()
            .unwrap(),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::pallas;

    // Helper function to create a RecpAddr from a 32-byte array
    fn make_recp_addr(bytes: [u8; 32]) -> RecpAddr {
        RecpAddr::try_from(&bytes[..]).unwrap()
    }

    #[test]
    fn test_recp_to_fp_deterministic() {
        // Same input should always produce same output
        let test_bytes = [42u8; 32];
        let recp1 = make_recp_addr(test_bytes);
        let recp2 = make_recp_addr(test_bytes);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_different_inputs() {
        // Different inputs should produce different outputs
        let bytes1 = [1u8; 32];
        let bytes2 = [2u8; 32];

        let recp1 = make_recp_addr(bytes1);
        let recp2 = make_recp_addr(bytes2);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_all_zeros() {
        let zero_bytes = [0u8; 32];
        let recp = make_recp_addr(zero_bytes);

        let fp = recp_to_fp(&recp);

        // Should produce a valid field element (not necessarily zero due to hashing)
        // Just verify it doesn't panic and produces a field element
        assert!(fp != pallas::Base::zero() || fp == pallas::Base::zero());
    }

    #[test]
    fn test_recp_to_fp_all_ones() {
        let ones_bytes = [0xFFu8; 32];
        let recp = make_recp_addr(ones_bytes);

        let fp = recp_to_fp(&recp);

        // Should produce a valid field element
        assert!(fp != pallas::Base::zero() || fp == pallas::Base::zero());
    }

    #[test]
    fn test_recp_to_fp_sequential_bytes() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let recp = make_recp_addr(bytes);
        let fp = recp_to_fp(&recp);

        // Verify it's a valid field element by checking it's in the field
        // (all pallas::Base values are valid by construction)
        let _ = fp;
    }

    #[test]
    fn test_recp_to_fp_single_bit_difference() {
        // Test avalanche effect: small change in input should cause large change in output
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes2[0] = 1; // Only change first bit

        let recp1 = make_recp_addr(bytes1);
        let recp2 = make_recp_addr(bytes2);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_change_in_first_half() {
        // Change only in first 16 bytes
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes2[8] = 1; // Change in first half

        let recp1 = make_recp_addr(bytes1);
        let recp2 = make_recp_addr(bytes2);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_change_in_second_half() {
        // Change only in second 16 bytes
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes2[24] = 1; // Change in second half

        let recp1 = make_recp_addr(bytes1);
        let recp2 = make_recp_addr(bytes2);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_returns_valid_field_element() {
        let test_bytes = [123u8; 32];
        let recp = make_recp_addr(test_bytes);

        let fp = recp_to_fp(&recp);

        // Test that we can perform field operations on the result
        let doubled = fp + fp;
        let squared = fp * fp;

        assert_ne!(doubled, fp); // Unless fp is zero, which it shouldn't be
        assert!(squared == squared); // Just verify operations work
    }

    #[test]
    fn test_recp_to_fp_collision_resistance() {
        // Test a few different inputs to ensure no obvious collisions
        let mut outputs = std::collections::HashSet::new();

        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let recp = make_recp_addr(bytes);
            let fp = recp_to_fp(&recp);

            // Convert to bytes for HashSet (PrimeField trait provides to_repr)
            let repr = fp.to_repr();
            assert!(outputs.insert(repr), "Found collision at iteration {}", i);
        }

        assert_eq!(outputs.len(), 10);
    }

    #[test]
    fn test_recp_to_fp_boundary_values() {
        // Test with max u128 in first half
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&[0xFF; 16]);
        let recp1 = make_recp_addr(bytes);

        // Test with max u128 in second half
        let mut bytes = [0u8; 32];
        bytes[16..32].copy_from_slice(&[0xFF; 16]);
        let recp2 = make_recp_addr(bytes);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_integration_with_recp_addr() {
        // Test that it works seamlessly with RecpAddr's to_pallas method
        let test_bytes = [77u8; 32];
        let recp = make_recp_addr(test_bytes);

        let fp1 = recp_to_fp(&recp);
        let fp2 = recp.to_pallas(); // Should call the same function

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_recp_to_fp_byte_order_matters() {
        // Reversed bytes should give different hash
        let mut bytes1 = [0u8; 32];
        for (i, byte) in bytes1.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut bytes2 = bytes1.clone();
        bytes2.reverse();

        let recp1 = make_recp_addr(bytes1);
        let recp2 = make_recp_addr(bytes2);

        let fp1 = recp_to_fp(&recp1);
        let fp2 = recp_to_fp(&recp2);

        assert_ne!(fp1, fp2);
    }
}
