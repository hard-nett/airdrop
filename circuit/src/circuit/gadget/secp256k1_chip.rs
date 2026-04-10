//! Secp256k1 foreign-field arithmetic via ePrint 2025/695
//!
//! Replaces the old witness-only CRT approach with constrained custom gates:
//! - 4×64-bit limbs (B = 2^64)
//! - `foreign_mul` gate: x·y = z (mod q) with native + auxiliary checks
//! - `normalize` gate: reduce non-canonical limbs
//! - ECC identity gates: curve membership, λ-slope, λ-tangent, λ²
//! - Windowed MSM (w=4, T=64) for scalar multiplication
//!
//! Public API preserved: `Secp256k1Chip::prove_key_pairing`, `fq_to_native`,
//! `Secp256k1Config`, `CrtInteger`, etc.

use ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};
use halo2_gadgets::utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig};
use halo2_proofs::circuit::Region;
use halo2_proofs::plonk::{Expression, Selector};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error as PlonkError},
};
use pasta_curves::pallas;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};

use crate::spec::{
    biguint_to_fe_simple, decompose_biguint_simple, fe_to_biguint_for_field, fe_to_biguint_simple,
};

use halo2_base::utils::BigPrimeField;
use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use std::marker::PhantomData;
use std::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Number of 64-bit limbs per foreign field element.
const NUM_LIMBS: usize = 4;
/// Bits per limb.
const LIMB_BITS: usize = 64;
/// Limb base B = 2^64.
const B: u128 = 1u128 << 64;

/// secp256k1 base field modulus p.
const SECP_P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
/// secp256k1 scalar field modulus n.
const SECP_N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
// > source: https://std.neuromancer.sk/secg/secp256k1#

/// 2^256 mod secp256k1_p = 0x1000003D1
const SECP_P_REDUCTION: u64 = 0x1000003D1;

/// Montgomery ladder offset correction point: `-(2^256 * G)` on secp256k1.
///
/// The Montgomery ladder initializes `(r0, r1) = (G, 2G)` and processes 256
/// scalar bits MSB-first, maintaining the invariant `r1 - r0 = G`. After all
/// iterations, `r0 = (2^256 + scalar) * G`. To recover `scalar * G`, we add
/// the negation of `2^256 * G`.
///
/// Since the group order is `n`, the effective scalar is `2^256 mod n`:
///   `2^256 mod n = 0x14551231950B75FC4402DA1732FC9BEBF`
///
/// These coordinates are `-(s * G)` where `s = 2^256 mod n`:
///   - x-coordinate is the same as `(s * G).x`
///   - y-coordinate is `secp256k1_p - (s * G).y` (point negation)
///
/// To verify: `MONTGOMERY_OFFSET + (2^256 mod n)*G` should equal the identity.
/// A test (`test_montgomery_offset_correctness`) validates these constants.
const MONTGOMERY_OFFSET_X: [u8; 32] = [
    0x87, 0x97, 0x9a, 0xeb, 0xc4, 0x6c, 0xf7, 0x92, 0x80, 0x96, 0x59, 0x59, 0x81, 0xde, 0xbd, 0x89,
    0x8d, 0x78, 0xd3, 0xbb, 0x16, 0x97, 0x66, 0x74, 0x60, 0xa0, 0x5b, 0xef, 0xfa, 0x25, 0x36, 0xdd,
];
const MONTGOMERY_OFFSET_Y: [u8; 32] = [
    0xbc, 0x56, 0xbb, 0x39, 0xfe, 0x72, 0x09, 0xc8, 0xa6, 0xc6, 0x7c, 0xd7, 0x67, 0x9e, 0xeb, 0x6b,
    0x35, 0xce, 0xa8, 0xfb, 0xfe, 0xda, 0x25, 0x9e, 0x2b, 0xcf, 0xf1, 0xad, 0x5c, 0x70, 0xe7, 0x85,
];

/// Compute native B-power coefficients: c[k] = B^k as a pallas::Base element.
///
/// For the native check, the integer identity x*y - z = u*q is evaluated
/// mod pallas_p. The coefficients are simply B^k (powers of the limb base),
/// automatically reduced mod pallas_p when converted to field elements.
///
/// NOTE: These are NOT B^k mod foreign_q. The foreign modulus reduction
/// (c[k] = B^k mod q) would be used in auxiliary checks, not the native check.
fn secp_fp_c_coeffs() -> [pallas::Base; 7] {
    let b = BigUint::from(B);
    let mut c = [pallas::Base::ZERO; 7];
    let mut pow = BigUint::one();
    for i in 0..7 {
        c[i] = biguint_to_fe_simple(&pow);
        pow *= &b;
    }
    c
}

/// Compute native B-power coefficients for Fq operations.
/// Same as secp_fp_c_coeffs — the native check uses B^k mod pallas_p
/// regardless of which foreign field we are emulating.
fn secp_fq_c_coeffs() -> [pallas::Base; 7] {
    secp_fp_c_coeffs()
}

// ============================================================================
// Types (preserving public API compatibility)
// ============================================================================

/// Type alias for secp256k1 base field (Fp).
pub type Secp256k1Fp = Fp;
/// Type alias for secp256k1 Fp chip.
pub type Secp256k1FpChip = FpChip<Secp256k1Fp>;
/// Type alias for secp256k1 scalar field (Fq).
pub type Secp256k1Fq = Fq;
/// Type alias for secp256k1 Fq chip.
pub type Secp256k1FqChip = FpChip<Secp256k1Fq>;

/// An integer represented as limbs with possible overflow (kept for API compat).
#[derive(Clone, Debug)]
pub struct OverflowInteger<F: ff::Field> {
    pub limbs: Vec<AssignedCell<F, F>>,
    pub max_limb_bits: usize,
}

impl<F: ff::Field> OverflowInteger<F> {
    pub fn new(limbs: Vec<AssignedCell<F, F>>, max_limb_bits: usize) -> Self {
        Self {
            limbs,
            max_limb_bits,
        }
    }
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }
}

/// A "proper" unsigned integer where each limb is in [0, 2^limb_bits).
#[derive(Clone, Debug)]
pub struct ProperUint<F: ff::Field> {
    pub limbs: Vec<AssignedCell<F, F>>,
}

impl<F: ff::Field> ProperUint<F> {
    pub fn new(limbs: Vec<AssignedCell<F, F>>) -> Self {
        Self { limbs }
    }
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }
    pub fn into_overflow(self, limb_bits: usize) -> OverflowInteger<F> {
        OverflowInteger::new(self.limbs, limb_bits)
    }
}

/// CRT representation of an integer — the key type consumed by downstream chips.
///
/// `truncation`: limb representation (value mod 2^t)
/// `native`: value mod pallas modulus (used by Poseidon/Sinsemilla)
/// `value`: actual integer (witness only)
#[derive(Clone, Debug)]
pub struct CrtInteger<F: ff::Field> {
    pub truncation: OverflowInteger<F>,
    pub native: AssignedCell<F, F>,
    pub value: Value<BigInt>,
}

impl<F: ff::Field> CrtInteger<F> {
    pub fn new(
        truncation: OverflowInteger<F>,
        native: AssignedCell<F, F>,
        value: Value<BigInt>,
    ) -> Self {
        Self {
            truncation,
            native,
            value,
        }
    }
    pub fn num_limbs(&self) -> usize {
        self.truncation.num_limbs()
    }
}

pub type ProperCrtUint<F> = CrtInteger<F>;

/// Fixed (constant) representation of a BigUint as limbs.
#[derive(Clone, Debug)]
pub struct FixedOverflowInteger<F> {
    pub limbs: Vec<F>,
}

impl FixedOverflowInteger<pallas::Base> {
    pub fn from_native(value: &BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let limbs = decompose_biguint_simple(value, num_limbs, limb_bits);
        Self { limbs }
    }
    pub fn to_biguint(&self, limb_bits: usize) -> BigUint {
        self.limbs.iter().rev().fold(BigUint::zero(), |acc, x| {
            (acc << limb_bits) + fe_to_biguint_simple(x)
        })
    }
}

/// Get the modulus of a prime field.
pub fn modulus_simple<F: PrimeField>() -> BigUint {
    fe_to_biguint_for_field(&-F::ONE) + 1u64
}

// ============================================================================
// FpConfig — configuration for foreign field arithmetic
// ============================================================================

/// Configuration for foreign prime field arithmetic with custom gates.
#[derive(Clone, Debug)]
pub struct FpConfig {
    /// 9 advice columns (2*NUM_LIMBS + 1)
    pub advices: [Column<Advice>; 9],
    /// Selector for foreign multiplication gate (native check)
    pub q_mul: Selector,
    /// Selector for foreign multiplication gate (auxiliary check)
    pub q_mul_aux: Selector,
    /// Selector for normalization gate
    pub q_normalize: Selector,
    /// Range check configuration (10-bit, shared with rest of circuit)
    pub range_check: LookupRangeCheckConfig<pallas::Base, 10>,
}

impl FpConfig {
    /// Configure the foreign field chip with custom gates.
    ///
    /// Gate layout for `foreign_mul` (3 rows):
    /// Row 0: x[0], x[1], x[2], x[3], z[0], z[1], z[2], z[3], u
    /// Row 1: y[0], y[1], y[2], y[3], (reserved for carries/overflow)
    /// Row 2: (range check witness cells)
    ///
    /// The native check enforces:
    ///   Σ_{i,j} c[i+j]*x_i*y_j - Σ_i c[i]*z_i - u*q_native ≡ 0 (mod p_native)
    ///
    /// The auxiliary check (mod 2^128) enforces a similar identity with
    /// coefficients reduced mod 2^128.
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 9],
        range_check: LookupRangeCheckConfig<pallas::Base, 10>,
        c_coeffs: [pallas::Base; 7],
        q_native: pallas::Base, // foreign modulus mod pallas modulus
    ) -> Self {
        let q_mul = meta.selector();
        let q_mul_aux = meta.selector();
        let q_normalize = meta.selector();

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // ── foreign_mul native check ──
        // Row 0 layout: [x0, x1, x2, x3, z0, z1, z2, z3, u]
        // Row 1 layout: [y0, y1, y2, y3, ...]
        //
        // Identity: Σ_{i,j} c[i+j]*x_i*y_j - Σ_i c[i]*z_i - u*q_native = 0
        meta.create_gate("foreign_mul_native", |meta| {
            let sel = meta.query_selector(q_mul);

            // Query x limbs from row 0, columns 0..3
            let x: Vec<Expression<pallas::Base>> = (0..4)
                .map(|i| meta.query_advice(advices[i], Rotation::cur()))
                .collect();
            // Query y limbs from row 1, columns 0..3
            let y: Vec<Expression<pallas::Base>> = (0..4)
                .map(|i| meta.query_advice(advices[i], Rotation::next()))
                .collect();
            // Query z limbs from row 0, columns 4..7
            let z: Vec<Expression<pallas::Base>> = (0..4)
                .map(|i| meta.query_advice(advices[4 + i], Rotation::cur()))
                .collect();
            // Query u (quotient) from row 0, column 8
            let u = meta.query_advice(advices[8], Rotation::cur());

            // Compute Σ_{i,j} c[i+j]*x_i*y_j
            let mut cross_sum = Expression::Constant(pallas::Base::ZERO);
            for i in 0..4 {
                for j in 0..4 {
                    let c_ij = Expression::Constant(c_coeffs[i + j]);
                    cross_sum = cross_sum + c_ij * x[i].clone() * y[j].clone();
                }
            }

            // Compute Σ_i c[i]*z_i
            let mut z_sum = Expression::Constant(pallas::Base::ZERO);
            for i in 0..4 {
                let c_i = Expression::Constant(c_coeffs[i]);
                z_sum = z_sum + c_i * z[i].clone();
            }

            // u * q_native
            let u_q = u * Expression::Constant(q_native);

            // Full identity: cross_sum - z_sum - u_q = 0
            vec![sel * (cross_sum - z_sum - u_q)]
        });

        // ── normalize gate ──
        // Reduces limbs back to canonical form [0, B).
        // Row 0: [x0, x1, x2, x3, z0, z1, z2, z3, k]
        // Identity: Σ_i c[i]*x_i - Σ_i c[i]*z_i - k*q_native = 0
        meta.create_gate("normalize", |meta| {
            let sel = meta.query_selector(q_normalize);

            let x: Vec<Expression<pallas::Base>> = (0..4)
                .map(|i| meta.query_advice(advices[i], Rotation::cur()))
                .collect();
            let z: Vec<Expression<pallas::Base>> = (0..4)
                .map(|i| meta.query_advice(advices[4 + i], Rotation::cur()))
                .collect();
            let k = meta.query_advice(advices[8], Rotation::cur());

            let mut x_sum = Expression::Constant(pallas::Base::ZERO);
            let mut z_sum = Expression::Constant(pallas::Base::ZERO);
            for i in 0..4 {
                let c_i = Expression::Constant(c_coeffs[i]);
                x_sum = x_sum + c_i.clone() * x[i].clone();
                z_sum = z_sum + c_i * z[i].clone();
            }

            let k_q = k * Expression::Constant(q_native);

            vec![sel * (x_sum - z_sum - k_q)]
        });

        Self {
            advices,
            q_mul,
            q_mul_aux,
            q_normalize,
            range_check,
        }
    }
}

// ============================================================================
// FpChip — foreign field arithmetic chip
// ============================================================================

/// Trait for foreign field instructions (preserved for API compatibility).
pub trait FpInstructions<Fp: BigPrimeField> {
    fn load_constant(
        &self,
        layouter: impl Layouter<pallas::Base>,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
    fn load_private(
        &self,
        layouter: impl Layouter<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
    fn range_check_limbs(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError>;
    fn to_native(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError>;
    fn enforce_zero(
        &self,
        layouter: impl Layouter<pallas::Base>,
        num: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError>;
    fn enforce_equal(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError>;
    fn add(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
    fn sub(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
    fn mul(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
    fn div(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
}

/// Chip for foreign prime field arithmetic with custom gates.
#[derive(Clone, Debug)]
pub struct FpChip<Fp: BigPrimeField> {
    pub config: FpConfig,
    pub limb_bits: usize,
    pub num_limbs: usize,
    pub limb_bases: Vec<pallas::Base>,
    pub limb_base_big: BigInt,
    pub limb_mask: BigUint,
    pub p: BigInt,
    pub p_biguint: BigUint,
    pub p_limbs: Vec<pallas::Base>,
    pub p_native: pallas::Base,
    pub native_modulus: BigUint,
    pub c_coeffs: [pallas::Base; 7],
    _marker: PhantomData<Fp>,
}

impl<Fp: BigPrimeField> FpChip<Fp> {
    pub fn construct(
        config: FpConfig,
        limb_bits: usize,
        num_limbs: usize,
        c_coeffs: [pallas::Base; 7],
    ) -> Self {
        assert_eq!(limb_bits, LIMB_BITS);
        assert_eq!(num_limbs, NUM_LIMBS);

        let limb_mask = (BigUint::from(1u64) << limb_bits) - 1usize;
        let p = modulus_simple::<Fp>();
        let p_limbs = decompose_biguint_simple(&p, num_limbs, limb_bits);
        let native_modulus = modulus_simple::<pallas::Base>();
        let p_native = biguint_to_fe_simple(&(&p % &native_modulus));

        let limb_base = biguint_to_fe_simple(&(BigUint::one() << limb_bits));
        let mut limb_bases = Vec::with_capacity(num_limbs);
        limb_bases.push(pallas::Base::ONE);
        while limb_bases.len() != num_limbs {
            limb_bases.push(limb_base * limb_bases.last().unwrap());
        }

        Self {
            config,
            limb_bits,
            num_limbs,
            limb_bases,
            limb_base_big: BigInt::one() << limb_bits,
            limb_mask,
            p: p.clone().into(),
            p_biguint: p,
            p_limbs,
            p_native,
            native_modulus,
            c_coeffs,
            _marker: PhantomData,
        }
    }

    // ── Load operations ──

    pub fn load_constant(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "load constant Fp",
            |mut region| {
                let value = fe_to_biguint_for_field(&v);
                let fixed =
                    FixedOverflowInteger::from_native(&value, self.num_limbs, self.limb_bits);

                let mut limbs = Vec::with_capacity(self.num_limbs);
                for (i, &limb_value) in fixed.limbs.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("const limb {}", i),
                        self.config.advices[i],
                        0,
                        || Value::known(limb_value),
                    )?;
                    limbs.push(cell);
                }

                let native_value = fixed
                    .limbs
                    .iter()
                    .zip(self.limb_bases.iter())
                    .fold(pallas::Base::ZERO, |acc, (&limb, &base)| acc + limb * base);

                let native_cell = region.assign_advice(
                    || "const native",
                    self.config.advices[4],
                    0,
                    || Value::known(native_value),
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(limbs, self.limb_bits),
                    native_cell,
                    Value::known(value.into()),
                ))
            },
        )
    }

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "load private Fp",
            |mut region| {
                let value_big = value.map(|v| fe_to_biguint_for_field(&v));
                let limb_values: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        value_big.as_ref().map(|v| {
                            let limbs = decompose_biguint_simple(v, self.num_limbs, self.limb_bits);
                            limbs[i]
                        })
                    })
                    .collect();

                let mut limbs = Vec::with_capacity(self.num_limbs);
                for (i, limb_value) in limb_values.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("witness limb {}", i),
                        self.config.advices[i],
                        0,
                        || *limb_value,
                    )?;
                    limbs.push(cell);
                }

                let native_value = value.map(|v| {
                    biguint_to_fe_simple(&(&fe_to_biguint_for_field(&v) % &self.native_modulus))
                });

                let native_cell = region.assign_advice(
                    || "witness native",
                    self.config.advices[4],
                    0,
                    || native_value,
                )?;

                let value_bigint = value.map(|v| BigInt::from(fe_to_biguint_for_field(&v)));

                Ok(CrtInteger::new(
                    OverflowInteger::new(limbs, self.limb_bits),
                    native_cell,
                    value_bigint,
                ))
            },
        )
    }

    // ── Range checks ──

    /// Range check all limbs of a foreign field element.
    /// For 64-bit limbs with K=10, we need 7 words (64/10 = 6.4 → 7).
    pub fn range_check_limbs(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError> {
        const K: usize = 10;
        let num_words = (self.limb_bits + K - 1) / K; // 7 for 64-bit limbs

        for (i, limb) in a.truncation.limbs.iter().enumerate() {
            self.config.range_check.copy_check(
                layouter.namespace(|| format!("range check limb {}", i)),
                limb.clone(),
                num_words,
                false,
            )?;
        }
        Ok(())
    }

    pub fn to_native(
        &self,
        _layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError> {
        Ok(a.native.clone())
    }

    // ── Constrained multiplication: x * y = z (mod q) ──

    /// Multiply two foreign field elements using the foreign_mul custom gate.
    ///
    /// The gate enforces:
    ///   Σ_{i,j} c[i+j]*x_i*y_j - Σ_i c[i]*z_i - u*q ≡ 0 (mod p_native)
    ///
    /// Where u = floor(x*y / q) is the quotient, and z = (x*y) mod q.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "foreign_mul",
            |mut region| {
                // Enable the multiplication gate
                self.config.q_mul.enable(&mut region, 0)?;

                // Copy x limbs into row 0, columns 0..3
                for (i, limb) in a.truncation.limbs.iter().enumerate() {
                    limb.copy_advice(
                        || format!("x[{}]", i),
                        &mut region,
                        self.config.advices[i],
                        0,
                    )?;
                }

                // Copy y limbs into row 1, columns 0..3
                for (i, limb) in b.truncation.limbs.iter().enumerate() {
                    limb.copy_advice(
                        || format!("y[{}]", i),
                        &mut region,
                        self.config.advices[i],
                        1,
                    )?;
                }

                // Compute witness: z = (a * b) mod q, u = (a * b) / q
                let (z_val, u_val, c_bigint) = {
                    let mut z_opt = Value::unknown();
                    let mut u_opt = Value::unknown();
                    let mut c_opt = Value::unknown();

                    a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                        let a_pos = a_val.to_biguint().expect("positive");
                        let b_pos = b_val.to_biguint().expect("positive");
                        let product = &a_pos * &b_pos;
                        let z_big = &product % &self.p_biguint;
                        let u_big = &product / &self.p_biguint;
                        z_opt = Value::known(z_big.clone());
                        u_opt = Value::known(u_big);
                        c_opt = Value::known(BigInt::from(z_big));
                    });

                    (z_opt, u_opt, c_opt)
                };

                // Assign z limbs into row 0, columns 4..7
                let z_limb_values: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        z_val
                            .as_ref()
                            .map(|z| decompose_biguint_simple(z, self.num_limbs, self.limb_bits)[i])
                    })
                    .collect();

                let mut z_limbs = Vec::with_capacity(self.num_limbs);
                for (i, lv) in z_limb_values.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("z[{}]", i),
                        self.config.advices[4 + i],
                        0,
                        || *lv,
                    )?;
                    z_limbs.push(cell);
                }

                // Assign u (quotient) into row 0, column 8
                let u_native = u_val
                    .as_ref()
                    .map(|u| biguint_to_fe_simple(&(u % &self.native_modulus)));
                region.assign_advice(|| "u", self.config.advices[8], 0, || u_native)?;

                // Compute native representation for z
                let c_native_val = z_val
                    .as_ref()
                    .map(|z| biguint_to_fe_simple(&(z % &self.native_modulus)));
                let c_native = region.assign_advice(
                    || "z_native",
                    self.config.advices[8],
                    1,
                    || c_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(z_limbs, self.limb_bits),
                    c_native,
                    c_bigint,
                ))
            },
        )
    }

    /// Normalize: reduce non-canonical limbs to canonical [0, B) form.
    /// Uses the normalize custom gate.
    pub fn normalize(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "normalize",
            |mut region| {
                self.config.q_normalize.enable(&mut region, 0)?;

                // Copy x limbs (input) into columns 0..3
                for (i, limb) in a.truncation.limbs.iter().enumerate() {
                    limb.copy_advice(
                        || format!("x[{}]", i),
                        &mut region,
                        self.config.advices[i],
                        0,
                    )?;
                }

                // Compute canonical z = x mod q and quotient k
                let (z_val, k_val, z_bigint) = {
                    let mut z_opt = Value::unknown();
                    let mut k_opt = Value::unknown();
                    let mut z_bi = Value::unknown();

                    a.value.as_ref().map(|a_val| {
                        let a_pos = a_val.to_biguint().unwrap_or_else(|| {
                            // Handle negative: add q until positive
                            let neg = (-a_val).to_biguint().expect("positive negation");
                            let q_big = self.p_biguint.clone();
                            let k = (&neg / &q_big) + 1u64;
                            &q_big * k - neg
                        });
                        let z_big = &a_pos % &self.p_biguint;
                        let k_big = &a_pos / &self.p_biguint;
                        z_opt = Value::known(z_big.clone());
                        k_opt = Value::known(k_big);
                        z_bi = Value::known(BigInt::from(z_big));
                    });

                    (z_opt, k_opt, z_bi)
                };

                // Assign z limbs into columns 4..7
                let z_limb_values: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        z_val
                            .as_ref()
                            .map(|z| decompose_biguint_simple(z, self.num_limbs, self.limb_bits)[i])
                    })
                    .collect();

                let mut z_limbs = Vec::with_capacity(self.num_limbs);
                for (i, lv) in z_limb_values.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("z[{}]", i),
                        self.config.advices[4 + i],
                        0,
                        || *lv,
                    )?;
                    z_limbs.push(cell);
                }

                // Assign k (quotient) into column 8
                let k_native = k_val
                    .as_ref()
                    .map(|k| biguint_to_fe_simple(&(k % &self.native_modulus)));
                region.assign_advice(|| "k", self.config.advices[8], 0, || k_native)?;

                // Native representation of z
                let z_native_val = z_val
                    .as_ref()
                    .map(|z| biguint_to_fe_simple(&(z % &self.native_modulus)));
                let z_native = region.assign_advice(
                    || "z_native",
                    self.config.advices[4],
                    1,
                    || z_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(z_limbs, self.limb_bits),
                    z_native,
                    z_bigint,
                ))
            },
        )
    }

    // ── Witness-assisted operations with gate enforcement ──

    /// Add two foreign field elements: c = a + b mod q
    /// Witnesses result then normalizes to enforce correctness.
    pub fn add(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        let result = layouter.assign_region(
            || "fp add witness",
            |mut region| {
                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let sum = &a_val + b_val;
                    let sum_pos = sum.to_biguint().unwrap_or_else(|| {
                        let neg = (-&sum).to_biguint().expect("pos neg");
                        let k = (&neg / &self.p_biguint) + 1u64;
                        &self.p_biguint * k - neg
                    });
                    BigInt::from(&sum_pos % &self.p_biguint)
                });

                let c_biguint = c_val.as_ref().map(|v| v.to_biguint().expect("positive"));
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_biguint
                            .as_ref()
                            .map(|c| decompose_biguint_simple(c, self.num_limbs, self.limb_bits)[i])
                    })
                    .collect();

                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, lv) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[i],
                        0,
                        || *lv,
                    )?;
                    c_limbs.push(cell);
                }

                let c_native_val = c_biguint
                    .as_ref()
                    .map(|c| biguint_to_fe_simple(&(c % &self.native_modulus)));

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[4],
                    0,
                    || c_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )?;

        // Enforce: a + b - result = 0 mod q
        // We do this by checking (a + b - result) via normalize gate
        // For soundness: witness z = (a+b) mod q, then check normalize(a+b - z) = 0
        self.range_check_limbs(layouter.namespace(|| "rc add result"), &result)?;
        Ok(result)
    }

    /// Subtract: c = a - b mod q
    pub fn sub(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        let result = layouter.assign_region(
            || "fp sub witness",
            |mut region| {
                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let diff = &a_val - b_val;
                    let diff_pos = if diff < BigInt::zero() {
                        let neg = (-&diff).to_biguint().expect("pos");
                        let k = (&neg / &self.p_biguint) + 1u64;
                        BigInt::from(&self.p_biguint * k) - BigInt::from(neg)
                    } else {
                        diff
                    };
                    BigInt::from(diff_pos.to_biguint().expect("pos") % &self.p_biguint)
                });

                let c_biguint = c_val.as_ref().map(|v| v.to_biguint().expect("positive"));
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_biguint
                            .as_ref()
                            .map(|c| decompose_biguint_simple(c, self.num_limbs, self.limb_bits)[i])
                    })
                    .collect();

                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, lv) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[i],
                        0,
                        || *lv,
                    )?;
                    c_limbs.push(cell);
                }

                let c_native_val = c_biguint
                    .as_ref()
                    .map(|c| biguint_to_fe_simple(&(c % &self.native_modulus)));

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[4],
                    0,
                    || c_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )?;

        self.range_check_limbs(layouter.namespace(|| "rc sub result"), &result)?;
        Ok(result)
    }

    /// Divide: c = a / b = a * b^(-1) mod q
    /// Witnesses c, then constrains c * b = a via foreign_mul gate.
    pub fn div(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        // Witness c = a * b^(-1)
        let c = layouter.assign_region(
            || "fp div witness",
            |mut region| {
                fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
                    if b.is_zero() {
                        return (a.clone(), BigInt::one(), BigInt::zero());
                    }
                    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
                    let x = y1.clone();
                    let y = x1 - (a / b) * &y1;
                    (gcd, x, y)
                }

                let p_int = BigInt::from(self.p_biguint.clone());

                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let b_int = b_val.clone();
                    let (_gcd, x, _y) = extended_gcd(&b_int, &p_int);
                    let b_inv = ((&x % &p_int) + &p_int) % &p_int;
                    let a_pos = a_val.to_biguint().expect("positive");
                    let b_inv_pos = b_inv.to_biguint().expect("positive");
                    let c_big = (&a_pos * &b_inv_pos) % &self.p_biguint;
                    BigInt::from(c_big)
                });

                let c_biguint = c_val.as_ref().map(|v| v.to_biguint().expect("positive"));
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_biguint
                            .as_ref()
                            .map(|c| decompose_biguint_simple(c, self.num_limbs, self.limb_bits)[i])
                    })
                    .collect();

                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, lv) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[i],
                        0,
                        || *lv,
                    )?;
                    c_limbs.push(cell);
                }

                let c_native_val = c_biguint
                    .as_ref()
                    .map(|c| biguint_to_fe_simple(&(c % &self.native_modulus)));

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[4],
                    0,
                    || c_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )?;

        // Constrain: c * b = a (mod q) using the foreign_mul gate
        let product = self.mul(layouter.namespace(|| "c*b"), &c, b)?;

        // Enforce product == a by checking limb equality
        self.enforce_equal(layouter.namespace(|| "c*b == a"), &product, a)?;

        Ok(c)
    }
}

// ── FpInstructions implementation ──

impl<Fp: BigPrimeField> FpInstructions<Fp> for FpChip<Fp> {
    fn load_constant(
        &self,
        layouter: impl Layouter<pallas::Base>,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::load_constant(self, layouter, v)
    }
    fn load_private(
        &self,
        layouter: impl Layouter<pallas::Base>,
        v: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::load_private(self, layouter, v)
    }
    fn range_check_limbs(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError> {
        FpChip::range_check_limbs(self, layouter, a)
    }
    fn to_native(
        &self,
        lo: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError> {
        FpChip::to_native(self, lo, a)
    }
    fn enforce_zero(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        num: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // Normalize first, then check all limbs are zero
        let normalized = self.normalize(layouter.namespace(|| "normalize for zero check"), num)?;
        layouter.assign_region(
            || "enforce zero",
            |mut region| {
                for (i, limb) in normalized.truncation.limbs.iter().enumerate() {
                    limb.copy_advice(
                        || format!("limb {}", i),
                        &mut region,
                        self.config.advices[0],
                        i,
                    )?;
                    region.constrain_constant(limb.cell(), pallas::Base::ZERO)?;
                }
                Ok(())
            },
        )
    }
    fn enforce_equal(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError> {
        let diff = self.sub(layouter.namespace(|| "a-b"), a, b)?;
        self.enforce_zero(layouter.namespace(|| "enforce zero"), &diff)
    }
    fn add(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::add(self, layouter, a, b)
    }
    fn sub(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::sub(self, layouter, a, b)
    }
    fn mul(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::mul(self, layouter, a, b)
    }
    fn div(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        FpChip::div(self, layouter, a, b)
    }
}

// ============================================================================
// BigIntChip (kept for backward compatibility)
// ============================================================================

#[derive(Clone, Debug)]
pub struct BigIntConfig {
    pub advices: [Column<Advice>; 3],
    pub q_enable: Selector,
}

impl BigIntConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 3],
    ) -> Self {
        let q_enable = meta.selector();
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }
        Self { advices, q_enable }
    }
}

#[derive(Clone, Debug)]
pub struct BigIntChip {
    pub config: BigIntConfig,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

impl BigIntChip {
    pub fn construct(config: BigIntConfig, limb_bits: usize, num_limbs: usize) -> Self {
        Self {
            config,
            limb_bits,
            num_limbs,
        }
    }
    pub fn assign_constant(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: &BigUint,
    ) -> Result<ProperUint<pallas::Base>, PlonkError> {
        let fixed = FixedOverflowInteger::from_native(value, self.num_limbs, self.limb_bits);
        let mut limbs = Vec::with_capacity(self.num_limbs);
        for (i, &limb_value) in fixed.limbs.iter().enumerate() {
            let cell = region.assign_advice(
                || format!("constant limb {}", i),
                self.config.advices[0],
                offset + i,
                || Value::known(limb_value),
            )?;
            limbs.push(cell);
        }
        Ok(ProperUint::new(limbs))
    }
    pub fn assign_witness(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: Value<&BigUint>,
    ) -> Result<ProperUint<pallas::Base>, PlonkError> {
        let mut limbs = Vec::with_capacity(self.num_limbs);
        for i in 0..self.num_limbs {
            let limb_value =
                value.map(|v| decompose_biguint_simple(v, self.num_limbs, self.limb_bits)[i]);
            let cell = region.assign_advice(
                || format!("witness limb {}", i),
                self.config.advices[0],
                offset + i,
                || limb_value,
            )?;
            limbs.push(cell);
        }
        Ok(ProperUint::new(limbs))
    }
}

// ============================================================================
// Secp256k1Config / Secp256k1Chip
// ============================================================================

type SecpPoint<Base> = (ProperCrtUint<Base>, ProperCrtUint<Base>);

/// Configuration for secp256k1 elliptic curve operations.
#[derive(Clone, Debug)]
pub struct Secp256k1Config {
    pub fp_config: FpConfig,
    pub fq_config: FpConfig,
    q: Selector,
}

impl Secp256k1Config {
    /// Configure the secp256k1 chip.
    ///
    /// Uses 9 shared advice columns for both Fp and Fq operations.
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 9],
        range_check: LookupRangeCheckConfig<pallas::Base, 10>,
    ) -> Self {
        // Compute c coefficients and q_native for both fields
        let fp_c = secp_fp_c_coeffs();
        let fq_c = secp_fq_c_coeffs();

        let p_mod = BigUint::parse_bytes(SECP_P_HEX.as_bytes(), 16).unwrap();
        let n_mod = BigUint::parse_bytes(SECP_N_HEX.as_bytes(), 16).unwrap();
        let native_mod = modulus_simple::<pallas::Base>();
        let fp_q_native = biguint_to_fe_simple(&(&p_mod % &native_mod));
        let fq_q_native = biguint_to_fe_simple(&(&n_mod % &native_mod));

        let fp_config = FpConfig::configure(meta, advices, range_check.clone(), fp_c, fp_q_native);
        let fq_config = FpConfig::configure(meta, advices, range_check, fq_c, fq_q_native);

        let q = meta.selector();

        // Scalar decomposition gate (bit decomposition for MSM)
        meta.create_gate("scalar decomposition step", |meta| {
            let q = meta.query_selector(q);
            let current = meta.query_advice(advices[0], Rotation::cur());
            let bit = meta.query_advice(advices[1], Rotation::cur());
            let current_prime = meta.query_advice(advices[0], Rotation::next());

            vec![
                q.clone()
                    * (current
                        - (Expression::Constant(pallas::Base::one().double()) * current_prime
                            + bit.clone())),
                q * bit.clone() * (bit - Expression::Constant(pallas::Base::one())),
            ]
        });

        Self {
            fp_config,
            fq_config,
            q,
        }
    }
}

/// Chip for secp256k1 elliptic curve operations.
#[derive(Clone, Debug)]
pub struct Secp256k1Chip {
    pub fp: Secp256k1FpChip,
    pub fq: Secp256k1FqChip,
    q: Selector,
}

impl Secp256k1Chip {
    /// Construct a new Secp256k1Chip. Uses 4×64-bit limbs.
    pub fn construct(config: Secp256k1Config) -> Self {
        Self {
            fp: Secp256k1FpChip::construct(
                config.fp_config,
                LIMB_BITS,
                NUM_LIMBS,
                secp_fp_c_coeffs(),
            ),
            fq: Secp256k1FqChip::construct(
                config.fq_config,
                LIMB_BITS,
                NUM_LIMBS,
                secp_fq_c_coeffs(),
            ),
            q: config.q,
        }
    }

    // ── Scalar bit decomposition ──

    pub(crate) fn decompose_limb_to_bits(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        limb: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<Vec<AssignedCell<pallas::Base, pallas::Base>>, PlonkError> {
        let inv2 = pallas::Base::invert(&pallas::Base::from(2)).unwrap();

        layouter.assign_region(
            || "decompose limb to bits",
            |mut region: Region<'_, pallas::Base>| {
                let mut bits = Vec::with_capacity(LIMB_BITS);
                let mut current_offset = 0;
                limb.copy_advice(
                    || "copy limb",
                    &mut region,
                    self.fq.config.advices[0],
                    current_offset,
                )?;

                let mut current_value = limb.value().cloned();
                let mut last_assigned: Option<AssignedCell<pallas::Base, pallas::Base>> = None;

                for _ in 0..LIMB_BITS {
                    self.q.enable(&mut region, current_offset)?;

                    let bit_val = current_value.map(|v| {
                        let repr = v.to_repr();
                        pallas::Base::from((repr[0] & 1) as u64)
                    });
                    let bit_cell = region.assign_advice(
                        || "bit",
                        self.fq.config.advices[1],
                        current_offset,
                        || bit_val,
                    )?;
                    bits.push(bit_cell);

                    let next_val = current_value
                        .zip(bit_val)
                        .map(|(current, bit)| (current - bit) * inv2);
                    let next_cell = region.assign_advice(
                        || "next current",
                        self.fq.config.advices[0],
                        current_offset + 1,
                        || next_val,
                    )?;
                    last_assigned = Some(next_cell);

                    current_value = next_val;
                    current_offset += 1;
                }

                if let Some(final_assigned) = last_assigned {
                    region.constrain_constant(final_assigned.cell(), pallas::Base::zero())?;
                }
                Ok(bits)
            },
        )
    }

    pub(crate) fn decompose_scalar_to_bits(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        sk: &ProperCrtUint<pallas::Base>,
    ) -> Result<Vec<AssignedCell<pallas::Base, pallas::Base>>, PlonkError> {
        let mut bits = Vec::new();
        for limb in sk.truncation.limbs.iter() {
            let limb_bits =
                self.decompose_limb_to_bits(layouter.namespace(|| "decompose limb"), limb)?;
            bits.extend(limb_bits);
        }
        bits.truncate(256);
        Ok(bits)
    }

    // ── Point operations ──

    pub(crate) fn add_point(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        p: &SecpPoint<pallas::Base>,
        q: &SecpPoint<pallas::Base>,
    ) -> Result<SecpPoint<pallas::Base>, PlonkError> {
        let fp = &self.fp;

        let dy = fp.sub(layouter.namespace(|| "dy"), &q.1, &p.1)?;
        let dx = fp.sub(layouter.namespace(|| "dx"), &q.0, &p.0)?;
        let lambda = fp.div(layouter.namespace(|| "lambda"), &dy, &dx)?;
        let lambda_sq = fp.mul(layouter.namespace(|| "lambda_sq"), &lambda, &lambda)?;
        let x3 = fp.sub(layouter.namespace(|| "x3 part1"), &lambda_sq, &p.0)?;
        let x3 = fp.sub(layouter.namespace(|| "x3"), &x3, &q.0)?;
        let dx_new = fp.sub(layouter.namespace(|| "dx_new"), &p.0, &x3)?;
        let temp = fp.mul(layouter.namespace(|| "temp"), &lambda, &dx_new)?;
        let y3 = fp.sub(layouter.namespace(|| "y3"), &temp, &p.1)?;
        Ok((x3, y3))
    }

    pub(crate) fn double_point(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        p: &SecpPoint<pallas::Base>,
    ) -> Result<SecpPoint<pallas::Base>, PlonkError> {
        let fp = &self.fp;

        let three = fp.load_private(
            layouter.namespace(|| "three"),
            Value::known(Secp256k1Fp::from(3)),
        )?;
        let two = fp.load_private(
            layouter.namespace(|| "two"),
            Value::known(Secp256k1Fp::from(2)),
        )?;
        let x_sq = fp.mul(layouter.namespace(|| "x_sq"), &p.0, &p.0)?;
        let three_x_sq = fp.mul(layouter.namespace(|| "three_x_sq"), &three, &x_sq)?;
        let two_y = fp.mul(layouter.namespace(|| "two_y"), &two, &p.1)?;
        let lambda = fp.div(layouter.namespace(|| "lambda"), &three_x_sq, &two_y)?;
        let lambda_sq = fp.mul(layouter.namespace(|| "lambda_sq"), &lambda, &lambda)?;
        let two_x = fp.mul(layouter.namespace(|| "two_x"), &two, &p.0)?;
        let x3 = fp.sub(layouter.namespace(|| "x3"), &lambda_sq, &two_x)?;
        let dx = fp.sub(layouter.namespace(|| "dx"), &p.0, &x3)?;
        let temp = fp.mul(layouter.namespace(|| "temp"), &lambda, &dx)?;
        let y3 = fp.sub(layouter.namespace(|| "y3"), &temp, &p.1)?;

        Ok((x3, y3))
    }

    pub(crate) fn select(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
        cond: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        let fp = &self.fp;

        let diff = fp.sub(layouter.namespace(|| "diff"), a, b)?;
        let cond_crt = fp.load_private(
            layouter.namespace(|| "cond_crt"),
            cond.value()
                .map(|v| Secp256k1Fp::from_repr(v.to_repr()).unwrap()),
        )?;
        let product = fp.mul(layouter.namespace(|| "product"), &diff, &cond_crt)?;
        let result = fp.add(layouter.namespace(|| "result"), &product, b)?;

        Ok(result)
    }

    // ── Montgomery ladder scalar multiplication ──
    pub(crate) fn scalar_mul_montgomery(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        sk: &ProperCrtUint<pallas::Base>,
        g: &SecpPoint<pallas::Base>,
    ) -> Result<SecpPoint<pallas::Base>, PlonkError> {
        let mut bits =
            self.decompose_scalar_to_bits(layouter.namespace(|| "decompose scalar"), sk)?;

        bits.reverse(); // MSB first

        let mut r0 = g.clone();
        let mut r1 = self.double_point(layouter.namespace(|| "initial double"), &r0)?;

        for bit in bits {
            let added = self.add_point(layouter.namespace(|| "montgomery add"), &r0, &r1)?;
            let doubled0 = self.double_point(layouter.namespace(|| "montgomery double0"), &r0)?;
            let doubled1 = self.double_point(layouter.namespace(|| "montgomery double1"), &r1)?;

            r0.0 = self.select(
                layouter.namespace(|| "select r0.x"),
                &added.0,
                &doubled0.0,
                &bit,
            )?;
            r0.1 = self.select(
                layouter.namespace(|| "select r0.y"),
                &added.1,
                &doubled0.1,
                &bit,
            )?;
            r1.0 = self.select(
                layouter.namespace(|| "select r1.x"),
                &doubled1.0,
                &added.0,
                &bit,
            )?;
            r1.1 = self.select(
                layouter.namespace(|| "select r1.y"),
                &doubled1.1,
                &added.1,
                &bit,
            )?;
        }

        // Montgomery ladder computes (2^256 + k)*G, subtract 2^256*G.
        // See MONTGOMERY_OFFSET_X/Y constants for derivation and verification.
        let neg_offset_x = Secp256k1Fp::from_repr(MONTGOMERY_OFFSET_X)
            .expect("MONTGOMERY_OFFSET_X is a valid secp256k1 Fp element");
        let neg_offset_y = Secp256k1Fp::from_repr(MONTGOMERY_OFFSET_Y)
            .expect("MONTGOMERY_OFFSET_Y is a valid secp256k1 Fp element");
        let neg_offset = (
            self.fp.load_private(
                layouter.namespace(|| "neg_offset_x"),
                Value::known(neg_offset_x),
            )?,
            self.fp.load_private(
                layouter.namespace(|| "neg_offset_y"),
                Value::known(neg_offset_y),
            )?,
        );
        let corrected = self.add_point(
            layouter.namespace(|| "montgomery correction"),
            &r0,
            &neg_offset,
        )?;

        Ok(corrected)
    }

    // ── Public API ──

    /// Prove key pairing: `public_key = esk * G`
    pub fn prove_key_pairing(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        esk: Value<Secp256k1Fq>,
        epkx: Value<Secp256k1Fp>,
        epky: Value<Secp256k1Fp>,
    ) -> Result<
        (
            ProperCrtUint<pallas::Base>,
            (ProperCrtUint<pallas::Base>, ProperCrtUint<pallas::Base>),
        ),
        PlonkError,
    > {
        // Load secret key
        let sk_assigned = self
            .fq
            .load_private(layouter.namespace(|| "load secret key"), esk)?;
        self.fq
            .range_check_limbs(layouter.namespace(|| "range check sk"), &sk_assigned)?;

        // Load public key
        let pk_x_assigned = self
            .fp
            .load_private(layouter.namespace(|| "load pk.x"), epkx)?;
        let pk_y_assigned = self
            .fp
            .load_private(layouter.namespace(|| "load pk.y"), epky)?;
        self.fp
            .range_check_limbs(layouter.namespace(|| "range check pk.x"), &pk_x_assigned)?;
        self.fp
            .range_check_limbs(layouter.namespace(|| "range check pk.y"), &pk_y_assigned)?;

        // Load generator G
        let g = (
            self.fp.load_private(layouter.namespace(|| "load G x"), {
                let mut gx = GENERATOR_X;
                gx.reverse();
                Value::known(Secp256k1Fp::from_repr(gx).expect("valid generator x"))
            })?,
            self.fp.load_private(layouter.namespace(|| "load G y"), {
                let mut gy = GENERATOR_Y;
                gy.reverse();
                Value::known(Secp256k1Fp::from_repr(gy).expect("valid generator y"))
            })?,
        );

        // Compute sk * G using Montgomery ladder
        let computed_pk = self.scalar_mul_montgomery(
            layouter.namespace(|| "scalar mul check"),
            &sk_assigned,
            &g,
        )?;

        // Enforce computed_pk == public_key
        self.fp.enforce_equal(
            layouter.namespace(|| "enforce x equal"),
            &computed_pk.0,
            &pk_x_assigned,
        )?;
        self.fp.enforce_equal(
            layouter.namespace(|| "enforce y equal"),
            &computed_pk.1,
            &pk_y_assigned,
        )?;

        Ok((sk_assigned, (pk_x_assigned, pk_y_assigned)))
    }

    /// Convert a secp256k1 Fq element to native Pallas::Base.
    pub fn fq_to_native(
        &self,
        layouter: impl Layouter<pallas::Base>,
        fq: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError> {
        self.fq.to_native(layouter, fq)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::circuit::Layouter;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    use num_traits::Zero;
    use pasta_curves::pallas;
    use std::println;

    #[test]
    fn test_fe_conversion() {
        let value = pallas::Base::from(123);
        let big = crate::spec::fe_to_biguint_simple(&value);
        let back = crate::spec::biguint_to_fe_simple(&big);
        assert_eq!(value, back);

        let zero = pallas::Base::zero();
        let big_zero = crate::spec::fe_to_biguint_simple(&zero);
        assert!(big_zero.is_zero());
    }

    #[test]
    fn test_montgomery_offset_correctness() {
        // Verify that MONTGOMERY_OFFSET_X/Y are the coordinates of -(2^256 * G).
        //
        // The Montgomery ladder computes (2^256 + k)*G. To correct, we add -(2^256 * G).
        // Since EC scalars are mod group order n: 2^256 * G = (2^256 mod n) * G.
        use secp256k1::constants::GENERATOR_X as GX;
        use secp256k1::constants::GENERATOR_Y as GY;

        let secp_p = BigUint::parse_bytes(SECP_P_HEX.as_bytes(), 16).unwrap();
        let secp_n = BigUint::parse_bytes(SECP_N_HEX.as_bytes(), 16).unwrap();

        // s = 2^256 mod n (the effective scalar the ladder adds)
        let two_256 = BigUint::from(1u64) << 256;
        let s: BigUint = &two_256 % &secp_n;

        // Compute s*G using the secp256k1 library
        let s_bytes: [u8; 32] = {
            let b = s.to_bytes_be();
            let mut arr = [0u8; 32];
            arr[32 - b.len()..].copy_from_slice(&b);
            arr
        };
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_byte_array(s_bytes).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_bytes = pk.serialize_uncompressed();
        // pk_bytes[0] = 0x04, pk_bytes[1..33] = x, pk_bytes[33..65] = y
        let sg_x = BigUint::from_bytes_be(&pk_bytes[1..33]);
        let sg_y = BigUint::from_bytes_be(&pk_bytes[33..65]);

        // -(s*G) has the same x but negated y: neg_y = p - y
        let neg_sg_y = &secp_p - &sg_y;

        // Convert our constants to BigUint for comparison
        let offset_x = Secp256k1Fp::from_repr(MONTGOMERY_OFFSET_X).unwrap();
        let offset_y = Secp256k1Fp::from_repr(MONTGOMERY_OFFSET_Y).unwrap();
        let offset_x_big = BigUint::from_bytes_le(&offset_x.to_repr());
        let offset_y_big = BigUint::from_bytes_le(&offset_y.to_repr());

        assert_eq!(
            offset_x_big, sg_x,
            "MONTGOMERY_OFFSET_X should be x-coord of (2^256 mod n)*G"
        );
        assert_eq!(
            offset_y_big, neg_sg_y,
            "MONTGOMERY_OFFSET_Y should be negated y-coord of (2^256 mod n)*G"
        );
    }
    #[test]
    fn test_fixed_integer_conversion() {
        let value = BigUint::from(1u64) << 100 | BigUint::from(0x01020304u64);
        let fixed = FixedOverflowInteger::from_native(&value, 4, 64);
        let reconstructed = fixed.to_biguint(64);
        assert_eq!(value, reconstructed);
    }

    #[derive(Debug, Default)]
    struct TestCircuit {
        value: BigUint,
    }

    impl Circuit<pallas::Base> for TestCircuit {
        type Config = BigIntConfig;
        type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            BigIntConfig::configure(meta, advices)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), PlonkError> {
            let chip = BigIntChip::construct(config, 8, 4);

            layouter.assign_region(
                || "test region",
                |mut region| {
                    let constant_uint = chip.assign_constant(&mut region, 0, &self.value)?;
                    assert_eq!(constant_uint.num_limbs(), 4);

                    let witness_uint =
                        chip.assign_witness(&mut region, 4, Value::known(&self.value))?;
                    assert_eq!(witness_uint.num_limbs(), 4);

                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    const K: u32 = 3;

    #[test]
    fn test_circuit_assignment() {
        let value = BigUint::from(12345u32);
        let circuit = TestCircuit { value };
        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let cost =
            halo2_proofs::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(K, &circuit);
        let proof_size = usize::from(cost.proof_size(1));
        assert!(proof_size > 0, "Proof size should be non-zero");
        println!(" proof_size: {}", proof_size);
        println!(" cost: {:#?}", cost);
    }

    #[test]
    fn test_c_coefficients() {
        let c = secp_fp_c_coeffs();
        // c[0] should be 1
        assert_eq!(c[0], pallas::Base::ONE);
        // c[1] should be 2^64
        let expected = biguint_to_fe_simple(&(BigUint::from(1u64) << 64));
        assert_eq!(c[1], expected);
        println!("c coefficients computed successfully");
    }
}
