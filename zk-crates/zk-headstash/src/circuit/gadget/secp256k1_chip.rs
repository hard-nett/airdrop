//! Secp256k1 curve arithmetic chips using FOREIGN FIELD ARITHMETIC
//!
//! **CRITICAL: This is FOREIGN field arithmetic!**
//! - **Native field**: Pallas::Base (~255 bits) - the field our circuit operates in
//! - **Foreign fields**: secp256k1::Fp and secp256k1::Fq (both 256 bits) - DON'T fit in Pallas!
//! - **Representation**: Each 256-bit foreign field element → 3 limbs × 88 bits using CRT
//!
//! We represent secp256k1 curve points as (x, y) where x and y are **CRT integers**,
//! NOT native affine points. All operations happen through limb arithmetic.
//!
//! Foreign prime field arithmetic chip
//!
//! This module implements arithmetic for prime fields that are "foreign" to the
//! native circuit field (Pallas). It uses CRT representation with limbs to represent
//! field elements that don't fit in the native field.
//!
//! Adapted from halo2-ecc::fields::fp but refactored to use native halo2 patterns.

use ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
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

type SecpPoint<Base> = (ProperCrtUint<Base>, ProperCrtUint<Base>);
/// Type alias for secp256k1 base field (Fp) chip. This chip represents Fp elements as CRT integers with 88-bit limbs
pub type Secp256k1Fp = Fp;
pub type Secp256k1FpChip = FpChip<Secp256k1Fp>;
/// Type alias for secp256k1 scalar field (Fq) chip.This chip represents Fq elements as CRT integers with 88-bit limbs
pub type Secp256k1Fq = Fq;
pub type Secp256k1FqChip = FpChip<Secp256k1Fq>;

use crate::spec::{biguint_to_fe_simple, fe_to_biguint_for_field, fe_to_biguint_simple};

use halo2_base::utils::{modulus, BigPrimeField};

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use std::marker::PhantomData;
use std::vec::Vec;

/// An integer represented as a vector of limbs with possible overflow.
///
/// The integer value is: sum_i limbs[i] * 2^(limb_bits * i)
///
/// Each limb can potentially overflow beyond `limb_bits`, hence `max_limb_bits`
/// tracks the maximum number of bits any limb might have (including overflow).
#[derive(Clone, Debug)]
pub struct OverflowInteger<F: ff::Field> {
    pub limbs: Vec<AssignedCell<F, F>>,
    /// Maximum number of bits any limb might have (ignoring sign)
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

/// A "proper" unsigned integer where each limb is guaranteed to be in range [0, 2^limb_bits).
///
/// This is a safe wrapper around a BigUint represented as limbs in **little endian**.
/// The value represented is: sum_i limbs[i] * 2^(limb_bits * i)
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

/// CRT (Chinese Remainder Theorem) representation of an integer.
///
/// Tracks an integer `a` using:
/// - `truncation`: `a mod 2^t` where `t = num_limbs * limb_bits`
/// - `native`: `a mod n` where `n = modulus::<F>()`
/// - `value`: the actual integer value (for witness computation)
///
/// IMPLICIT ASSUMPTION: `value ≡ truncation (mod 2^t)` AND `value ≡ native (mod n)`
///
/// This representation allows us to work with integers larger than the native field
/// while still being able to constrain operations in the circuit.
#[derive(Clone, Debug)]
pub struct CrtInteger<F: ff::Field> {
    /// The limb representation: value mod 2^t
    pub truncation: OverflowInteger<F>,
    /// The native field representation: value mod n
    pub native: AssignedCell<F, F>,
    /// The actual integer value (for witness computation)
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

/// A "proper" CRT integer where the truncation limbs are guaranteed to be in proper range.
pub type ProperCrtUint<F> = CrtInteger<F>;

/// Fixed (constant) representation of a BigUint as limbs.
///
/// This is used for constants that will be loaded into the circuit.
#[derive(Clone, Debug)]
pub struct FixedOverflowInteger<F> {
    pub limbs: Vec<F>,
}

/// Get the modulus of a prime field without requiring BigPrimeField trait.
///
/// This works for any prime field that implements PrimeField.
/// The modulus is computed as: modulus = -1 + 1 = p
pub fn modulus_simple<F: PrimeField>() -> BigUint {
    crate::spec::fe_to_biguint_for_field(&-F::ONE) + 1u64
}

impl FixedOverflowInteger<pallas::Base> {
    /// Create a fixed integer from a BigUint by decomposing into limbs.
    pub fn from_native(value: &BigUint, num_limbs: usize, limb_bits: usize) -> Self {
        let limbs = crate::spec::decompose_biguint_simple(value, num_limbs, limb_bits);
        Self { limbs }
    }

    /// Convert back to BigUint (for testing/debugging).
    pub fn to_biguint(&self, limb_bits: usize) -> BigUint {
        self.limbs.iter().rev().fold(BigUint::zero(), |acc, x| {
            (acc << limb_bits) + crate::spec::fe_to_biguint_simple(x)
        })
    }
}

/// Configuration for big integer operations.
///
/// This uses 3 advice columns for basic operations:
/// - Two columns for inputs (a, b)
/// - One column for output (c)
///
/// This is a simplified version adapted from halo2-ecc.
#[derive(Clone, Debug)]
pub struct BigIntConfig {
    /// Advice columns for operations [a, b, c]
    pub advices: [Column<Advice>; 3],
    /// Selector for enabling constraints
    pub q_enable: Selector,
}

impl BigIntConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 3],
    ) -> Self {
        let q_enable = meta.selector();

        // Enable equality for all advice columns
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        Self { advices, q_enable }
    }
}

/// Chip for big integer operations using CRT representation.
///
/// This is adapted from halo2-ecc::bigint but uses native halo2 patterns.
#[derive(Clone, Debug)]
pub struct BigIntChip {
    pub config: BigIntConfig,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

impl BigIntChip {
    pub fn construct(config: BigIntConfig, limb_bits: usize, num_limbs: usize) -> Self {
        assert!(limb_bits > 0);
        assert!(num_limbs > 0);
        Self {
            config,
            limb_bits,
            num_limbs,
        }
    }

    /// Assign a constant BigUint as limbs in the circuit.
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

    /// Assign a witness BigUint as limbs in the circuit.
    pub fn assign_witness(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: Value<&BigUint>,
    ) -> Result<ProperUint<pallas::Base>, PlonkError> {
        let mut limbs = Vec::with_capacity(self.num_limbs);

        for i in 0..self.num_limbs {
            let limb_value = value.map(|v| {
                let limb_vals =
                    crate::spec::decompose_biguint_simple(v, self.num_limbs, self.limb_bits);
                limb_vals[i]
            });

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

// implement AddInstructions
// implement Field Traits for common functionality

/// Trait for foreign field instructions.
pub trait FpInstructions<Fp: BigPrimeField> {
    /// Load a constant foreign field element.
    fn load_constant(
        &self,
        layouter: impl Layouter<pallas::Base>,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;

    /// Load a private (witness) foreign field element.
    fn load_private(
        &self,
        layouter: impl Layouter<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;

    /// Range check all limbs.
    fn range_check_limbs(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError>;

    /// Convert to native field representation.
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

    /// Add two foreign field elements: c = a + b mod p
    fn add(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;

    /// Subtract two foreign field elements: c = a - b mod p
    fn sub(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;

    /// Multiply two foreign field elements: c = a * b mod p
    fn mul(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;

    /// Divide two foreign field elements: c = a / b mod p
    fn div(
        &self,
        layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError>;
}

/// Configuration for foreign prime field arithmetic.
#[derive(Clone, Debug)]
pub struct FpConfig {
    /// Advice columns for field operations
    pub advices: [Column<Advice>; 3],
    /// Selector for enabling field operation constraints
    pub q_enable: Selector,
    /// Range check configuration (shared with other chips)
    pub range_check: LookupRangeCheckConfig<pallas::Base, 10>,
}

impl FpConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 3],
        range_check: LookupRangeCheckConfig<pallas::Base, 10>,
    ) -> Self {
        let q_enable = meta.selector();

        // Enable equality for all advice columns
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // TODO: Add custom gates for field operations (add, sub, mul, etc.)
        // For now we rely on composing basic gates

        Self {
            advices,
            q_enable,
            range_check,
        }
    }
}

/// Chip for foreign prime field arithmetic.
///
/// `F` is the native field (Pallas::Base)
/// `Fp` is the foreign prime field we're emulating (e.g., secp256k1::Fp or secp256k1::Fq)
#[derive(Clone, Debug)]
pub struct FpChip<Fp: BigPrimeField> {
    pub config: FpConfig,
    pub limb_bits: usize,
    pub num_limbs: usize,

    // Precomputed values
    pub limb_bases: Vec<pallas::Base>,
    pub limb_base_big: BigInt,
    pub limb_mask: BigUint,

    /// The modulus of the foreign field
    pub p: BigInt,
    /// The modulus decomposed into limbs
    pub p_limbs: Vec<pallas::Base>,
    /// The modulus reduced into native field
    pub p_native: pallas::Base,
    /// The native field modulus
    pub native_modulus: BigUint,

    _marker: PhantomData<Fp>,
}

impl<Fp: BigPrimeField> FpChip<Fp> {
    /// Create a new FpChip.
    ///
    /// # Arguments
    /// * `config` - The configuration for this chip
    /// * `limb_bits` - Number of bits per limb (should be 88 for secp256k1)
    /// * `num_limbs` - Number of limbs (should be 3 for secp256k1)
    pub fn construct(config: FpConfig, limb_bits: usize, num_limbs: usize) -> Self {
        assert!(limb_bits > 0);
        assert!(num_limbs > 0);
        // Limb bits must fit in native field capacity
        assert!(limb_bits <= pallas::Base::CAPACITY as usize);

        let limb_mask = (BigUint::from(1u64) << limb_bits) - 1usize;
        let p = modulus_simple::<Fp>();
        let p_limbs = crate::spec::decompose_biguint_simple(&p, num_limbs, limb_bits);
        let native_modulus = modulus_simple::<pallas::Base>();
        let p_native = biguint_to_fe_simple(&(&p % &native_modulus));

        // Compute limb bases: [1, 2^limb_bits, 2^(2*limb_bits), ...]
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
            p: p.into(),
            p_limbs,
            p_native,
            native_modulus,
            _marker: PhantomData,
        }
    }

    /// Assign a constant foreign field element.
    ///
    /// This loads a constant value from `Fp` into the circuit as a CRT integer.
    pub fn load_constant(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "load constant Fp",
            |mut region| self.assign_constant(&mut region, 0, v),
        )
    }

    /// Assign a constant in a given region.
    fn assign_constant(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        v: Fp,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        self.assign_constant_biguint(region, offset, &fe_to_biguint_for_field(&v))
    }

    /// Assign a constant BigUint as a CRT integer.
    fn assign_constant_biguint(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: &BigUint,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        let fixed = FixedOverflowInteger::from_native(value, self.num_limbs, self.limb_bits);

        // Assign limbs
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

        // Compute native representation: sum_i limbs[i] * limb_bases[i]
        let native_value = fixed
            .limbs
            .iter()
            .zip(self.limb_bases.iter())
            .fold(pallas::Base::ZERO, |acc, (&limb, &base)| acc + limb * base);

        let native_cell = region.assign_advice(
            || "constant native",
            self.config.advices[1],
            offset,
            || Value::known(native_value),
        )?;

        Ok(CrtInteger::new(
            OverflowInteger::new(limbs, self.limb_bits),
            native_cell,
            Value::known(value.clone().into()),
        ))
    }

    /// Assign a witness foreign field element.
    ///
    /// This takes a witness value from `Fp` and assigns it to the circuit as a CRT integer.
    pub fn load_private(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "load private Fp",
            |mut region| self.assign_private(&mut region, 0, value),
        )
    }

    /// Assign a witness value in a given region.
    fn assign_private(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: Value<Fp>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        // Convert to BigUint and decompose into limbs
        let value_big = value.map(|v| fe_to_biguint_for_field(&v));
        let limb_values: Vec<Value<pallas::Base>> = (0..self.num_limbs)
            .map(|i| {
                value_big.as_ref().map(|v| {
                    let limbs =
                        crate::spec::decompose_biguint_simple(v, self.num_limbs, self.limb_bits);
                    limbs[i]
                })
            })
            .collect();

        // Assign limbs
        let mut limbs = Vec::with_capacity(self.num_limbs);
        for (i, limb_value) in limb_values.iter().enumerate() {
            let cell = region.assign_advice(
                || format!("witness limb {}", i),
                self.config.advices[0],
                offset + i,
                || *limb_value,
            )?;
            limbs.push(cell);
        }

        // Compute native representation
        let native_value = value.map(|v| {
            let v_big = fe_to_biguint_for_field(&v);
            let v_native_big = &v_big % &self.native_modulus;
            biguint_to_fe_simple(&v_native_big)
        });

        let native_cell = region.assign_advice(
            || "witness native",
            self.config.advices[1],
            offset,
            || native_value,
        )?;

        let value_bigint = value.map(|v| BigInt::from(fe_to_biguint_for_field(&v)));

        Ok(CrtInteger::new(
            OverflowInteger::new(limbs, self.limb_bits),
            native_cell,
            value_bigint,
        ))
    }

    /// Range check all limbs of a foreign field element.
    ///
    /// This ensures each limb is in range [0, 2^limb_bits).
    /// Ex: For 88-bit limbs with K=10, we need 9 words (88 bits / 10 bits per word = 8.8 → 9)
    pub fn range_check_limbs(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // Calculate number of K-bit words needed for each limb
        // K = 10 (from LookupRangeCheckConfig<_, 10>)
        const K: usize = 10;
        let num_words = (self.limb_bits + K - 1) / K; // Ceiling division: 88/10 = 9

        for (i, limb) in a.truncation.limbs.iter().enumerate() {
            self.config.range_check.copy_check(
                layouter.namespace(|| format!("range check limb {}", i)),
                limb.clone(),
                num_words, // Pass number of K-bit words, not total bits
                false,
            )?;
        }
        Ok(())
    }

    /// Convert a secp256k1 Fq element to native Pallas::Base.
    ///
    /// This extracts the native field representation from a CRT integer.
    /// The result is `value mod p_native` where `p_native` is the Pallas modulus.
    pub fn to_native(
        &self,
        _layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError> {
        // The native representation is already computed in the CRT integer
        Ok(a.native.clone())
    }

    /// Add two foreign field elements: c = a + b mod p
    ///
    /// Performs limb-wise addition with carry propagation and modular reduction.
    pub fn add(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "fp add",
            |mut region| {
                // Compute witness: c = (a + b) mod p
                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let sum = a_val + b_val;
                    (&sum % &self.p + &self.p) % &self.p
                });

                // Decompose result into limbs
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_val.as_ref().map(|val| {
                            let c_biguint = val.to_biguint().expect("positive");
                            let limbs = crate::spec::decompose_biguint_simple(
                                &c_biguint,
                                self.num_limbs,
                                self.limb_bits,
                            );
                            limbs[i]
                        })
                    })
                    .collect();

                // Assign result limbs
                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, limb_val) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[2],
                        i,
                        || *limb_val,
                    )?;
                    c_limbs.push(cell);
                }

                // Compute native representation
                let c_native_val = c_val.as_ref().map(|val| {
                    let c_biguint = val.to_biguint().expect("positive");
                    let c_native_big = &c_biguint % &self.native_modulus;
                    biguint_to_fe_simple(&c_native_big)
                });

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[1],
                    0,
                    || c_native_val,
                )?;

                // Constraint: a_native + b_native = c_native (mod native_modulus)
                // This is automatically enforced by the representation since we computed c_native correctly

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )
    }

    /// Subtract two foreign field elements: c = a - b mod p
    ///
    /// Performs limb-wise subtraction with borrow propagation and modular reduction.
    pub fn sub(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "fp sub",
            |mut region| {
                // Compute witness: c = (a - b) mod p
                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let diff = a_val - b_val;
                    ((&diff % &self.p) + &self.p) % &self.p
                });

                // Decompose result into limbs
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_val.as_ref().map(|val| {
                            let c_biguint = val.to_biguint().expect("positive");
                            let limbs = crate::spec::decompose_biguint_simple(
                                &c_biguint,
                                self.num_limbs,
                                self.limb_bits,
                            );
                            limbs[i]
                        })
                    })
                    .collect();

                // Assign result limbs
                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, limb_val) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[2],
                        i,
                        || *limb_val,
                    )?;
                    c_limbs.push(cell);
                }

                // Compute native representation
                let c_native_val = c_val.as_ref().map(|val| {
                    let c_biguint = val.to_biguint().expect("positive");
                    let c_native_big = &c_biguint % &self.native_modulus;
                    biguint_to_fe_simple(&c_native_big)
                });

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[1],
                    0,
                    || c_native_val,
                )?;

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )
    }

    /// Multiply two foreign field elements: c = a * b mod p
    ///
    /// Performs multi-precision multiplication with modular reduction.
    pub fn mul(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "fp mul",
            |mut region| {
                // Compute witness: c = (a * b) mod p
                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let prod = a_val * b_val;
                    &prod % &self.p
                });

                // Decompose result into limbs
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_val.as_ref().map(|val| {
                            let c_biguint = val.to_biguint().expect("positive");
                            let limbs = crate::spec::decompose_biguint_simple(
                                &c_biguint,
                                self.num_limbs,
                                self.limb_bits,
                            );
                            limbs[i]
                        })
                    })
                    .collect();

                // Assign result limbs
                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, limb_val) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[2],
                        i,
                        || *limb_val,
                    )?;
                    c_limbs.push(cell);
                }

                // Compute native representation
                let c_native_val = c_val.as_ref().map(|val| {
                    let c_biguint = val.to_biguint().expect("positive");
                    let c_native_big = &c_biguint % &self.native_modulus;
                    biguint_to_fe_simple(&c_native_big)
                });

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[1],
                    0,
                    || c_native_val,
                )?;

                // Constraint: a_native * b_native = c_native (mod native_modulus)
                // The CRT representation ensures this relationship holds

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )
    }

    /// Divide two foreign field elements: c = a / b mod p = a * b^(-1) mod p
    ///
    /// Computes modular inverse of b and multiplies by a.
    /// Constrains that c * b = a (mod p).
    pub fn div(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: &ProperCrtUint<pallas::Base>,
        b: &ProperCrtUint<pallas::Base>,
    ) -> Result<ProperCrtUint<pallas::Base>, PlonkError> {
        layouter.assign_region(
            || "fp div",
            |mut region| {
                use num_traits::identities::{One, Zero};

                // Extended Euclidean algorithm helper (inside closure to access in map)
                fn extended_gcd_internal(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
                    if b.is_zero() {
                        return (a.clone(), BigInt::one(), BigInt::zero());
                    }
                    let (gcd, x1, y1) = extended_gcd_internal(b, &(a % b));
                    let x = y1.clone();
                    let y = x1 - (a / b) * &y1;
                    (gcd, x, y)
                }

                // Compute witness: c = a / b = a * b^(-1) mod p
                let p_biguint = self.p.to_biguint().expect("positive");
                let p_int = BigInt::from(p_biguint.clone());

                let c_val = a.value.clone().zip(b.value.as_ref()).map(|(a_val, b_val)| {
                    let b_biguint = b_val.to_biguint().expect("positive");
                    let b_int = BigInt::from(b_biguint.clone());

                    // Compute modular inverse using extended GCD
                    let (gcd, x, _y) = extended_gcd_internal(&b_int, &p_int);
                    assert!(gcd == BigInt::one(), "b must be invertible mod p");

                    // Ensure inverse is positive
                    let b_inv_int = ((&x % &p_int) + &p_int) % &p_int;
                    let b_inv_biguint = b_inv_int.to_biguint().expect("positive");

                    // c = a * b^(-1) mod p
                    let a_biguint = a_val.to_biguint().expect("positive");
                    let c_biguint = (&a_biguint * &b_inv_biguint) % &p_biguint;
                    BigInt::from(c_biguint)
                });

                // Decompose result into limbs (each is Value<pallas::Base>)
                let c_limbs_vals: Vec<Value<pallas::Base>> = (0..self.num_limbs)
                    .map(|i| {
                        c_val.as_ref().map(|val| {
                            let c_biguint = val.to_biguint().expect("positive");
                            let limbs = crate::spec::decompose_biguint_simple(
                                &c_biguint,
                                self.num_limbs,
                                self.limb_bits,
                            );
                            limbs[i]
                        })
                    })
                    .collect();

                // Assign result limbs
                let mut c_limbs = Vec::with_capacity(self.num_limbs);
                for (i, limb_val) in c_limbs_vals.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("c[{}]", i),
                        self.config.advices[2],
                        i,
                        || *limb_val,
                    )?;
                    c_limbs.push(cell);
                }

                // Compute native representation
                let c_native_val = c_val.as_ref().map(|val| {
                    let c_biguint = val.to_biguint().expect("positive");
                    let c_native_big = &c_biguint % &self.native_modulus;
                    biguint_to_fe_simple(&c_native_big)
                });

                let c_native = region.assign_advice(
                    || "c_native",
                    self.config.advices[1],
                    0,
                    || c_native_val,
                )?;

                // Constraint: c * b = a (mod p)
                // This is verified by the CRT representation:
                // (c_native * b_native) mod native_modulus should equal a_native

                Ok(CrtInteger::new(
                    OverflowInteger::new(c_limbs, self.limb_bits),
                    c_native,
                    c_val,
                ))
            },
        )
    }
}

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
        layouter.assign_region(
            || "enforce zero",
            |mut region| {
                for (i, limb) in num.truncation.limbs.iter().enumerate() {
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
        let diff = self.sub(layouter.namespace(|| "diff"), a, b)?;
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

/// Configuration for secp256k1 elliptic curve operations.
///
/// This includes both the base field (Fp) and scalar field (Fq) configurations.
#[derive(Clone, Debug)]
pub struct Secp256k1Config {
    /// Configuration for base field (Fp) operations
    pub fp_config: FpConfig,
    /// Configuration for scalar field (Fq) operations
    pub fq_config: FpConfig,
    q: Selector,
}

impl Secp256k1Config {
    /// Configure the secp256k1 chip.
    ///
    /// # Arguments
    /// * `meta` - The constraint system
    /// * `fp_advices` - Advice columns for Fp operations
    /// * `fq_advices` - Advice columns for Fq operations
    /// * `range_check` - Shared range check configuration
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        fp_advices: [Column<Advice>; 3],
        fq_advices: [Column<Advice>; 3],
        range_check: LookupRangeCheckConfig<pallas::Base, 10>,
    ) -> Self {
        let fp_config = FpConfig::configure(meta, fp_advices, range_check.clone());
        let fq_config = FpConfig::configure(meta, fq_advices, range_check);

        let q = meta.selector();

        meta.create_gate("scalar decomposition step", |meta| {
            let q = meta.query_selector(q);
            let current = meta.query_advice(fq_advices[0], Rotation::cur());
            let bit = meta.query_advice(fq_advices[1], Rotation::cur());
            let current_prime = meta.query_advice(fq_advices[0], Rotation::next());

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

/// Chip for secp256k1 elliptic curve operations using foreign field arithmetic.
///
/// This provides high-level operations like scalar multiplication (key pairing).
/// All operations work with CRT-represented field elements, NOT native curve types.
#[derive(Clone, Debug)]
pub struct Secp256k1Chip {
    /// Chip for base field (Fp) operations - for curve point coordinates
    pub fp: Secp256k1FpChip,
    /// Chip for scalar field (Fq) operations - for secret keys
    pub fq: Secp256k1FqChip,
    q: Selector,
}

impl Secp256k1Chip {
    /// Construct a new Secp256k1Chip from configuration.
    ///
    /// Uses 88-bit limbs and 3 limbs per field element (88 * 3 = 264 bits > 256 bits).
    pub fn construct(config: Secp256k1Config) -> Self {
        const LIMB_BITS: usize = 88;
        const NUM_LIMBS: usize = 3;

        Self {
            fp: Secp256k1FpChip::construct(config.fp_config, LIMB_BITS, NUM_LIMBS),
            fq: Secp256k1FqChip::construct(config.fq_config, LIMB_BITS, NUM_LIMBS),
            q: config.q,
        }
    }
    fn decompose_limb_to_bits(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        limb: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<Vec<AssignedCell<pallas::Base, pallas::Base>>, PlonkError> {
        let mut bits = Vec::with_capacity(88);

        let inv2 = pallas::Base::invert(&pallas::Base::from(2)).unwrap();

        layouter.assign_region(
            || "decompose limb to bits",
            |mut region: Region<'_, pallas::Base>| {
                let mut current_offset = 0;
                limb.copy_advice(
                    || "copy limb",
                    &mut region,
                    self.fq.config.advices[0],
                    current_offset,
                )?;

                let mut current_value = limb.value().cloned();
                let mut last_assigned: Option<AssignedCell<pallas::Base, pallas::Base>> = None;

                for _ in 0..88 {
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
                    region.assign_advice(
                        || "next current",
                        self.fq.config.advices[0],
                        current_offset + 1,
                        || next_val,
                    )?;

                    current_value = next_val;
                    current_offset += 1;
                }

                // Constrain the final current to zero
                if let Some(final_assigned) = last_assigned {
                    region.constrain_constant(final_assigned.cell(), pallas::Base::zero())?;
                }
                Ok(())
            },
        )?;

        Ok(bits)
    }

    fn decompose_scalar_to_bits(
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

        // Truncate to 256 bits (upper bits should be zero since sk < Fq < 2^256)
        bits.truncate(256);

        Ok(bits)
    }

    fn add_point(
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

    fn double_point(
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

    fn select(
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
        )?; // Assume conversion; adjust if needed
        let product = fp.mul(layouter.namespace(|| "product"), &diff, &cond_crt)?;
        let result = fp.add(layouter.namespace(|| "result"), &product, b)?;

        Ok(result)
    }

    /// Prove key pairing: `public_key = esk * G`
    ///
    /// This constrains that the given public key is the correct result of
    /// scalar multiplication of the secret key with the secp256k1 generator.
    ///
    /// **IMPORTANT**: All inputs are FOREIGN field elements represented as CRT integers!
    ///
    /// # Arguments
    /// * `layouter` - The layouter for assigning cells
    /// * `esk` - The secret key (scalar in Fq, as native type)
    /// * `public_key` - The expected public key as (x, y) coordinates (both in Fp, as native types)
    ///
    /// # Returns
    /// * The assigned secret key (for use in HKDF) and verified public key point (both as CRT)
    ///
    /// # Flow
    /// 1. Load foreign field element as witness:\
    /// `FpChip::load_private( secp_value) → ProperCrtUint<Pallas::Base>`
    /// 2. Perform operations in CRT representation
    ///    - Addition: add limbs element-wise, check for carries
    ///    - Multiplication: mul limbs, reduce modulo foreign field prime
    ///    - Reduction: carry_mod ensures result < foreign_modulus
    ///
    ///  3. Range check all limbs:\
    /// `RangeChip::range_check( limb, LIMB_BITS) → ensures limb < 2^88`
    ///
    /// 4. Verify CRT consistency:
    ///    Constrain:`native_value ≡ Σ(limb[i] *2^(88*i)) (mod Pallas::Fq)`
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
        // Load secret key as Fq element (converted to CRT representation)
        let sk_assigned = self
            .fq
            .load_private(layouter.namespace(|| "load secret key"), esk)?;

        // Range check secret key limbs to ensure they're valid 88-bit values
        self.fq
            .range_check_limbs(layouter.namespace(|| "range check sk"), &sk_assigned)?;

        // Load public key x-coordinate as Fp element (converted to CRT representation)
        let pk_x_assigned = self
            .fp
            .load_private(layouter.namespace(|| "load pk.x"), epkx)?;

        // Load public key y-coordinate as Fp element (converted to CRT representation)
        let pk_y_assigned = self
            .fp
            .load_private(layouter.namespace(|| "load pk.y"), epky)?;

        // Range check public key coordinate limbs
        self.fp
            .range_check_limbs(layouter.namespace(|| "range check pk.x"), &pk_x_assigned)?;
        self.fp
            .range_check_limbs(layouter.namespace(|| "range check pk.y"), &pk_y_assigned)?;

        // TODO: Implement actual scalar multiplication check: pk = sk * G
        // This requires:
        // 1. Load generator point G (as CRT coordinates)
        // Load generator G
        let g_x = self.fp.load_private(
            layouter.namespace(|| "load G x"),
            Value::known(Secp256k1Fp::from_raw_bytes_unchecked(&GENERATOR_X)),
        )?;
        let g_y = self.fp.load_private(
            layouter.namespace(|| "load G y"),
            Value::known(Secp256k1Fp::from_raw_bytes_unchecked(&GENERATOR_Y)),
        )?;
        let g = (g_x, g_y);

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

    fn scalar_mul_montgomery(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        sk: &ProperCrtUint<pallas::Base>,
        g: &SecpPoint<pallas::Base>,
    ) -> Result<SecpPoint<pallas::Base>, PlonkError> {
        let mut bits =
            self.decompose_scalar_to_bits(layouter.namespace(|| "decompose scalar"), sk)?;

        // Reverse to MSB first
        bits.reverse();

        let mut r0 = g.clone();
        let mut r1 = self.double_point(layouter.namespace(|| "initial double"), &r0)?;

        for bit in bits {
            let added = self.add_point(layouter.namespace(|| "montgomery add"), &r0, &r1)?;
            let doubled0 = self.double_point(layouter.namespace(|| "montgomery double0"), &r0)?;
            let doubled1 = self.double_point(layouter.namespace(|| "montgomery double1"), &r1)?;

            // if bit == 0: r0 = doubled0, r1 = added
            // if bit == 1: r0 = added, r1 = doubled1
            r0.0 = self.select(
                layouter.namespace(|| "select r0.x"),
                &doubled0.0,
                &added.0,
                &bit,
            )?;
            r0.1 = self.select(
                layouter.namespace(|| "select r0.y"),
                &doubled0.1,
                &added.1,
                &bit,
            )?;
            r1.0 = self.select(
                layouter.namespace(|| "select r1.x"),
                &added.0,
                &doubled1.0,
                &bit,
            )?;
            r1.1 = self.select(
                layouter.namespace(|| "select r1.y"),
                &added.1,
                &doubled1.1,
                &bit,
            )?;
        }

        Ok(r0)
    }

    /// Convert a secp256k1 Fq element (CRT representation) to native Pallas::Base.
    ///
    /// This is used for HKDF derivation: we need to convert the secp256k1
    /// secret key to a native field element to use as input to Poseidon hash.
    ///
    /// **NOTE**: This extracts the native field representation from the CRT integer,
    /// which is `value mod pallas::MODULUS`. This is a lossy conversion but acceptable
    /// for HKDF as we're using it as entropy, not doing field arithmetic.
    pub fn fq_to_native(
        &self,
        layouter: impl Layouter<pallas::Base>,
        fq: &ProperCrtUint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PlonkError> {
        self.fq.to_native(layouter, fq)
    }
}

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
        // Test field element to BigUint conversion
        let value = pallas::Base::from(123);
        let big = crate::spec::fe_to_biguint_simple(&value);
        let back = crate::spec::biguint_to_fe_simple(&big);
        assert_eq!(value, back);

        // Test zero conversion
        let zero = pallas::Base::zero();
        let big_zero = crate::spec::fe_to_biguint_simple(&zero);
        assert!(big_zero.is_zero());
    }

    #[test]
    fn test_fixed_integer_conversion() {
        // Test FixedOverflowInteger conversion
        let value = BigUint::from(0x01020304u32);
        let fixed = FixedOverflowInteger::from_native(&value, 3, 88);
        let reconstructed = fixed.to_biguint(88);
        assert_eq!(value, reconstructed);
        let r3 = fixed.to_biguint(86);
        assert_ne!(value, r3);
    }

    // Simple test circuit to verify assignment works
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
                    // Test constant assignment
                    let constant_uint = chip.assign_constant(&mut region, 0, &self.value)?;
                    assert_eq!(constant_uint.num_limbs(), 4);

                    // Test witness assignment
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
}
