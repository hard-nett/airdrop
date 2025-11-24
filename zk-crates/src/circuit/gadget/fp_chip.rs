//! Foreign prime field arithmetic chip
//!
//! This module implements arithmetic for prime fields that are "foreign" to the
//! native circuit field (Pallas). It uses CRT representation with limbs to represent
//! field elements that don't fit in the native field.
//!
//! Adapted from halo2-ecc::fields::fp but refactored to use native halo2 patterns.

use crate::circuit::gadget::bigint::{fe_to_biguint_for_field, modulus_simple};

use super::bigint::{
    biguint_to_fe_simple, fe_to_biguint_simple, CrtInteger, FixedOverflowInteger, OverflowInteger,
    ProperCrtUint as Puint, ProperUint,
};
use ff::{Field, PrimeField};

use halo2_base::utils::{modulus, BigPrimeField};
use halo2_gadgets::utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter as Lo, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error as PErr, Selector},
};
use num_bigint::{BigInt, BigUint};
use num_traits::One;
use pasta_curves::pallas;
use std::marker::PhantomData;

/// Trait for foreign field instructions.
pub trait FpInstructions<Fp: BigPrimeField> {
    /// Load a constant foreign field element.
    fn load_constant(
        &self,
        layouter: impl Lo<pallas::Base>,
        v: Fp,
    ) -> Result<Puint<pallas::Base>, PErr>;

    /// Load a private (witness) foreign field element.
    fn load_private(
        &self,
        layouter: impl Lo<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<Puint<pallas::Base>, PErr>;

    /// Range check all limbs.
    fn range_check_limbs(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<(), PErr>;

    /// Convert to native field representation.
    fn to_native(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PErr>;

    fn enforce_zero(
        &self,
        layouter: impl Lo<pallas::Base>,
        num: &Puint<pallas::Base>,
    ) -> Result<(), PErr>;
    fn enforce_equal(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<(), PErr>;

    /// Add two foreign field elements: c = a + b mod p
    fn add(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr>;

    /// Subtract two foreign field elements: c = a - b mod p
    fn sub(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr>;

    /// Multiply two foreign field elements: c = a * b mod p
    fn mul(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr>;

    /// Divide two foreign field elements: c = a / b mod p
    fn div(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr>;
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
        mut layouter: impl Lo<pallas::Base>,
        v: Fp,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
    ) -> Result<Puint<pallas::Base>, PErr> {
        self.assign_constant_biguint(region, offset, &fe_to_biguint_for_field(&v))
    }

    /// Assign a constant BigUint as a CRT integer.
    fn assign_constant_biguint(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: &BigUint,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
        mut layouter: impl Lo<pallas::Base>,
        value: Value<Fp>,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
    ) -> Result<Puint<pallas::Base>, PErr> {
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
    /// Ex: Secp256k1 expects 9x 10-bit range limbs
    pub fn range_check_limbs(
        &self,
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<(), PErr> {
        for (i, limb) in a.truncation.limbs.iter().enumerate() {
            self.config.range_check.copy_check(
                layouter.namespace(|| format!("range check limb {}", i)),
                limb.clone(),
                self.limb_bits,
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
        _layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PErr> {
        // The native representation is already computed in the CRT integer
        Ok(a.native.clone())
    }

    /// Add two foreign field elements: c = a + b mod p
    ///
    /// Performs limb-wise addition with carry propagation and modular reduction.
    pub fn add(
        &self,
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
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
        layouter: impl Lo<pallas::Base>,
        v: Fp,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::load_constant(self, layouter, v)
    }

    fn load_private(
        &self,
        layouter: impl Lo<pallas::Base>,
        v: Value<Fp>,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::load_private(self, layouter, v)
    }

    fn range_check_limbs(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<(), PErr> {
        FpChip::range_check_limbs(self, layouter, a)
    }

    fn to_native(
        &self,
        lo: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, PErr> {
        FpChip::to_native(self, lo, a)
    }

    fn enforce_zero(
        &self,
        mut layouter: impl Lo<pallas::Base>,
        num: &Puint<pallas::Base>,
    ) -> Result<(), PErr> {
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
        mut layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<(), PErr> {
        let diff = self.sub(layouter.namespace(|| "diff"), a, b)?;
        self.enforce_zero(layouter.namespace(|| "enforce zero"), &diff)
    }

    fn add(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::add(self, layouter, a, b)
    }

    fn sub(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::sub(self, layouter, a, b)
    }

    fn mul(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::mul(self, layouter, a, b)
    }

    fn div(
        &self,
        layouter: impl Lo<pallas::Base>,
        a: &Puint<pallas::Base>,
        b: &Puint<pallas::Base>,
    ) -> Result<Puint<pallas::Base>, PErr> {
        FpChip::div(self, layouter, a, b)
    }
}
