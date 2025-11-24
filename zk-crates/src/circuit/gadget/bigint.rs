//! BigInt types for foreign field arithmetic using CRT representation
//!
//! This module provides types and utilities for representing large integers
//! that don't fit in the native field using Chinese Remainder Theorem (CRT).
//!
//! A CRT integer tracks a value using:
//! - Truncation: limbs representing `value mod 2^t` where `t = num_limbs * limb_bits`
//! - Native: a field element representing `value mod p` where `p` is the native field modulus
//!
//! This is adapted from halo2-ecc but refactored to use native halo2 patterns
//! (Layouter, Region, AssignedCell) instead of halo2-base abstractions.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error as PlonkError, Selector},
};
use num_bigint::{BigInt, BigUint};
use num_traits::identities::Zero;
use pasta_curves::pallas;

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

/// Get the modulus of a prime field without requiring BigPrimeField trait.
///
/// This works for any prime field that implements PrimeField.
/// The modulus is computed as: modulus = -1 + 1 = p
pub fn modulus_simple<F: PrimeField>() -> BigUint {
    fe_to_biguint_for_field(&-F::ONE) + 1u64
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
            (acc << limb_bits) + fe_to_biguint_simple(x)
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

/// Convert a generic field element to BigUint.
///
/// This is a generic version that works for any PrimeField, not just pallas::Base.
pub fn fe_to_biguint_for_field<F: PrimeField>(fe: &F) -> BigUint {
    let bytes = fe.to_repr();
    BigUint::from_bytes_le(bytes.as_ref())
}

// implement AddInstructions
// implement Field Traits for common functionality

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::circuit::Layouter;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::Circuit;
    use pasta_curves::pallas;

    #[test]
    fn test_fe_conversion() {
        // Test field element to BigUint conversion
        let value = pallas::Base::from(123);
        let big = fe_to_biguint_simple(&value);
        let back = biguint_to_fe_simple(&big);
        assert_eq!(value, back);

        // Test zero conversion
        let zero = pallas::Base::zero();
        let big_zero = fe_to_biguint_simple(&zero);
        assert!(big_zero.is_zero());
    }

    #[test]
    fn test_fixed_integer_conversion() {
        // Test FixedOverflowInteger conversion
        let value = BigUint::from(0x01020304u32);
        let fixed = FixedOverflowInteger::from_native(&value, 4, 8);
        let reconstructed = fixed.to_biguint(8);
        assert_eq!(value, reconstructed);
    }

    // Simple test circuit to verify assignment works
    #[derive(Default)]
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

    #[test]
    fn test_circuit_assignment() {
        let value = BigUint::from(12345u32);
        let circuit = TestCircuit { value };

        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
