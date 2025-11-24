//! Secp256k1 curve arithmetic chips using FOREIGN FIELD ARITHMETIC
//!
//! **CRITICAL: This is FOREIGN field arithmetic!**
//! - **Native field**: Pallas::Base (~255 bits) - the field our circuit operates in
//! - **Foreign fields**: secp256k1::Fp and secp256k1::Fq (both 256 bits) - DON'T fit in Pallas!
//! - **Representation**: Each 256-bit foreign field element → 3 limbs × 88 bits using CRT
//!
//! We represent secp256k1 curve points as (x, y) where x and y are **CRT integers**,
//! NOT native affine points. All operations happen through limb arithmetic.

use super::bigint::ProperCrtUint;
use super::fp_chip::{FpChip, FpConfig, FpInstructions};
use ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};
use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::circuit::{Cell, Region};
use halo2_proofs::plonk::{Expression, Selector};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error as PlonkError},
};
use pasta_curves::pallas;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};

pub type Secp256k1Fp = Fp;
pub type Secp256k1Fq = Fq;
/// Type alias for secp256k1 base field (Fp) chip
/// This chip represents Fp elements as CRT integers with 88-bit limbs
pub type Secp256k1FpChip = FpChip<Secp256k1Fp>;

/// Type alias for secp256k1 scalar field (Fq) chip
/// This chip represents Fq elements as CRT integers with 88-bit limbs
pub type Secp256k1FqChip = FpChip<Secp256k1Fq>;

type SecpPoint<Base> = (ProperCrtUint<Base>, ProperCrtUint<Base>);

/// Configuration for secp256k1 elliptic curve operations.
///
/// This includes both the base field (Fp) and scalar field (Fq) configurations.
#[derive(Clone, Debug)]
pub struct Secp256k1Config {
    /// Configuration for base field (Fp) operations
    pub fp_config: FpConfig,
    /// Configuration for scalar field (Fq) operations
    pub fq_config: FpConfig,
    decomp_selector: Selector,
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

        let decomp_selector = meta.selector();

        meta.create_gate("scalar decomposition step", |meta| {
            let q = meta.query_selector(decomp_selector);
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
            decomp_selector,
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
    pub fp_chip: Secp256k1FpChip,
    /// Chip for scalar field (Fq) operations - for secret keys
    pub fq_chip: Secp256k1FqChip,
    decomp_selector: Selector,
}

impl Secp256k1Chip {
    /// Construct a new Secp256k1Chip from configuration.
    ///
    /// Uses 88-bit limbs and 3 limbs per field element (88 * 3 = 264 bits > 256 bits).
    pub fn construct(config: Secp256k1Config) -> Self {
        const LIMB_BITS: usize = 88;
        const NUM_LIMBS: usize = 3;

        Self {
            fp_chip: Secp256k1FpChip::construct(config.fp_config, LIMB_BITS, NUM_LIMBS),
            fq_chip: Secp256k1FqChip::construct(config.fq_config, LIMB_BITS, NUM_LIMBS),
            decomp_selector: config.decomp_selector,
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
                    self.fq_chip.config.advices[0],
                    current_offset,
                )?;

                let mut current_value = limb.value().cloned();
                let mut last_assigned: Option<AssignedCell<pallas::Base, pallas::Base>> = None;

                for _ in 0..88 {
                    self.decomp_selector.enable(&mut region, current_offset)?;

                    let bit_val = current_value.map(|v| {
                        let repr = v.to_repr();
                        pallas::Base::from((repr[0] & 1) as u64)
                    });
                    let bit_cell = region.assign_advice(
                        || "bit",
                        self.fq_chip.config.advices[1],
                        current_offset,
                        || bit_val,
                    )?;

                    bits.push(bit_cell);

                    let next_val = current_value
                        .zip(bit_val)
                        .map(|(current, bit)| (current - bit) * inv2);
                    region.assign_advice(
                        || "next current",
                        self.fq_chip.config.advices[0],
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
        let fp = &self.fp_chip;

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
        let fp = &self.fp_chip;

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
        let fp = &self.fp_chip;

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

    /// Prove key pairing: `public_key = secret_key * G`
    ///
    /// This constrains that the given public key is the correct result of
    /// scalar multiplication of the secret key with the secp256k1 generator.
    ///
    /// **IMPORTANT**: All inputs are FOREIGN field elements represented as CRT integers!
    ///
    /// # Arguments
    /// * `layouter` - The layouter for assigning cells
    /// * `secret_key` - The secret key (scalar in Fq, as native type)
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
        secret_key: Value<Secp256k1Fq>,
        public_key_x: Value<Secp256k1Fp>,
        public_key_y: Value<Secp256k1Fp>,
    ) -> Result<
        (
            ProperCrtUint<pallas::Base>,
            (ProperCrtUint<pallas::Base>, ProperCrtUint<pallas::Base>),
        ),
        PlonkError,
    > {
        // Load secret key as Fq element (converted to CRT representation)
        let sk_assigned = self
            .fq_chip
            .load_private(layouter.namespace(|| "load secret key"), secret_key)?;

        // Range check secret key limbs to ensure they're valid 88-bit values
        self.fq_chip
            .range_check_limbs(layouter.namespace(|| "range check sk"), &sk_assigned)?;

        // Load public key x-coordinate as Fp element (converted to CRT representation)
        let pk_x_assigned = self
            .fp_chip
            .load_private(layouter.namespace(|| "load pk.x"), public_key_x)?;

        // Load public key y-coordinate as Fp element (converted to CRT representation)
        let pk_y_assigned = self
            .fp_chip
            .load_private(layouter.namespace(|| "load pk.y"), public_key_y)?;

        // Range check public key coordinate limbs
        self.fp_chip
            .range_check_limbs(layouter.namespace(|| "range check pk.x"), &pk_x_assigned)?;
        self.fp_chip
            .range_check_limbs(layouter.namespace(|| "range check pk.y"), &pk_y_assigned)?;

        // TODO: Implement actual scalar multiplication check: pk = sk * G
        // This requires:
        // 1. Load generator point G (as CRT coordinates)
        // Load generator G
        let g_x = self.fp_chip.load_private(
            layouter.namespace(|| "load G x"),
            Value::known(Secp256k1Fp::from_raw_bytes_unchecked(&GENERATOR_X)),
        )?;
        let g_y = self.fp_chip.load_private(
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
        self.fp_chip.enforce_equal(
            layouter.namespace(|| "enforce x equal"),
            &computed_pk.0,
            &pk_x_assigned,
        )?;
        self.fp_chip.enforce_equal(
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
        self.fq_chip.to_native(layouter, fq)
    }
}
