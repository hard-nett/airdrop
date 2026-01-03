//! generate the note leaf from its inputs and constrain it to root.
//! Sinsemilla leaf hash with canonicity constraints for merkle tree inclusion proofs.
//!
//! This module implements the leaf hash computation for the merkle tree, ensuring that
//! the leaf data (epk, nd, v, fdi) is properly constrained and canonically encoded.

use core::iter;
use std::{println, vec::Vec};

use group::ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

use crate::{
    circuit::gadget::secp256k1_chip::CrtInteger,
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains, T_P},
    value::NoteValue,
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, NonIdentityEccPoint},
        NonIdentityPoint, Point, ScalarFixed,
    },
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, HashDomain, HashDomains, Message, MessagePiece, SinsemillaInstructions,
    },
    utilities::{
        bool_check,
        lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
        FieldValue, RangeConstrained,
    },
};

/// Derive the leaf hash for a note in the merkle tree with sinsemilla and canonicity constraints.
pub fn derive_leaf(
    lo: impl Layouter<pallas::Base>,
    sc: &SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    ecc_chip: &EccChip<OrchardFixedBases>,
    leaf_hash_chip: &LeafHashChip,
    epk: (CrtInteger<pallas::Base>, CrtInteger<pallas::Base>),
    fdi: AssignedCell<pallas::Base, pallas::Base>,
    v: AssignedCell<NoteValue, pallas::Base>,
    nd: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
    gadgets::hash_leaf(
        sc.clone(),
        ecc_chip.clone(),
        leaf_hash_chip.clone(),
        lo,
        epk,
        fdi,
        v,
        nd,
    )
}

/// LeafHashConfig
#[derive(Clone, Debug)]
pub struct LeafHashConfig {
    q_leaf_hash: Selector,
    advices: [Column<Advice>; 10],
}

/// LeafHashChip
#[derive(Clone, Debug)]
pub struct LeafHashChip {
    config: LeafHashConfig,
}

impl LeafHashChip {
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
    ) -> LeafHashConfig {
        let q_leaf_hash = meta.selector();

        let config = LeafHashConfig {
            q_leaf_hash,
            advices,
        };

        // Gate for constraining decompositions and canonicity of leaf hash inputs.
        meta.create_gate("LeafHash canonicity check", |meta| {
            let q_leaf_hash = meta.query_selector(config.q_leaf_hash);

            let two_pow_5 = pallas::Base::from(1 << 5);
            let two_pow_64 = pallas::Base::from_u128(1u128 << 64);

            let epk_x = meta.query_advice(config.advices[0], Rotation::cur());
            let nd = meta.query_advice(config.advices[2], Rotation::cur());
            let v = meta.query_advice(config.advices[3], Rotation::cur());
            let fdi = meta.query_advice(config.advices[4], Rotation::cur());

            let b0 = meta.query_advice(config.advices[5], Rotation::cur());
            let z13_a = meta.query_advice(config.advices[6], Rotation::cur());
            let a_prime = meta.query_advice(config.advices[7], Rotation::cur());
            let z13_a_prime = meta.query_advice(config.advices[8], Rotation::cur());

            let two_pow_250 = pallas::Base::from_u128(1u128 << 125).square();
            let epk_x_decomposition = {
                // y parity byte
                let a = meta.query_advice(config.advices[1], Rotation::cur());
                a.clone() + b0.clone() * Expression::Constant(two_pow_250) - epk_x.clone()
            };

            let a_prime_check = {
                let a = meta.query_advice(config.advices[1], Rotation::cur());
                let two_pow_250_expr = Expression::Constant(two_pow_250);
                let t_p = Expression::Constant(pallas::Base::from_u128(T_P));
                a + two_pow_250_expr - t_p - a_prime.clone()
            };

            let d0 = meta.query_advice(config.advices[5], Rotation::next());
            let z13_d = meta.query_advice(config.advices[6], Rotation::next());
            let nd_prime = meta.query_advice(config.advices[7], Rotation::next());
            let z13_nd_prime = meta.query_advice(config.advices[8], Rotation::next());

            let two_pow_4 = pallas::Base::from(1 << 4);
            let two_pow_254 = two_pow_250 * pallas::Base::from(1 << 4);
            let nd_decomposition = {
                let c = meta.query_advice(config.advices[1], Rotation::next());
                let b2 = meta.query_advice(config.advices[5], Rotation::cur());
                b2 + c.clone() * Expression::Constant(two_pow_4)
                    + d0.clone() * Expression::Constant(two_pow_254)
                    - nd.clone()
            };

            let nd_prime_check = {
                let t_p = Expression::Constant(pallas::Base::from_u128(T_P));
                nd.clone() + Expression::Constant(two_pow_254) - t_p - nd_prime.clone()
            };

            let b0_bool = bool_check(b0);
            let d0_bool = bool_check(d0);

            Constraints::with_selector(
                q_leaf_hash,
                iter::empty()
                    .chain(Some(("epk_x_decomposition", epk_x_decomposition)))
                    .chain(Some(("a_prime_check", a_prime_check)))
                    .chain(Some(("nd_decomposition", nd_decomposition)))
                    .chain(Some(("nd_prime_check", nd_prime_check)))
                    .chain(Some(("b0_bool", b0_bool)))
                    .chain(Some(("d0_bool", d0_bool))),
            )
        });

        config
    }

    pub(in crate::circuit) fn construct(config: LeafHashConfig) -> Self {
        Self { config }
    }
}

pub(in crate::circuit) mod gadgets {
    use halo2_gadgets::ecc::NonIdentityPoint;
    use halo2_gadgets::utilities::{FieldValue, RangeConstrained};
    use halo2_proofs::circuit::Chip;

    use super::*;

    /// Hash a leaf in the merkle tree with sinsemilla and constrain canonicity.
    #[allow(non_snake_case)]
    pub(in crate::circuit) fn hash_leaf(
        sc: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        ecc_chip: EccChip<OrchardFixedBases>,
        leaf_hash_chip: LeafHashChip,
        mut lo: impl Layouter<pallas::Base>,
        epk: (CrtInteger<pallas::Base>, CrtInteger<pallas::Base>),
        fdi: AssignedCell<pallas::Base, pallas::Base>,
        v: AssignedCell<NoteValue, pallas::Base>,
        nd: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
        let lc = sc.config().lookup_config();
        let domain = OrchardHashDomains::Leaf;

        let vv = v.value().map(|v| pallas::Base::from(v.inner()));

        // Piece a: bits 0-249 of epk.x (250 bits)
        let a = MessagePiece::from_subpieces(
            sc.clone(),
            lo.namespace(|| "a: epk.x[0..250)"),
            [RangeConstrained::bitrange_of(epk.0.native.value(), 0..250)],
        )?;

        // Piece b: epk.x[250..255] || epk.y[0] || nd[0..4] (10 bits)
        let (b_0, b_1, b_2, b) = {
            let b_0 = RangeConstrained::witness_short(
                &lc,
                lo.namespace(|| "b_0: epk.x[250..255)"),
                epk.0.native.value(),
                250..255,
            )?;
            let b_1 = RangeConstrained::bitrange_of(epk.1.native.value(), 0..1);
            let b_2 = RangeConstrained::bitrange_of(nd.value(), 0..4);

            let b = MessagePiece::from_subpieces(
                sc.clone(),
                lo.namespace(|| "b: epk.x[250..255) || epk.y[0] || nd[0..4)"),
                [b_0.value(), b_1, b_2],
            )?;

            (b_0, b_1, b_2, b)
        };

        // Piece c: bits 4..254 of nd (250 bits)
        let c = MessagePiece::from_subpieces(
            sc.clone(),
            lo.namespace(|| "c: nd[4..254)"),
            [RangeConstrained::bitrange_of(nd.value(), 4..254)],
        )?;

        // Piece d: nd[254..255] || v[0..9] (10 bits)
        let ([d_0, d_1], d) = {
            let d0 = RangeConstrained::bitrange_of(nd.value(), 254..255);
            let d1 = RangeConstrained::bitrange_of(vv.value(), 0..9);
            (
                [d0, d1],
                MessagePiece::from_subpieces(
                    sc.clone(),
                    lo.namespace(|| "d: nd[254] || v[0..9)"),
                    [d0, d1],
                )?,
            )
        };

        // Piece e: v[9..59] (50 bits)
        let e = MessagePiece::from_subpieces(
            sc.clone(),
            lo.namespace(|| "e: v[9..59)"),
            [RangeConstrained::bitrange_of(vv.value(), 9..59)],
        )?;

        // Piece f: v[59..64] || fdi[0..5] (10 bits)
        let ([f_0, f_1], f) = {
            let f0 = RangeConstrained::bitrange_of(vv.value(), 59..64);
            let f1 = RangeConstrained::bitrange_of(fdi.value(), 0..5);
            (
                [f0, f1],
                MessagePiece::from_subpieces(
                    sc.clone(),
                    lo.namespace(|| "f: v[59..64) || fdi[0..5)"),
                    [f0, f1],
                )?,
            )
        };

        // Piece g: fdi[5..55] (50 bits)
        let g = MessagePiece::from_subpieces(
            sc.clone(),
            lo.namespace(|| "g: fdi[5..55)"),
            [RangeConstrained::bitrange_of(fdi.value(), 5..55)],
        )?;

        // Piece h: fdi[55..64] || padding (10 bits)
        let ([h_0, h_1], h) = {
            let h0 = RangeConstrained::bitrange_of(fdi.value(), 55..64);
            let h1 = RangeConstrained::bitrange_of(Value::known(&pallas::Base::zero()), 0..1);
            (
                [h0, h1],
                MessagePiece::from_subpieces(
                    sc.clone(),
                    lo.namespace(|| "h: fdi[55..64) || padding"),
                    [h0, h1],
                )?,
            )
        };

        let message =
            Message::from_pieces(sc.clone(), vec![a.clone(), b, c.clone(), d, e, f, g, h]);

        let (hash, zs) = {
            let domain_inst = HashDomain::new(sc, ecc_chip, &domain);
            domain_inst.hash_to_point(lo.namespace(|| "Hash leaf"), message)?
        };

        let z13_a = zs[0][13].clone();
        let z13_c = zs[2][13].clone();

        let (a_prime, z13_a_prime) = epk_x_canonicity(
            &lc,
            lo.namespace(|| "epk.x canonicity"),
            a.inner().cell_value(),
        )?;

        let (nd_prime, z13_nd_prime) = nd_canonicity(
            &lc,
            lo.namespace(|| "nd canonicity"),
            c.inner().cell_value(),
        )?;

        let gate_cells = GateCells {
            epk_x: epk.0.native.clone(),
            epk_y: epk.1.native.clone(),
            nd: nd.clone(),
            v,
            fdi: fdi.clone(),
            b_0,
            b_1,
            b_2,
            d_0,
            d_1,
            f_0,
            f_1,
            h_0,
            h_1,
            z13_a,
            z13_c,
            a_prime,
            z13_a_prime,
            nd_prime,
            z13_nd_prime,
        };

        leaf_hash_chip.config.assign_gate(
            lo.namespace(|| "Assign cells for leaf hash canonicity gate"),
            gate_cells,
        )?;

        Ok(hash)
    }

    fn epk_x_canonicity(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut lo: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        let a_prime = {
            let two_pow_250 = Value::known(pallas::Base::from_u128(1u128 << 125).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            a.value() + two_pow_250 - t_p
        };
        let zs = lc.witness_check(
            lo.namespace(|| "Decompose low 250 bits of (a + 2^250 - t_P)"),
            a_prime,
            25,
            false,
        )?;
        let a_prime = zs[0].clone();
        assert_eq!(zs.len(), 26);

        Ok((a_prime, zs[25].clone()))
    }

    fn nd_canonicity(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut lo: impl Layouter<pallas::Base>,
        c: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        let nd_prime = {
            let two_pow_254 = Value::known(pallas::Base::from_u128(1u128 << 127).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            c.value() + two_pow_254 - t_p
        };
        let zs = lc.witness_check(
            lo.namespace(|| "Decompose low 254 bits of (nd + 2^254 - t_P)"),
            nd_prime,
            25,
            false,
        )?;
        let nd_prime = zs[0].clone();
        assert_eq!(zs.len(), 26);

        Ok((nd_prime, zs[25].clone()))
    }
}

impl LeafHashConfig {
    fn assign_gate(
        &self,
        mut lo: impl Layouter<pallas::Base>,
        gate_cells: GateCells,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "Assign cells for leaf hash canonicity gate",
            |mut region| {
                self.q_leaf_hash.enable(&mut region, 0)?;

                {
                    let offset = 0;

                    gate_cells.epk_x.copy_advice(
                        || "epk_x",
                        &mut region,
                        self.advices[0],
                        offset,
                    )?;

                    gate_cells.b_0.inner().copy_advice(
                        || "b_0",
                        &mut region,
                        self.advices[5],
                        offset,
                    )?;

                    gate_cells.z13_a.copy_advice(
                        || "z13_a",
                        &mut region,
                        self.advices[6],
                        offset,
                    )?;

                    gate_cells.a_prime.copy_advice(
                        || "a_prime",
                        &mut region,
                        self.advices[7],
                        offset,
                    )?;

                    gate_cells.z13_a_prime.copy_advice(
                        || "z13_a_prime",
                        &mut region,
                        self.advices[8],
                        offset,
                    )?;
                }

                {
                    let offset = 1;

                    gate_cells
                        .nd
                        .copy_advice(|| "nd", &mut region, self.advices[2], offset)?;

                    gate_cells
                        .v
                        .copy_advice(|| "v", &mut region, self.advices[3], offset)?;

                    gate_cells
                        .fdi
                        .copy_advice(|| "fdi", &mut region, self.advices[4], offset)?;

                    region.assign_advice(
                        || "d_0",
                        self.advices[5],
                        offset,
                        || *gate_cells.d_0.inner(),
                    )?;

                    gate_cells.z13_c.copy_advice(
                        || "z13_c",
                        &mut region,
                        self.advices[6],
                        offset,
                    )?;

                    gate_cells.nd_prime.copy_advice(
                        || "nd_prime",
                        &mut region,
                        self.advices[7],
                        offset,
                    )?;

                    gate_cells.z13_nd_prime.copy_advice(
                        || "z13_nd_prime",
                        &mut region,
                        self.advices[8],
                        offset,
                    )?;
                }

                Ok(())
            },
        )
    }
}

struct GateCells {
    epk_x: AssignedCell<pallas::Base, pallas::Base>,
    epk_y: AssignedCell<pallas::Base, pallas::Base>,
    nd: AssignedCell<pallas::Base, pallas::Base>,
    v: AssignedCell<NoteValue, pallas::Base>,
    fdi: AssignedCell<pallas::Base, pallas::Base>,
    b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    b_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    b_2: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    d_0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    d_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    f_0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    f_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    h_0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    h_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    z13_a: AssignedCell<pallas::Base, pallas::Base>,
    z13_c: AssignedCell<pallas::Base, pallas::Base>,
    a_prime: AssignedCell<pallas::Base, pallas::Base>,
    z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    nd_prime: AssignedCell<pallas::Base, pallas::Base>,
    z13_nd_prime: AssignedCell<pallas::Base, pallas::Base>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::gadget::{
            assign_free_advice,
            secp256k1_chip::{Secp256k1Chip, Secp256k1Config, Secp256k1Fp},
        },
        Note,
    };
    use ff::PrimeField;
    use halo2_gadgets::{
        ecc::chip::{EccChip, EccConfig},
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{ConstraintSystem, Error},
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_leaf_hash_basic() {
        #[derive(Default)]
        struct LeafHashCircuit {
            epk_x: Value<Secp256k1Fp>,
            epk_y: Value<Secp256k1Fp>,
            nd: Value<pallas::Base>,
            v: Value<NoteValue>,
            fdi: Value<pallas::Base>,
        }

        impl halo2_proofs::plonk::Circuit<pallas::Base> for LeafHashCircuit {
            type Config = (
                LeafHashConfig,
                SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
                EccConfig<OrchardFixedBases>,
                Secp256k1Config,
            );
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
                let advices = [
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                ];

                let constants = meta.fixed_column();
                meta.enable_constant(constants);

                for advice in advices.iter() {
                    meta.enable_equality(*advice);
                }

                let table_idx = meta.lookup_table_column();
                let lookup = (
                    table_idx,
                    meta.lookup_table_column(),
                    meta.lookup_table_column(),
                );
                let lagrange_coeffs = [
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                ];

                let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

                let sinsemilla_config = SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                >::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[6],
                    lagrange_coeffs[0],
                    lookup,
                    range_check.clone(),
                    false,
                );

                let leaf_hash_config = LeafHashChip::configure(meta, advices);

                let ecc_config = EccChip::<OrchardFixedBases>::configure(
                    meta,
                    advices,
                    lagrange_coeffs,
                    range_check,
                );

                let secp256k1 = Secp256k1Config::configure(
                    meta,
                    [advices[0], advices[1], advices[2]],
                    [advices[3], advices[4], advices[5]],
                    range_check.clone(),
                );

                (leaf_hash_config, sinsemilla_config, ecc_config, secp256k1)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut lo: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (leaf_hash_config, sinsemilla_config, ecc_config, secp256k1_config) = config;

                SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                >::load(sinsemilla_config.clone(), &mut lo)?;

                let sinsemilla_chip = SinsemillaChip::construct(sinsemilla_config);
                let ecc_chip = EccChip::construct(ecc_config);
                let lhc = LeafHashChip::construct(leaf_hash_config);
                let secp256k1 = Secp256k1Chip::construct(secp256k1_config);

                let epkx = secp256k1
                    .fp
                    .load_private(lo.namespace(|| "load pk.x"), self.epk_x)?;
                let epky = secp256k1
                    .fp
                    .load_private(lo.namespace(|| "load pk.xy"), self.epk_y)?;

                let nd = assign_free_advice(
                    lo.namespace(|| "witness nd"),
                    lhc.config.advices[0],
                    self.nd,
                )?;

                let v = assign_free_advice(
                    lo.namespace(|| "witness v"),
                    lhc.config.advices[0],
                    self.v,
                )?;
                let fdi = assign_free_advice(
                    lo.namespace(|| "witness fdi"),
                    lhc.config.advices[0],
                    self.fdi,
                )?;

                let _leaf = gadgets::hash_leaf(
                    sinsemilla_chip,
                    ecc_chip,
                    lhc.clone(),
                    lo,
                    (epkx, epky),
                    fdi,
                    v,
                    nd,
                )?;

                Ok(())
            }
        }
        let (_, _, esk, _) = Note::dummy(&mut OsRng, None);
        let (epkx, epky) = esk.epk().xy();
        let (epkx, epky) = (
            Secp256k1Fp::from_bytes(&epkx).expect("valid Fp"),
            Secp256k1Fp::from_bytes(&epky).expect("valid Fp"),
        );
        let circuit = LeafHashCircuit {
            epk_x: Value::known(epkx),
            epk_y: Value::known(epky),
            nd: Value::known(pallas::Base::from(42u64)),
            v: Value::known(NoteValue::one()),
            fdi: Value::known(pallas::Base::from(100u64)),
        };

        let prover = MockProver::<pallas::Base>::run(17, &circuit, vec![]);
        assert!(prover.is_ok());
        assert_eq!(prover.unwrap().verify(), Ok(()));
    }

    #[test]
    fn test_leaf_hash_various_inputs() {
        #[derive(Default)]
        struct LeafHashCircuit {
            epk_x: Value<Secp256k1Fp>,
            epk_y: Value<Secp256k1Fp>,
            nd: Value<pallas::Base>,
            v: Value<NoteValue>,
            fdi: Value<pallas::Base>,
        }

        impl halo2_proofs::plonk::Circuit<pallas::Base> for LeafHashCircuit {
            type Config = (
                LeafHashConfig,
                SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
                EccConfig<OrchardFixedBases>,
                Secp256k1Config,
            );
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
                let advices = [
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                ];

                let constants = meta.fixed_column();
                meta.enable_constant(constants);

                for advice in advices.iter() {
                    meta.enable_equality(*advice);
                }

                let table_idx = meta.lookup_table_column();
                let lookup = (
                    table_idx,
                    meta.lookup_table_column(),
                    meta.lookup_table_column(),
                );
                let lagrange_coeffs = [
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                ];

                let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

                let sinsemilla_config = SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                >::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[6],
                    lagrange_coeffs[0],
                    lookup,
                    range_check.clone(),
                    false,
                );

                let leaf_hash_config = LeafHashChip::configure(meta, advices);

                let ecc_config = EccChip::<OrchardFixedBases>::configure(
                    meta,
                    advices,
                    lagrange_coeffs,
                    range_check,
                );

                let secp256k1_config = Secp256k1Config::configure(
                    meta,
                    [advices[0], advices[1], advices[2]],
                    [advices[3], advices[4], advices[5]],
                    range_check.clone(),
                );

                (
                    leaf_hash_config,
                    sinsemilla_config,
                    ecc_config,
                    secp256k1_config,
                )
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut lo: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (leaf_hash_config, sinsemilla_config, ecc_config, secp256k1_config) = config;

                SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                >::load(sinsemilla_config.clone(), &mut lo)?;

                let sinsemilla_chip = SinsemillaChip::construct(sinsemilla_config.clone());
                let ecc_chip = EccChip::construct(ecc_config);
                let lhc = LeafHashChip::construct(leaf_hash_config.clone());
                let secp256k1 = Secp256k1Chip::construct(secp256k1_config);

                let epkx = secp256k1
                    .fp
                    .load_private(lo.namespace(|| "load pk.x"), self.epk_x)?;
                let epky = secp256k1
                    .fp
                    .load_private(lo.namespace(|| "load pk.xy"), self.epk_y)?;

                let nd = assign_free_advice(
                    lo.namespace(|| "witness nd"),
                    lhc.config.advices[0],
                    self.nd,
                )?;

                let v = assign_free_advice(
                    lo.namespace(|| "witness v"),
                    lhc.config.clone().advices[0],
                    self.v,
                )?;

                let fdi = assign_free_advice(
                    lo.namespace(|| "witness fdi"),
                    lhc.config.advices[0],
                    self.fdi,
                )?;

                let leaf = gadgets::hash_leaf(
                    sinsemilla_chip,
                    ecc_chip,
                    lhc,
                    lo,
                    (epkx, epky),
                    fdi,
                    v,
                    nd,
                )?;

                Ok(())
            }
        }

        let two_pow_254 = pallas::Base::from_u128(1u128 << 127).square();

        let (_, _, esk, _) = Note::dummy(&mut OsRng, None);
        let (epkx, epky) = esk.epk().xy();
        let (epkx, epky) = (
            Secp256k1Fp::from_bytes(&epkx).expect("valid Fp"),
            Secp256k1Fp::from_bytes(&epky).expect("valid Fp"),
        );

        let test_cases = vec![
            (
                "minimal values",
                pallas::Base::one(),
                NoteValue::one(),
                pallas::Base::one(),
            ),
            (
                "max field values",
                -pallas::Base::one(),
                NoteValue::one(),
                -pallas::Base::one(),
            ),
            (
                "max u64 values",
                pallas::Base::from(u64::MAX),
                NoteValue::one(),
                pallas::Base::from(u64::MAX),
            ),
            (
                "254-bit boundary",
                two_pow_254 - pallas::Base::one(),
                NoteValue::one(),
                two_pow_254 - pallas::Base::one(),
            ),
            (
                "zero nd",
                pallas::Base::zero(),
                NoteValue::one(),
                pallas::Base::from(100u64),
            ),
            (
                "zero fdi",
                pallas::Base::from(200u64),
                NoteValue::one(),
                pallas::Base::zero(),
            ),
            (
                "power of 2",
                pallas::Base::from(1u64 << 30),
                NoteValue::one(),
                pallas::Base::from(1u64 << 32),
            ),
            (
                "alternating bits",
                pallas::Base::from(0xAAAAAAAAAAAAAAAAu64),
                NoteValue::one(),
                pallas::Base::from(0x5555555555555555u64),
            ),
        ];

        for (name, nd, v, fdi) in test_cases.iter() {
            println!("Running test case: {}", name);
            let circuit = LeafHashCircuit {
                epk_x: Value::known(epkx),
                epk_y: Value::known(epky),
                nd: Value::known(*nd),
                v: Value::known(*v),
                fdi: Value::known(*fdi),
            };

            let prover = MockProver::<pallas::Base>::run(17, &circuit, vec![]);
            assert!(
                prover.is_ok(),
                "Test case '{}' prover creation failed",
                name
            );
            assert_eq!(
                prover.unwrap().verify(),
                Ok(()),
                "Test case '{}' verification failed",
                name
            );
        }
    }
}
