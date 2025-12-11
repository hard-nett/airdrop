// each piece is 60 bits.
// we hav n pieces of data ordered in ∫ sequence to create note-commit.
// l is length of total sum of bits in n
// we keep track of each n bounds coordiates (start,end) in set of ∫
// generate circuits to automatically of decompose sections based on unique ∫n

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
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains, T_P},
    value::NoteValue,
};
use halo2_gadgets::{
    ecc::{chip::EccChip, Point, ScalarFixed},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, Message, MessagePiece,
    },
    utilities::{
        bool_check,
        lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
        FieldValue, RangeConstrained,
    },
};

type NoteCommitPiece = MessagePiece<
    pallas::Affine,
    SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    10,
    253,
>;

/// The vs of the running sum at the start and end of the range being used for a
/// canonicity check.
type CanonicityBounds = (
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
);

/// b = b_0 || b_1 || b_2 || b_3
///   = (bits 250..=253 of x(g_d)) || (bit 254 of x(g_d)) || (ỹ bit of g_d) || (bits 0..=3 of pk★_d)
///
/// | A_6 | A_7 | A_8 | q_notecommit_b |
/// ------------------------------------
/// |  b  | b_0 | b_1 |       1        |
/// |     | b_2 | b_3 |       0        |
///
/// <https://p.z.cash/orchard-0.1:note-commit-decomposition-b?partial>
#[derive(Clone, Debug)]
struct DecomposeB {
    q_notecommit_b: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeB {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_4: pallas::Base,
        two_pow_5: pallas::Base,
        two_pow_6: pallas::Base,
    ) -> Self {
        let q_notecommit_b = meta.selector();

        meta.create_gate("NoteCommit MessagePiece b", |meta| {
            let q_notecommit_b = meta.query_selector(q_notecommit_b);

            // b has been constrained to 60 bits by the Sinsemilla hash.
            let b = meta.query_advice(col_l, Rotation::cur());
            // b_0 has been constrained to be 5 bits outside this gate.
            let b_0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains to be 55 bits outside this gate.
            let b_1 = meta.query_advice(col_r, Rotation::cur());
            // // This gate constrains b_2 to be boolean.
            // let b_2 = meta.query_advice(col_m, Rotation::next());
            // // b_3 has been constrained to 4 bits outside this gate.
            // let b_3 = meta.query_advice(col_r, Rotation::next());

            // b = b_0 + (2^4) b_1 + (2^5) b_2 + (2^6) b_3
            let decomposition_check = b - (b_0 + b_1.clone() * two_pow_5);

            Constraints::with_selector(
                q_notecommit_b,
                [
                    // ("bool_check b_1", bool_check(b_1)),
                    // ("bool_check b_2", bool_check(b_2)),
                    ("decomposition", decomposition_check),
                ],
            )
        });

        Self {
            q_notecommit_b,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        nd: &AssignedCell<pallas::Base, pallas::Base>,
        v: &AssignedCell<NoteValue, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
        ),
        Error,
    > {
        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));

        let b0 = RangeConstrained::bitrange_of(nd.value(), 250..255);
        let b1 = RangeConstrained::bitrange_of(value_val.value(), 0..55);
        // Piece b: bits 250..255 of nd || 0..55 of v  (5 + 55 = 60 bits)
        let b = MessagePiece::from_subpieces(
            chip.clone(),
            lo.namespace(|| "piece_b: nd[250..255) || v[0..55)"),
            [b0, b1],
        )?;
        Ok((b, b0, b1))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        b: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        layouter.assign_region(
            || "NoteCommit MessagePiece b",
            |mut region| {
                self.q_notecommit_b.enable(&mut region, 0)?;
                b.inner()
                    .cell_value()
                    .copy_advice(|| "b", &mut region, self.col_l, 0)?;
                b_0.inner()
                    .copy_advice(|| "b_0", &mut region, self.col_m, 0)?;
                let b_1 = region.assign_advice(|| "b_1", self.col_r, 0, || *b_1.inner())?;
                Ok(b_1)
            },
        )
    }
}

#[derive(Clone, Debug)]
struct DecomposeC {
    q_notecommit_c: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeC {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_4: pallas::Base,
        two_pow_5: pallas::Base,
        two_pow_6: pallas::Base,
    ) -> Self {
        let q_notecommit_c = meta.selector();

        meta.create_gate("NoteCommit MessagePiece c", |meta| {
            let q_notecommit_c = meta.query_selector(q_notecommit_c);

            // c has been constrained to 10 bits by the Sinsemilla hash.
            let c = meta.query_advice(col_l, Rotation::cur());
            // c_0 has been constrained to 4 bits outside this gate.
            let c_0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains c_1 to be boolean.
            let c_1 = meta.query_advice(col_r, Rotation::cur());
            // This gate constrains c_2 to be boolean.
            let c_2 = meta.query_advice(col_m, Rotation::next());
            // c_3 has been constrained to 4 bits outside this gate.
            let c_3 = meta.query_advice(col_r, Rotation::next());

            // c = c_0 + (2^4) c_1 + (2^5) c_2 + (2^6) c_3
            let decomposition_check =
                c - (c_0 + c_1.clone() * two_pow_4 + c_2.clone() * two_pow_5 + c_3 * two_pow_6);

            Constraints::with_selector(
                q_notecommit_c,
                [
                    ("bool_check c_1", bool_check(c_1)),
                    ("bool_check c_2", bool_check(c_2)),
                    ("decomposition", decomposition_check),
                ],
            )
        });

        Self {
            q_notecommit_c,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        v: &AssignedCell<NoteValue, pallas::Base>,
        fdi: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
        ),
        Error,
    > {
        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));

        let (c, c0, c1) = {
            let c0 = RangeConstrained::bitrange_of(value_val.value(), 55..64);
            let c1 = RangeConstrained::bitrange_of(fdi.value(), 0..51);
            println!("c: {:#?}", (c0.num_bits(), c1.num_bits()));
            (
                MessagePiece::from_subpieces(
                    chip.clone(),
                    lo.namespace(|| "piece_c: v[55..64) || pad(0)"),
                    [c0, c1],
                )?,
                c0,
                c1,
            )
        };

        Ok((c, c0, c1))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        c: NoteCommitPiece,
        c_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        c_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        c_2: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        c_3: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        layouter.assign_region(
            || "NoteCommit MessagePiece c",
            |mut region| {
                self.q_notecommit_c.enable(&mut region, 0)?;

                c.inner()
                    .cell_value()
                    .copy_advice(|| "c", &mut region, self.col_l, 0)?;
                c_0.inner()
                    .copy_advice(|| "c_0", &mut region, self.col_m, 0)?;
                let c_1 = region.assign_advice(|| "c_1", self.col_r, 0, || *c_1.inner())?;

                let c_2 = region.assign_advice(|| "c_2", self.col_m, 1, || *c_2.inner())?;
                c_3.inner()
                    .copy_advice(|| "c_3", &mut region, self.col_r, 1)?;

                Ok(c_1)
            },
        )
    }
}

/// d = bits 114-253 of rho || bits 0-109 of esk (250 bits)
///   For the gate, we decompose a 10-bit boundary: d_0 || d_1 || d_2 || d_3
///
/// | A_6 | A_7 | A_8 | q_notecommit_d |
/// ------------------------------------
/// |  d  | d_0 | d_1 |       1        |
/// |     | d_2 | d_3 |       0        |
#[derive(Clone, Debug)]
struct DecomposeD {
    q_notecommit_d: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeD {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two: pallas::Base,
        two_pow_2: pallas::Base,
        two_pow_10: pallas::Base,
    ) -> Self {
        let q_notecommit_d = meta.selector();

        meta.create_gate("NoteCommit MessagePiece d", |meta| {
            let q_notecommit_d = meta.query_selector(q_notecommit_d);

            // d has been constrained to 60 bits by the Sinsemilla hash.
            let d = meta.query_advice(col_l, Rotation::cur());
            // This gate constrains d_0 to be boolean.
            let d_0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains d_1 to be boolean.
            let d_1 = meta.query_advice(col_r, Rotation::cur());
            // d_2 has been constrained to 8 bits outside this gate.
            let d_2 = meta.query_advice(col_m, Rotation::next());
            // d_3 is set to z1_d.
            let d_3 = meta.query_advice(col_r, Rotation::next());

            // d = d_0 + (2) d_1 + (2^2) d_2 + (2^10) d_3
            let decomposition_check =
                d - (d_0.clone() + d_1.clone() * two + d_2 * two_pow_2 + d_3 * two_pow_10);

            Constraints::with_selector(
                q_notecommit_d,
                [
                    ("bool_check d_0", bool_check(d_0)),
                    ("bool_check d_1", bool_check(d_1)),
                    ("decomposition", decomposition_check),
                ],
            )
        });

        Self {
            q_notecommit_d,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        fdi: &AssignedCell<pallas::Base, pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
        ),
        Error,
    > {
        let (d0, d1) = (
            RangeConstrained::bitrange_of(fdi.value(), 51..64),
            RangeConstrained::bitrange_of(recp.value(), 0..7),
        );
        println!("d: {:#?}", (d0.num_bits(), d1.num_bits(),));
        let d = MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "d"), [d0, d1])?;

        Ok((d, d0, d1))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        d: NoteCommitPiece,
        d_0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        d_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        d_2: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        z1_d: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        layouter.assign_region(
            || "NoteCommit MessagePiece d",
            |mut region| {
                self.q_notecommit_d.enable(&mut region, 0)?;

                d.inner()
                    .cell_value()
                    .copy_advice(|| "d", &mut region, self.col_l, 0)?;
                let d_0 = region.assign_advice(|| "d_0", self.col_m, 0, || *d_0.inner())?;
                region.assign_advice(|| "d_1", self.col_r, 0, || *d_1.inner())?;

                d_2.inner()
                    .copy_advice(|| "d_2", &mut region, self.col_m, 1)?;
                z1_d.copy_advice(|| "d_3 = z1_d", &mut region, self.col_r, 1)?;

                Ok(d_0)
            },
        )
    }
}

/// e = bits 110-253 of esk || bits 0-105 of psi (250 bits)
///   For the gate, we decompose a 10-bit boundary: e_0 || e_1
///
/// | A_6 | A_7 | A_8 | q_notecommit_e |
/// ------------------------------------
/// |  e  | e_0 | e_1 |       1        |
#[derive(Clone, Debug)]
struct DecomposeE {
    q_notecommit_e: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeE {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        two_pow_6: pallas::Base,
    ) -> Self {
        let q_notecommit_e = meta.selector();

        meta.create_gate("NoteCommit MessagePiece e", |meta| {
            let q_notecommit_e = meta.query_selector(q_notecommit_e);

            // e has been constrained to 10 bits by the Sinsemilla hash.
            let e = meta.query_advice(col_l, Rotation::cur());
            // e_0 has been constrained to 6 bits outside this gate.
            let e_0 = meta.query_advice(col_m, Rotation::cur());
            // e_1 has been constrained to 4 bits outside this gate.
            let e_1 = meta.query_advice(col_r, Rotation::cur());

            // e = e_0 + (2^6) e_1
            let decomposition_check = e - (e_0 + e_1 * two_pow_6);

            Constraints::with_selector(q_notecommit_e, Some(("decomposition", decomposition_check)))
        });

        Self {
            q_notecommit_e,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            [NoteCommitPiece; 5],
            [RangeConstrained<pallas::Base, Value<pallas::Base>>; 6],
        ),
        Error,
    > {
        let (e0, e1, e2, e3, e4, e5) = (
            RangeConstrained::bitrange_of(recp.value(), 7..67),
            RangeConstrained::bitrange_of(recp.value(), 67..127),
            RangeConstrained::bitrange_of(recp.value(), 127..187),
            RangeConstrained::bitrange_of(recp.value(), 187..247),
            RangeConstrained::bitrange_of(recp.value(), 247..255),
            RangeConstrained::bitrange_of(esk.value(), 0..2),
        );
        println!(
            "e: {:#?}",
            (
                e0.num_bits(),
                e1.num_bits(),
                e2.num_bits(),
                e3.num_bits(),
                e4.num_bits(),
                e5.num_bits(),
            )
        );
        let (ea, eb, ec, ed, ee) = (
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ea: e0"), [e0])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "eb: e1"), [e1])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ec: e2"), [e2])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ed: e3,  "), [e3])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ee: e4,e5"), [e4, e5])?,
        );

        Ok(([ea, eb, ec, ed, ee], [e0, e1, e2, e3, e4, e5]))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        e: NoteCommitPiece,
        e_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit MessagePiece e",
            |mut region| {
                self.q_notecommit_e.enable(&mut region, 0)?;

                e.inner()
                    .cell_value()
                    .copy_advice(|| "e", &mut region, self.col_l, 0)?;
                e_0.inner()
                    .copy_advice(|| "e_0", &mut region, self.col_m, 0)?;
                e_1.inner()
                    .copy_advice(|| "e_1", &mut region, self.col_r, 0)?;

                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
struct DecomposeF {
    q_notecommit_f: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeF {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        // col_z: Column<Advice>,
        // two_pow_130: Expression<pallas::Base>,
        // two_pow_250: pallas::Base,
        // two_pow_254: pallas::Base,
        // t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_f = meta.selector();

        Self {
            q_notecommit_f,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
        ),
        Error,
    > {
        //   Piece f: bits 2.252 of esk  (250 bits)
        let f0 = RangeConstrained::bitrange_of(esk.value(), 2..252);
        println!("f:{:#?}", f0.num_bits());
        let f = MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "f0"), [f0])?;

        Ok((f, f0))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        a: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: AssignedCell<pallas::Base, pallas::Base>,
        a_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_a: AssignedCell<pallas::Base, pallas::Base>,
        z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                recp.copy_advice(|| "recp", &mut region, self.col_l, 0)?;

                b_0.inner()
                    .copy_advice(|| "b_0", &mut region, self.col_m, 0)?;
                b_1.copy_advice(|| "b_1", &mut region, self.col_m, 1)?;

                // a.inner()
                //     .cell_value()
                //     .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                // a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                // z13_a.copy_advice(|| "z13_a", &mut region, self.c, 0)?;
                // z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_f.enable(&mut region, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
struct DecomposeG {
    q_notecommit_g: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeG {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        // col_z: Column<Advice>,
        // two_pow_130: Expression<pallas::Base>,
        // two_pow_250: pallas::Base,
        // two_pow_254: pallas::Base,
        // t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_g = meta.selector();

        Self {
            q_notecommit_g,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            [RangeConstrained<pallas::Base, Value<pallas::Base>>; 2],
        ),
        Error,
    > {
        //   Piece g: bits 252..255 of esk || 0-57 rho ||  (3 + 57 = 60 bits)
        let (g0, g1) = (
            RangeConstrained::bitrange_of(esk.value(), 252..255),
            RangeConstrained::bitrange_of(rho.value(), 0..57),
        );
        println!("g: {:#?}", (g0.num_bits(), g1.num_bits(),));
        let g = MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ga: g0"), [g0, g1])?;
        Ok((g, [g0, g1]))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        a: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: AssignedCell<pallas::Base, pallas::Base>,
        a_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_a: AssignedCell<pallas::Base, pallas::Base>,
        z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                recp.copy_advice(|| "recp", &mut region, self.col_l, 0)?;

                b_0.inner()
                    .copy_advice(|| "b_0", &mut region, self.col_m, 0)?;
                b_1.copy_advice(|| "b_1", &mut region, self.col_m, 1)?;

                // a.inner()
                //     .cell_value()
                //     .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                // a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                // z13_a.copy_advice(|| "z13_a", &mut region, self.c, 0)?;
                // z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_g.enable(&mut region, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
struct DecomposeH {
    q_notecommit_h: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeH {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        // col_z: Column<Advice>,
        // two_pow_130: Expression<pallas::Base>,
        // two_pow_250: pallas::Base,
        // two_pow_254: pallas::Base,
        // t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_h = meta.selector();

        Self {
            q_notecommit_h,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            [NoteCommitPiece; 4],
            [RangeConstrained<pallas::Base, Value<pallas::Base>>; 4],
        ),
        Error,
    > {
        // let (h_alf, h_num) = DecomposeH::decompose(&lc, chip.clone(), &mut lo, &rho)?;
        //   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
        let (h0, h1, h2, h3) = (
            RangeConstrained::bitrange_of(rho.value(), 57..117),
            RangeConstrained::bitrange_of(rho.value(), 117..177),
            RangeConstrained::bitrange_of(rho.value(), 177..237),
            RangeConstrained::bitrange_of(rho.value(), 237..247),
        );

        println!(
            "H:{:#?}",
            (h0.num_bits(), h1.num_bits(), h2.num_bits(), h3.num_bits(),)
        );

        let (ha, hb, hc, hd) = (
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ha: h0"), [h0])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hb: h1"), [h1])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hc: h2"), [h2])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hd"), [h3])?,
        );
        Ok(([ha, hb, hc, hd], [h0, h1, h2, h3]))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        a: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: AssignedCell<pallas::Base, pallas::Base>,
        a_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_a: AssignedCell<pallas::Base, pallas::Base>,
        z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                recp.copy_advice(|| "recp", &mut region, self.col_l, 0)?;

                b_0.inner()
                    .copy_advice(|| "b_0", &mut region, self.col_m, 0)?;
                b_1.copy_advice(|| "b_1", &mut region, self.col_m, 1)?;

                // a.inner()
                //     .cell_value()
                //     .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                // a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                // z13_a.copy_advice(|| "z13_a", &mut region, self.c, 0)?;
                // z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_h.enable(&mut region, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
struct DecomposeI {
    q_notecommit_i: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
}

impl DecomposeI {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        // col_z: Column<Advice>,
        // two_pow_130: Expression<pallas::Base>,
        // two_pow_250: pallas::Base,
        // two_pow_254: pallas::Base,
        // t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_i = meta.selector();

        Self {
            q_notecommit_i,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
        psi: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            [NoteCommitPiece; 3],
            [RangeConstrained<pallas::Base, Value<pallas::Base>>; 5],
        ),
        Error,
    > {
        // let (i_alf, i_num) = DecomposeI::decompose(&lc, chip.clone(), &mut lo, &psi)?;
        //   piece i: bits 247..255 of psi   5 bit padding (8 + 2 = 10 bits)
        let (i0, i1, i2, i3, i4) = (
            RangeConstrained::bitrange_of(rho.value(), 247..255),
            RangeConstrained::bitrange_of(psi.value(), 0..2),
            RangeConstrained::bitrange_of(psi.value(), 2..252),
            RangeConstrained::bitrange_of(psi.value(), 252..255),
            RangeConstrained::bitrange_of(Value::known(&pallas::Base::zero()), 0..7), // 7 bit padding
        );

        println!("i:{:#?}", (i0.num_bits(), i1.num_bits(),));

        // i = i0||i1
        let (ia, ib, ic) = (
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i0, i1])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i2])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i3, i4])?,
        );
        Ok(([ia, ib, ic], [i0, i1, i2, i3, i4]))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        a: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: AssignedCell<pallas::Base, pallas::Base>,
        a_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_a: AssignedCell<pallas::Base, pallas::Base>,
        z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                recp.copy_advice(|| "recp", &mut region, self.col_l, 0)?;

                b_0.inner()
                    .copy_advice(|| "b_0", &mut region, self.col_m, 0)?;
                b_1.copy_advice(|| "b_1", &mut region, self.col_m, 1)?;

                // a.inner()
                //     .cell_value()
                //     .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                // a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                // z13_a.copy_advice(|| "z13_a", &mut region, self.c, 0)?;
                // z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_i.enable(&mut region, 0)
            },
        )
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct NoteCommitConfig {
    b: DecomposeB,
    c: DecomposeC,
    d: DecomposeD,
    e: DecomposeE,
    f: DecomposeF,
    g: DecomposeG,
    h: DecomposeH,
    i: DecomposeI,
    // nd: NdCanonicity,
    // v: ValueCanonicity,
    // fdi: FdiCanonicity,
    // recp: RecpCanonicity,
    // esk: EskCanonicity,
    // rho: RhoCanonicity,
    // psi: PsiCanonicity,
    advices: [Column<Advice>; 10],
    sinsemilla_config:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
}

#[derive(Clone, Debug)]
pub struct NoteCommitChip {
    config: NoteCommitConfig,
}

impl NoteCommitChip {
    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        sinsemilla_config: SinsemillaConfig<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
        >,
    ) -> NoteCommitConfig {
        // Useful constants
        let two = pallas::Base::from(2);
        let two_pow_2 = pallas::Base::from(1 << 2);
        let two_pow_4 = two_pow_2.square();
        let two_pow_5 = two_pow_4 * two;
        let two_pow_6 = two_pow_5 * two;
        let two_pow_8 = two_pow_4.square();
        let two_pow_9 = two_pow_8 * two;
        let two_pow_10 = two_pow_9 * two;
        let two_pow_58 = pallas::Base::from(1 << 58);
        let two_pow_130 = Expression::Constant(pallas::Base::from_u128(1 << 65).square());
        let two_pow_140 = Expression::Constant(pallas::Base::from_u128(1 << 70).square());
        let two_pow_249 = pallas::Base::from_u128(1 << 124).square() * two;
        let two_pow_250 = two_pow_249 * two;
        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();

        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

        // Columns used for MessagePiece and message input gates.
        let col_l = advices[6];
        let col_m = advices[7];
        let col_r = advices[8];
        let col_z = advices[9];

        let b = DecomposeB::configure(meta, col_l, col_m, col_r, two_pow_4, two_pow_5, two_pow_6);
        let c = DecomposeC::configure(meta, col_l, col_m, col_r, two_pow_4, two_pow_5, two_pow_6);
        let d = DecomposeD::configure(meta, col_l, col_m, col_r, two, two_pow_2, two_pow_10);
        let e = DecomposeE::configure(meta, col_l, col_m, col_r, two_pow_6);
        let f = DecomposeF::configure(meta, col_l, col_m, col_r);
        let g = DecomposeG::configure(meta, col_l, col_m, col_r);
        let h = DecomposeH::configure(meta, col_l, col_m, col_r);
        let i = DecomposeI::configure(meta, col_l, col_m, col_r);

        // let nd = NdCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_4,
        //     two_pow_140.clone(),
        //     two_pow_254,
        //     t_p.clone(),
        // );
        // let v = ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58);
        // let fdi = FdiCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_4,
        //     two_pow_140.clone(),
        //     two_pow_254,
        //     t_p.clone(),
        // );

        // let recp = RecpCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_130.clone(),
        //     two_pow_250,
        //     two_pow_254,
        //     t_p.clone(),
        // );

        // let esk = EskCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_6,
        //     two_pow_140.clone(),
        //     two_pow_254,
        //     t_p.clone(),
        // );

        // let rho = RhoCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_4,
        //     two_pow_140.clone(),
        //     two_pow_254,
        //     t_p.clone(),
        // );

        // let psi = PsiCanonicity::configure(
        //     meta,
        //     col_l,
        //     col_m,
        //     col_r,
        //     col_z,
        //     two_pow_9,
        //     two_pow_130.clone(),
        //     two_pow_249,
        //     two_pow_254,
        //     t_p.clone(),
        // );

        NoteCommitConfig {
            b,
            c,
            d,
            e,
            f,
            g,
            h,
            i,
            // nd,
            // v,
            // fdi,
            // recp,
            // rho,
            // esk,
            // psi,
            advices,
            sinsemilla_config,
        }
    }

    pub(in crate::circuit) fn construct(config: NoteCommitConfig) -> Self {
        Self { config }
    }
}

pub(in crate::circuit) mod gadgets {
    use halo2_proofs::circuit::{Chip, Value};

    use super::*;

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn note_commit(
        mut lo: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        ecc_chip: EccChip<OrchardFixedBases>,
        note_commit_chip: NoteCommitChip,
        nd: AssignedCell<pallas::Base, pallas::Base>,
        v: AssignedCell<NoteValue, pallas::Base>,
        fdi: AssignedCell<pallas::Base, pallas::Base>,
        recp: AssignedCell<pallas::Base, pallas::Base>,
        esk: AssignedCell<pallas::Base, pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        rcm: ScalarFixed<pallas::Affine, EccChip<OrchardFixedBases>>,
    ) -> Result<Point<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
        // Headstash NoteCommitment Message: nd(254) || v(64) || fdi(64) || recp(254) || esk(254) || rho(254) || psi(254)
        // Total: 1398 bits
        //
        // Optimized decomposition for Sinsemilla (250 bit pieces, 10-bit limb alignment):
        //   Piece g: bits 252..255 of esk || 0-57 rho ||  (3 + 57 = 60 bits)
        //   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
        //   piece i: bits 56-116 of psi  || 117-177 of psi || 178..-238 pdi || 239..=254 of rho || 5 bit padding (60+ 60+ 60 + 15 + 5 = 200 bits)
        let lc = chip.config().lookup_config();
        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));

        // Piece a: bits 0-249 of nd (250 bits)
        let a = MessagePiece::from_subpieces(
            chip.clone(),
            lo.namespace(|| "piece_a: nd[0..250)"),
            [RangeConstrained::bitrange_of(nd.value(), 0..250)],
        )?;

        // Piece b: bits 250..255 of nd || 0..55 of v  (5 + 55 = 60 bits)
        let (b, b0, b1) = DecomposeB::decompose(&lc, chip.clone(), &mut lo, &nd, &v)?;

        // Piece c: bits 55-64 of v || 0-51 of fdi  (9 + 51 = 60 bits)
        let (c, c0, c1) = DecomposeC::decompose(&lc, chip.clone(), &mut lo, &v, &fdi)?;

        // Piece d: bits  51-64 of fdi || 0..7 of recp (13 + 7 = 20 bits)
        let (d, d0, d1) = DecomposeD::decompose(&lc, chip.clone(), &mut lo, &fdi, &recp)?;
        // Piece e: bits 7..67 of recp (60) || 67..127 of recp (60)  || 127..187 of recp (60)  || 187..247 of recp  (20) || 247..255 recp 8 || 0..2 esk
        let ([ea, eb, ec, ed, ee], [e0, e1, e2, e3, e4, e5]) =
            DecomposeE::decompose(&lc, chip.clone(), &mut lo, &recp, &esk)?;
        // Piece f: bits 2.252 of esk  (250 bits)
        let (f, f0) = DecomposeF::decompose(&lc, chip.clone(), &mut lo, &esk)?;

        let (g, ([go, g1])) = DecomposeG::decompose(&lc, chip.clone(), &mut lo, &esk, &rho)?;
        let ([ha, hb, hc, hd], ([h0, h1, h2, h3])) =
            DecomposeH::decompose(&lc, chip.clone(), &mut lo, &esk, &rho)?;
        let ([ia, ib, ic], ([i0, i1, i2, i3, i4])) =
            DecomposeI::decompose(&lc, chip.clone(), &mut lo, &rho, &psi)?;

        // cm = NoteCommit^Headstash_rcm( nd || i2lebsp_{64}(v) || i2lebsp_{64}(fdi) || recp || esk  || rho || psi )
        //
        // `cm = ⊥` is handled internally to `CommitDomain::commit`: incomplete addition
        // constraints allows ⊥ to occur, and then during synthesis it detects these edge
        // cases and raises an error (aborting proof creation).
        let (cm, zs) = {
            let message = Message::from_pieces(
                chip.clone(),
                vec![
                    a.clone(),
                    b.clone(),
                    c.clone(),
                    d.clone(),
                    ea.clone(),
                    eb.clone(),
                    ec.clone(),
                    ed.clone(),
                    ee.clone(),
                    f.clone(),
                    g.clone(),
                    ha.clone(),
                    hb.clone(),
                    hc.clone(),
                    hd.clone(),
                    ia.clone(),
                    ib.clone(),
                    ic.clone(),
                ],
            );
            let domain = CommitDomain::new(chip, ecc_chip, &OrchardCommitDomains::NoteCommit);
            domain.commit(lo.namespace(|| "Process NoteCommit inputs"), message, rcm)?
        };

        // `CommitDomain::commit` returns the running sum for each `MessagePiece`. Grab
        // the outputs that we will need for canonicity checks.
        //  println!("{:#?}", zs );
        let z13_a = zs[0][13].clone();
        // let z13_c = zs[2][13].clone();
        let z1_d = zs[3][1].clone();
        // let z13_f = zs[5][13].clone();
        let z1_g = zs[6][1].clone();
        let g_2 = z1_g.clone();
        // let z13_g = zs[6][13].clone();

        // Finally, assign vs to all of the NoteCommit regions.
        let cfg = note_commit_chip.config;

        Ok(cm)
    }
}

#[cfg(test)]
mod tests {
    use core::{iter, u64};
    use std::{println, vec::Vec};

    use super::NoteCommitConfig;
    use crate::{
        circuit::{
            gadget::assign_free_advice,
            note_commit::{gadgets, NoteCommitChip},
        },
        constants::{
            fixed_bases::NOTE_COMMITMENT_PERSONALIZATION, OrchardCommitDomains, OrchardFixedBases,
            OrchardHashDomains, L_ORCHARD_BASE, L_VALUE, T_Q,
        },
        value::NoteValue,
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::{
            chip::{SinsemillaChip, SinsemillaConfig},
            primitives::CommitDomain,
            Message, MessagePiece,
        },
        utilities::{
            lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
            FieldValue, RangeConstrained,
        },
    };

    use ff::{Field, PrimeField, PrimeFieldBits};
    use group::Curve;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::{arithmetic::CurveAffine, pallas};

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn decomposition_values() {
        let u = u64::MAX;

        for i in &u.to_le_bytes()[0..7] {
            assert_eq!(i.to_le_bytes().len(), 1);
            println!("H:{:#?}", i);
            println!("H:{:#?}", u);
        }
    }

    #[test]
    fn note_commit() {
        #[derive(Default)]
        struct MyCircuit {
            nd: Value<pallas::Base>,
            v: Value<NoteValue>,
            fdi: Value<pallas::Base>,
            recp: Value<pallas::Base>,
            esk: Value<pallas::Base>,
            rho: Value<pallas::Base>,
            psi: Value<pallas::Base>,
        }

        impl halo2_proofs::plonk::Circuit<pallas::Base> for MyCircuit {
            type Config = (NoteCommitConfig, EccConfig<OrchardFixedBases>);
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

                // Shared fixed column for loading constants.
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
                    advices[2],
                    lagrange_coeffs[0],
                    lookup,
                    range_check,
                    false,
                );
                let note_commit_config =
                    NoteCommitChip::configure(meta, advices, sinsemilla_config);

                let ecc_config = EccChip::<OrchardFixedBases>::configure(
                    meta,
                    advices,
                    lagrange_coeffs,
                    range_check,
                );

                (note_commit_config, ecc_config)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut lo: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (note_commit_config, ecc_config) = config;

                // Load the Sinsemilla generator lookup table used by the whole circuit.
                SinsemillaChip::<
                OrchardHashDomains,
                OrchardCommitDomains,
                OrchardFixedBases,
            >::load(note_commit_config.sinsemilla_config.clone(), &mut lo)?;

                // Construct a Sinsemilla chip
                let sinsemilla_chip =
                    SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

                // Construct an ECC chip
                let ecc_chip = EccChip::construct(ecc_config);

                // Construct a NoteCommit chip
                let note_commit_chip = NoteCommitChip::construct(note_commit_config.clone());

                // Witness nd.
                let nd = assign_free_advice(
                    lo.namespace(|| "witness nd"),
                    note_commit_config.advices[0],
                    self.nd,
                )?;

                // // Witness a random non-negative u64 note v
                // // A note v cannot be negative.

                let v = assign_free_advice(
                    lo.namespace(|| "witness v"),
                    note_commit_config.advices[0],
                    self.v,
                )?;

                // Witness fdi.
                let fdi = assign_free_advice(
                    lo.namespace(|| "witness fdi"),
                    note_commit_config.advices[0],
                    self.fdi,
                )?;

                // Witness recp.
                let recp = assign_free_advice(
                    lo.namespace(|| "witness recp"),
                    note_commit_config.advices[0],
                    self.recp,
                )?;
                // Witness esk.
                let esk = assign_free_advice(
                    lo.namespace(|| "witness esk"),
                    note_commit_config.advices[0],
                    self.esk,
                )?;

                // Witness rho
                let rho = assign_free_advice(
                    lo.namespace(|| "witness rho"),
                    note_commit_config.advices[0],
                    self.rho,
                )?;

                // Witness psi
                let psi = assign_free_advice(
                    lo.namespace(|| "witness psi"),
                    note_commit_config.advices[0],
                    self.psi,
                )?;

                let rcm = pallas::Scalar::random(OsRng);
                let rcm_gadget =
                    ScalarFixed::new(ecc_chip.clone(), lo.namespace(|| "rcm"), Value::known(rcm))?;

                let cm = gadgets::note_commit(
                    lo.namespace(|| "Hash NoteCommit pieces"),
                    sinsemilla_chip,
                    ecc_chip.clone(),
                    note_commit_chip,
                    nd,
                    v,
                    fdi,
                    recp,
                    esk,
                    rho,
                    psi,
                    rcm_gadget,
                )?;
                let expected_cm = {
                    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
                    // Hash nd || i2lebsp_{64}(v) || i2lebsp_{64}(fdi) || recp || esk || rho || psi || 7 bit padding

                    // Debug: Print expected test values
                    // println!("\n=== TEST EXPECTED VALUES ===");
                    // self.nd.map(|v| println!("test nd: {:?}", v));
                    // self.v.map(|v| println!("test v: {:?}", v));
                    // self.fdi.map(|v| println!("test fdi: {:?}", v));
                    // self.recp.map(|v| println!("test recp: {:?}", v));
                    // self.esk.map(|v| println!("test esk: {:?}", v));
                    // self.rho.map(|v| println!("test rho: {:?}", v));
                    // self.psi.map(|v| println!("test psi: {:?}", v));

                    let point = self
                        .nd
                        .zip(self.v)
                        .zip(self.fdi.zip(self.recp.zip(self.esk)))
                        .zip(self.rho.zip(self.psi))
                        .map(|(((nd, v), (fdi, (recp, esk))), (rho, psi))| {
                            domain
                                .commit(
                                    nd.to_le_bits()
                                        .iter()
                                        .by_vals()
                                        .take(L_ORCHARD_BASE)
                                        .chain(v.to_le_bits().iter().by_vals().take(L_VALUE))
                                        .chain(fdi.to_le_bits().iter().by_vals().take(L_VALUE))
                                        .chain(
                                            recp.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            esk.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            rho.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            psi.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            pallas::Base::zero()
                                                .to_le_bits()
                                                .iter()
                                                .by_vals()
                                                .take(7),
                                        ),
                                    &rcm,
                                )
                                .unwrap()
                                .to_affine()
                        });
                    NonIdentityPoint::new(ecc_chip, lo.namespace(|| "witness cm"), point)?
                };
                println!("{:#?}", cm.extract_p());
                println!("{:#?}", expected_cm.extract_p());
                println!("cm == synth");
                cm.constrain_equal(lo.namespace(|| "cm == expected cm"), &expected_cm)
            }
        }

        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
        // Test different vs of `ak`, `nk`
        let circuits = [
            // `gd_x` = -1, `pkd_x` = -1 (these have to be x-coordinates of curve points)
            // `rho` = 0, `psi` = 0
            MyCircuit {
                nd: Value::known(pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::zero()),
                psi: Value::known(pallas::Base::zero()),
            },
            // // `rho` = T_Q - 1, `psi` = T_Q - 1
            MyCircuit {
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128(T_Q - 1)),
                psi: Value::known(pallas::Base::from_u128(T_Q - 1)),
            },
            // // `rho` = T_Q, `psi` = T_Q
            MyCircuit {
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128(T_Q)),
                psi: Value::known(pallas::Base::from_u128(T_Q)),
            },
            // `rho` = 2^127 - 1, `psi` = 2^127 - 1
            MyCircuit {
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
                psi: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
            },
            // `rho` = 2^127, `psi` = 2^127
            MyCircuit {
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128(1 << 127)),
                psi: Value::known(pallas::Base::from_u128(1 << 127)),
            },
            // // `rho` = 2^254 - 1, `psi` = 2^254 - 1
            MyCircuit {
                rho: Value::known(two_pow_254 - pallas::Base::one()),
                psi: Value::known(two_pow_254 - pallas::Base::one()),
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
            },
            // // `rho` = 2^254, `psi` = 2^254
            MyCircuit {
                rho: Value::known(two_pow_254),
                psi: Value::known(two_pow_254),
                nd: Value::known(-pallas::Base::one()),
                v: Value::known(NoteValue::one()),
                fdi: Value::known(pallas::Base::one()),
                recp: Value::known(-pallas::Base::one()),
                esk: Value::known(pallas::Base::one()),
            },
        ];

        for circuit in circuits.iter() {
            let prover = MockProver::<pallas::Base>::run(11, circuit, vec![]).unwrap();
            #[cfg(feature = "dev-graph")]
            {
                use plotters::prelude::*;
                let root = BitMapBackend::new("note-commit.png", (1024, 768)).into_drawing_area();
                halo2_proofs::dev::CircuitLayout::default()
                    // You can optionally render only a section of the circuit.
                    .view_width(0..33)
                    .view_height(0..1024)
                    .render(13, circuit, &root) // 13 is the k value (number of rows)
                    .unwrap();
            }
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
