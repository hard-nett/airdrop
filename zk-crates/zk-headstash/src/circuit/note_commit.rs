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

/// b = b0 || b1  = (bits 250..=254 of nd) || (bits 0..=54 of v)
///
/// | A_6 | A_7 | A_8 | q_notecommit_b |
/// ------------------------------------
/// |  b  | b0  | b1  |       1        |
///
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
        two_pow_5: pallas::Base,
    ) -> Self {
        let q_notecommit_b = meta.selector();

        // TODO: do we need any bool checks for decomposition constraint accuracy, or do we accomplish this logics functionality in the circuit
        meta.create_gate("NoteCommit MessagePiece b", |meta| {
            let q_notecommit_b = meta.query_selector(q_notecommit_b);

            // b has been constrained to 60 bits by the Sinsemilla hash.
            let b = meta.query_advice(col_l, Rotation::cur());
            // b0 has been constrained to be 5 bits outside this gate.
            let b0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains to be 55 bits outside this gate.
            let b1 = meta.query_advice(col_r, Rotation::cur());

            // b = b0 + (2^1) b1 + (2^5)
            let decomposition_check = b - (b0 + b1.clone() * two_pow_5);

            Constraints::with_selector(
                q_notecommit_b,
                [
                    // ("bool_check b1", bool_check(b1)),
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
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        nd: &AssignedCell<pallas::Base, pallas::Base>,
        v: &AssignedCell<NoteValue, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,                                     // b
            RangeConstrained<pallas::Base, Value<pallas::Base>>, // b0
            RangeConstrained<pallas::Base, Value<pallas::Base>>, // b1
        ),
        Error,
    > {
        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));

        let b0 = RangeConstrained::bitrange_of(nd.value(), 250..255); // 5 nd
        let b1 = RangeConstrained::bitrange_of(value_val.value(), 0..55); // 55 v
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
        lo: &mut impl Layouter<pallas::Base>,
        b: NoteCommitPiece,
        b0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        b1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece b",
            |mut region| {
                self.q_notecommit_b.enable(&mut region, 0)?;

                // Assign the full 60-bit value b
                b.inner()
                    .cell_value()
                    .copy_advice(|| "b", &mut region, self.col_l, 0)?;

                // Assign b0 (5 bits from nd[250..255))
                let b0 = region.assign_advice(|| "b0", self.col_m, 0, || *b0.inner())?;

                // Assign b1 (55 bits from v[0..55))
                let b1 = region.assign_advice(|| "b1", self.col_r, 0, || *b1.inner())?;

                Ok([b0, b1])
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
        two_pow_9: pallas::Base,
    ) -> Self {
        let q_notecommit_c = meta.selector();

        meta.create_gate("NoteCommit MessagePiece c: configure", |meta| {
            let q_notecommit_c = meta.query_selector(q_notecommit_c);
            // Piece c: bits 55-64 of v || 0-51 of fdi  (9 + 51 = 60 bits)
            let c = meta.query_advice(col_l, Rotation::cur());
            // c0 has been constrained to be 9 bits outside this gate.
            let c0 = meta.query_advice(col_m, Rotation::cur());
            // c1 has been constrained to be 51 bits outside this gate.
            let c1 = meta.query_advice(col_r, Rotation::cur());

            // c = c0 + (2^9) c1 + (2^51)
            let decomposition_check = c - (c0 + c1.clone() * two_pow_9);

            Constraints::with_selector(
                q_notecommit_c,
                [
                    ("bool_check c1", bool_check(c1)),
                    // ("bool_check c_2", bool_check(c_2)),
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
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        v: &AssignedCell<NoteValue, pallas::Base>,
        fdi: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>, // c0
            RangeConstrained<pallas::Base, Value<pallas::Base>>, // c1
        ),
        Error,
    > {
        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));
        // Piece c: bits 55-64 of v || 0-51 of fdi  (9 + 51 = 60 bits)
        let (c, c0, c1) = {
            let c0 = RangeConstrained::bitrange_of(value_val.value(), 55..64); // 9 v
            let c1 = RangeConstrained::bitrange_of(fdi.value(), 0..51); // 51 fdi
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
        lo: &mut impl Layouter<pallas::Base>,
        c: NoteCommitPiece,
        c0: RangeConstrained<pallas::Base, Value<pasta_curves::Fp>>,
        c1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece c: assign",
            |mut region| {
                self.q_notecommit_c.enable(&mut region, 0)?;

                c.inner()
                    .cell_value()
                    .copy_advice(|| "c", &mut region, self.col_l, 0)?;
                let c0 = region.assign_advice(|| "c", self.col_m, 0, || *c0.inner())?;
                let c1 = region.assign_advice(|| "c1", self.col_r, 0, || *c1.inner())?;

                Ok([c0, c1])
            },
        )
    }
}

// Piece d: bits  51-64 of fdi || 0..7 of recp (13 + 7 = 20 bits)
///   For the gate, we decompose a 10-bit boundary: d0 || d1
///
/// | A_6 | A_7 | A_8 | q_notecommit_d |
/// ------------------------------------
/// |  d  | d0 | d1 |       1        |
/// |     | d2 | d_3 |       0        |
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
    ) -> Self {
        let q_notecommit_d = meta.selector();

        meta.create_gate("NoteCommit MessagePiece d", |meta| {
            let q_notecommit_d = meta.query_selector(q_notecommit_d);

            // d has been constrained to 20 bits by the Sinsemilla hash.
            let d = meta.query_advice(col_l, Rotation::cur());
            // This gate constrains d0 to be boolean.
            let d0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains d1 to be boolean.
            let d1 = meta.query_advice(col_r, Rotation::cur());

            // d = d0 + (2) d1 + (2^2) d2 + (2^10) d_3
            let decomposition_check = d - (d0.clone() + d1.clone() * two);

            Constraints::with_selector(
                q_notecommit_d,
                [
                    ("bool_check d0", bool_check(d0)),
                    ("bool_check d1", bool_check(d1)),
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
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
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
        // Piece d: bits  51-64 of fdi || 0..7 of recp (13 + 7 = 20 bits)
        let (d0, d1) = (
            RangeConstrained::bitrange_of(fdi.value(), 51..64), // 13 fdi
            RangeConstrained::bitrange_of(recp.value(), 0..7),  // 7 recp
        );
        println!("d: {:#?}", (d0.num_bits(), d1.num_bits(),));
        let d = MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "d"), [d0, d1])?;

        Ok((d, d0, d1))
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        d: NoteCommitPiece,
        d0: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        d1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        z1_d: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece d",
            |mut region| {
                self.q_notecommit_d.enable(&mut region, 0)?;
                d.inner()
                    .cell_value()
                    .copy_advice(|| "d", &mut region, self.col_l, 0)?;
                let d0 = region.assign_advice(|| "d0", self.col_m, 0, || *d0.inner())?;
                region.assign_advice(|| "d1", self.col_r, 0, || *d1.inner())?;
                z1_d.copy_advice(|| "d_3 = z1_d", &mut region, self.col_r, 1)?;

                Ok(d0)
            },
        )
    }
}

/// Piece e: bits 7..67 of recp (60) || 67..127 of recp (60) || 127..187 of recp (60) || 187..247 of recp (60) || 247..255 recp (8) || 0..2 esk (2)
///   Total: 250 bits, decomposed into 5 message pieces and 6 sub-components
///
/// | A_6 | A_7 | A_8 | q_notecommit_e |
/// ------------------------------------
/// |  e  | ea  | eb  |       1        |  (Row 0: full value, first two 60-bit pieces)
/// |     | ec  | ed  |       0        |  (Row 1: next two 60-bit pieces)
/// | e4  | e5  |     |       0        |  (Row 2: last 8-bit and 2-bit components)
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
        two_pow_60: pallas::Base,
    ) -> Self {
        let q_notecommit_e = meta.selector();

        meta.create_gate("NoteCommit MessagePiece e", |meta| {
            let q_notecommit_e = meta.query_selector(q_notecommit_e);

            // e is the full 251-bit value
            let e = meta.query_advice(col_l, Rotation::cur());
            // e_0: bits 7..67 of recp (60 bits)
            let e_0 = meta.query_advice(col_m, Rotation::cur());
            // e_1: bits 67..127 of recp (60 bits)
            let e_1 = meta.query_advice(col_r, Rotation::cur());
            // e_2: bits 127..187 of recp (60 bits)
            let e_2 = meta.query_advice(col_m, Rotation::next());
            // e_3: bits 187..247 of recp (60 bits)
            let e_3 = meta.query_advice(col_r, Rotation::next());
            // e_4: bits 247..255 of recp (8 bits)
            let e_4 = meta.query_advice(col_l, Rotation(2));
            // e_5: bits 0..2 of esk (2 bits)
            let e_5 = meta.query_advice(col_m, Rotation(2));

            // e = e_0 + 2^60 * e_1 + 2^120 * e_2 + 2^180 * e_3 + 2^240 * e_4 + 2^248 * e_5
            let two_pow_120 = two_pow_60.square();
            let two_pow_180 = two_pow_60 * two_pow_120;
            let two_pow_240 = two_pow_120.square();
            let two_pow_248 = two_pow_240 * pallas::Base::from(1u64 << 8);

            let decomposition_check = e
                - (e_0
                    + e_1 * two_pow_60
                    + e_2 * two_pow_120
                    + e_3 * two_pow_180
                    + e_4 * two_pow_240
                    + e_5 * two_pow_248);

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
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
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
        // Piece e: bits 7..67 of recp (60) || 67..127 of recp (60)  || 127..187 of recp (60)  || 187..247 of recp  (20) || 247..255 recp 8 || 0..2 esk
        let (e0, e1, e2, e3, e4, e5) = (
            RangeConstrained::bitrange_of(recp.value(), 7..67), // 60 recp
            RangeConstrained::bitrange_of(recp.value(), 67..127), // 60 recp
            RangeConstrained::bitrange_of(recp.value(), 127..187), // 60 recp
            RangeConstrained::bitrange_of(recp.value(), 187..247), // 60 recp
            RangeConstrained::bitrange_of(recp.value(), 247..255), // 8 recp
            RangeConstrained::bitrange_of(esk.value(), 0..2),   // 2 esk
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
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ed: e3"), [e3])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ee: e4,e5"), [e4, e5])?,
        );

        Ok(([ea, eb, ec, ed, ee], [e0, e1, e2, e3, e4, e5]))
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        e_pieces: [NoteCommitPiece; 5], // [ea, eb, ec, ed, ee]
        e_ranges: [RangeConstrained<pallas::Base, Value<pallas::Base>>; 6], // [e0, e1, e2, e3, e4, e5]
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 2], Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece e",
            |mut region| {
                let [ea, eb, ec, ed, ee] = &e_pieces;
                let [e0, e1, e2, e3, e4, e5] = e_ranges;
                // Enable selector only on the first row
                self.q_notecommit_e.enable(&mut region, 0)?;
                // copy_advice from all piecies of e into table

                // assign advices as expected for our table

                // // Calculate the full e value from all pieces
                // e = e0 + 2^60 * e1 + 2^120 * e2 + 2^180 * e3 + 2^240 * e4 + 2^248 * e5
                let e_full = {
                    let two_60 = pallas::Base::from_u128(1u128 << 60);
                    let two_120 = two_60.square();
                    let two_180 = two_60 * two_120;
                    let two_240 = two_120.square();
                    let two_248 = two_240 * pallas::Base::from(1u64 << 8);

                    e0.inner()
                        + e1.inner() * Value::known(two_60)
                        + e2.inner() * Value::known(two_120)
                        + e3.inner() * Value::known(two_180)
                        + e4.inner() * Value::known(two_240)
                        + e5.inner() * Value::known(two_248)
                };

                // Row 0: e (full value), ea (60 bits), eb (60 bits)
                region.assign_advice(|| "e", self.col_l, 0, || e_full)?;

                // ea (e0)
                ea.inner()
                    .cell_value()
                    .copy_advice(|| "e_0 (ea)", &mut region, self.col_m, 0)?;

                // eb (e1)
                eb.inner()
                    .cell_value()
                    .copy_advice(|| "e_1 (eb)", &mut region, self.col_r, 0)?;

                // ec (e2)
                ec.inner()
                    .cell_value()
                    .copy_advice(|| "e_2 (ec)", &mut region, self.col_m, 1)?;

                // Copy message piece ed (e3)
                ed.inner()
                    .cell_value()
                    .copy_advice(|| "e_3 (ed)", &mut region, self.col_r, 1)?;

                // Row 2: ee's components need to be assigned separately
                // ee = e4 || e5 (8 bits || 2 bits)
                let e4_cell =
                    region.assign_advice(|| "e_4", self.col_l, 2, || *e_ranges[4].inner())?;
                let e5_cell =
                    region.assign_advice(|| "e_5", self.col_m, 2, || *e_ranges[5].inner())?;

                Ok([e4_cell, e5_cell])
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

//   Piece g: bits 252..255 of esk || 0-57 rho ||  (3 + 57 = 60 bits)
impl DecomposeG {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
    ) -> Self {
        let q_notecommit_g = meta.selector();

        meta.create_gate("NoteCommit MessagePiece e", |meta| {
            let q_notecommit_e = meta.query_selector(q_notecommit_g);
            let two_3 = pallas::Base::from_u128(1u128 << 3);
            let two_57 = pallas::Base::from_u128(1u128 << 57);
            // g is the full 60-bit value
            let g = meta.query_advice(col_l, Rotation::cur());
            // g0: bits 252..255 of esk (3 bits)
            let g0 = meta.query_advice(col_m, Rotation::cur());
            // g1: bits 0..57 of rho (57 bits)
            let g1 = meta.query_advice(col_r, Rotation::cur());

            let decomposition_check = g - (g0 + g1 * two_57);

            Constraints::with_selector(q_notecommit_e, Some(("decomposition", decomposition_check)))
        });

        Self {
            q_notecommit_g,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
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
            RangeConstrained::bitrange_of(esk.value(), 252..255), // 3
            RangeConstrained::bitrange_of(rho.value(), 0..57),    // 57
        );
        println!("g: {:#?}", (g0.num_bits(), g1.num_bits(),));
        let g = MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ga: g0"), [g0, g1])?;
        Ok((g, [g0, g1]))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
        g: NoteCommitPiece,
        g0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        g1: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                esk.copy_advice(|| "esk", &mut region, self.col_l, 0)?;
                rho.copy_advice(|| "rho", &mut region, self.col_m, 0)?;
                g0.inner()
                    .copy_advice(|| "g0", &mut region, self.col_l, 1)?;
                g1.copy_advice(|| "g1", &mut region, self.col_m, 1)?;

                self.q_notecommit_g.enable(&mut region, 0)
            },
        )
    }
}

//   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
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

        meta.create_gate("NoteCommit MessagePiece e", |meta| {
            let q_notecommit_h = meta.query_selector(q_notecommit_h);
            //   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
            let two_pow_60 = pallas::Base::from(1u64 << 60);
            let two_pow_120 = two_pow_60.square();
            let two_pow_180 = two_pow_60 * two_pow_120;

            // h is the full 190-bit value
            let h = meta.query_advice(col_l, Rotation::cur());
            // h0: bits 57..117 of rho (60 bits)
            let h0 = meta.query_advice(col_m, Rotation::cur());
            // h1: bits 117..177 of rho (60 bits)
            let h1 = meta.query_advice(col_r, Rotation::cur());
            // h2: bits 177..237 of rho (60 bits)
            let h2 = meta.query_advice(col_m, Rotation::next());
            // e_3: bits 237..247 of rho (10 bits)
            let h3 = meta.query_advice(col_r, Rotation::next());

            // h = h0 + 2^60 * h1 + 2^120 * h2 + 2^180 * h3
            let decomposition_check =
                h - (h0 + h1 * two_pow_60 + h2 * two_pow_120 + h3 * two_pow_180);

            Constraints::with_selector(
                q_notecommit_h,
                Some(("h decomposition", decomposition_check)),
            )
        });

        Self {
            q_notecommit_h,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        lo: &mut impl Layouter<pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            [NoteCommitPiece; 4],
            [RangeConstrained<pallas::Base, Value<pallas::Base>>; 4],
        ),
        Error,
    > {
        //   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
        let (h0, h1, h2, h3) = (
            RangeConstrained::bitrange_of(rho.value(), 57..117), // 60 rho
            RangeConstrained::bitrange_of(rho.value(), 117..177), // 60 rho
            RangeConstrained::bitrange_of(rho.value(), 177..237), // 60 rho
            RangeConstrained::bitrange_of(rho.value(), 237..247), // 10 rho
        );

        println!(
            "H:{:#?}",
            (h0.num_bits(), h1.num_bits(), h2.num_bits(), h3.num_bits())
        );

        let (ha, hb, hc, hd) = (
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ha: h0"), [h0])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hb: h1"), [h1])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hc: h2"), [h2])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "hd"), [h3])?,
        );
        Ok(([ha, hb, hc, hd], [h0, h1, h2, h3]))
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        h_pieces: [NoteCommitPiece; 4], // [ha, hb, hc, hd]
        h_ranges: [RangeConstrained<pallas::Base, Value<pallas::Base>>; 4], // [h0, h1, h2, h3]
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 4], Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece h",
            |mut region| {
                // Enable selector only on the first row
                self.q_notecommit_h.enable(&mut region, 0)?;

                // Piece h: bits 57-117 of rho || 117-177 of rho || 177-237 of rho || 237-247 of rho
                // (60 + 60 + 60 + 10 = 190 bits)

                // Calculate the full h value from all pieces
                // h = h0 + 2^60 * h1 + 2^120 * h2 + 2^180 * h3
                let h_full = {
                    let two_60 = pallas::Base::from_u128(1u128 << 60);
                    let two_120 = two_60.square();
                    let two_180 = two_60 * two_120;

                    h_ranges[0].inner().value()
                        + h_ranges[1].inner().value() * Value::known(two_60)
                        + h_ranges[2].inner().value() * Value::known(two_120)
                        + h_ranges[3].inner().value() * Value::known(two_180)
                };

                // Row 0: h (full 190-bit value), h0 (60 bits), h1 (60 bits)
                // Assign the full h value
                region.assign_advice(|| "h", self.col_l, 0, || h_full)?;

                // Copy the message pieces ha and hb (which are already constrained by Sinsemilla)
                h_pieces[0].inner().cell_value().copy_advice(
                    || "h0",
                    &mut region,
                    self.col_m,
                    0,
                )?;
                h_pieces[1].inner().cell_value().copy_advice(
                    || "h1",
                    &mut region,
                    self.col_r,
                    0,
                )?;

                // Row 1: empty, h2 (60 bits), h3 (10 bits)
                // Copy the message pieces hc and hd
                h_pieces[2].inner().cell_value().copy_advice(
                    || "h2",
                    &mut region,
                    self.col_m,
                    1,
                )?;
                let h3_cell = h_pieces[3].inner().cell_value().copy_advice(
                    || "h3",
                    &mut region,
                    self.col_r,
                    1,
                )?;

                // Return the cells (we can return the copied cells if needed)
                Ok([
                    h_pieces[0].inner().cell_value().clone(),
                    h_pieces[1].inner().cell_value().clone(),
                    h_pieces[2].inner().cell_value().clone(),
                    h_pieces[3].inner().cell_value().clone(),
                ])
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
    ) -> Self {
        let q_notecommit_i = meta.selector();

        meta.create_gate("NoteCommit MessagePiece i", |meta| {
            let q_notecommit_i = meta.query_selector(q_notecommit_i);

            let two_3 = pallas::Base::from(1u64 << 3);
            let two_8 = pallas::Base::from(1u64 << 8);

            // ia: bits 247..255 of rho || 0..2 of psi (8 + 2 = 10 bits)
            let ia = meta.query_advice(col_l, Rotation::cur());
            // ib: bits 2..252 of psi (250 bits)
            let ib = meta.query_advice(col_m, Rotation::cur());
            // ic: bits 252..255 of psi || 7 bits padding (3 + 7 = 10 bits)
            let ic = meta.query_advice(col_r, Rotation::cur());

            // Row 1: Component bits
            // i0: bits 247..255 of rho (8 bits)
            let i0 = meta.query_advice(col_l, Rotation::next());
            // i1: bits 0..2 of psi (2 bits)
            let i1 = meta.query_advice(col_m, Rotation::next());
            // i2: bits 2..252 of psi (250 bits)
            let i2 = meta.query_advice(col_r, Rotation::next());

            let i3 = meta.query_advice(col_l, Rotation::next());
            // i4: 7 bits of padding
            let i4 = meta.query_advice(col_m, Rotation::next());

            // Decomposition constraints:
            // ia = i0 + 2^8 * i1
            let ia_check = ia - (i0 + i1 * two_8);

            // ib = i2
            let ib_check = ib - i2;

            // ic = i3 + 2^3 * i4
            let ic_check = ic - (i3 + i4 * two_3);

            Constraints::with_selector(
                q_notecommit_i,
                [
                    ("ia decomposition", ia_check),
                    ("ib decomposition", ib_check),
                    ("ic decomposition", ic_check),
                ],
            )
        });

        Self {
            q_notecommit_i,
            col_l,
            col_m,
            col_r,
        }
    }

    #[allow(clippy::type_complexity)]
    fn decompose(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
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
        //   piece ia,ib,ic: || 247..255 rho || 0..2 of psi || 2..252 of psi || 252..255 of psi || 7 bit padding (8+ 2+ 250 + 3 + 7 = (10,250,10) bits)
        let (i0, i1, i2, i3, i4) = (
            RangeConstrained::bitrange_of(rho.value(), 247..255), // 8
            RangeConstrained::bitrange_of(psi.value(), 0..2),     // 2
            RangeConstrained::bitrange_of(psi.value(), 2..252),   // 250
            RangeConstrained::bitrange_of(psi.value(), 252..255), // 3
            RangeConstrained::bitrange_of(Value::known(&pallas::Base::zero()), 0..7), // 7
        );

        println!(
            "i:{:#?}",
            (
                i0.num_bits(),
                i1.num_bits(),
                i2.num_bits(),
                i3.num_bits(),
                i4.num_bits()
            )
        );

        //   piece ia: bits 247..255 of rho  || 0..2 of psi (8 + 2 = 10 bits)
        //   piece ib: 250 bits
        //   piece ic: bits 252.255 psi || 0..7 padding (3 + 2 = 10 bits)
        let (ia, ib, ic) = (
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i0, i1])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i2])?,
            MessagePiece::from_subpieces(chip.clone(), lo.namespace(|| "ia: i0"), [i3, i4])?,
        );
        Ok(([ia, ib, ic], [i0, i1, i2, i3, i4]))
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        i_alf: [NoteCommitPiece; 3], // [ia, ib, ic]
        i_num: [RangeConstrained<pallas::Base, Value<pallas::Base>>; 5],
    ) -> Result<[AssignedCell<pallas::Base, pallas::Base>; 5], Error> {
        lo.assign_region(
            || "NoteCommit MessagePiece i",
            |mut region| {
                // Enable selector only on the first row
                self.q_notecommit_i.enable(&mut region, 0)?;

                // Row 0: ia, ib, ic (the three message pieces) - copy from NoteCommitPieces
                i_alf[0]
                    .inner()
                    .cell_value()
                    .copy_advice(|| "ia", &mut region, self.col_l, 0)?;
                i_alf[1]
                    .inner()
                    .cell_value()
                    .copy_advice(|| "ib", &mut region, self.col_m, 0)?;
                i_alf[2]
                    .inner()
                    .cell_value()
                    .copy_advice(|| "ic", &mut region, self.col_r, 0)?;

                // Row 1: i0, i1, i2 (component bits)
                let i0 = region.assign_advice(|| "i0  ", self.col_l, 1, || *i_num[0].inner())?;
                let i1 = region.assign_advice(|| "i1  )", self.col_m, 1, || *i_num[1].inner())?;
                let i2 = region.assign_advice(|| "i2  ", self.col_r, 1, || *i_num[2].inner())?;

                // Row 2: i3, i4 (3-bit psi piece, 7-bit padding)
                let i3 = region.assign_advice(|| "i3  ", self.col_l, 2, || *i_num[3].inner())?;
                let i4 = region.assign_advice(|| "i4", self.col_m, 2, || *i_num[4].inner())?;

                Ok([i0, i1, i2, i3, i4])
            },
        )
    }
}

/// |  A_6   | A_7 |   A_8   |     A_9     | q_notecommit_nd |
/// -----------------------------------------------------------
/// | nd     | b0  | a       | z13_a       |        1         |
/// |        |     | a_prime | z13_a_prime |        0         |
///
#[derive(Clone, Debug)]
struct NdCanonicity {
    q_notecommit_nd: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl NdCanonicity {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_130: Expression<pallas::Base>,
        two_pow_250: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_nd = meta.selector();

        meta.create_gate("NoteCommit input g_d", |meta| {
            let q_notecommit_nd = meta.query_selector(q_notecommit_nd);

            // nd is the full 255-bit value
            let nd = meta.query_advice(col_l, Rotation::cur());
            // b0 is bits 250-254 of nd (5 bits)
            let b0 = meta.query_advice(col_m, Rotation::cur());
            // a is bits 0-249 of nd (250 bits)
            let a = meta.query_advice(col_r, Rotation::cur());
            let a_prime = meta.query_advice(col_r, Rotation::next());
            let z13_a = meta.query_advice(col_z, Rotation::cur());
            let z13_a_prime = meta.query_advice(col_z, Rotation::next());

            // Decomposition: nd = a + b0 * 2^250
            let decomposition_check = a.clone() + b0.clone() * two_pow_250 - nd;

            // a_prime = a + 2^130 - t_P
            let a_prime_check = a + two_pow_130 - t_p - a_prime;

            // Check if nd >= 2^254 (i.e., b0 >= 2^4)
            let b0_high_bit = b0.clone() - Expression::Constant(pallas::Base::from(16));

            Constraints::with_selector(
                q_notecommit_nd,
                iter::empty()
                    .chain(Some(("decomposition", decomposition_check)))
                    .chain(Some(("a_prime_check", a_prime_check)))
                    .chain(
                        iter::empty()
                            .chain(Some(("high nd => z13_a = 0", b0_high_bit.clone() * z13_a))) // If b0 >= 16, enforce z13_a = 0
                            .chain(Some((
                                "high nd => z13_a_prime = 0",
                                b0_high_bit * z13_a_prime, // If b0 >= 16, enforce z13_a_prime = 0
                            ))),
                    ),
            )
        });

        Self {
            q_notecommit_nd,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        nd: &AssignedCell<pallas::Base, pallas::Base>,
        a: NoteCommitPiece,
        b0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        a_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_a: AssignedCell<pallas::Base, pallas::Base>,
        z13_a_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit input g_d",
            |mut region| {
                nd.copy_advice(|| "nd", &mut region, self.col_l, 0)?;

                b0.inner()
                    .copy_advice(|| "b0", &mut region, self.col_m, 0)?;

                a.inner()
                    .cell_value()
                    .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                z13_a.copy_advice(|| "z13_a", &mut region, self.col_z, 0)?;
                z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_nd.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6  | A_7 | A_8 | A_9 | q_notecommit_v |
/// -----------------------------------------
/// | value| b1  |  0  | c0  |      1         |
///
#[derive(Clone, Debug)]
struct ValueCanonicity {
    q_notecommit_v: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl ValueCanonicity {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_9: pallas::Base,
        two_51: pallas::Base,
    ) -> Self {
        let q_notecommit_v = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_notecommit_v = meta.query_selector(q_notecommit_v);
            // full value 60 bit value
            let value = meta.query_advice(col_l, Rotation::cur());
            // b1 has been constrained to 9 bits outside this gate.
            let b1 = meta.query_advice(col_m, Rotation::cur());
            // z1_d has been constrained to 50 bits by the Sinsemilla hash.
            let z1_d = meta.query_advice(col_r, Rotation::cur());
            let d_3 = z1_d;
            // `c0` has been constrained to 51 bits outside this gate.
            let c0 = meta.query_advice(col_z, Rotation::cur());

            // value = d2 + (2^8)d_3 + (2^58)e_0
            let value_check = b1 + d_3 * two_9 + c0 * two_51 - value;

            Constraints::with_selector(q_notecommit_v, Some(("value_check", value_check)))
        });

        Self {
            q_notecommit_v,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        value: AssignedCell<NoteValue, pallas::Base>,
        b1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        z1_b: AssignedCell<pallas::Base, pallas::Base>,
        c0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit value canonicity",
            |mut region| {
                value.copy_advice(|| "value", &mut region, self.col_l, 0)?;
                b1.inner()
                    .copy_advice(|| "b1", &mut region, self.col_m, 0)?;
                z1_b.copy_advice(|| "d3 = z1_b", &mut region, self.col_r, 0)?;
                c0.inner()
                    .copy_advice(|| "c0", &mut region, self.col_z, 0)?;

                self.q_notecommit_v.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6  | A_7 | A_8 |  q_notecommit_fdi |
/// --------------------------------------------
/// | fdi  | c1  |  d0  |        0         |
///
#[derive(Clone, Debug)]
struct FdiCanonicity {
    q_notecommit_fdi: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl FdiCanonicity {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_51: pallas::Base,
    ) -> Self {
        let q_notecommit_fdi = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_notecommit_fdi = meta.query_selector(q_notecommit_fdi);

            // Full 64-bit fdi
            let fdi = meta.query_advice(col_l, Rotation::cur());
            // c1: bits 0..51 of fdi (51 bits, constrained by DecomposeC)
            let c1 = meta.query_advice(col_m, Rotation::cur());
            // d0: bits 51..64 of fdi (13 bits, constrained by DecomposeD)
            let d0 = meta.query_advice(col_r, Rotation::cur());
            // fdi = c1 + d0 * 2^51
            let fdi_check = c1 + d0 * two_pow_51 - fdi;

            Constraints::with_selector(q_notecommit_fdi, Some(("fdi_check", fdi_check)))
        });

        Self {
            q_notecommit_fdi,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        fdi: AssignedCell<pallas::Base, pallas::Base>,
        c1: AssignedCell<pallas::Base, pallas::Base>, // From DecomposeC.assign()[1]
        d0: AssignedCell<pallas::Base, pallas::Base>, // From DecomposeD.assign()[0]
        z1_d: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit input value",
            |mut region| {
                fdi.copy_advice(|| "fdi", &mut region, self.col_l, 0)?;
                c1.copy_advice(|| "c1 (bits 0-50)", &mut region, self.col_m, 0)?;
                // z1_d.copy_advice(|| "d3 = z1_d", &mut region, self.col_r, 0)?;
                d0.copy_advice(|| "d0 (bits 51-63)", &mut region, self.col_z, 0)?;
                self.q_notecommit_fdi.enable(&mut region, 0)
            },
        )
    }
}

#[derive(Clone, Debug)]
struct RecpCanonicity {
    q_notecommit_recp: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl RecpCanonicity {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_7: pallas::Base,
    ) -> Self {
        let q_notecommit_recp = meta.selector();
        // recp = bits 0..7 of (d1) || 67..127 of recp (60)  || 127..187 of recp (60)  || 187..247 of recp  (20) || 247..255 recp 8
        meta.create_gate("NoteCommit input value", |meta| {
            let q_notecommit_recp = meta.query_selector(q_notecommit_recp);

            let recp = meta.query_advice(col_l, Rotation::cur()); // full recp row 0
            let d1 = meta.query_advice(col_m, Rotation::cur()); // row 0: bits 0-6
            let e0 = meta.query_advice(col_r, Rotation::cur()); // row 0: bits 7-66
            let e1 = meta.query_advice(col_m, Rotation::next()); // row 1: bits 67-126
            let e2 = meta.query_advice(col_r, Rotation::next()); // row 1: bits 127-186
            let e3 = meta.query_advice(col_z, Rotation::cur()); // row 0: bits 187-246 (adjust position if row1)

            let two_pow_60 = pallas::Base::from(1u64 << 60); // or param
            let two_pow_67 = two_pow_7 * two_pow_60;
            let two_pow_127 = two_pow_67 * two_pow_60;
            let two_pow_187 = two_pow_127 * two_pow_60;

            // value = d2 + (2^8)d_3 + (2^58)e_0
            let recp_check = recp
                - (d1 + e0 * two_pow_7 + e1 * two_pow_67 + e2 * two_pow_127 + e3 * two_pow_187);

            Constraints::with_selector(q_notecommit_recp, Some(("recp_check", recp_check)))
        });

        Self {
            q_notecommit_recp,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        recp: AssignedCell<pallas::Base, pallas::Base>,
        d1: AssignedCell<pallas::Base, pallas::Base>,
        e0: AssignedCell<pallas::Base, pallas::Base>,
        e1: AssignedCell<pallas::Base, pallas::Base>,
        e2: AssignedCell<pallas::Base, pallas::Base>,
        e3: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit recp canonicity",
            |mut region| {
                // Row 0
                recp.copy_advice(|| "recp full", &mut region, self.col_l, 0)?;
                d1.copy_advice(|| "d1 (0-6)", &mut region, self.col_m, 0)?;
                e0.copy_advice(|| "e0 (7-66)", &mut region, self.col_r, 0)?;
                e3.copy_advice(|| "e3 (187-246)", &mut region, self.col_z, 0)?;
                // Row 1
                e1.copy_advice(|| "e1 (67-126)", &mut region, self.col_m, 1)?;
                e2.copy_advice(|| "e2 (127-186)", &mut region, self.col_r, 1)?;
                self.q_notecommit_recp.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6 | A_7 | A_8 | A_9 | q_notecommit_esk |
/// -------------------------------------------
/// | esk | e5  |  f  | g0  |       1          |
#[derive(Clone, Debug)]
struct EskCanonicity {
    q_notecommit_esk: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl EskCanonicity {
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_2: pallas::Base,
        two_pow_252: pallas::Base,
    ) -> Self {
        let q_notecommit_esk = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_notecommit_esk = meta.query_selector(q_notecommit_esk);

            let esk = meta.query_advice(col_l, Rotation::cur());
            let e5 = meta.query_advice(col_m, Rotation::cur()); // bits 0-1 (piece e5)
            let f = meta.query_advice(col_r, Rotation::cur()); // bits 2-251 (piece f)
            let g0 = meta.query_advice(col_z, Rotation::cur()); // bits 252-254 (piece g0)

            // esk = e5 + f * 2^2 + g0 * 2^252
            let esk_check = esk - (e5 + f * two_pow_2 + g0 * two_pow_252);

            Constraints::with_selector(q_notecommit_esk, Some(("esk_check", esk_check)))
        });

        Self {
            q_notecommit_esk,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        esk: AssignedCell<pallas::Base, pallas::Base>,
        e5: AssignedCell<pallas::Base, pallas::Base>, // e5 cell from DecomposeE
        f_piece: NoteCommitPiece,                     // piece f
        g0: AssignedCell<pallas::Base, pallas::Base>, // g0 from DecomposeG
    ) -> Result<(), Error> {
        lo.assign_region(
            || "NoteCommit esk canonicity",
            |mut region| {
                esk.copy_advice(|| "esk full", &mut region, self.col_l, 0)?;
                e5.copy_advice(|| "e5 (bits 0-2)", &mut region, self.col_m, 0)?;
                f_piece.inner().cell_value().copy_advice(
                    || "f (bits 2-251)",
                    &mut region,
                    self.col_r,
                    0,
                )?;
                g0.copy_advice(|| "g0 (bits 252-255)", &mut region, self.col_z, 0)?;
                self.q_notecommit_esk.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6 | A_7 | A_8 | A_9 | q_notecommit_rho |
/// -------------------------------------------
/// | rho | g1  | ha  | z13_h|        1         |
/// |     | hb  | hc  | hd   |        0         |
/// |     | i0  |     |      |        0         |
#[derive(Clone, Debug)]
struct RhoCanonicity {
    q_notecommit_rho: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl RhoCanonicity {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_57: pallas::Base,
        two_pow_117: pallas::Base,
        two_pow_177: pallas::Base,
        two_pow_237: pallas::Base,
        two_pow_247: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_rho = meta.selector();

        meta.create_gate("NoteCommit input rho", |meta| {
            let q_notecommit_rho = meta.query_selector(q_notecommit_rho);

            let rho = meta.query_advice(col_l, Rotation::cur());  // full 255-bit rho
            
            // Row 0: g1(0-56,57b), ha(57-116,60b)
            let g1 = meta.query_advice(col_m, Rotation::cur());
            let ha = meta.query_advice(col_r, Rotation::cur());
            
            // Row 1: hb(117-176,60b), hc(177-236,60b)  
            let hb = meta.query_advice(col_m, Rotation::next());
            let hc = meta.query_advice(col_r, Rotation::next());
            
            // Row 0: z13_h (sinsemilla proxy for h pieces)
            let z13_h = meta.query_advice(col_z, Rotation::cur());
            
            // Row 2: i0(247-254,8b) - high bit proxy
            let i0 = meta.query_advice(col_m, Rotation(2));

            // Full decomposition: rho = g1 + ha*2^57 + hb*2^117 + hc*2^177 + hd*2^237 + i0*2^247
            let decomposition_check = rho - (
                g1 + 
                ha * two_pow_57 +
                hb * two_pow_117 + 
                hc * two_pow_177 +
                z13_h.clone() * two_pow_237 +  // proxy for hd
                i0.clone() * two_pow_247
            );

            // e1_f_prime = e_1 + (2^4)f + 2^140 - t_P
            // let e1_f_prime_check = g1 + (f * two_pow_4) + two_pow_140 - t_p - e1_f_prime;
                // Conditional canonicity: if i0 msb=1 then z13_h=0 (high bits canonical)
            let i0_msb = i0.clone() - Expression::Constant(pallas::Base::from(128u64));  
            let canonicity_check = i0_msb * z13_h;


            Constraints::with_selector(q_notecommit_rho, [
                ("decomposition", decomposition_check),
                ("i0_msb => z13_h=0", canonicity_check),
            ])
        });

        Self {
            q_notecommit_rho,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        g1_cell: AssignedCell<pallas::Base, pallas::Base>,  // DecomposeG g1
        ha_cell: AssignedCell<pallas::Base, pallas::Base>, // DecomposeH ha
        hb_cell: AssignedCell<pallas::Base, pallas::Base>, // DecomposeH hb  
        hc_cell: AssignedCell<pallas::Base, pallas::Base>, // DecomposeH hc
        z13_h: AssignedCell<pallas::Base, pallas::Base>,   // sinsemilla zs[13] for h
        i0_cell: AssignedCell<pallas::Base, pallas::Base>, // DecomposeI i0
    ) -> Result<(), Error> {
        lo.assign_region(|| "NoteCommit rho canonicity", |mut region| {
            // Row 0
            rho.copy_advice(|| "rho full", &mut region, self.col_l, 0)?;
            g1_cell.copy_advice(|| "g1 (0-56)", &mut region, self.col_m, 0)?;
            ha_cell.copy_advice(|| "ha (57-116)", &mut region, self.col_r, 0)?;
            z13_h.copy_advice(|| "z13_h", &mut region, self.col_z, 0)?;
            
            // Row 1
            hb_cell.copy_advice(|| "hb (117-176)", &mut region, self.col_m, 1)?;
            hc_cell.copy_advice(|| "hc (177-236)", &mut region, self.col_r, 1)?;
            
            // Row 2  
            i0_cell.copy_advice(|| "i0 (247-254)", &mut region, self.col_m, 2)?;
            
            self.q_notecommit_rho.enable(&mut region, 0)
        })
    }
}

/// | A_6 | A_7 | A_8 | A_9 | q_notecommit_psi |
/// -------------------------------------------
/// | psi | i1  | i2  | z13_i|        1         |
/// |     | i3  |     |      |        0         |
///
#[derive(Clone, Debug)]
struct PsiCanonicity {
    q_notecommit_psi: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl PsiCanonicity {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
      two_pow_2: pallas::Base,
        two_pow_252: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_psi = meta.selector();

        meta.create_gate("NoteCommit input psi", |meta| {
      let q_notecommit_psi = meta.query_selector(q_notecommit_psi);

            let psi = meta.query_advice(col_l, Rotation::cur());  // full 255-bit psi
            
            // Row 0: i1(0-1,2bits), i2(2-251,250bits)
            let i1 = meta.query_advice(col_m, Rotation::cur());
            let i2 = meta.query_advice(col_r, Rotation::cur());
            
            // Row 1: i3(252-254,3bits) - high bit proxy
            let i3 = meta.query_advice(col_m, Rotation::next());
            
            // Row 0: z13_i (sinsemilla proxy for i pieces)
            let z13_i = meta.query_advice(col_z, Rotation::cur());

            // psi = i1 + i2 * 2^2 + i3 * 2^252
            let decomposition_check = psi - (
                i1 + 
                i2 * two_pow_2 + 
                i3.clone() * two_pow_252
            );

            // Conditional canonicity: if i3 msb=1 then z13_i=0 (high bits canonical)
            let i3_msb = i3.clone() - Expression::Constant(pallas::Base::from(4u64));  // i3 >= 4 (msb set)
            let canonicity_check = i3_msb * z13_i;

            Constraints::with_selector(q_notecommit_psi, [
                ("decomposition", decomposition_check),
                ("i3_msb => z13_i=0", canonicity_check),
            ])
        });

        Self {
            q_notecommit_psi,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        lo: &mut impl Layouter<pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        i1_cell: AssignedCell<pallas::Base, pallas::Base>,  // DecomposeI i1 (0-1)
        i2_cell: AssignedCell<pallas::Base, pallas::Base>,  // DecomposeI i2 (2-251)
        i3_cell: AssignedCell<pallas::Base, pallas::Base>,  // DecomposeI i3 (252-254)
        z13_i: AssignedCell<pallas::Base, pallas::Base>,    // sinsemilla zs[13] for i pieces
    ) -> Result<(), Error> {
        lo.assign_region(|| "NoteCommit psi canonicity", |mut region| {
            // Row 0
            psi.copy_advice(|| "psi full", &mut region, self.col_l, 0)?;
            i1_cell.copy_advice(|| "i1 (0-1)", &mut region, self.col_m, 0)?;
            i2_cell.copy_advice(|| "i2 (2-251)", &mut region, self.col_r, 0)?;
            z13_i.copy_advice(|| "z13_i", &mut region, self.col_z, 0)?;
            
            // Row 1
            i3_cell.copy_advice(|| "i3 (252-254)", &mut region, self.col_m, 1)?;
            
            self.q_notecommit_psi.enable(&mut region, 0)
        })
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct NoteCommitConfig {
    b: DecomposeB,
    c: DecomposeC,
    d: DecomposeD,
    e: DecomposeE,

    g: DecomposeG,
    h: DecomposeH,
    i: DecomposeI,
    nd: NdCanonicity,
    v: ValueCanonicity,
    fdi: FdiCanonicity,
    recp: RecpCanonicity,
    esk: EskCanonicity,
    rho: RhoCanonicity,
    psi: PsiCanonicity,
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
        let two_pow_7 = two_pow_6 * two;
        let two_pow_8 = two_pow_4.square();
        let two_pow_9 = two_pow_8 * two;
        let two_pow_10 = two_pow_9 * two;
        let two_pow_51 = pallas::Base::from(1 << 51);
        let two_pow_57 = two_pow_51 * two_pow_6;
        let two_pow_58 = pallas::Base::from(1 << 58);
        let two_pow_60 = pallas::Base::from(1 << 60);
        let two_pow_117 = two_pow_57 * two_pow_60;
        let two_pow_130 = Expression::Constant(pallas::Base::from_u128(1 << 65).square());
        let two_pow_140 = Expression::Constant(pallas::Base::from_u128(1 << 70).square());
        let two_pow_249 = pallas::Base::from_u128(1 << 124).square() * two;
        let two_pow_177 = two_pow_117 * two_pow_60;
        let two_pow_237 = two_pow_177 * two_pow_60;
        let two_pow_247 = two_pow_237 * two_pow_10;
        let two_pow_247 = two_pow_177 * two_pow_60;
        let two_pow_250 = two_pow_249 * two;
        let two_pow_252 = two_pow_250 * two;
        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();

        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

        // Columns used for MessagePiece and message input gates.
        let col_l = advices[6];
        let col_m = advices[7];
        let col_r = advices[8];
        let col_z = advices[9];

        let b = DecomposeB::configure(meta, col_l, col_m, col_r, two_pow_5);
        let c = DecomposeC::configure(meta, col_l, col_m, col_r, two_pow_9);
        let d = DecomposeD::configure(meta, col_l, col_m, col_r, two);
        let e = DecomposeE::configure(meta, col_l, col_m, col_r, two_pow_6);

        let g = DecomposeG::configure(meta, col_l, col_m, col_r);
        let h = DecomposeH::configure(meta, col_l, col_m, col_r);
        let i = DecomposeI::configure(meta, col_l, col_m, col_r);

        let nd = NdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_130.clone(),
            two_pow_250.clone(),
            t_p.clone(),
        );
        let v = ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_9, two_pow_51);
        let fdi = FdiCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_51);
        let recp = RecpCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_7);
        let esk = EskCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58);

        let rho = RhoCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_57,
            two_pow_117.clone(),
            two_pow_177,
            two_pow_237,
            two_pow_247,
            t_p.clone(),
        );

        let psi = PsiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
         two_pow_2,
          two_pow_252,
            t_p.clone(),
        );

        NoteCommitConfig {
            b,
            c,
            d,
            e,

            g,
            h,
            i,
            nd,
            v,
            fdi,
            recp,
            rho,
            esk,
            psi,
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
        let f: MessagePiece<_, _, _, _> = MessagePiece::from_subpieces(
            chip.clone(),
            lo.namespace(|| "piece_e: esk[2..252)"),
            [RangeConstrained::bitrange_of(esk.value(), 2..252)],
        )?;
        //   Piece g: bits 252..255 of esk || 0-57 rho ||  (3 + 57 = 60 bits)
        let (g, ([go, g1])) = DecomposeG::decompose(&lc, chip.clone(), &mut lo, &esk, &rho)?;
        //   Piece h: bits 57-117 of rho  || 117..=177 of rho  || 177..=237 of rho  || 237..=247 of rho   (60+ 60+ 60 +10 = 190 bits)
        let ([ha, hb, hc, hd], ([h0, h1, h2, h3])) =
            DecomposeH::decompose(&lc, chip.clone(), &mut lo, &rho)?;
        //   piece ia,ib,ic: || 247..255 rho || 0..2 of psi || 2..252 of psi || 252..255 of psi || 7 bit padding (8+ 2+ 250 + 3 + 7 = (10,250,10) bits)
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
        println!("zs0:{:#?}", zs[0]);
        println!("zs1:{:#?}", zs[1]);
        println!("zs2:{:#?}", zs[2]);
        println!("zs2:{:#?}", zs[6]);

        let z13_a = zs[0][13].clone();
        let z13_c = zs[2][5].clone();
        let z1_d = zs[3][1].clone();
        let z13_f = zs[5][5].clone();
        let z1_g = zs[6][1].clone();
        let g_2 = z1_g.clone();
        let z13_g = zs[6][5].clone();

        // Witness and constrain the bounds we need to ensure canonicity.
        let (a_prime, z13_a_prime) = canon_bitshift_130(
            &lc,
            lo.namespace(|| "nd canonicity"),
            a.inner().cell_value(),
        )?;

        let (b1_c_prime, z14_b1_c_prime) = v_canonicity(
            &lc,
            lo.namespace(|| "v canonicity"),
            b1.clone(),
            c.inner().cell_value(),
        )?;

        // let (b1_c_prime, z14_b1_c_prime) = fdi_canonicity(
        //     &lc,
        //     lo.namespace(|| "v canonicity"),
        //     b1.clone(),
        //     c.inner().cell_value(),
        // )?;

        // let (e1_f_prime, z14_e1_f_prime) = recp_canonicity(
        //     &lc,
        //     lo.namespace(|| "v canonicity"),
        //     b1.clone(),
        //     f.inner().cell_value(),
        // )?;

        // let (g1_g2_prime, z13_g1_g2_prime) =
        //     esk_canonicity(&lc, lo.namespace(|| "v canonicity"), g1.clone(), g_2)?;

        // let (g1_g2_prime, z13_g1_g2_prime) =
        //     rho_canonicity(&lc, lo.namespace(|| "rho canonicity"), e1.clone(), g_2)?;

        // let (g1_g2_prime, z13_g1_g2_prime) =
        //     psi_canonicity(&lc, lo.namespace(|| "rho canonicity"), g1.clone(), g_2)?;

        // Finally, assign vs to all of the NoteCommit regions.
        let cfg = note_commit_chip.config;

        let [b0, b1] = cfg.b.assign(&mut lo, b, b0.clone(), b1)?;
        let [c0, c1] = cfg.c.assign(&mut lo, c, c0.clone(), c1)?;
        let d = cfg.d.assign(&mut lo, d, d0, d1, z1_d)?;
        let e = cfg
            .e
            .assign(&mut lo, [ea, eb, ec, ed, ee], [e0, e1, e2, e3, e4, e5])?;
        // let f = cfg.f.assign(&mut lo, f, d0, d1, z1_d)?;
        // let g = cfg.g.assign(&mut lo, g, d0, d1, z1_d)?;
        // let h = cfg.h.assign(&mut lo, h, d0, d1, z1_d)?;
        // let i = cfg.i.assign(&mut lo, i, d0, d1, z1_d)?;
        // cfg.nd
        //     .assign(lo, nd, a, b0, b1, a_prime, z13_a, z13_a_prime)?;
        // cfg.v.assign(lo, v, d2, z1_d, e_0)?;
        // cfg.fdi.assign(lo, fdi, d2, z1_d, e_0);
        // cfg.recp.assign(lo, recp, d2, z1_d, e_0)?;
        // cfg.esk.assign(lo, esk, d2, z1_d, e_0)?;
        // cfg.rho
        //     .assign(lo, rho, e_1, f, g_0, e1_f_prime, z13_f, z14_e1_f_prime)?;
        // cfg.psi.assign(
        //     lo,
        //     psi,
        //     g_1,
        //     z1_g,
        //     h_0,
        //     h_1,
        //     g1_g2_prime,
        //     z13_g,
        //     z13_g1_g2_prime,
        // )?;
        Ok(cm)
    }

    /// A canonicity check helper used in checking nd,...
    fn canon_bitshift_130(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut lo: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // element = `a (250 bits) || b0 (4 bits) || b1 (1 bit)`
        // - b1 = 1 => b0 = 0
        // - b1 = 1 => a < t_P
        //     - 0 ≤ a < 2^130 (z_13 of SinsemillaHash(a))
        //     - 0 ≤ a + 2^130 - t_P < 2^130 (thirteen 10-bit lookups)

        // Decompose the low 130 bits of a_prime = a + 2^130 - t_P, and output
        // the running sum at the end of it. If a_prime < 2^130, the running sum
        // will be 0.
        let a_prime = {
            let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            a.value() + two_pow_130 - t_p
        };
        let zs = lc.witness_check(
            lo.namespace(|| "Decompose low 130 bits of (a + 2^130 - t_P)"),
            a_prime,
            13,
            false,
        )?;
        let a_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

        Ok((a_prime, zs[13].clone()))
    }

    /// Check canonicity of `v` encoding.
    fn v_canonicity(
        lc: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut lo: impl Layouter<pallas::Base>,
        b1: RangeConstrained<pallas::Base, Value<pasta_curves::Fp>>,
        c: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `v` = `b1 (55 bits) || c0 (9 bits)`
        // where b1 represents the lower 55 bits and c0 represents the upper 9 bits
        //
        // Canonicity check: b1 + 2^55 * c0 < t_P
        //     - 0 ≤ b1 + 2^55 * c0 < 2^64 (since v is 64 bits)
        //         - b1 is part of the Sinsemilla message piece
        //         - b1 is individually constrained to be 55 bits
        //         - c0 is constrained to be 9 bits (upper bits of v)
        //     - To check b1 + 2^55 * c0 < t_P without overflow:
        //       0 ≤ b1 + 2^55 * c0 + 2^140 - t_P < 2^140 (14 ten-bit lookups)
        //
        // Decompose the low 140 bits of b1_c0_prime = b1 + 2^55 * c0 + 2^140 - t_P,
        // and output the running sum at the end of it.
        // If b1_c0_prime < 2^140, the running sum will be 0.
        let b1_c0_prime = {
            let two_pow_55 = Value::known(pallas::Base::from(1u64 << 55));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            b1.inner().value() + (two_pow_55 * c.value()) + two_pow_140 - t_p
        };

        let zs = lc.witness_check(
            lo.namespace(|| "Decompose low 140 bits of (b1 + 2^55 * c0 + 2^140 - t_P)"),
            b1_c0_prime,
            14,
            false,
        )?;

        let b1_c0_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((b1_c0_prime, zs[14].clone()))
    }

    // /// Check canonicity of `fdi` encoding.
    // fn fdi_canonicity(
    //     lc: &LookupRangeCheckConfig<pallas::Base, 10>,
    //     mut lo: impl Layouter<pallas::Base>,
    //     b1: RangeConstrained<pallas::Base, Value<pasta_curves::Fp>>,
    //     c: AssignedCell<pallas::Base, pallas::Base>,
    // ) -> Result<CanonicityBounds, Error> {
    //     let b1_c_prime = {
    //         let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
    //         let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
    //         let t_p = Value::known(pallas::Base::from_u128(T_P));
    //         b1.inner().value() + (two_pow_4 * c.value()) + two_pow_140 - t_p
    //     };

    //     let zs = lc.witness_check(
    //         lo.namespace(|| "Decompose low 140 bits of (b_3 + 2^4 c + 2^140 - t_P)"),
    //         b1_c_prime,
    //         14,
    //         false,
    //     )?;
    //     let b1_c_prime = zs[0].clone();
    //     assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

    //     Ok((b1_c_prime, zs[14].clone()))
    // }

    // /// Check canonicity of `recp` encoding.
    // fn recp_canonicity(
    //     lc: &LookupRangeCheckConfig<pallas::Base, 10>,
    //     mut lo: impl Layouter<pallas::Base>,
    //     b1: RangeConstrained<pallas::Base, Value<pasta_curves::Fp>>,
    //     c: AssignedCell<pallas::Base, pallas::Base>,
    // ) -> Result<CanonicityBounds, Error> {
    //     let b1_c_prime = {
    //         let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
    //         let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
    //         let t_p = Value::known(pallas::Base::from_u128(T_P));
    //         b1.inner().value() + (two_pow_4 * c.value()) + two_pow_140 - t_p
    //     };

    //     let zs = lc.witness_check(
    //         lo.namespace(|| "Decompose low 140 bits of (b_3 + 2^4 c + 2^140 - t_P)"),
    //         b1_c_prime,
    //         14,
    //         false,
    //     )?;
    //     let b1_c_prime = zs[0].clone();
    //     assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

    //     Ok((b1_c_prime, zs[14].clone()))
    // }
    // /// Check canonicity of `esk` encoding.
    // fn esk_canonicity(
    //     lc: &LookupRangeCheckConfig<pallas::Base, 10>,
    //     mut lo: impl Layouter<pallas::Base>,
    //     b1: RangeConstrained<pallas::Base, Value<pasta_curves::Fp>>,
    //     c: AssignedCell<pallas::Base, pallas::Base>,
    // ) -> Result<CanonicityBounds, Error> {
    //     let b1_c_prime = {
    //         let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
    //         let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
    //         let t_p = Value::known(pallas::Base::from_u128(T_P));
    //         b1.inner().value() + (two_pow_4 * c.value()) + two_pow_140 - t_p
    //     };

    //     let zs = lc.witness_check(
    //         lo.namespace(|| "Decompose low 140 bits of (b_3 + 2^4 c + 2^140 - t_P)"),
    //         b1_c_prime,
    //         14,
    //         false,
    //     )?;
    //     let b1_c_prime = zs[0].clone();
    //     assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

    //     Ok((b1_c_prime, zs[14].clone()))
    // }

    // /// Check canonicity of `rho` encoding.
    // ///
    // /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-rho?partial).
    // fn rho_canonicity(
    //     lc: &LookupRangeCheckConfig<pallas::Base, 10>,
    //     mut lo: impl Layouter<pallas::Base>,
    //     e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    //     f: AssignedCell<pallas::Base, pallas::Base>,
    // ) -> Result<CanonicityBounds, Error> {
    //     // `rho` = `e_1 (4 bits) || f (250 bits) || g_0 (1 bit)`
    //     // - g_0 = 1 => e_1 + 2^4 f < t_P
    //     // - 0 ≤ e_1 + 2^4 f < 2^134
    //     //     - e_1 is part of the Sinsemilla message piece
    //     //       e = e_0 (56 bits) || e_1 (4 bits)
    //     //     - e_1 is individually constrained to be 4 bits.
    //     //     - z_13 of SinsemillaHash(f) == 0 constrains bits 4..=253 of rho
    //     //       to 130 bits. z13_f == 0 is directly checked in the gate.
    //     // - 0 ≤ e_1 + 2^4 f + 2^140 - t_P < 2^140 (14 ten-bit lookups)

    //     let e1_f_prime = {
    //         let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
    //         let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
    //         let t_p = Value::known(pallas::Base::from_u128(T_P));
    //         e_1.inner().value() + (two_pow_4 * f.value()) + two_pow_140 - t_p
    //     };

    //     // Decompose the low 140 bits of e1_f_prime = e_1 + 2^4 f + 2^140 - t_P,
    //     // and output the running sum at the end of it.
    //     // If e1_f_prime < 2^140, the running sum will be 0.
    //     let zs = lc.witness_check(
    //         lo.namespace(|| "Decompose low 140 bits of (e_1 + 2^4 f + 2^140 - t_P)"),
    //         e1_f_prime,
    //         14,
    //         false,
    //     )?;
    //     let e1_f_prime = zs[0].clone();
    //     assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

    //     Ok((e1_f_prime, zs[14].clone()))
    // }

    // /// Check canonicity of `psi` encoding.
    // ///
    // /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-psi?partial).
    // fn psi_canonicity(
    //     lc: &LookupRangeCheckConfig<pallas::Base, 10>,
    //     mut lo: impl Layouter<pallas::Base>,
    //     g_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    //     g_2: AssignedCell<pallas::Base, pallas::Base>,
    // ) -> Result<CanonicityBounds, Error> {
    //     // `psi` = `g_1 (9 bits) || g_2 (240 bits) || h_0 (5 bits) || h_1 (1 bit)`
    //     // - h_1 = 1 => (h_0 = 0) ∧ (g_1 + 2^9 g_2 < t_P)
    //     // - 0 ≤ g_1 + 2^9 g_2 < 2^130
    //     //     - g_1 is individually constrained to be 9 bits
    //     //     - z_13 of SinsemillaHash(g) == 0 constrains bits 0..=248 of psi
    //     //       to 130 bits. z13_g == 0 is directly checked in the gate.
    //     // - 0 ≤ g_1 + (2^9)g_2 + 2^130 - t_P < 2^130 (13 ten-bit lookups)

    //     // Decompose the low 130 bits of g1_g2_prime = g_1 + (2^9)g_2 + 2^130 - t_P,
    //     // and output the running sum at the end of it.
    //     // If g1_g2_prime < 2^130, the running sum will be 0.
    //     let g1_g2_prime = {
    //         let two_pow_9 = Value::known(pallas::Base::from(1u64 << 9));
    //         let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
    //         let t_p = Value::known(pallas::Base::from_u128(T_P));
    //         g_1.inner().value() + (two_pow_9 * g_2.value()) + two_pow_130 - t_p
    //     };

    //     let zs = lc.witness_check(
    //         lo.namespace(|| "Decompose low 130 bits of (g_1 + (2^9)g_2 + 2^130 - t_P)"),
    //         g1_g2_prime,
    //         13,
    //         false,
    //     )?;
    //     let g1_g2_prime = zs[0].clone();
    //     assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

    //     Ok((g1_g2_prime, zs[13].clone()))
    // }
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
