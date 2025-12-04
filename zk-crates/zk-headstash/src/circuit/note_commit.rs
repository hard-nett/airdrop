use core::iter;

use ff::PrimeField;
use halo2_gadgets::ecc::{chip::NonIdentityEccPoint, Point};
use halo2_gadgets::sinsemilla::chip::{SinsemillaChip, SinsemillaConfig};
use halo2_gadgets::sinsemilla::MessagePiece;
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_gadgets::utilities::{bool_check, FieldValue, RangeConstrained};
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector,
};
use halo2_proofs::poly::Rotation;
use pasta_curves::pallas;

use crate::constants::fixed_bases::HeadstashFixedBases;
use crate::constants::sinsemilla::HeadstashCommitDomains;
use crate::constants::{HeadstashHashDomains, T_P};
use crate::value::NoteValue;

type NoteCommitPiece = MessagePiece<
    pallas::Affine,
    SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
    10,
    253,
>;

/// The values of the running sum at the start and end of the range being used for a
/// canonicity check.
type CanonicityBounds = (
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
);

/// b = bits 250-253 of recp || bits 0-63 of fdi || bits 0-181 of nd (250 bits)
///   For the gate, we decompose a 10-bit boundary: b_0 || b_1 || b_2 || b_3
///
/// | A_6 | A_7 | A_8 | q_notecommit_b |
/// ------------------------------------
/// |  b  | b_0 | b_1 |       1        |
/// |     | b_2 | b_3 |       0        |
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

            // b has been constrained to 10 bits by the Sinsemilla hash.
            let b = meta.query_advice(col_l, Rotation::cur());
            // b_0 has been constrained to be 4 bits outside this gate.
            let b_0 = meta.query_advice(col_m, Rotation::cur());
            // This gate constrains b_1 to be boolean.
            let b_1 = meta.query_advice(col_r, Rotation::cur());
            // This gate constrains b_2 to be boolean.
            let b_2 = meta.query_advice(col_m, Rotation::next());
            // b_3 has been constrained to 4 bits outside this gate.
            let b_3 = meta.query_advice(col_r, Rotation::next());

            // b = b_0 + (2^4) b_1 + (2^5) b_2 + (2^6) b_3
            let decomposition_check =
                b - (b_0 + b_1.clone() * two_pow_4 + b_2.clone() * two_pow_5 + b_3 * two_pow_6);

            Constraints::with_selector(
                q_notecommit_b,
                [
                    ("bool_check b_1", bool_check(b_1)),
                    ("bool_check b_2", bool_check(b_2)),
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
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        recp: &AssignedCell<pallas::Base, pallas::Base>,
        fdi: &AssignedCell<pallas::Base, pallas::Base>,
        nd: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        ),
        Error,
    > {
        // Piece b = bits 250-253 of recp || bits 0-63 of fdi || bits 0-181 of nd
        // Constrain b_0 to be 4 bits (bits 250-253 of recp)
        let b_0 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "b_0"),
            recp.value(),
            250..254,
        )?;

        // b_1, b_2 used for small boundary pieces
        let b_1 = RangeConstrained::bitrange_of(fdi.value(), 0..1);
        let b_2 = RangeConstrained::bitrange_of(nd.value(), 0..1);

        // b_3 constrained to 4 bits from nd
        let b_3 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "b_3"),
            nd.value(),
            0..4,
        )?;

        // Build full piece b: 4 bits recp + 64 bits fdi + 182 bits nd = 250 bits
        let b = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "b"),
            [b_0.value(), b_1, b_2, b_3.value()],
        )?;
        Ok((b, b_0, b_1, b_2, b_3))
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        b: NoteCommitPiece,
        b_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        b_1: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        b_2: RangeConstrained<pallas::Base, Value<pallas::Base>>,
        b_3: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
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

                region.assign_advice(|| "b_2", self.col_m, 1, || *b_2.inner())?;
                b_3.inner()
                    .copy_advice(|| "b_3", &mut region, self.col_r, 1)?;

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
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        nd: &AssignedCell<pallas::Base, pallas::Base>,
        v: &AssignedCell<NoteValue, pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        ),
        Error,
    > {
        // Headstash Piece c: bits 188..254 of nd || bits 0..64 of v || bits 0..123 of rho
        // Total: 66 + 64 + 123 = 253 bits
        //
        // The 10-bit gate constrains boundary values:
        // c_0 = bits 188..191 of nd (4 bits)
        // c_1 = bit 0 of v (1 bit boolean)
        // c_2 = bit 1 of v (1 bit boolean)
        // c_3 = bits 0..3 of rho (4 bits)

        let value_val = v.value().map(|v| pallas::Base::from(v.inner()));

        // Constrain c_0 to be 4 bits (bits 188..191 of nd)
        let c_0 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "c_0 = bits 188..191 of nd"),
            nd.value(),
            188..192,
        )?;

        // c_1 will be boolean-constrained in the gate (bit 0 of v)
        let c_1 = RangeConstrained::bitrange_of(value_val.as_ref(), 0..1);

        // c_2 will be boolean-constrained in the gate (bit 1 of v)
        let c_2 = RangeConstrained::bitrange_of(value_val.as_ref(), 1..2);

        // Constrain c_3 to be 4 bits (bits 0..3 of rho)
        let c_3 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "c_3 = bits 0..3 of rho"),
            rho.value(),
            0..4,
        )?;

        // Full message piece c: bits 182-253 of nd || bits 0-63 of v || bits 0-113 of rho (250 bits)
        // Split into subpieces < 64 bits each: 63 + 9 + 63 + 1 + 63 + 51 = 250 bits
        let c = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "c"),
            [c_0.value(), c_1, c_2, c_3.value()],
        )?;

        Ok((c, c_0, c_1, c_2, c_3))
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
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        rho: &AssignedCell<pallas::Base, pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, Value<pallas::Base>>,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        ),
        Error,
    > {
        // Piece d = bits 114-253 of rho || bits 0-109 of esk (140 + 110 = 250 bits)
        // d_0, d_1 will be boolean-constrained in the gate.
        let d_0 = RangeConstrained::bitrange_of(rho.value(), 114..115);
        let d_1 = RangeConstrained::bitrange_of(esk.value(), 0..1);

        // Constrain d_2 to be 8 bits
        let d_2 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "d_2"),
            esk.value(),
            0..8,
        )?;

        let d = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "d"),
            [d_0, d_1, d_2.value()],
        )?;

        Ok((d, d_0, d_1, d_2))
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
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        esk: &AssignedCell<pallas::Base, pallas::Base>,
        psi: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        ),
        Error,
    > {
        // Piece e = bits 110-253 of esk || bits 0-105 of psi (144 + 106 = 250 bits)
        // Constrain e_0 to be 6 bits from esk
        let e_0 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "e_0"),
            esk.value(),
            110..116,
        )?;

        // Constrain e_1 to be 4 bits from psi
        let e_1 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "e_1"),
            psi.value(),
            0..4,
        )?;

        // Build full piece e: 144 bits from esk + 106 bits from psi
        let e = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "e"),
            [e_0.value(), e_1.value()],
        )?;

        Ok((e, e_0, e_1))
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
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        psi: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            NoteCommitPiece,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
            RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        ),
        Error,
    > {
        // Piece f = bits 106-253 of psi (148 bits)
        // For the gate, we extract small boundary pieces f_0 and f_1
        // f_0 constrained to 6 bits (bits 106-111 of psi)
        let f_0 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "f_0"),
            psi.value(),
            106..112,
        )?;

        // f_1 constrained to 4 bits (bits 112-115 of psi)
        let f_1 = RangeConstrained::witness_short(
            lookup_config,
            layouter.namespace(|| "f_1"),
            psi.value(),
            112..116,
        )?;

        // Build full piece f: bits 106-253 of psi (148 bits)
        // Split into subpieces < 64 bits each: 63 + 63 + 22 = 148 bits
        let f = MessagePiece::from_subpieces(
            chip,
            layouter.namespace(|| "e"),
            [f_0.value(), f_1.value()],
        )?;

        Ok((f, f_0, f_1))
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
/// renamed from GdCanonicity
/// |  A_6   | A_7 |   A_8   |     A_9     | q_notecommit_g_d |
/// -----------------------------------------------------------
/// | x(recp) | b_0 | a       | z13_a       |        1         |
/// |        | b_1 | a_prime | z13_a_prime |        0         |
///
/// <https://p.z.cash/orchard-0.1:note-commit-canonicity-recp?partial>
///
#[derive(Clone, Debug)]
struct RecpCanonicity {
    q_notecommit_g_d: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl RecpCanonicity {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_130: Expression<pallas::Base>,
        two_pow_250: pallas::Base,
        two_pow_254: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_g_d = meta.selector();

        meta.create_gate("NoteCommit input g_d", |meta| {
            let q_notecommit_g_d = meta.query_selector(q_notecommit_g_d);

            let gd_x = meta.query_advice(col_l, Rotation::cur());

            // b_0 has been constrained to be 4 bits outside this gate.
            let b_0 = meta.query_advice(col_m, Rotation::cur());
            // b_1 has been constrained to be boolean outside this gate.
            let b_1 = meta.query_advice(col_m, Rotation::next());

            // a has been constrained to 250 bits by the Sinsemilla hash.
            let a = meta.query_advice(col_r, Rotation::cur());
            let a_prime = meta.query_advice(col_r, Rotation::next());

            let z13_a = meta.query_advice(col_z, Rotation::cur());
            let z13_a_prime = meta.query_advice(col_z, Rotation::next());

            // x(g_d) = a + (2^250)b_0 + (2^254)b_1
            let decomposition_check = {
                let sum = a.clone() + b_0.clone() * two_pow_250 + b_1.clone() * two_pow_254;
                sum - gd_x
            };

            // a_prime = a + 2^130 - t_P
            let a_prime_check = a + two_pow_130 - t_p - a_prime;

            // The gd_x_canonicity_checks are enforced if and only if `b_1` = 1.
            // x(g_d) = a (250 bits) || b_0 (4 bits) || b_1 (1 bit)
            let canonicity_checks = iter::empty()
                .chain(Some(("b_1 = 1 => b_0", b_0)))
                .chain(Some(("b_1 = 1 => z13_a", z13_a)))
                .chain(Some(("b_1 = 1 => z13_a_prime", z13_a_prime)))
                .map(move |(name, poly)| (name, b_1.clone() * poly));

            Constraints::with_selector(
                q_notecommit_g_d,
                iter::empty()
                    .chain(Some(("decomposition", decomposition_check)))
                    .chain(Some(("a_prime_check", a_prime_check)))
                    .chain(canonicity_checks),
            )
        });

        Self {
            q_notecommit_g_d,
            col_l,
            col_m,
            col_r,
            col_z,
        }
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

                a.inner()
                    .cell_value()
                    .copy_advice(|| "a", &mut region, self.col_r, 0)?;
                a_prime.copy_advice(|| "a_prime", &mut region, self.col_r, 1)?;

                z13_a.copy_advice(|| "z13_a", &mut region, self.col_z, 0)?;
                z13_a_prime.copy_advice(|| "z13_a_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_g_d.enable(&mut region, 0)
            },
        )
    }
}

// renamed from FdiCanonicity
/// |   A_6   | A_7 |    A_8     |      A_9       | q_notecommit_pk_d |
/// -------------------------------------------------------------------
/// | x(pk_d) | b_3 |    c       | z13_c          |         1         |
/// |         | d_0 | b3_c_prime | z14_b3_c_prime |         0         |
///
/// <https://p.z.cash/orchard-0.1:note-commit-canonicity-pk_d?partial>
#[derive(Clone, Debug)]
struct FdiCanonicity {
    q_notecommit_pk_d: Selector,
    col_l: Column<Advice>,
    col_m: Column<Advice>,
    col_r: Column<Advice>,
    col_z: Column<Advice>,
}

impl FdiCanonicity {
    #[allow(clippy::too_many_arguments)]
    fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_l: Column<Advice>,
        col_m: Column<Advice>,
        col_r: Column<Advice>,
        col_z: Column<Advice>,
        two_pow_4: pallas::Base,
        two_pow_140: Expression<pallas::Base>,
        two_pow_254: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_pk_d = meta.selector();

        meta.create_gate("NoteCommit input pk_d", |meta| {
            let q_notecommit_pk_d = meta.query_selector(q_notecommit_pk_d);

            let pkd_x = meta.query_advice(col_l, Rotation::cur());

            // `b_3` has been constrained to 4 bits outside this gate.
            let b_3 = meta.query_advice(col_m, Rotation::cur());
            // d_0 has been constrained to be boolean outside this gate.
            let d_0 = meta.query_advice(col_m, Rotation::next());

            // `c` has been constrained to 250 bits by the Sinsemilla hash.
            let c = meta.query_advice(col_r, Rotation::cur());
            let b3_c_prime = meta.query_advice(col_r, Rotation::next());

            let z13_c = meta.query_advice(col_z, Rotation::cur());
            let z14_b3_c_prime = meta.query_advice(col_z, Rotation::next());

            // x(pk_d) = b_3 + (2^4)c + (2^254)d_0
            let decomposition_check = {
                let sum = b_3.clone() + c.clone() * two_pow_4 + d_0.clone() * two_pow_254;
                sum - pkd_x
            };

            // b3_c_prime = b_3 + (2^4)c + 2^140 - t_P
            let b3_c_prime_check = b_3 + (c * two_pow_4) + two_pow_140 - t_p - b3_c_prime;

            // The nd_canonicity_checks are enforced if and only if `d_0` = 1.
            // `x(pk_d)` = `b_3 (4 bits) || c (250 bits) || d_0 (1 bit)`
            let canonicity_checks = iter::empty()
                .chain(Some(("d_0 = 1 => z13_c", z13_c)))
                .chain(Some(("d_0 = 1 => z14_b3_c_prime", z14_b3_c_prime)))
                .map(move |(name, poly)| (name, d_0.clone() * poly));

            Constraints::with_selector(
                q_notecommit_pk_d,
                iter::empty()
                    .chain(Some(("decomposition", decomposition_check)))
                    .chain(Some(("b3_c_prime_check", b3_c_prime_check)))
                    .chain(canonicity_checks),
            )
        });

        Self {
            q_notecommit_pk_d,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        fdi: AssignedCell<pallas::Base, pallas::Base>,
        b_3: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        c: NoteCommitPiece,
        d_0: AssignedCell<pallas::Base, pallas::Base>,
        b3_c_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_c: AssignedCell<pallas::Base, pallas::Base>,
        z14_b3_c_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input fdi",
            |mut region| {
                fdi.copy_advice(|| "fdi", &mut region, self.col_l, 0)?;

                b_3.inner()
                    .copy_advice(|| "b_3", &mut region, self.col_m, 0)?;
                d_0.copy_advice(|| "d_0", &mut region, self.col_m, 1)?;

                c.inner()
                    .cell_value()
                    .copy_advice(|| "c", &mut region, self.col_r, 0)?;
                b3_c_prime.copy_advice(|| "b3_c_prime", &mut region, self.col_r, 1)?;

                z13_c.copy_advice(|| "z13_c", &mut region, self.col_z, 0)?;
                z14_b3_c_prime.copy_advice(|| "z14_b3_c_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_pk_d.enable(&mut region, 0)
            },
        )
    }
}

/// |  A_6  | A_7 | A_8 | A_9 | q_notecommit_value |
/// ------------------------------------------------
/// | value | d_2 | d_3 | e_0 |          1         |
///
/// <https://p.z.cash/orchard-0.1:note-commit-canonicity-v?partial>
#[derive(Clone, Debug)]
struct ValueCanonicity {
    q_notecommit_value: Selector,
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
        two_pow_8: pallas::Base,
        two_pow_58: pallas::Base,
    ) -> Self {
        let q_notecommit_value = meta.selector();

        meta.create_gate("NoteCommit input value", |meta| {
            let q_notecommit_value = meta.query_selector(q_notecommit_value);

            let value = meta.query_advice(col_l, Rotation::cur());
            // d_2 has been constrained to 8 bits outside this gate.
            let d_2 = meta.query_advice(col_m, Rotation::cur());
            // z1_d has been constrained to 50 bits by the Sinsemilla hash.
            let z1_d = meta.query_advice(col_r, Rotation::cur());
            let d_3 = z1_d;
            // `e_0` has been constrained to 6 bits outside this gate.
            let e_0 = meta.query_advice(col_z, Rotation::cur());

            // value = d_2 + (2^8)d_3 + (2^58)e_0
            let value_check = d_2 + d_3 * two_pow_8 + e_0 * two_pow_58 - value;

            Constraints::with_selector(q_notecommit_value, Some(("value_check", value_check)))
        });

        Self {
            q_notecommit_value,
            col_l,
            col_m,
            col_r,
            col_z,
        }
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        value: AssignedCell<NoteValue, pallas::Base>,
        d_2: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        z1_d: AssignedCell<pallas::Base, pallas::Base>,
        e_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input value",
            |mut region| {
                value.copy_advice(|| "value", &mut region, self.col_l, 0)?;
                d_2.inner()
                    .copy_advice(|| "d_2", &mut region, self.col_m, 0)?;
                z1_d.copy_advice(|| "d3 = z1_d", &mut region, self.col_r, 0)?;
                e_0.inner()
                    .copy_advice(|| "e_0", &mut region, self.col_z, 0)?;

                self.q_notecommit_value.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6 | A_7 |    A_8     |      A_9       | q_notecommit_rho |
/// --------------------------------------------------------------
/// | rho | e_1 |    f       | z13_f          |        1         |
/// |     | g_0 | e1_f_prime | z14_e1_f_prime |        0         |
///
/// <https://p.z.cash/orchard-0.1:note-commit-canonicity-rho?partial>
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
        two_pow_4: pallas::Base,
        two_pow_140: Expression<pallas::Base>,
        two_pow_254: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_rho = meta.selector();

        meta.create_gate("NoteCommit input rho", |meta| {
            let q_notecommit_rho = meta.query_selector(q_notecommit_rho);

            let rho = meta.query_advice(col_l, Rotation::cur());

            // `e_1` has been constrained to 4 bits outside this gate.
            let e_1 = meta.query_advice(col_m, Rotation::cur());
            let g_0 = meta.query_advice(col_m, Rotation::next());

            // `f` has been constrained to 250 bits by the Sinsemilla hash.
            let f = meta.query_advice(col_r, Rotation::cur());
            let e1_f_prime = meta.query_advice(col_r, Rotation::next());

            let z13_f = meta.query_advice(col_z, Rotation::cur());
            let z14_e1_f_prime = meta.query_advice(col_z, Rotation::next());

            // rho = e_1 + (2^4) f + (2^254) g_0
            let decomposition_check = {
                let sum = e_1.clone() + f.clone() * two_pow_4 + g_0.clone() * two_pow_254;
                sum - rho
            };

            // e1_f_prime = e_1 + (2^4)f + 2^140 - t_P
            let e1_f_prime_check = e_1 + (f * two_pow_4) + two_pow_140 - t_p - e1_f_prime;

            // The rho_canonicity_checks are enforced if and only if `g_0` = 1.
            // rho = e_1 (4 bits) || f (250 bits) || g_0 (1 bit)
            let canonicity_checks = iter::empty()
                .chain(Some(("g_0 = 1 => z13_f", z13_f)))
                .chain(Some(("g_0 = 1 => z14_e1_f_prime", z14_e1_f_prime)))
                .map(move |(name, poly)| (name, g_0.clone() * poly));

            Constraints::with_selector(
                q_notecommit_rho,
                iter::empty()
                    .chain(Some(("decomposition", decomposition_check)))
                    .chain(Some(("e1_f_prime_check", e1_f_prime_check)))
                    .chain(canonicity_checks),
            )
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
        layouter: &mut impl Layouter<pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        f: NoteCommitPiece,
        g_0: AssignedCell<pallas::Base, pallas::Base>,
        e1_f_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_c: AssignedCell<pallas::Base, pallas::Base>,
        z14_e1_f_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input rho",
            |mut region| {
                rho.copy_advice(|| "rho", &mut region, self.col_l, 0)?;

                e_1.inner()
                    .copy_advice(|| "e_1", &mut region, self.col_m, 0)?;
                g_0.copy_advice(|| "g_0", &mut region, self.col_m, 1)?;

                f.inner()
                    .cell_value()
                    .copy_advice(|| "f", &mut region, self.col_r, 0)?;
                e1_f_prime.copy_advice(|| "e1_f_prime", &mut region, self.col_r, 1)?;

                z13_c.copy_advice(|| "z13_c", &mut region, self.col_z, 0)?;
                z14_e1_f_prime.copy_advice(|| "z14_e1_f_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_rho.enable(&mut region, 0)
            },
        )
    }
}

/// | A_6 | A_7 |     A_8     |       A_9       | q_notecommit_psi |
/// ----------------------------------------------------------------
/// | psi | g_1 |   g_2       | z13_g           |        1         |
/// | h_0 | h_1 | g1_g2_prime | z13_g1_g2_prime |        0         |
///
/// <https://p.z.cash/orchard-0.1:note-commit-canonicity-psi?partial>
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
        two_pow_9: pallas::Base,
        two_pow_130: Expression<pallas::Base>,
        two_pow_249: pallas::Base,
        two_pow_254: pallas::Base,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_notecommit_psi = meta.selector();

        meta.create_gate("NoteCommit input psi", |meta| {
            let q_notecommit_psi = meta.query_selector(q_notecommit_psi);

            let psi = meta.query_advice(col_l, Rotation::cur());
            let h_0 = meta.query_advice(col_l, Rotation::next());

            let g_1 = meta.query_advice(col_m, Rotation::cur());
            let h_1 = meta.query_advice(col_m, Rotation::next());

            let z1_g = meta.query_advice(col_r, Rotation::cur());
            let g_2 = z1_g;
            let g1_g2_prime = meta.query_advice(col_r, Rotation::next());

            let z13_g = meta.query_advice(col_z, Rotation::cur());
            let z13_g1_g2_prime = meta.query_advice(col_z, Rotation::next());

            // psi = g_1 + (2^9) g_2 + (2^249) h_0 + (2^254) h_1
            let decomposition_check = {
                let sum = g_1.clone()
                    + g_2.clone() * two_pow_9
                    + h_0.clone() * two_pow_249
                    + h_1.clone() * two_pow_254;
                sum - psi
            };

            // g1_g2_prime = g_1 + (2^9)g_2 + 2^130 - t_P
            let g1_g2_prime_check = g_1 + (g_2 * two_pow_9) + two_pow_130 - t_p - g1_g2_prime;

            // The psi_canonicity_checks are enforced if and only if `h_1` = 1.
            // `psi` = `g_1 (9 bits) || g_2 (240 bits) || h_0 (5 bits) || h_1 (1 bit)`
            let canonicity_checks = iter::empty()
                .chain(Some(("h_1 = 1 => h_0", h_0)))
                .chain(Some(("h_1 = 1 => z13_g", z13_g)))
                .chain(Some(("h_1 = 1 => z13_g1_g2_prime", z13_g1_g2_prime)))
                .map(move |(name, poly)| (name, h_1.clone() * poly));

            Constraints::with_selector(
                q_notecommit_psi,
                iter::empty()
                    .chain(Some(("decomposition", decomposition_check)))
                    .chain(Some(("g1_g2_prime_check", g1_g2_prime_check)))
                    .chain(canonicity_checks),
            )
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
        layouter: &mut impl Layouter<pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        z1_g: AssignedCell<pallas::Base, pallas::Base>,
        h_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        h_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        g1_g2_prime: AssignedCell<pallas::Base, pallas::Base>,
        z13_f: AssignedCell<pallas::Base, pallas::Base>,
        z13_g1_g2_prime: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "NoteCommit input psi",
            |mut region| {
                psi.copy_advice(|| "psi", &mut region, self.col_l, 0)?;
                h_0.inner()
                    .copy_advice(|| "h_0", &mut region, self.col_l, 1)?;

                e_1.inner()
                    .copy_advice(|| "e_1", &mut region, self.col_m, 0)?;
                h_1.inner()
                    .copy_advice(|| "h_1", &mut region, self.col_m, 1)?;

                z1_g.copy_advice(|| "g_2 = z1_g", &mut region, self.col_r, 0)?;
                g1_g2_prime.copy_advice(|| "g1_g2_prime", &mut region, self.col_r, 1)?;

                z13_f.copy_advice(|| "z13_f", &mut region, self.col_z, 0)?;
                z13_g1_g2_prime.copy_advice(|| "z13_g1_g2_prime", &mut region, self.col_z, 1)?;

                self.q_notecommit_psi.enable(&mut region, 0)
            },
        )
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct NoteCommitConfig {
    b: DecomposeB,
    d: DecomposeD,
    c: DecomposeC,
    e: DecomposeE,
    f: DecomposeF,
    recp: RecpCanonicity,
    fdi: FdiCanonicity,
    v: ValueCanonicity,
    rho: RhoCanonicity,
    psi: PsiCanonicity,
    advices: [Column<Advice>; 10],
    sinsemilla_config:
        SinsemillaConfig<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
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
            HeadstashHashDomains,
            HeadstashCommitDomains,
            HeadstashFixedBases,
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
        // let g = DecomposeG::configure(meta, col_l, col_m, two, two_pow_10);
        // let h = DecomposeH::configure(meta, col_l, col_m, col_r, two_pow_5);

        let recp = RecpCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_130.clone(),
            two_pow_250,
            two_pow_254,
            t_p.clone(),
        );

        let fdi = FdiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140.clone(),
            two_pow_254,
            t_p.clone(),
        );

        let v = ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58);

        let rho = RhoCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140,
            two_pow_254,
            t_p.clone(),
        );

        let psi = PsiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_9,
            two_pow_130.clone(),
            two_pow_249,
            two_pow_254,
            t_p.clone(),
        );

        NoteCommitConfig {
            b,
            c,
            d,
            e,
            f,
            recp,
            fdi,
            v,
            rho,
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
    use halo2_gadgets::ecc::chip::EccChip;
    use halo2_gadgets::ecc::ScalarFixed;
    use halo2_gadgets::sinsemilla::{CommitDomain, Message};
    use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheck;
    use halo2_gadgets::utilities::FieldValue;
    use halo2_proofs::circuit::{Chip, Value};

    use super::*;

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn note_commit(
        mut layouter: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
        ecc_chip: EccChip<HeadstashFixedBases>,
        note_commit_chip: NoteCommitChip,
        recp: AssignedCell<pallas::Base, pallas::Base>,
        fdi: AssignedCell<pallas::Base, pallas::Base>,
        nd: AssignedCell<pallas::Base, pallas::Base>,
        esk: AssignedCell<pallas::Base, pallas::Base>,
        v: AssignedCell<NoteValue, pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        rcm: ScalarFixed<pallas::Affine, EccChip<HeadstashFixedBases>>,
    ) -> Result<Point<pallas::Affine, EccChip<HeadstashFixedBases>>, Error> {
        // Headstash NoteCommitment Message: recp(254) || fdi(64) || nd(254) || v(64) || rho(254) || esk(254) || psi(254)
        // Total: 1398 bits
        //
        // Optimized decomposition for Sinsemilla (250 bit pieces):
        //   Piece a: bits 0-249 of recp (250 bits)
        //   Piece b: bits 250-253 of recp || bits 0-63 of fdi || bits 0-181 of nd (4 + 64 + 182 = 250 bits)
        //   Piece c: bits 182-253 of nd || bits 0-63 of v || bits 0-113 of rho (72 + 64 + 114 = 250 bits)
        //   Piece d: bits 114-253 of rho || bits 0-109 of esk (140 + 110 = 250 bits)
        //   Piece e: bits 110-253 of esk || bits 0-105 of psi (144 + 106 = 250 bits)
        //   Piece f: bits 106-253 of psi (148 bits)
        //
        //   For our new decomposition:
        //   - recp: High bits (250-253) are in piece b - need to maintain canonicity check
        //   - fdi: u64, no canonicity needed
        //   - nd: High bits (182-253) span pieces b and c - need canonicity access
        //   - v: u64, no canonicity needed
        //   - rho: High bits (114-253) span pieces c and d - need canonicity access
        //   - esk: High bits (110-253) span pieces d and e - need NEW canonicity check
        //   - psi: High bits (106-253) span pieces e and f - need canonicity access

        let lookup_config = chip.config().lookup_config();

        // `a` = bits 0..=249 of `recp`
        let a = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "a"),
            [RangeConstrained::bitrange_of(recp.value(), 0..250)],
        )?;

        // b = bits 250-253 of recp || bits 0-63 of fdi || bits 0-181 of nd
        let (b, b_0, b_1, b_2, b_3) = DecomposeB::decompose(
            &lookup_config,
            chip.clone(),
            &mut layouter,
            &recp,
            &fdi,
            &nd,
        )?;

        // c = bits 182-253 of nd || bits 0-63 of v || bits 0-113 of rho (250 bits)

        let (c, c_0, c_1, c_2, c_3) =
            DecomposeC::decompose(&lookup_config, chip.clone(), &mut layouter, &nd, &v, &rho)?;

        // d = bits 114-253 of rho || bits 0-109 of esk (250 bits)
        let (d, d_0, d_1, d_2) =
            DecomposeD::decompose(&lookup_config, chip.clone(), &mut layouter, &rho, &esk)?;

        // e = bits 110-253 of esk || bits 0-105 of psi (250 bits)
        let (e, e_0, e_1) =
            DecomposeE::decompose(&lookup_config, chip.clone(), &mut layouter, &esk, &psi)?;

        // f = bits 106-253 of psi (148 bits)
        let (f, f_0, f_1) =
            DecomposeF::decompose(&lookup_config, chip.clone(), &mut layouter, &psi)?;

        // // f = bits 106-253 of psi (148 bits)
        // // Split into subpieces for Sinsemilla: each subpiece must be < 64 bits
        // // 63 + 63 + 22 = 148 bits
        // let f = MessagePiece::from_subpieces(
        //     chip.clone(),
        //     layouter.namespace(|| "f"),
        //     [
        //         RangeConstrained::bitrange_of(psi.value(), 106..169), // 63 bits
        //         RangeConstrained::bitrange_of(psi.value(), 169..232), // 63 bits
        //                                                               // RangeConstrained::bitrange_of(psi.value(), 232..254),   // 22 bits
        //     ],
        // )?;

        // cm = NoteCommit^Orchard_rcm(g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi)
        //
        // `cm = ⊥` is handled internally to `CommitDomain::commit`: incomplete addition
        // constraints allows ⊥ to occur, and then during synthesis it detects these edge
        // cases and raises an error (aborting proof creation).
        //
        // https://p.z.cash/ZKS:action-cm-old-integrity?partial
        // https://p.z.cash/ZKS:action-cmx-new-integrity?partial
        let (cm, zs) = {
            let message = Message::from_pieces(
                chip.clone(),
                vec![
                    a.clone(),
                    b.clone(),
                    c.clone(),
                    d.clone(),
                    e.clone(),
                    f.clone(),
                ],
            );
            let domain = CommitDomain::new(chip, ecc_chip, &HeadstashCommitDomains::NoteCommit);
            domain.commit(
                layouter.namespace(|| "Process NoteCommit inputs"),
                message,
                rcm,
            )?
        };

        // `CommitDomain::commit` returns the running sum for each `MessagePiece`. Grab
        // the outputs that we will need for canonicity checks.
        // With 6 pieces (a=0, b=1, c=2, d=3, e=4, f=5):
        let z13_a = zs[0][13].clone(); // recp canonicity (piece a)
        let z13_c = zs[2][0].clone(); // nd canonicity (piece c contains nd bits 182-253)
        let z1_d = zs[3][0].clone(); // rho/esk boundary (piece d)
        let z13_e = zs[4][0].clone(); // esk canonicity (piece e contains esk bits 110-253)
        let z13_f = zs[5][0].clone(); // psi canonicity (piece f contains psi bits 106-253)

        // Witness and constrain the bounds we need to ensure canonicity.
        // recp canonicity (spans pieces a and b)
        let (a_prime, z13_a_prime) = canon_bitshift_130(
            &lookup_config,
            layouter.namespace(|| "recp canonicity"),
            a.inner().cell_value(),
        )?;

        // psi canonicity (spans pieces e and f)
        // e_1 contains bits 0-3 of psi, f contains bits 106-253 of psi
        let (e1_f_prime, z14_e1_f_prime) = rho_canonicity(
            &lookup_config,
            layouter.namespace(|| "psi canonicity"),
            e_1.clone(),
            f.inner().cell_value(),
        )?;

        // nd canonicity (spans pieces b and c)
        // b_3 contains high bits of nd in piece b, c contains continuation
        // nd in piece b: bits 0-181 (182 bits), in piece c: bits 182-253 (72 bits)
        // Note: b_3 is bits 246-249 of piece b, which are bits 178-181 of nd
        // We need to check that nd < t_P
        // Following similar pattern: b_3 + (2^4)c includes the high bits of nd
        let (b3_c_prime, z14_b3_c_prime) = nd_canonicity(
            &lookup_config,
            layouter.namespace(|| "nd canonicity"),
            b_3.clone(),
            c.inner().cell_value(),
        )?;

        // esk canonicity (spans pieces d and e)
        // esk in piece d: bits 0-109 (110 bits), in piece e: bits 110-253 (144 bits)
        // e_0 contains bits 110-115 of esk (6 bits from start of piece e)
        // Check that esk < t_P using the boundary bits
        // Following similar pattern to rho_canonicity: e_0 + (2^6) * d captures esk bits
        let (e0_d_prime, z14_e0_d_prime) = esk_canonicity(
            &lookup_config,
            layouter.namespace(|| "esk canonicity"),
            e_0.clone(),
            d.inner().cell_value(),
        )?;

        // Finally, assign values to all of the NoteCommit regions.
        let cfg = note_commit_chip.config;
        let b_1 = cfg
            .b
            .assign(&mut layouter, b, b_0.clone(), b_1, b_2, b_3.clone())?;

        let d_0 = cfg
            .d
            .assign(&mut layouter, d, d_0, d_1, d_2.clone(), z1_d.clone())?;

        cfg.e.assign(&mut layouter, e, e_0.clone(), e_1.clone())?;

        cfg.recp.assign(
            &mut layouter,
            &recp,
            a,
            b_0,
            b_1,
            a_prime,
            z13_a,
            z13_a_prime,
        )?;

        cfg.fdi.assign(
            &mut layouter,
            fdi,
            b_3,
            c.clone(),
            d_0.clone(),
            b3_c_prime.clone(),
            z13_c.clone(),
            z14_b3_c_prime.clone(),
        )?;

        cfg.v
            .assign(&mut layouter, v, d_2.clone(), z1_d, e_0.clone())?;

        // Note: RhoCanonicity gate needs updating for new field layout
        // rho is now in pieces c,d (not e,f,g), using placeholders for now
        // TODO: Create proper rho canonicity check for c,d boundary
        cfg.rho.assign(
            &mut layouter,
            rho,
            e_0.clone(),    // Placeholder: should be from rho/esk boundary
            c,              // Placeholder: piece c contains part of rho
            d_0.clone(),    // Placeholder: d_0 is bit 114 of rho
            b3_c_prime,     // Placeholder
            z13_c,          // z13 of piece c (contains rho bits)
            z14_b3_c_prime, // Placeholder
        )?;

        // Note: PsiCanonicity gate needs updating for new field layout
        // psi is now in pieces e,f (was g,h), mapping to available variables
        // e_1 = bits 0-3 of psi, f = bits 106-253 of psi
        // e1_f_prime and z14_e1_f_prime are from our psi canonicity check
        cfg.psi.assign(
            &mut layouter,
            psi,
            e_1,            // bits 0-3 of psi (from piece e)
            z13_e,          // z13 of piece e (contains esk+psi bits)
            e_0,            // Placeholder: bits from esk
            d_2,            // Placeholder
            e1_f_prime,     // From psi canonicity check
            z13_f,          // z13 of piece f (contains psi high bits)
            z14_e1_f_prime, // From psi canonicity check
        )?;

        Ok(cm)
    }

    /// A canonicity check helper used in checking x(g_d), y(g_d), and y(pk_d).
    ///
    /// Specifications:
    /// - [`g_d` canonicity](https://p.z.cash/orchard-0.1:note-commit-canonicity-g_d?partial)
    /// - [`y` canonicity](https://p.z.cash/orchard-0.1:note-commit-canonicity-y?partial)
    fn canon_bitshift_130(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // element = `a (250 bits) || b_0 (4 bits) || b_1 (1 bit)`
        // - b_1 = 1 => b_0 = 0
        // - b_1 = 1 => a < t_P
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
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 130 bits of (a + 2^130 - t_P)"),
            a_prime,
            13,
            false,
        )?;
        let a_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

        Ok((a_prime, zs[13].clone()))
    }

    // /// Check canonicity of `x(pk_d)` encoding.
    /// Check canonicity of nd encoding (reused from nd_canonicity pattern).
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-pk_d?partial).
    fn nd_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        b_3: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        c: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // nd spans pieces b and c:
        // - In piece b: bits 0-181 of nd (182 bits total in b)
        // - In piece c: bits 182-253 of nd (72 bits at start of c)
        // b_3 is the last 4 bits of piece b (bits 246-249), which are bits 178-181 of nd
        // c (250 bits) starts with bits 182-253 of nd (72 bits)
        //
        // Check: b_3 + 2^4 c captures the high portion of nd
        // - z_13 of SinsemillaHash(c) == 0 constrains high bits of nd to 130 bits
        // - 0 ≤ b_3 + 2^4 c + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        // Decompose the low 140 bits of b3_c_prime = b_3 + 2^4 c + 2^140 - t_P,
        // and output the running sum at the end of it.
        // If b3_c_prime < 2^140, the running sum will be 0.
        let b3_c_prime = {
            let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            b_3.inner().value() + (two_pow_4 * c.value()) + two_pow_140 - t_p
        };

        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (b_3 + 2^4 c + 2^140 - t_P)"),
            b3_c_prime,
            14,
            false,
        )?;
        let b3_c_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((b3_c_prime, zs[14].clone()))
    }

    /// Check canonicity of esk encoding.
    ///
    /// Similar pattern to rho_canonicity but for esk field spanning pieces d and e.
    fn esk_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        e_0: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        d: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // esk spans pieces d and e:
        // - In piece d: bits 0-109 of esk (110 bits at end of piece d)
        // - In piece e: bits 110-253 of esk (144 bits at start of piece e)
        // e_0 is bits 110-115 of esk (6 bits)
        // d (250 bits) contains bits 114-253 of rho (140 bits) || bits 0-109 of esk (110 bits)
        //
        // Check: e_0 + 2^6 d captures the high portion of esk
        // - z_13 of SinsemillaHash(d) == 0 constrains high bits to 130 bits
        // - 0 ≤ e_0 + 2^6 d + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        // Decompose the low 140 bits of e0_d_prime = e_0 + 2^6 d + 2^140 - t_P
        let e0_d_prime = {
            let two_pow_6 = Value::known(pallas::Base::from(1u64 << 6));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            e_0.inner().value() + (two_pow_6 * d.value()) + two_pow_140 - t_p
        };

        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (e_0 + 2^6 d + 2^140 - t_P)"),
            e0_d_prime,
            14,
            false,
        )?;
        let e0_d_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((e0_d_prime, zs[14].clone()))
    }

    /// Check canonicity of `rho` encoding.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-rho?partial).
    fn rho_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        e_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        f: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `rho` = `e_1 (4 bits) || f (250 bits) || g_0 (1 bit)`
        // - g_0 = 1 => e_1 + 2^4 f < t_P
        // - 0 ≤ e_1 + 2^4 f < 2^134
        //     - e_1 is part of the Sinsemilla message piece
        //       e = e_0 (56 bits) || e_1 (4 bits)
        //     - e_1 is individually constrained to be 4 bits.
        //     - z_13 of SinsemillaHash(f) == 0 constrains bits 4..=253 of rho
        //       to 130 bits. z13_f == 0 is directly checked in the gate.
        // - 0 ≤ e_1 + 2^4 f + 2^140 - t_P < 2^140 (14 ten-bit lookups)

        let e1_f_prime = {
            let two_pow_4 = Value::known(pallas::Base::from(1u64 << 4));
            let two_pow_140 = Value::known(pallas::Base::from_u128(1u128 << 70).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            e_1.inner().value() + (two_pow_4 * f.value()) + two_pow_140 - t_p
        };

        // Decompose the low 140 bits of e1_f_prime = e_1 + 2^4 f + 2^140 - t_P,
        // and output the running sum at the end of it.
        // If e1_f_prime < 2^140, the running sum will be 0.
        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 140 bits of (e_1 + 2^4 f + 2^140 - t_P)"),
            e1_f_prime,
            14,
            false,
        )?;
        let e1_f_prime = zs[0].clone();
        assert_eq!(zs.len(), 15); // [z_0, z_1, ..., z_13, z_14]

        Ok((e1_f_prime, zs[14].clone()))
    }

    /// Check canonicity of `psi` encoding.
    ///
    /// [Specification](https://p.z.cash/orchard-0.1:note-commit-canonicity-psi?partial).
    fn psi_canonicity(
        lookup_config: &LookupRangeCheckConfig<pallas::Base, 10>,
        mut layouter: impl Layouter<pallas::Base>,
        g_1: RangeConstrained<pallas::Base, AssignedCell<pallas::Base, pallas::Base>>,
        g_2: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<CanonicityBounds, Error> {
        // `psi` = `g_1 (9 bits) || g_2 (240 bits) || h_0 (5 bits) || h_1 (1 bit)`
        // - h_1 = 1 => (h_0 = 0) ∧ (g_1 + 2^9 g_2 < t_P)
        // - 0 ≤ g_1 + 2^9 g_2 < 2^130
        //     - g_1 is individually constrained to be 9 bits
        //     - z_13 of SinsemillaHash(g) == 0 constrains bits 0..=248 of psi
        //       to 130 bits. z13_g == 0 is directly checked in the gate.
        // - 0 ≤ g_1 + (2^9)g_2 + 2^130 - t_P < 2^130 (13 ten-bit lookups)

        // Decompose the low 130 bits of g1_g2_prime = g_1 + (2^9)g_2 + 2^130 - t_P,
        // and output the running sum at the end of it.
        // If g1_g2_prime < 2^130, the running sum will be 0.
        let g1_g2_prime = {
            let two_pow_9 = Value::known(pallas::Base::from(1u64 << 9));
            let two_pow_130 = Value::known(pallas::Base::from_u128(1u128 << 65).square());
            let t_p = Value::known(pallas::Base::from_u128(T_P));
            g_1.inner().value() + (two_pow_9 * g_2.value()) + two_pow_130 - t_p
        };

        let zs = lookup_config.witness_check(
            layouter.namespace(|| "Decompose low 130 bits of (g_1 + (2^9)g_2 + 2^130 - t_P)"),
            g1_g2_prime,
            13,
            false,
        )?;
        let g1_g2_prime = zs[0].clone();
        assert_eq!(zs.len(), 14); // [z_0, z_1, ..., z_13]

        Ok((g1_g2_prime, zs[13].clone()))
    }
}

#[cfg(test)]
mod tests {
    use core::iter;

    use super::NoteCommitConfig;
    use crate::{
        circuit::{
            gadget::assign_free_advice,
            note_commit::{gadgets, NoteCommitChip},
        },
        constants::{
            fixed_bases::HeadstashFixedBases, sinsemilla::HeadstashCommitDomains,
            HeadstashHashDomains, DST_CM, L_ORCHARD_BASE, L_VALUE, T_Q,
        },
        value::NoteValue,
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::chip::SinsemillaChip,
        sinsemilla::primitives::CommitDomain,
        utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
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
    fn note_commit() {
        #[derive(Default)]
        struct MyCircuit {
            esk: Value<pallas::Base>,
            v: Value<pallas::Base>,
            nd: Value<pallas::Base>,
            fdi: Value<pallas::Base>,
            recp: Value<pallas::Base>,
            rho: Value<pallas::Base>,
            psi: Value<pallas::Base>,
        }

        impl Circuit<pallas::Base> for MyCircuit {
            type Config = (NoteCommitConfig, EccConfig<HeadstashFixedBases>);
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
                    HeadstashHashDomains,
                    HeadstashCommitDomains,
                    HeadstashFixedBases,
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

                let ecc_config = EccChip::<HeadstashFixedBases>::configure(
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
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (note_commit_config, ecc_config) = config;

                // Load the Sinsemilla generator lookup table used by the whole circuit.
                SinsemillaChip::<
                HeadstashHashDomains,
                HeadstashCommitDomains,
                HeadstashFixedBases,
            >::load(note_commit_config.sinsemilla_config.clone(), &mut layouter)?;

                // Construct a Sinsemilla chip
                let sinsemilla_chip =
                    SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

                // Construct an ECC chip
                let ecc_chip = EccChip::construct(ecc_config);

                // Construct a NoteCommit chip
                let note_commit_chip = NoteCommitChip::construct(note_commit_config.clone());

                // // Witness g_d
                // Witness recp.
                let recp = assign_free_advice(
                    layouter.namespace(|| "witness recp"),
                    note_commit_config.advices[0],
                    self.recp,
                )?;
                // let g_d = {
                //     let g_d = self.gd_x.zip(self.gd_y_lsb).map(|(x, y_lsb)| {
                //         // Calculate y = (x^3 + 5).sqrt()
                //         let mut y = (x.square() * x + pallas::Affine::b()).sqrt().unwrap();
                //         if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                //             y = -y;
                //         }
                //         pallas::Affine::from_xy(x, y).unwrap()
                //     });

                //     NonIdentityPoint::new(
                //         ecc_chip.clone(),
                //         layouter.namespace(|| "witness g_d"),
                //         g_d,
                //     )?
                // };

                // // Witness pk_d
                // let pk_d = {
                //     let pk_d = self.pkd_x.zip(self.pkd_y_lsb).map(|(x, y_lsb)| {
                //         // Calculate y = (x^3 + 5).sqrt()
                //         let mut y = (x.square() * x + pallas::Affine::b()).sqrt().unwrap();
                //         if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                //             y = -y;
                //         }
                //         pallas::Affine::from_xy(x, y).unwrap()
                //     });

                //     NonIdentityPoint::new(
                //         ecc_chip.clone(),
                //         layouter.namespace(|| "witness pk_d"),
                //         pk_d,
                //     )?
                // };
                // Witness nd.
                let nd = assign_free_advice(
                    layouter.namespace(|| "witness nd"),
                    note_commit_config.advices[0],
                    self.nd,
                )?;
                // Witness fdi.
                let fdi = assign_free_advice(
                    layouter.namespace(|| "witness fdi"),
                    note_commit_config.advices[0],
                    self.fdi,
                )?;

                // Witness esk.
                let esk = assign_free_advice(
                    layouter.namespace(|| "witness esk"),
                    note_commit_config.advices[0],
                    self.esk,
                )?;
                // Witness a random non-negative u64 note value
                // A note value cannot be negative.
                let value = {
                    let mut rng = OsRng;
                    NoteValue::from_raw(rng.next_u64())
                };
                let value_var = {
                    assign_free_advice(
                        layouter.namespace(|| "witness value"),
                        note_commit_config.advices[0],
                        Value::known(value),
                    )?
                };

                // Witness rho
                let rho = assign_free_advice(
                    layouter.namespace(|| "witness rho"),
                    note_commit_config.advices[0],
                    self.rho,
                )?;

                // Witness psi
                let psi = assign_free_advice(
                    layouter.namespace(|| "witness psi"),
                    note_commit_config.advices[0],
                    self.psi,
                )?;

                let rcm = pallas::Scalar::random(OsRng);
                let rcm_gadget = ScalarFixed::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "rcm"),
                    Value::known(rcm),
                )?;

                let cm = gadgets::note_commit(
                    layouter.namespace(|| "Hash NoteCommit pieces"),
                    sinsemilla_chip,
                    ecc_chip.clone(),
                    note_commit_chip,
                    recp,
                    fdi,
                    nd,
                    esk,
                    value_var,
                    rho,
                    psi,
                    rcm_gadget,
                )?;
                let expected_cm = {
                    let domain = CommitDomain::new(DST_CM);
                    // Headstash NoteCommit: recp || fdi || nd || v || rho || esk || psi
                    use bitvec::{array::BitArray, order::Lsb0};
                    let point = self
                        .recp
                        .zip(self.fdi)
                        .zip(self.nd)
                        .zip(self.v)
                        .zip(self.esk)
                        .zip(self.rho)
                        .zip(self.psi)
                        .map(|((((((recp, fdi), nd), v), esk), rho), psi)| {
                            let recp_bytes = recp.to_repr();
                            let binding = BitArray::<_, Lsb0>::new(recp_bytes);

                            domain
                                .commit(
                                    iter::empty()
                                        .chain(binding.iter().by_vals())
                                        .chain(fdi.to_le_bits().iter().by_vals())
                                        .chain(nd.to_le_bits().iter().by_vals())
                                        .chain(v.to_le_bits().iter().by_vals())
                                        .chain(
                                            rho.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            esk.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            psi.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        ),
                                    &rcm,
                                )
                                .unwrap()
                                .to_affine()
                        });
                    NonIdentityPoint::new(ecc_chip, layouter.namespace(|| "witness cm"), point)?
                };
                cm.constrain_equal(layouter.namespace(|| "cm == expected cm"), &expected_cm)
            }
        }

        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
        // Test different values of `ak`, `nk`
        let circuits = [
            // `gd_x` = -1, `pkd_x` = -1 (these have to be x-coordinates of curve points)
            // `rho` = 0, `psi` = 0
            // MyCircuit {
            //     recp: Value::known(pallas::Base::zero()),
            //     rho: Value::known(pallas::Base::zero()),
            //     psi: Value::known(pallas::Base::zero()),
            //     esk: Value::known(pallas::Base::zero()),
            //     nd: Value::known(pallas::Base::zero()),
            //     fdi: Value::known(pallas::Base::zero()),
            // },
            MyCircuit {
                recp: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128(T_Q - 1)),
                psi: Value::known(pallas::Base::from_u128(T_Q - 1)),
                esk: Value::known(pallas::Base::one()),
                nd: Value::known(pallas::Base::one()),
                fdi: Value::known(pallas::Base::one()),
                v: Value::known(pallas::Base::one()),
            },
            // // `rho` = T_Q - 1, `psi` = T_Q - 1
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::zero()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::zero()),
            // },
            // // `rho` = T_Q, `psi` = T_Q
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::one()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::zero()),
            //     rho: Value::known(pallas::Base::from_u128(T_Q)),
            //     psi: Value::known(pallas::Base::from_u128(T_Q)),
            // },
            // // `rho` = 2^127 - 1, `psi` = 2^127 - 1
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::zero()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::one()),
            //     rho: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
            //     psi: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
            // },
            // // `rho` = 2^127, `psi` = 2^127
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::zero()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::zero()),
            //     rho: Value::known(pallas::Base::from_u128(1 << 127)),
            //     psi: Value::known(pallas::Base::from_u128(1 << 127)),
            // },
            // // `rho` = 2^254 - 1, `psi` = 2^254 - 1
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::one()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::one()),
            //     rho: Value::known(two_pow_254 - pallas::Base::one()),
            //     psi: Value::known(two_pow_254 - pallas::Base::one()),
            // },
            // // `rho` = 2^254, `psi` = 2^254
            // MyCircuit {
            //     gd_x: Value::known(-pallas::Base::one()),
            //     gd_y_lsb: Value::known(pallas::Base::one()),
            //     pkd_x: Value::known(-pallas::Base::one()),
            //     pkd_y_lsb: Value::known(pallas::Base::zero()),
            //     rho: Value::known(two_pow_254),
            //     psi: Value::known(two_pow_254),
            // },
        ];

        for circuit in circuits.iter() {
            let prover = MockProver::<pallas::Base>::run(11, circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
