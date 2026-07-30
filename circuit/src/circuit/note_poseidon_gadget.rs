//! In-circuit Poseidon-v1 gadgets for **private note commitment**.
//!
//! Pure off-circuit SSOT: [`crate::note_poseidon`].
//! ADR: `docs/plans/spectrum/ADR-POSEIDON-NOTE-COMMIT.md` (option A lift).

use halo2_gadgets::{
    ecc::{
        chip::EccChip,
        FixedPointBaseField, Point,
    },
    poseidon::{
        primitives::{ConstantLength, P128Pow5T3},
        Hash as PoseidonHash, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig,
    },
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, Error},
};
use pasta_curves::pallas;

use crate::constants::{OrchardFixedBases, OrchardFixedBasesBase};
use crate::note_poseidon::note_commit_tag;

/// Assign a fixed field element as an advice cell (constant witness).
fn assign_constant(
    mut layouter: impl Layouter<pallas::Base>,
    column: Column<Advice>,
    label: &str,
    value: pallas::Base,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || label,
        |mut region| region.assign_advice(|| label, column, 0, || Value::known(value)),
    )
}

/// Poseidon-v1 private note commitment digest `cmx`.
///
/// ```text
/// Poseidon^P128Pow5T3 / ConstantLength<9>(
///   tag_note_commit, nd, v, fdi, recp, esk, rho, psi, rcm_base
/// )
/// ```
///
/// Matches [`crate::note_poseidon::poseidon_note_cmx`]. Tag is assigned as a fixed
/// constant (prover cannot choose the domain).
#[allow(clippy::too_many_arguments)]
pub fn derive_note_cmx_poseidon(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_config: &PoseidonConfig<pallas::Base, 3, 2>,
    advice: Column<Advice>,
    nd: AssignedCell<pallas::Base, pallas::Base>,
    v: AssignedCell<pallas::Base, pallas::Base>,
    fdi: AssignedCell<pallas::Base, pallas::Base>,
    recp: AssignedCell<pallas::Base, pallas::Base>,
    esk: AssignedCell<pallas::Base, pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    rcm_base: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    let tag = assign_constant(
        layouter.namespace(|| "note-commit personalization tag"),
        advice,
        "tag_note_commit",
        note_commit_tag(),
    )?;

    let poseidon_chip = PoseidonChip::construct(poseidon_config.clone());
    let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<9>, 3, 2>::init(
        poseidon_chip,
        layouter.namespace(|| "Poseidon note-commit init"),
    )?;
    hasher.hash(
        layouter.namespace(|| "Poseidon note cmx"),
        [tag, nd, v, fdi, recp, esk, rho, psi, rcm_base],
    )
}

/// Lift `cmx` to `cm_point = [cmx] · NoteCommitR` (ADR option A).
pub fn lift_note_cmx_gadget(
    mut layouter: impl Layouter<pallas::Base>,
    ecc_chip: EccChip<OrchardFixedBases>,
    cmx: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<Point<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
    let note_commit_r =
        FixedPointBaseField::from_inner(ecc_chip, OrchardFixedBasesBase::NoteCommitR);
    note_commit_r.mul(
        layouter.namespace(|| "[cmx] NoteCommitR"),
        cmx,
    )
}

/// Full private note commitment: Poseidon `cmx` + lift to point.
///
/// Returns `(cm_point, cmx_cell)`.
#[allow(clippy::too_many_arguments)]
pub fn note_commit_poseidon(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_config: &PoseidonConfig<pallas::Base, 3, 2>,
    ecc_chip: EccChip<OrchardFixedBases>,
    advice: Column<Advice>,
    nd: AssignedCell<pallas::Base, pallas::Base>,
    v: AssignedCell<pallas::Base, pallas::Base>,
    fdi: AssignedCell<pallas::Base, pallas::Base>,
    recp: AssignedCell<pallas::Base, pallas::Base>,
    esk: AssignedCell<pallas::Base, pallas::Base>,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: AssignedCell<pallas::Base, pallas::Base>,
    rcm_base: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<
    (
        Point<pallas::Affine, EccChip<OrchardFixedBases>>,
        AssignedCell<pallas::Base, pallas::Base>,
    ),
    Error,
> {
    let cmx = derive_note_cmx_poseidon(
        layouter.namespace(|| "Poseidon note cmx"),
        poseidon_config,
        advice,
        nd,
        v,
        fdi,
        recp,
        esk,
        rho,
        psi,
        rcm_base,
    )?;
    let cm_point = lift_note_cmx_gadget(
        layouter.namespace(|| "lift cmx to NoteCommitR"),
        ecc_chip,
        cmx.clone(),
    )?;
    Ok((cm_point, cmx))
}

/// Pure/circuit consistency tests for Poseidon note `cmx` (no ECC lift tables).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::note_poseidon::{poseidon_note_cmx, rcm_to_base};
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem},
    };

    #[derive(Default)]
    struct NoteCmxCircuit {
        nd: Value<pallas::Base>,
        v: Value<pallas::Base>,
        fdi: Value<pallas::Base>,
        recp: Value<pallas::Base>,
        esk: Value<pallas::Base>,
        rho: Value<pallas::Base>,
        psi: Value<pallas::Base>,
        rcm_base: Value<pallas::Base>,
    }

    #[derive(Clone)]
    struct NoteCmxConfig {
        advice: [Column<Advice>; 10],
        poseidon: PoseidonConfig<pallas::Base, 3, 2>,
        instance: halo2_proofs::plonk::Column<halo2_proofs::plonk::Instance>,
    }

    impl Circuit<pallas::Base> for NoteCmxCircuit {
        type Config = NoteCmxConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let instance = meta.instance_column();
            meta.enable_equality(instance);
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
            for a in &advices {
                meta.enable_equality(*a);
            }
            let rc_a = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];
            let rc_b = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];
            meta.enable_constant(rc_b[0]);
            let poseidon = PoseidonChip::configure::<P128Pow5T3>(
                meta,
                advices[0..3].try_into().unwrap(),
                advices[3],
                rc_a,
                rc_b,
            );
            NoteCmxConfig {
                advice: advices,
                poseidon,
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let mut load = |col: Column<Advice>, val: Value<pallas::Base>| {
                layouter.assign_region(
                    || "load",
                    |mut region| region.assign_advice(|| "v", col, 0, || val),
                )
            };
            let nd = load(config.advice[0], self.nd)?;
            let v = load(config.advice[1], self.v)?;
            let fdi = load(config.advice[2], self.fdi)?;
            let recp = load(config.advice[3], self.recp)?;
            let esk = load(config.advice[4], self.esk)?;
            let rho = load(config.advice[5], self.rho)?;
            let psi = load(config.advice[6], self.psi)?;
            let rcm_base = load(config.advice[7], self.rcm_base)?;

            let cmx = derive_note_cmx_poseidon(
                layouter.namespace(|| "note cmx"),
                &config.poseidon,
                config.advice[0],
                nd,
                v,
                fdi,
                recp,
                esk,
                rho,
                psi,
                rcm_base,
            )?;
            layouter.constrain_instance(cmx.cell(), config.instance, 0)?;
            Ok(())
        }
    }

    #[test]
    fn poseidon_note_cmx_gadget_matches_pure() {
        let nd = pallas::Base::from(1u64);
        let v = pallas::Base::from(2u64);
        let fdi = pallas::Base::from(3u64);
        let recp = pallas::Base::from(4u64);
        let esk = pallas::Base::from(5u64);
        let rho = pallas::Base::from(6u64);
        let psi = pallas::Base::from(7u64);
        let rcm_base = rcm_to_base(pasta_curves::pallas::Scalar::from(8u64));
        let expected = poseidon_note_cmx(nd, v, fdi, recp, esk, rho, psi, rcm_base);

        let circuit = NoteCmxCircuit {
            nd: Value::known(nd),
            v: Value::known(v),
            fdi: Value::known(fdi),
            recp: Value::known(recp),
            esk: Value::known(esk),
            rho: Value::known(rho),
            psi: Value::known(psi),
            rcm_base: Value::known(rcm_base),
        };
        // k enough for a single ConstantLength<9> Poseidon
        let prover = MockProver::run(11, &circuit, vec![vec![expected]]).unwrap();
        prover.assert_satisfied();
    }
}
