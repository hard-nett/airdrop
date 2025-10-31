//! Gadgets used in the Headstash circuit
//!
use ff::Field;
use halo2_gadgets::ecc::chip::EccChip;
use halo2_gadgets::ecc::{EccInstructions, FixedPointBaseField, Point, X};
use halo2_gadgets::poseidon::primitives::ConstantLength;
use halo2_gadgets::poseidon::{
    Hash as PoseidonHash, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
    primitives::{self as poseidon},
};
use pasta_curves::pallas;

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{self, Advice, Assigned, Column},
};

use crate::circuit::AddChip;
use crate::constants::fixed_bases::{HeadstashFixedBases, NullifierK};

pub(in crate::circuit) mod add_chip;

impl super::HeadstashConfig {
    pub(super) fn add_chip(&self) -> add_chip::AddChip {
        add_chip::AddChip::construct(self.add_config.clone())
    }
    pub(super) fn ecc_chip(&self) -> EccChip<HeadstashFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    pub(super) fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }
}

/// An instruction set for adding two circuit words (field elements).
pub(in crate::circuit) trait AddInstruction<F: Field>: Chip<F> {
    /// Constraints `a + b` and returns the sum.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, plonk::Error>;
}

/// `DeriveNullifier` from [Section 4.16: Note Commitments and Nullifiers].
pub(in crate::circuit) fn derive_nullifier<
    PoseidonChip: PoseidonSpongeInstructions<pallas::Base, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>,
    AddChip: AddInstruction<pallas::Base>,
    EccChip: EccInstructions<
            pallas::Affine,
            FixedPoints = HeadstashFixedBases,
            Var = AssignedCell<pallas::Base, pallas::Base>,
        >,
>(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: &AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
    // hash = poseidon_hash(nk, rho)
    let hash = {
        let poseidon_message = [nk, rho];
        let poseidon_hasher =
            PoseidonHash::init(poseidon_chip, layouter.namespace(|| "Poseidon init"))?;
        poseidon_hasher.hash(
            layouter.namespace(|| "Poseidon hash (nk, rho)"),
            poseidon_message,
        )?
    };

    // Add hash output to psi.
    // `scalar` = poseidon_hash(nk, rho) + psi.
    let scalar = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash,
        psi,
    )?;

    // Multiply scalar by NullifierK
    // `product` = [poseidon_hash(nk, rho) + psi] NullifierK.
    //
    let product = {
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
        nullifier_k.mul(
            layouter.namespace(|| "[poseidon_output + psi] NullifierK"),
            scalar,
        )?
    };
    // Add cm to multiplied fixed base to get nf
    // cm + [poseidon_output + psi] NullifierK
    cm.add(layouter.namespace(|| "nf"), &product)
        .map(|res| res.extract_p())
}

/// Witnesses the given value in a standalone region.
///
/// Usages of this helper are technically superfluous, as the single-cell region is only
/// ever used in equality constraints. We could eliminate them with a
/// [write-on-copy abstraction](https://github.com/zcash/halo2/issues/334).
pub(in crate::circuit) fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, plonk::Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}
