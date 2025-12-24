//! generate the note leaf from its inputs and constrain it to root.

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
        Point, ScalarFixed,
    },
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, HashDomains, Message, MessagePiece, SinsemillaInstructions,
    },
    utilities::{
        bool_check,
        lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
        FieldValue, RangeConstrained,
    },
};

/// derive leaf
pub fn derive_leaf(
    mut lo: impl Layouter<pallas::Base>,
    sc: &SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    ecc_chip: &EccChip<OrchardFixedBases>,
    epk: (CrtInteger<pallas::Base>, CrtInteger<pallas::Base>), // (x,y), where both are 3x88 bit limbs
    fdi: AssignedCell<pallas::Base, pallas::Base>,
    v: AssignedCell<NoteValue, pallas::Base>,
    nd: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<
    // (
    //     NonIdentityEccPoint,
    //     Vec<Vec<halo2_proofs::circuit::AssignedCell<pasta_curves::Fp, pasta_curves::Fp>>>,
    // ),()
    ((), ()),
    Error,
> {
    let domain = OrchardHashDomains::Leaf;
    let vv = v.value().map(|v| pallas::Base::from(v.inner()));
    // Prepare message as bits from DST_HKDF + epk_sum.to_le_bits() + fdi.to_le_bits() + v.to_le_bits() + nd.to_le_bits()
    // Decompose AssignedValue to bits using range check utilities
    // Construct Messages

    // epk (255): a 0..250 || b0 250..255
    // nd (255) b1 0..5 || c 5..255
    // v (64) d 0..60 || e0 60..64
    // fdi (64) || e1 0..6 || f0 6..64

    // constrain the sum of the 3x88 bit limb representation before defining message subpiece
    // Piece a: bits 0-249 of nd (250 bits)
    let b1 = RangeConstrained::bitrange_of(nd.value(), 0..5);

    let c = MessagePiece::from_subpieces(
        sc.clone(),
        lo.namespace(|| "piece_a: nd[0..250)"),
        [RangeConstrained::bitrange_of(nd.value(), 5..255)],
    )?;

    let d = MessagePiece::from_subpieces(
        sc.clone(),
        lo.namespace(|| "piece_a: nd[0..250)"),
        [RangeConstrained::bitrange_of(vv.value(), 0..60)],
    )?;

    let message = Message::from_pieces(sc.clone(), vec![]);
    // s.hash_to_point(lo, OrchardHashDomains::Leaf.Q(), message)
    Ok(((), ()))
}
