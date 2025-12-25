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
        CommitDomain, HashDomain, HashDomains, Message, MessagePiece, SinsemillaInstructions,
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
    // epk (255): a 0..250 || b0 250..255 || b1 epk.y-parity (1 bit)
    // nd (255) b2 0..4 || c 4..254 || d0 254..255
    // v (64) d1 0..64
    // fdi (64) || d2 0..5 || f0 5..64

    // Piece a: bits 0-249 of epk.x (250 bits)
    let a = MessagePiece::from_subpieces(
        sc.clone(),
        lo.namespace(|| "a: epk.x[0..250)"),
        [RangeConstrained::bitrange_of(epk.0.native.value(), 0..250)],
    )?;

    // Piece b0: bits 250..255 of epk.x (5 bits)
    let b0 = RangeConstrained::bitrange_of(epk.0.native.value(), 250..255);
    // Piece b1: parity bit for y value in compressed esk.
    let b1 = RangeConstrained::bitrange_of(epk.1.native.value(), 0..1);
    // Piece b2: bits 0..4 of nd (4 bits)
    let b2 = RangeConstrained::bitrange_of(nd.value(), 0..4);
    // Piece b: concatenation of b0, b1, b2 (10 bits)
    let b = MessagePiece::from_subpieces(sc.clone(), lo.namespace(|| "b"), [b0, b1, b2])?;

    // Piece c: bits 4..254 of nd (250 bits)
    let c0 = RangeConstrained::bitrange_of(nd.value(), 4..254);
    let c = MessagePiece::from_subpieces(sc.clone(), lo.namespace(|| "c: nd[4..254)"), [c0])?;
    // Piece d: concatenation of d0, d1, d2 (1 + 64 + 5 = 70 bits)
    let d0 = RangeConstrained::bitrange_of(epk.0.native.value(), 254..255);
    let d1 = RangeConstrained::bitrange_of(vv.value(), 0..64);
    let d2 = RangeConstrained::bitrange_of(fdi.value(), 0..5);
    let d = MessagePiece::from_subpieces(sc.clone(), lo.namespace(|| "piece_d"), [d0, d1, d2])?;
    // Piece e: e0 - bits 5..64 of fdi,  e1 - 1 bit padding (60 bits)
    let e0 = RangeConstrained::bitrange_of(fdi.value(), 5..64);
    let e1 = RangeConstrained::bitrange_of(Value::known(&pallas::Base::zero()), 0..1);
    let e = MessagePiece::from_subpieces(sc.clone(), lo.namespace(|| "piece_f"), [e0, e1])?;
    let message = Message::from_pieces(sc.clone(), vec![a, b, c, d, e]);

    let (hash, zs) =
        HashDomain::new(sc.clone(), ecc_chip.clone(), &domain).hash_to_point(lo, message)?;

    println!("Running sums length:");
    println!("zs:{:#?}", zs.len());
    println!("zs[0]:{:#?}", zs[0].len());
    println!("zs[1]:{:#?}", zs[1].len());
    println!("zs[2]:{:#?}", zs[2].len());
    println!("zs[3]:{:#?}", zs[3].len());

    // Check decomposition of epk.x
    // Check decomposition of epk.y parity byte
    // Check decomposition of nd
    // Check decomposition of v
    // Check decomposition of fdi

    // assign epk.x canonicity
    // assign epk.y parity byte canonicity 
    // assign nd canonicity 
    // assign 

    Ok(((), ()))
}
