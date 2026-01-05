//! proove that H(v||nd||fdi||epk) was derived accurately using the sinsemilla hash domain.
//!  - public inputs (exposed as instance columns): v,nd, H_sinsemilla
//!  - private inputs: fdi,epk

use std::marker::PhantomData;

use zk_headstash::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains};

use halo2_gadgets::ecc::chip::{EccChip, EccConfig};
use halo2_gadgets::sinsemilla::chip::{SinsemillaChip, SinsemillaConfig};
use halo2_gadgets::sinsemilla::{HashDomain, Message, MessagePiece, SinsemillaInstructions};
use halo2_gadgets::utilities::lookup_range_check::PallasLookupRangeCheck;
use halo2_gadgets::utilities::{FieldValue, RangeConstrained};
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::{SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, Column, Instance, Selector};
use pasta_curves::{pallas, Fp};

type MySinsemillaHashDomainConfig<Lookup> = (
    EccConfig<OrchardFixedBases, Lookup>,
    Column<Instance>,
    SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    // supports up to 2^32 bits
    Selector,
);

/// MySinsemillaHashDomainCircuit
#[derive(Default, Debug)]
pub struct MySinsemillaHashDomainCircuit<Lookup: PallasLookupRangeCheck> {
    _lookup_marker: PhantomData<Lookup>,
    v: Value<Fp>,
    nd: Value<Fp>,
    fdi: Value<Fp>,
    epk: Value<Fp>,
    path: [(Value<bool>, Value<pallas::Base>); 2],
    root: Value<pallas::Base>,
}

impl<Lookup: PallasLookupRangeCheck> MySinsemillaHashDomainCircuit<Lookup> {
    /// new
    pub fn new() -> Self {
        Self {
            _lookup_marker: PhantomData,
            v: Value::default(),
            nd: Value::default(),
            fdi: Value::default(),
            epk: Value::default(),
            root: Value::default(),
            path: [(Value::default(), Value::default()); 2],
        }
    }
}

impl<Lookup: PallasLookupRangeCheck> Circuit<pallas::Base>
    for MySinsemillaHashDomainCircuit<Lookup>
{
    type Config = MySinsemillaHashDomainConfig<Lookup>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        MySinsemillaHashDomainCircuit::new()
    }

    fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        // Advice columns for Sinsemilla (bit decomposition, running sum, etc.)
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

        let primary = meta.instance_column();
        meta.enable_equality(primary);

        let q_enabled = meta.complex_selector();

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

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

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // We have a lot of free space in the right-most advice columns; use one of them
        // for all of our range checks.
        let range_check = Lookup::configure(meta, advices[9], table_idx);

        let ecc_config = EccChip::<OrchardFixedBases, Lookup>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check,
        );

        // sinsemilla config uses 5 advice columns
        let sinsemilla_config = SinsemillaChip::configure(
            meta,
            advices[..5].try_into().unwrap(),
            advices[6], // is this correct advice colum for witness_pieces
            lagrange_coeffs[0],
            lookup,
            range_check,
            false,
        );

        (ecc_config, primary, sinsemilla_config, q_enabled)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let ecc_chip = EccChip::construct(config.0);

        // Load the Sinsemilla chip
        // The two `SinsemillaChip`s share the same lookup table.
        SinsemillaChip::<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases,Lookup>::load(
            config.2.clone(),
            &mut layouter,
        )?;

        let sinsemilla_chip = SinsemillaChip::construct(config.2.clone());

        let merkle_crh = HashDomain::new(
            sinsemilla_chip.clone(),
            ecc_chip.clone(),
            &OrchardHashDomains::MerkleCrh,
        );

        // === Step 1: Compute leaf = H(v || nd || fdi || epk) ===

        // `a` = bits 0..=249 of `x(v)`
        let a = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "v bits 0..250"),
            [RangeConstrained::bitrange_of(self.v.value(), 0..250)],
        )?;

        // b = bits 250..253 of v (3 bits), and bit 253 is sign (ỹ) — but we only need the bits
        let b = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "v bits 250..253"),
            [RangeConstrained::bitrange_of(self.v.value(), 250..253)],
        )?;

        let c = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "nd bits 0..250"),
            [RangeConstrained::bitrange_of(self.nd.value(), 0..250)],
        )?;

        // d = bits 250..253 of nd
        let d = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "nd bits 250..253"),
            [RangeConstrained::bitrange_of(self.nd.value(), 250..253)],
        )?;

        // e = bits 0..250 of fdi
        let e = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "fdi bits 0..250"),
            [RangeConstrained::bitrange_of(self.fdi.value(), 0..250)],
        )?;

        // f = bits 250..253 of fdi
        let f = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "fdi bits 250..253"),
            [RangeConstrained::bitrange_of(self.fdi.value(), 250..253)],
        )?;

        // g = bits 0..250 of epk
        let g = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "epk bits 0..250"),
            [RangeConstrained::bitrange_of(self.epk.value(), 0..250)],
        )?;

        // h = bits 250..253 of epk
        let h = MessagePiece::from_subpieces(
            sinsemilla_chip.clone(),
            layouter.namespace(|| "epk bits 250..253"),
            [RangeConstrained::bitrange_of(self.epk.value(), 250..253)],
        )?;

        // === Assemble full message representing leaf ===
        let message = Message::from_pieces(sinsemilla_chip.clone(), vec![a, b, c, d, e, f, g, h]);

        // === Hash to point, generating leaf ===
        let (leaf_point, _aux) =
            merkle_crh.hash_to_point(layouter.namespace(|| "hash v||nd||fdi||epk"), message)?;

        // Extract leaf as field element (x-coordinate)
        let binding = leaf_point.inner().x();

        let mut current = binding.value();

        fn select<T>(selector: Value<bool>, true_val: Value<T>, false_val: Value<T>) -> Value<T> {
            selector
                .zip(true_val)
                .zip(false_val)
                .map(|((b, t), f)| if b { t } else { f })
        }

        // === Step 2: Compute Merkle root using path ===
        // this will always be the closest index to the root, because we do not append leaves to this tree.
        for (i, (is_right, sibling)) in self.path.iter().enumerate() {
            // Convert sibling: &Value<Fp>  -->  Value<&Fp>
            let sibling_ref: Value<&Fp> = sibling.as_ref();
            let is_right_value: Value<bool> = *is_right;

            let left_value = select(is_right_value, sibling_ref, current);
            let right_value = select(is_right_value, current, sibling_ref);

            // Convert each to MessagePieces (same decomposition)
            let l_lo = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "left lo"),
                [RangeConstrained::bitrange_of(left_value, 0..250)],
            )?;
            let l_hi = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "left hi"),
                [RangeConstrained::bitrange_of(left_value, 250..253)],
            )?;

            let r_lo = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "right lo"),
                [RangeConstrained::bitrange_of(right_value, 0..250)],
            )?;
            let r_hi = MessagePiece::from_subpieces(
                sinsemilla_chip.clone(),
                layouter.namespace(|| "right hi"),
                [RangeConstrained::bitrange_of(right_value, 250..253)],
            )?;

            // Construct single message: left_lo || left_hi || right_lo || right_hi
            let message =
                Message::from_pieces(sinsemilla_chip.clone(), vec![l_lo, l_hi, r_lo, r_hi]);

            // Hash: H(left || right)
            let (parent_point, _) = merkle_crh.hash_to_point(
                layouter.namespace(|| format!("merkle level {}", i)),
                message,
            )?;

            // Update current to x-coordinate of parent point
            let current = leaf_point.inner().x().value().copied();
        }

        // === Step 3: Constrain computed_leaf == private_leaf ===

        // === Step 4: Constrain computed root == public root ===
        let computed_root_cell = sinsemilla_chip.witness_message_piece(
            layouter.namespace(|| "witness final root"),
            current.cloned(),
            253,
        )?;
        layouter.constrain_instance(computed_root_cell.cell(), config.1, 2)?; // index 2

        // === Step 5: Constrain root is tree of leaf

        Ok(())
    }
}
