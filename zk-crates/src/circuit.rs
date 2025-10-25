use self::gadget::add_chip::{AddChip, AddConfig};
use halo2_gadgets::{
    ecc::{
        FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarFixedShort, ScalarVar,
        chip::{EccChip, EccConfig},
    },
    poseidon::{Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig, primitives as poseidon},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        merkle::{
            MerklePath,
            chip::{MerkleChip, MerkleConfig},
        },
    },
    utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
};
use halo2_proofs::{
    circuit::{Layouter, Value, floor_planner},
    plonk::{self, Column, Instance as InstanceColumn},
};
use pasta_curves::pallas;

use crate::{
    constants::{
        HeadstashHashDomains, MERKLE_DEPTH_HEADSTASH, fixed_bases::HeadstashFixedBases,
        sinsemilla::HeadstashCommitDomains,
    },
    tree::MerkleHashHeadstash,
};

pub mod gadget;

#[derive(Clone, Debug)]
pub struct HeadstashConfig {
    primary: Column<InstanceColumn>,
    add_config: AddConfig,
    ecc_config: EccConfig<HeadstashFixedBases>,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config_1:
        MerkleConfig<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
    sinsemilla_config_1:
        SinsemillaConfig<HeadstashHashDomains, HeadstashCommitDomains, HeadstashFixedBases>,
    // old_note_commit_config: NoteCommitConfig,
    // new_note_commit_config: NoteCommitConfig,
    // genesis_sinsemilla_config: MerkleConfig<>
}

/// The Headstash Action circuit.
#[derive(Clone, Debug, Default)]
pub struct Circuit {
    pub(crate) path: Value<[MerkleHashHeadstash; MERKLE_DEPTH_HEADSTASH]>,
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = HeadstashConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
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

        let q_orchard = meta.selector();

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
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
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // We have a lot of free space in the right-most advice columns; use one of them
        // for all of our range checks.
        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config =
            EccChip::<HeadstashFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
                false,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        HeadstashConfig {
            primary,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            sinsemilla_config_1,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;
        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip();
        Ok(())
    }
}
