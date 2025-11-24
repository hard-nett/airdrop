 

use ff::{Field, PrimeField, PrimeFieldBits};
use halo2_gadgets::{
    ecc::{
        FixedPoints, NonIdentityPoint, ScalarFixed,
        chip::{
            BaseFieldElem, EccChip, EccConfig, FixedPoint, FullScalar, H, NUM_WINDOWS,
            NUM_WINDOWS_SHORT, ShortScalar, find_zs_and_us,
        },
    },
    poseidon::Hash,
    sinsemilla::{
        CommitDomain, CommitDomains, HashDomain, HashDomains, Message, MessagePiece,
        chip::{SinsemillaChip, SinsemillaConfig},
    },
    utilities::lookup_range_check::{LookupRangeCheckConfig, PallasLookupRangeCheck},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    pasta::Fp,
    plonk::{ConstraintSystem, Error},
};
use pasta_curves::{
    group::{Curve, Group},
    pallas,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use lazy_static::lazy_static;
use sinsemilla::K;
use std::path::Path;
use std::{fs, marker::PhantomData};

pub(crate) const PERSONALIZATION: &str = "HeadstashMerkleCRH";

lazy_static! {
    static ref BASE: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS).unwrap();
    static ref COMMIT_DOMAIN: sinsemilla::CommitDomain =
        sinsemilla::CommitDomain::new(PERSONALIZATION);
    static ref Q: pallas::Affine = COMMIT_DOMAIN.Q().to_affine();
    static ref R: pallas::Affine = COMMIT_DOMAIN.R().to_affine();
    static ref R_ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*R, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap();
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct FullWidth(pallas::Affine, &'static [(u64, [pallas::Base; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Short;

impl FullWidth {
    pub(crate) fn from_pallas_generator() -> Self {
        FullWidth(*BASE, &ZS_AND_US)
    }

    pub(crate) fn from_parts(
        base: pallas::Affine,
        zs_and_us: &'static [(u64, [pallas::Base; H])],
    ) -> Self {
        FullWidth(base, zs_and_us)
    }
}

impl FixedPoint<pallas::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        self.0
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        self.1
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        self.1.iter().map(|(z, _)| *z).collect()
    }
}

// #[derive(Debug, Serialize, Deserialize)]
// struct HeadstashDistribution {
//     addr: String,
//     tokens: Vec<HeadstashToken>,
// }
// #[derive(Debug, Serialize, Deserialize)]
// struct HeadstashToken {
//     token: String,
//     amount: u128,
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct MerkleProof {
//     leaf: String,
//     root: String,
//     path: Vec<String>,
//     index: usize,
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct MerkleTreeOutput {
//     root: String,
//     leaves: Vec<String>,
//     proofs: Vec<MerkleProof>,
// }

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct HeadstashFixedBases;
impl FixedPoints<pallas::Affine> for HeadstashFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}

// ensure every hash uses the same fixed base point
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct HeadstashHashDomain;
impl HashDomains<pallas::Affine> for HeadstashHashDomain {
    fn Q(&self) -> pallas::Affine {
        *Q
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct HeadstashCommitDomain;
impl CommitDomains<pallas::Affine, HeadstashFixedBases, HeadstashHashDomain>
    for HeadstashCommitDomain
{
    fn r(&self) -> FullWidth {
        FullWidth::from_parts(*R, &R_ZS_AND_US)
    }

    fn hash_domain(&self) -> HeadstashHashDomain {
        HeadstashHashDomain
    }
}

struct SinsemillaHeadstashCircuit<Lookup: PallasLookupRangeCheck> {
    _lookup_marker: PhantomData<Lookup>,
}

impl<Lookup: PallasLookupRangeCheck> SinsemillaHeadstashCircuit<Lookup> {
    fn new() -> Self {
        Self {
            _lookup_marker: PhantomData,
        }
    }
}

impl FixedPoint<pallas::Affine> for Short {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US_SHORT
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

type EccSinsemillaConfig<Lookup> = (
    EccConfig<HeadstashFixedBases, Lookup>,
    SinsemillaConfig<HeadstashHashDomain, HeadstashCommitDomain, HeadstashFixedBases, Lookup>,
    SinsemillaConfig<HeadstashHashDomain, HeadstashCommitDomain, HeadstashFixedBases, Lookup>,
);

fn configure<Lookup: PallasLookupRangeCheck>(
    meta: &mut ConstraintSystem<pallas::Base>,
    allow_init_from_private_point: bool,
) -> EccSinsemillaConfig<Lookup> {
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

    // Shared fixed column for loading constants
    let constants = meta.fixed_column();
    meta.enable_constant(constants);

    let table_idx = meta.lookup_table_column();
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

    // Fixed columns for the Sinsemilla generator lookup table
    let lookup = (
        table_idx,
        meta.lookup_table_column(),
        meta.lookup_table_column(),
    );

    let range_check = Lookup::configure(meta, advices[9], table_idx);

    let ecc_config = EccChip::<HeadstashFixedBases, Lookup>::configure(
        meta,
        advices,
        lagrange_coeffs,
        range_check,
    );

    let config1 = SinsemillaChip::configure(
        meta,
        advices[..5].try_into().unwrap(),
        advices[2],
        lagrange_coeffs[0],
        lookup,
        range_check,
        allow_init_from_private_point,
    );
    let config2 = SinsemillaChip::configure(
        meta,
        advices[5..].try_into().unwrap(),
        advices[7],
        lagrange_coeffs[1],
        lookup,
        range_check,
        allow_init_from_private_point,
    );
    (ecc_config, config1, config2)
}

fn synthesize<Lookup: PallasLookupRangeCheck>(
    config: EccSinsemillaConfig<Lookup>,
    mut layouter: impl Layouter<pallas::Base>,
) -> Result<(), Error> {
    let rng = OsRng;

    let ecc_chip = EccChip::construct(config.0);

    // The two `SinsemillaChip`s share the same lookup table.
    SinsemillaChip::<HeadstashHashDomain, HeadstashCommitDomain, HeadstashFixedBases, Lookup>::load(
        config.1.clone(),
        &mut layouter,
    )?;

    // This MerkleCRH example is purely for illustrative purposes.
    // It is not an implementation of the Orchard protocol spec.
    {
        let chip1 = SinsemillaChip::construct(config.1);

        let merkle_crh = HashDomain::new(chip1.clone(), ecc_chip.clone(), &HeadstashHashDomain);

        // Layer 31, l = MERKLE_DEPTH - 1 - layer = 0
        let l_bitstring = vec![Value::known(false); K];
        let l =
            MessagePiece::from_subpieces(chip1.clone(), layouter.namespace(|| "l"), &l_bitstring)?;

        // Left leaf
        let left_bitstring: Vec<Value<bool>> = (0..250)
            .map(|_| Value::known(rand::random::<bool>()))
            .collect();
        let left = MessagePiece::from_bitstring(
            chip1.clone(),
            layouter.namespace(|| "left"),
            &left_bitstring,
        )?;

        // Right leaf
        let l_bitstring: Value<Vec<bool>> = l_bitstring.into_iter().collect();
        let left_bitstring: Value<Vec<bool>> = left_bitstring.into_iter().collect();
        let right_bitstring: Value<Vec<bool>> = right_bitstring.into_iter().collect();

        // Witness expected parent
        let expected_parent = {
            let expected_parent =
                l_bitstring
                    .zip(left_bitstring.zip(right_bitstring))
                    .map(|(l, (left, right))| {
                        let merkle_crh = sinsemilla::HashDomain::from_Q((*Q).into());
                        let point = merkle_crh
                            .hash_to_point(
                                l.into_iter()
                                    .chain(left.into_iter())
                                    .chain(right.into_iter()),
                            )
                            .unwrap();
                        point.to_affine()
                    });

            NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "Witness expected parent"),
                expected_parent,
            )?
        };

        // Parent
        let (parent, _) = {
            let message = Message::from_pieces(chip1, vec![l, left, right]);
            merkle_crh.hash_to_point(layouter.namespace(|| "parent"), message)?
        };

        parent.constrain_equal(
            layouter.namespace(|| "parent == expected parent"),
            &expected_parent,
        )?;
    }

    {
        let chip2 = SinsemillaChip::construct(config.2);

        let test_commit =
            CommitDomain::new(chip2.clone(), ecc_chip.clone(), &HeadstashCommitDomain);
        let r_val = pallas::Scalar::random(rng);
        let message: Vec<Value<bool>> = (0..500)
            .map(|_| Value::known(rand::random::<bool>()))
            .collect();

        let (result, _) = {
            let r = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "r"),
                Value::known(r_val),
            )?;
            let message = Message::from_bitstring(
                chip2,
                layouter.namespace(|| "witness message"),
                message.clone(),
            )?;
            test_commit.commit(layouter.namespace(|| "commit"), message, r)?
        };

        // Witness expected result.
        let expected_result = {
            let message: Value<Vec<bool>> = message.into_iter().collect();
            let expected_result = message.map(|message| {
                let domain = sinsemilla::CommitDomain::new(PERSONALIZATION);
                let point = domain.commit(message.into_iter(), &r_val).unwrap();
                point.to_affine()
            });

            NonIdentityPoint::new(
                ecc_chip,
                layouter.namespace(|| "Witness expected result"),
                expected_result,
            )?
        };

        result.constrain_equal(
            layouter.namespace(|| "result == expected result"),
            &expected_result,
        )
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //     let input_path = Path::new("input.json");
    //     let output_path = Path::new("merkle_tree_output.json");

    //     // Read JSON input
    //     let data = fs::read_to_string(input_path)?;
    //     let entries: Vec<String> = serde_json::from_str(&data)?;

    //     println!("Loaded {} entries", entries.len());

    //     // Step 1: Hash each entry to Fp using Sinsemilla

    //     // Step 2: Build Merkle tree

    //     // Step 3: Generate proofs for all leaves (for demo)

    //     // Step 4: Output result

    Ok(())
}
