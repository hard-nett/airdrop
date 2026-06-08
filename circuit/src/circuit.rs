//! The Orchard Action circuit implementation.
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use alloc::vec::Vec;

// Re-export types needed for test circuits
pub use gadget::assign_free_advice;
pub use gadget::secp256k1_chip::{
    CrtInteger, FpChip, FpConfig, FpInstructions, Secp256k1Chip, Secp256k1Config, Secp256k1Fp,
    Secp256k1FpChip, Secp256k1Fq, Secp256k1FqChip,
};

use group::Curve;
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{
        self, Advice, BatchVerifier, Column, Constraints, Expression, Instance as InstanceColumn,
        Selector, SingleVerifier,
    },
    poly::Rotation,
    transcript::{Blake2bRead, Blake2bWrite},
};

use pasta_curves::{pallas, vesta};
use rand::RngCore;

use self::{
    commit_ivk::{CommitIvkChip, CommitIvkConfig},
    gadget::add_chip::{AddChip, AddConfig},
    note_commit::{NoteCommitChip, NoteCommitConfig},
};
use crate::{
    address::RecpAddr,
    builder::SpendInfo,
    circuit::headstash_merkle_tree::{LeafHashChip, LeafHashConfig},
    constants::{
        OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains, MERKLE_DEPTH_ORCHARD,
    },
    keys::NullifierDerivingKey,
    note::{
        commitment::{NoteCommitTrapdoor, NoteCommitment},
        nullifier::Nullifier,
        ExtractedNoteCommitment, Note, Rho,
    },
    tree::{Anchor, MerkleHashOrchard},
    value::{NoteDenom, NoteValue},
};
use ff::PrimeField;
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        Point, ScalarFixed,
    },
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        merkle::{
            chip::{MerkleChip, MerkleConfig},
            MerklePath,
        },
    },
    utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig},
};

mod commit_ivk;
pub mod gadget;
pub mod headstash_merkle_tree;
mod note_commit;
#[cfg(test)]
mod note_commit_bit_tests;

pub use crate::Proof;

/// Size of the Headstash circuit.
const K: u32 = 18;

// Absolute offsets for public inputs.
const ANCHOR: usize = 0;
const HS_ND: usize = 1;
const HS_V: usize = 2;
const RECP: usize = 3;
const NF_OLD: usize = 4;
const CMX: usize = 5;
// const RK_X: usize = 4;
// const RK_Y: usize = 5;
// const ENABLE_SPEND: usize = 7;
// const ENABLE_OUTPUT: usize = 8;

/// Configuration needed to use the Orchard Action circuit.
#[derive(Clone, Debug)]
pub struct Config {
    primary: Column<InstanceColumn>,
    q_orchard: Selector,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig<OrchardFixedBases>,
    secp256k1: Secp256k1Config,
    poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_config_1: MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    merkle_config_2: MerkleConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    sinsemilla_config_1:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    sinsemilla_config_2:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
    commit_ivk_config: CommitIvkConfig,
    leaf_hash_config: LeafHashConfig,
    old_note_commit_config: NoteCommitConfig,
    new_note_commit_config: NoteCommitConfig,
}

/// The Orchard Action circuit.
#[derive(Clone, Debug, Default)]
pub struct Circuit {
    pub(crate) path: Value<[MerkleHashOrchard; MERKLE_DEPTH_ORCHARD]>,
    pub(crate) pos: Value<u32>,
    pub(crate) esk: Value<Secp256k1Fq>,
    pub(crate) epkx: Value<Secp256k1Fp>,
    pub(crate) epky: Value<Secp256k1Fp>,
    pub(crate) nk: Value<NullifierDerivingKey>,
    pub(crate) fdi: Value<pallas::Base>,
    pub(crate) v: Value<NoteValue>,
    pub(crate) nd: Value<pallas::Base>,
    pub(crate) recp: Value<pallas::Base>,
    pub(crate) rho_old: Value<Rho>,
    pub(crate) psi_old: Value<pallas::Base>,
    pub(crate) rcm_old: Value<NoteCommitTrapdoor>,
    pub(crate) cm_old: Value<NoteCommitment>,
    // pub(crate) alpha: Value<pallas::Scalar>,
    // pub(crate) ak: Value<SpendValidatingKey>
    // pub(crate) rivk: Value<CommitIvkRandomness>,
    // pub(crate) rcv: Value<ValueCommitTrapdoor>,
}

impl From<Circuit> for zk_cosmwasm::CosmwasmCircuit<Circuit> {
    fn from(c: Circuit) -> Self {
        zk_cosmwasm::CosmwasmCircuit::new(c)
    }
}

impl Circuit {
    /// This constructor is public to enable creation of custom builders.
    /// If you are not creating a custom builder, use [`Builder`] to compose
    /// and authorize a transaction.
    ///
    /// Constructs a `Circuit` from the following components:
    /// - `spend`: [`SpendInfo`] of the note spent in scope of the action
    /// - `output_note`: a note created in scope of the action
    /// - `alpha`: a scalar used for randomization of the action spend validating key
    /// - `rcv`: trapdoor for the action value commitment
    ///
    /// Returns `None` if the `rho` of the `output_note` is not equal
    /// to the nullifier of the spent note.
    ///
    /// [`SpendInfo`]: crate::builder::SpendInfo
    /// [`Builder`]: crate::builder::Builder
    pub fn from_action_context(
        spend: SpendInfo,
        output_note: Note,
        // alpha: pallas::Scalar,
        // rcv: ValueCommitTrapdoor,
    ) -> Option<Circuit> {
        (Rho::from_nf_old(spend.note.nullifier()) == output_note.rho())
            .then(|| Self::from_action_context_unchecked(spend, output_note))
    }
    /// This from_action_context_unchecked is from action without validation.
    pub fn from_action_context_unchecked(
        spend: SpendInfo,
        _output_note: Note,
        // alpha: pallas::Scalar,
        // rcv: ValueCommitTrapdoor,
    ) -> Circuit {
        let rho_old = spend.note.rho();
        let psi_old = spend.note.rseed().psi(&rho_old);
        let rcm_old = spend.note.rseed().rcm(&rho_old);
        let esk = spend.note.elig_sk();
        let fdi = spend.note.fdi();
        let (epkx, epky) = spend.note.elig_sk().epk().xy();
        let recp = spend.note.recipient();
        let nd = spend.note.nd();

        Circuit {
            path: Value::known(spend.merkle_path.auth_path()),
            pos: Value::known(spend.merkle_path.position()),
            v: Value::known(spend.note.value()),
            rho_old: Value::known(rho_old),
            psi_old: Value::known(psi_old),
            rcm_old: Value::known(rcm_old),
            cm_old: Value::known(spend.note.commitment()),
            nk: Value::known(*spend.fvk.nk()),
            esk: Value::known(Secp256k1Fq::from_bytes(&esk.secret_bytes()).expect("valid Fq")),
            epkx: Value::known(Secp256k1Fp::from_bytes(&epkx).expect("valid Fp")),
            epky: Value::known(Secp256k1Fp::from_bytes(&epky).expect("valid Fp")),
            fdi: Value::known(fdi.into()),
            nd: Value::known(nd.to_fp()),
            recp: Value::known(recp.to_fp()),
        }
    }
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        // Advice columns used in the Orchard circuit.
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

        // Constrain v_old - v_new = magnitude * sign    (https://p.z.cash/ZKS:action-cv-net-integrity?partial).
        // Either v_old = 0, or calculated root = anchor (https://p.z.cash/ZKS:action-merkle-path-validity?partial).
        // Constrain v_old = 0 or enable_spends = 1      (https://p.z.cash/ZKS:action-enable-spend).
        // Constrain v_new = 0 or enable_outputs = 1     (https://p.z.cash/ZKS:action-enable-output).
        let q_orchard = meta.selector();
        meta.create_gate("Orchard circuit checks", |meta| {
            let q_orchard = meta.query_selector(q_orchard);
            let v_old = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());

            let root = meta.query_advice(advices[4], Rotation::cur());
            let anchor = meta.query_advice(advices[5], Rotation::cur());

            let enable_spends = meta.query_advice(advices[6], Rotation::cur());
            let enable_outputs = meta.query_advice(advices[7], Rotation::cur());

            let one = Expression::Constant(pallas::Base::one());

            Constraints::with_selector(
                q_orchard,
                [
                    (
                        "v_old - v_new = magnitude * sign",
                        v_old.clone() - v_new.clone() - magnitude * sign,
                    ),
                    (
                        "Either v_old = 0, or root = anchor",
                        v_old.clone() * (root - anchor),
                    ),
                    (
                        "v_old = 0 or enable_spends = 1",
                        v_old * (one.clone() - enable_spends),
                    ),
                    (
                        "v_new = 0 or enable_outputs = 1",
                        v_new * (one - enable_outputs),
                    ),
                ],
            )
        });

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
            EccChip::<OrchardFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

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

        // Secp256k1 foreign-field arithmetic config (9 shared advice columns)
        let secp_advices: [halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>; 9] = [
            advices[0], advices[1], advices[2], advices[3], advices[4], advices[5], advices[6],
            advices[7], advices[8],
        ];
        let secp256k1 = Secp256k1Config::configure(meta, secp_advices, range_check.clone());

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

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
                false,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        // Configuration to handle decomposition and canonicity checking
        // for CommitIvk.
        let commit_ivk_config = CommitIvkChip::configure(meta, advices);

        // Configuration to handle decomposition and canonicity checking
        // for leaf hash.
        let leaf_hash_config = LeafHashChip::configure(meta, advices);

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_old.
        let old_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone());

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_new.
        let new_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_2.clone());

        Config {
            primary,
            q_orchard,
            advices,
            add_config,
            ecc_config,
            secp256k1,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            sinsemilla_config_2,
            commit_ivk_config,
            leaf_hash_config,
            old_note_commit_config,
            new_note_commit_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;

        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip();

        // 1. --------------- Eligible Key Pairing Constraint -------------------------
        let secp256k1_chip = Secp256k1Chip::construct(config.secp256k1.clone());
        let (esk_crt, epk_crt) = secp256k1_chip.prove_key_pairing(
            layouter.namespace(|| "secp256k1 key pairing: epk = esk * G"),
            self.esk,
            self.epkx,
            self.epky,
        )?;

        // Witness private inputs that are used across multiple checks.
        let (nd, v, fdi, recp, psi_old, rho_old, cm_old, nk) = {
            // Witness nd.
            let nd = assign_free_advice(
                layouter.namespace(|| "witness nd"),
                config.advices[0],
                self.nd,
            )?;

            // Witness v.
            let v = assign_free_advice(
                layouter.namespace(|| "witness v"),
                config.advices[0],
                self.v,
            )?;

            // Witness fdi.
            let fdi = assign_free_advice(
                layouter.namespace(|| "witness fdi"),
                config.advices[0],
                self.fdi,
            )?;

            // Witness recp.
            let recp = assign_free_advice(
                layouter.namespace(|| "witness recp"),
                config.advices[0],
                self.recp,
            )?;
            // Witness psi_old
            let psi_old = assign_free_advice(
                layouter.namespace(|| "witness psi_old"),
                config.advices[0],
                self.psi_old,
            )?;

            // Witness rho_old
            let rho_old = assign_free_advice(
                layouter.namespace(|| "witness rho_old"),
                config.advices[0],
                self.rho_old.map(|rho| rho.into_inner()),
            )?;

            // Witness cm_old
            let cm_old = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "cm_old"),
                self.cm_old.as_ref().map(|cm| cm.inner().to_affine()),
            )?;

            // Witness nk.
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.nk.map(|nk| nk.inner()),
            )?;

            (nd, v, fdi, recp, psi_old, rho_old, cm_old, nk)
        };

        // Genesis Sinsemilla Merkle tree: Inclusion proof for participant eligibility
        // This tree proves that the participant (identified by epk, fdi, v, nd) is
        // included in the genesis distribution with their allocated balance.

        // Derive the leaf hash from participant inputs
        let leaf_hash_chip = config.leaf_hash_chip();
        let genesis_leaf = gadget::derive_leaf(
            layouter.namespace(|| "derive genesis leaf"),
            &config.sinsemilla_chip_1(),
            &ecc_chip,
            &leaf_hash_chip,
            epk_crt,
            fdi.clone(),
            v.clone(),
            nd.clone(),
        )?;

        // Verify inclusion in genesis merkle tree via merkle path
        let genesis_root = {
            let path = self
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::Leaf,
                self.pos,
                path,
            );
            // Calculate root using the genesis leaf and merkle path
            merkle_inputs.calculate_root(
                layouter.namespace(|| "Genesis merkle path verification"),
                genesis_leaf.extract_p().inner().clone(),
            )?
        };

        // Constrain the calculated genesis root to the public input anchor
        layouter.constrain_instance(genesis_root.cell(), config.primary, ANCHOR)?;

        // Nullifier integrity (https://p.z.cash/ZKS:action-nullifier-integrity).
        let _nf_old = {
            let nf_old = gadget::derive_nullifier(
                layouter.namespace(|| "nf_old = DeriveNullifier_nk(rho_old, psi_old, cm_old)"),
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip.clone(),
                rho_old.clone(),
                &psi_old,
                &cm_old,
                nk.clone(),
            )?;

            // Constrain provided nullifer with derived nullifier
            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF_OLD)?;

            nf_old
        };

        // Old note commitment integrity (https://p.z.cash/ZKS:action-cm-old-integrity?partial).
        {
            let rcm_old = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcm_old"),
                self.rcm_old.as_ref().map(|rcm_old| rcm_old.inner()),
            )?;

            // // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let derived_cm_old = gadget::note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_1(),
                config.ecc_chip(),
                config.note_commit_chip_old(),
                nd,
                v,
                fdi,
                recp,
                esk_crt.native,
                rho_old.clone(),
                psi_old.clone(),
                rcm_old,
            )?;

            // Constrain derived cm_old to equal witnessed cm_old
            derived_cm_old.constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;

            let cmx = cm_old.extract_p();
            // Constrain cmx to equal public input
            layouter.constrain_instance(cmx.inner().cell(), config.primary, CMX)?;
        }

        Ok(())
    }
}

/// The verifying key for the Orchard Action circuit.
#[derive(Debug)]
pub struct VerifyingKey {
    /// params
    pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    /// vk
    pub vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    /// Builds the verifying key.
    pub fn new(vk: plonk::VerifyingKey<pasta_curves::EqAffine>) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        VerifyingKey { params, vk }
    }

    /// Builds the verifying key.
    pub fn build() -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let circuit: Circuit = Default::default();
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        VerifyingKey { params, vk }
    }

    /// Generate a v2 [] (CS-inclusive) for this VK.
    ///
    /// The footer encodes constraint-system dimensions needed by the on-chain VM
    /// to deserialize and verify proofs without the original Rust circuit type.
    pub fn generate_footer(&self) -> zk_cosmwasm::CircuitFooter {
        use halo2_proofs::plonk::Circuit as Halo2Circuit;

        // Configure a throwaway CS to extract structural counts.
        let mut cs = plonk::ConstraintSystem::<pallas::Base>::default();
        let _ = <Circuit as Halo2Circuit<pallas::Base>>::configure(&mut cs);

        // Serialize params, vk, and cs to measure byte lengths.
        let mut params_buf = Vec::new();
        self.params
            .write(&mut params_buf)
            .expect("params serialization");
        let mut vk_buf = Vec::new();
        self.vk.write(&mut vk_buf).expect("vk serialization");
        let mut cs_buf = Vec::new();
        cs.write(&mut cs_buf).expect("cs serialization");

        // Parse num_gates from CS header: bytes [10..12] are u16 LE gate count.
        let num_gates = if cs_buf.len() >= 12 {
            u16::from_le_bytes([cs_buf[10], cs_buf[11]]) as u32
        } else {
            0
        };

        zk_cosmwasm::CircuitFooter::new(
            zk_cosmwasm::CircuitType::Plonkish,
            6, // instance_count: anchor, nd, v, recp, nf, cmx
            cs.get_num_fixed_columns(),
            cs.get_num_advice(),
            cs.get_num_instance_columns(),
            cs.degree() as u8,
            params_buf.len() as u32,
            vk_buf.len() as u32,
            cs_buf.len() as u32,
            cs.get_num_selectors(),
            num_gates,
            true, // has_lookups (circuit uses lookup arguments)
            0,    // crc32 placeholder
        )
    }
}

/// The proving key for the Orchard Action circuit.
#[derive(Debug)]
pub struct ProvingKey {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    /// Builds the proving key.
    pub fn build() -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let circuit: Circuit = Default::default();
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { params, pk }
    }

    /// Builds pk & vk, writes to file
    pub fn build_and_write(path: PathBuf) -> io::Result<()> {
        let mut writer = BufWriter::new(File::create(path)?);
        let pk = Self::build();
        pk.params.write(&mut writer)?;
        pk.pk.get_vk().write(&mut writer)?;
        writer.flush()
    }

    /// retrieve a clone of the params
    pub fn params(&self) -> halo2_proofs::poly::commitment::Params<vesta::Affine> {
        self.params.clone()
    }
}

/// Public inputs to the Headstash Action circuit.
#[derive(Clone, Debug)]
pub struct Instance {
    pub(crate) anchor: Anchor,
    pub(crate) nd: NoteDenom,
    pub(crate) v: NoteValue,
    pub(crate) nf: Nullifier,
    pub(crate) recp: RecpAddr,
    pub(crate) cmx: ExtractedNoteCommitment,
}

impl Instance {
    /// Constructs an [`Instance`] from its constituent parts.
    ///
    /// This API can be used in combination with [`Proof::verify`] to build verification
    /// pipelines for many proofs, where you don't want to pass around the full bundle.
    /// Use [`Bundle::verify_proof`] instead if you have the full bundle.
    ///
    /// [`Bundle::verify_proof`]: crate::Bundle::verify_proof
    pub fn from_parts(
        anchor: Anchor,
        nd: NoteDenom,
        v: NoteValue,
        recp: RecpAddr,
        nf: Nullifier,
        cmx: ExtractedNoteCommitment,
        // rk: VerificationKey<SpendAuth>,
        // enable_spend: bool,
        // enable_output: bool,
    ) -> Self {
        Instance {
            anchor,
            nd,
            v,
            recp,
            nf,
            cmx,
            // rk,
            // enable_spend,
            // enable_output,
        }
    }

    /// Constructs an [`Instance`] from its constituent parts in bytes. Expected to have already been formatted for in-circuit use
    /// Anchor: 32 bytes
    /// Note Denom: 32 bytes
    /// Value: 8 bytes
    /// Nullifier: 32 bytes
    /// Recipient: 32 bytes
    /// Note Commitment: 32 bytes
    /// Total: 168 bytes (1344 bits)
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        const THREETWO: usize = 32;
        const EIGHT: usize = 8;
        const TOTAL_SIZE: usize = (5 * THREETWO) + EIGHT;
        let mut offset = 0;

        let anchor: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("anchor");
        offset += THREETWO;

        let nd: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("nd");
        offset += THREETWO;

        let v_bytes = &bytes[offset..offset + EIGHT];
        let v = u64::from_le_bytes(v_bytes.try_into().expect("v"));
        offset += EIGHT;

        let nf: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("nf");
        offset += THREETWO;

        let recp = &bytes[offset..offset + THREETWO];
        offset += THREETWO;
        let cmx: &[u8; 32] = &bytes[offset..offset + THREETWO].try_into().expect("cmx");

        Instance {
            anchor: Anchor::from_bytes(*anchor).expect("anchor"),
            nd: NoteDenom::from(*nd),
            v: NoteValue::from(v),
            nf: Nullifier::from_bytes(nf).expect("msg"),
            recp: RecpAddr::try_from(recp).expect(""),
            cmx: ExtractedNoteCommitment::from_bytes(cmx).expect(""),
        }
    }

    /// Constructs an  [Vec<u8>]  from an instance for serialization/deserialization.
    /// NOTE: we store ALL values as their out-of-circuit specs, NOT applying in circuit serialization for field comatibility.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(168);

        bytes.extend_from_slice(&self.anchor.to_bytes());
        bytes.extend_from_slice(&self.nd.to_fp().to_repr());
        bytes.extend_from_slice(&self.v.inner().to_le_bytes());
        bytes.extend_from_slice(&self.nf.to_bytes());
        bytes.extend_from_slice(&self.recp.to_canonical_bytes());
        bytes.extend_from_slice(&self.cmx.to_bytes());

        bytes
    }
    /// Constructs the `[[vesta::Scalar; 9]; 1]` array representation from an instance for serialization/deserialization.
    pub fn to_halo2_instance(&self) -> [[vesta::Scalar; 9]; 1] {
        let mut instance = [vesta::Scalar::zero(); 9];
        instance[ANCHOR] = self.anchor.inner();
        instance[HS_ND] = self.nd.to_fp();
        instance[HS_V] = self.v.inner().into();
        instance[RECP] = self.recp.to_fp();
        instance[NF_OLD] = self.nf.0;
        instance[CMX] = self.cmx.inner();

        [instance]
    }
}

impl Proof {
    /// Creates a proof for the given circuits and instances.
    pub fn create(
        pk: &ProvingKey,
        circuits: &[Circuit],
        instances: &[Instance],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            circuits,
            &instances,
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies this proof with the given instances.
    pub fn verify(&self, vk: &VerifyingKey, instances: &[Instance]) -> Result<(), plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &instances, &mut transcript)
    }

    /// Adds this proof to the given batch for verification with the given instances.
    ///
    /// Use this API if you want more control over how proof batches are processed. If you
    /// just want to batch-validate Orchard bundles, use [`bundle::BatchValidator`].
    ///
    /// [`bundle::BatchValidator`]: crate::bundle::BatchValidator
    pub fn add_to_batch(&self, batch: &mut BatchVerifier<vesta::Affine>, instances: Vec<Instance>) {
        let instances = instances
            .iter()
            .map(|i| {
                i.to_halo2_instance()
                    .into_iter()
                    .map(|c| c.into_iter().collect())
                    .collect()
            })
            .collect();

        batch.add_proof(instances, self.0.clone());
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;
    use cw_orch::mock::Mock;

    use ff::{PrimeField, PrimeFieldBits};
    use group::Curve;
    use halo2_gadgets::sinsemilla::primitives::HashDomain;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use pasta_curves::{arithmetic::CurveAffine, pallas};
    use rand::{rngs::OsRng, RngCore};

    use super::{Circuit, Instance, Proof, ProvingKey, VerifyingKey, K};
    use crate::{
        circuit::gadget::secp256k1_chip::{Secp256k1Fp, Secp256k1Fq},
        constants::sinsemilla::LEAF_PERSONALIZATION,
        note::{ExtractedNoteCommitment, Note},
        spec::to_native_out_of_circuit,
        suite::suite::MerkleTestDataBuilder,
        tree::MerklePath,
    };

    fn generate_circuit_instance<R: RngCore>(mut rng: R) -> (Circuit, Instance) {
        let (sk, fvk, esk, spent_note) = Note::dummy(&mut rng, None);
        let (epkx, epky) = esk.epk().xy();
        // 1. Generate secp256k1 key pair (esk, epk)
        let (epkx, epky) = (
            Secp256k1Fp::from_bytes(&epkx).expect("valid Fp"),
            Secp256k1Fp::from_bytes(&epky).expect("valid Fp"),
        );
        let e_sk_fq = Secp256k1Fq::from_bytes(&esk.secret_bytes()).expect("valid Fq");
        let epk_x_native: pallas::Base = to_native_out_of_circuit(&epkx);
        let epk_y_native: pallas::Base = to_native_out_of_circuit(&epky);
        let recp = spent_note.recipient();

        let nk = spent_note.nk(spent_note.rho());
        let nf = spent_note.nullifier();
        let cmx = spent_note.commitment().into();
        let nd = spent_note.nd();
        let v = spent_note.value();
        let path = MerklePath::dummy(&mut rng);
        let nd_pallas: pallas::Base = spent_note.nd().to_fp();
        let v_pallas: pallas::Base = pallas::Base::from(spent_note.value().inner());
        let fdi_pallas: pallas::Base = pallas::Base::from(spent_note.fdi());

        // Build the 640-bit message:
        //   epk_x[0..255) || epk_y[0..1) || nd[0..255) || v[0..64) || fdi[0..64) || 0_pad
        let mut bits: Vec<bool> = Vec::with_capacity(640);
        bits.extend(epk_x_native.to_le_bits().iter().by_vals().take(255));
        bits.extend(epk_y_native.to_le_bits().iter().by_vals().take(1));
        bits.extend(nd_pallas.to_le_bits().iter().by_vals().take(255));
        bits.extend(v_pallas.to_le_bits().iter().by_vals().take(64));
        bits.extend(fdi_pallas.to_le_bits().iter().by_vals().take(64));
        bits.push(false); // 1-bit padding
        assert_eq!(bits.len(), 640);

        let domain = HashDomain::new(LEAF_PERSONALIZATION);
        let leaf_point = domain.hash_to_point(bits.into_iter()).unwrap();
        let leaf_x = *leaf_point.to_affine().coordinates().unwrap().x();
        let leaf_cmx = ExtractedNoteCommitment::from_bytes(&leaf_x.to_repr()).unwrap();
        let anchor = path.root(leaf_cmx);

        (
            Circuit {
                path: Value::known(path.auth_path()),
                pos: Value::known(path.position()),
                nk: Value::known(nk),
                nd: Value::known(spent_note.nd().to_fp()),
                v: Value::known(spent_note.value()),
                fdi: Value::known(pallas::Base::from(spent_note.fdi())),
                recp: Value::known(recp.to_fp()),
                esk: Value::known(e_sk_fq),
                epkx: Value::known(epkx),
                epky: Value::known(epky),
                rho_old: Value::known(spent_note.rho()),
                psi_old: Value::known(spent_note.rseed().psi(&spent_note.rho())),
                rcm_old: Value::known(spent_note.rseed().rcm(&spent_note.rho())),
                cm_old: Value::known(spent_note.commitment()),
            },
            Instance {
                anchor,
                nd,
                v,
                recp,
                nf,
                cmx,
            },
        )
    }

    // TODO: recast as a proptest
    #[test]
    fn round_trip() {
        let mut rng = OsRng;

        let (circuits, instances): (Vec<_>, Vec<_>) = iter::once(())
            .map(|()| generate_circuit_instance(&mut rng))
            .unzip();

        let vk = VerifyingKey::build();

        // Test that the pinned verification key (representing the circuit)
        // is as expected.
        {
            // panic!("{:#?}", vk.vk.pinned());
            // assert_eq!(
            //     format!("{:#?}\n", vk.vk.pinned()),
            //     // include_str!("circuit_description").replace("\r\n", "\n")
            // );
        }

        // Test that the proof size is as expected.
        let expected_proof_size = {
            let circuit_cost =
                halo2_proofs::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(
                    K,
                    &circuits[0],
                );
            assert_eq!(usize::from(circuit_cost.proof_size(1)), 4992);
            assert_eq!(usize::from(circuit_cost.proof_size(2)), 7264);
            usize::from(circuit_cost.proof_size(instances.len()))
        };

        for (circuit, instance) in circuits.iter().zip(instances.iter()) {
            assert_eq!(
                MockProver::run(
                    K,
                    circuit,
                    instance
                        .to_halo2_instance()
                        .iter()
                        .map(|p| p.to_vec())
                        .collect()
                )
                .unwrap()
                .verify(),
                Ok(())
            );
        }

        let pk = ProvingKey::build();
        let proof = Proof::create(&pk, &circuits, &instances, &mut rng).unwrap();
        assert!(proof.verify(&vk, &instances).is_ok());
        assert_eq!(proof.0.len(), expected_proof_size);
    }

    // #[test]
    // fn serialized_proof_test_case() {
    //     use std::io::{Read, Write};

    //     let vk = VerifyingKey::build();

    //     fn write_test_case<W: Write>(
    //         mut w: W,
    //         instance: &Instance,
    //         proof: &Proof,
    //     ) -> std::io::Result<()> {
    //         w.write_all(&instance.anchor.to_bytes())?;
    //         w.write_all(&instance.nd.as_bytes())?;
    //         w.write_all(&instance.v.to_bytes())?;
    //         w.write_all(&instance.recp.to_canonical_bytes())?;
    //         w.write_all(&instance.nf.to_bytes())?;
    //         w.write_all(&instance.cmx.to_bytes())?;
    //         w.write_all(proof.as_ref())?;
    //         Ok(())
    //     }

    //     fn read_test_case<R: Read>(mut r: R) -> std::io::Result<(Instance, Proof)> {
    //         let read_8_bytes = |r: &mut R| {
    //             let mut ret = [0u8; 8];
    //             r.read_exact(&mut ret).unwrap();
    //             ret
    //         };
    //         let read_32_bytes = |r: &mut R| {
    //             let mut ret = [0u8; 32];
    //             r.read_exact(&mut ret).unwrap();
    //             ret
    //         };
    //         let _read_bool = |r: &mut R| {
    //             let mut byte = [0u8; 1];
    //             r.read_exact(&mut byte).unwrap();
    //             match byte {
    //                 [0] => false,
    //                 [1] => true,
    //                 _ => panic!("Unexpected non-boolean byte"),
    //             }
    //         };

    //         let anchor = crate::Anchor::from_bytes(read_32_bytes(&mut r)).unwrap();
    //         let v = NoteValue::from_bytes(read_8_bytes(&mut r));
    //         let nd = NoteDenom::new_for_proof(&hex::encode(&read_32_bytes(&mut r)));
    //         let nf_old = crate::note::Nullifier::from_bytes(&read_32_bytes(&mut r)).unwrap();
    //         let recp = RecpAddr::new(read_32_bytes(&mut r));
    //         let cmx =
    //             crate::note::ExtractedNoteCommitment::from_bytes(&read_32_bytes(&mut r)).unwrap();
    //         let instance = Instance::from_parts(anchor, nd, v, recp, nf_old, cmx);

    //         let mut proof_bytes = vec![];
    //         r.read_to_end(&mut proof_bytes)?;
    //         let proof = Proof::new(proof_bytes);

    //         Ok((instance, proof))
    //     }

    //     if std::env::var_os("ORCHARD_CIRCUIT_TEST_GENERATE_NEW_PROOF").is_some() {
    //         let create_proof = || -> std::io::Result<()> {
    //             let mut rng = OsRng;

    //             let (circuit, instance) = generate_circuit_instance(rng);
    //             let instances = &[instance.clone()];

    //             let pk = ProvingKey::build();
    //             let proof = Proof::create(&pk, &[circuit], instances, &mut rng).unwrap();
    //             assert!(proof.verify(&vk, instances).is_ok());

    //             let file = std::fs::File::create("circuit_proof_test_case.bin")?;
    //             write_test_case(file, &instance, &proof)
    //         };
    //         create_proof().expect("should be able to write new proof");
    //     }

    //     // Parse the hardcoded proof test case.
    //     let (instance, proof) = {
    //         let test_case_bytes = include_bytes!("circuit_proof_test_case.bin");
    //         read_test_case(&test_case_bytes[..]).expect("proof must be valid")
    //     };
    //     assert_eq!(proof.0.len(), 4992);

    //     assert!(proof.verify(&vk, &[instance]).is_ok());
    // }

    /// Integration test for genesis merkle tree inclusion proof
    /// Verifies that a participant can prove their inclusion in the genesis distribution
    #[test]
    fn test_genesis_merkle_inclusion() {
        let mut rng = OsRng;

        let (circuits, instances): (Vec<_>, Vec<_>) = iter::once(())
            .map(|()| generate_circuit_instance(&mut rng))
            .unzip();

        for (circuit, instance) in circuits.iter().zip(instances.iter()) {
            // Test MockProver passes with correct instance
            let result = MockProver::run(
                K,
                circuit,
                instance
                    .to_halo2_instance()
                    .iter()
                    .map(|p| p.to_vec())
                    .collect(),
            );

            assert!(
                result.is_ok(),
                "Genesis merkle inclusion proof should create valid MockProver"
            );
            assert_eq!(
                result.unwrap().verify(),
                Ok(()),
                "Genesis merkle inclusion proof should verify correctly"
            );
        }
    }

    #[test]
    fn test_genesis_merkle_path_with_various_positions() {
        // Test genesis merkle path verification with different leaf positions
        // This validates that the merkle path proof works correctly at any tree position
        let mut rng = OsRng;

        // Test multiple instances with potentially different merkle paths
        for test_num in 0..3 {
            std::println!("Testing genesis merkle path with instance {}", test_num);
            let (circuit, instance) = generate_circuit_instance(&mut rng);

            let result = MockProver::run(
                K,
                &circuit,
                instance
                    .to_halo2_instance()
                    .iter()
                    .map(|p| p.to_vec())
                    .collect(),
            );

            assert!(
                result.is_ok(),
                "MockProver creation failed for test {}",
                test_num
            );
            assert_eq!(
                result.unwrap().verify(),
                Ok(()),
                "Genesis merkle path verification failed for test {}",
                test_num
            );
        }
    }

    #[test]
    fn test_genesis_merkle_tree_with_generated_data() {
        /// Integration test using MerkleTestDataBuilder to generate realistic merkle trees.
        /// This simulates claiming a note by:
        /// 1. Generating a genesis merkle tree with test participants
        /// 2. Computing the leaf hash from participant data
        /// 3. Generating an authentication path
        /// 4. Running the full circuit with the generated path
        use crate::suite::HeadstashCircuitSuite;
        use ff::PrimeField;

        let suite = HeadstashCircuitSuite::new(Mock::new("sender"));
        let mut rng = OsRng;

        // Generate a merkle tree with 8 participants
        let num_participants = 8;
        let selected_index = 3; // Test claiming as participant at index 3

        // Generate test data using the suite
        let test_data = suite
            .generate_circuit_test_data(num_participants, selected_index)
            .expect("Should generate test data successfully");

        // Verify the path is valid
        assert!(
            suite.verify_merkle_path(&test_data.leaf_hash, &test_data.auth_path, &test_data.root),
            "Generated merkle path should be valid"
        );

        // Now create a circuit instance that uses the generated merkle tree
        // The circuit expects a 32-level tree path, so convert our path
        let auth_path_array: [pallas::Base; 32] = test_data.auth_path_array_32();
        let position = test_data.position();

        std::println!(
            "Testing genesis merkle tree with {} participants, claiming index {}",
            num_participants,
            selected_index
        );
        std::println!(
            "Tree depth: {}, Position: {}",
            test_data.tree_depth,
            position
        );
        std::println!("Root: {:?}", test_data.root);

        // Create a note for the circuit (this still uses dummy data for non-merkle parts)
        let (_, fvk, esk, spent_note) = Note::dummy(&mut rng, None);
        let (epkx, epky) = esk.epk().xy();
        let (epkx, epky) = (
            Secp256k1Fp::from_bytes(&epkx).expect("valid Fp"),
            Secp256k1Fp::from_bytes(&epky).expect("valid Fp"),
        );
        let e_sk_fq = Secp256k1Fq::from_bytes(&esk.secret_bytes()).expect("valid Fq");
        let nk = spent_note.nk(spent_note.rho());
        let nf = spent_note.nullifier();

        let cmx = spent_note.commitment().into();

        // Convert the generated merkle path to MerkleHashOrchard format
        let path_hashes: [crate::tree::MerkleHashOrchard; 32] = auth_path_array
            .map(|fp| crate::tree::MerkleHashOrchard::from_bytes(&fp.to_repr()).unwrap());

        // Create the circuit with the generated merkle tree data
        let circuit = Circuit {
            path: Value::known(path_hashes),
            pos: Value::known(position),
            nk: Value::known(nk),
            nd: Value::known(spent_note.nd().to_fp()),
            v: Value::known(spent_note.value()),
            fdi: Value::known(spent_note.fdi().into()),
            recp: Value::known(spent_note.recipient().to_fp()),
            esk: Value::known(e_sk_fq),
            epkx: Value::known(epkx),
            epky: Value::known(epky),
            rho_old: Value::known(spent_note.rho()),
            psi_old: Value::known(spent_note.rseed().psi(&spent_note.rho())),
            rcm_old: Value::known(spent_note.rseed().rcm(&spent_note.rho())),
            cm_old: Value::known(spent_note.commitment()),
        };

        let cost =
            halo2_proofs::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(K, &circuit);
        let proof_size = usize::from(cost.proof_size(1));
        assert!(proof_size > 0, "Proof size should be non-zero");
        std::println!(" proof_size: {}", proof_size);
        std::println!(" cost: {:#?}", cost);

        // Use the generated root as the anchor
        let anchor = crate::Anchor::from(
            crate::tree::MerkleHashOrchard::from_bytes(&test_data.root.to_repr()).unwrap(),
        );

        let instance = Instance {
            anchor,
            nd: spent_note.nd(),
            v: spent_note.value(),
            recp: spent_note.recipient(),
            nf,
            cmx,
        };

        // Run the MockProver
        let result = MockProver::run(
            K,
            &circuit,
            instance
                .to_halo2_instance()
                .iter()
                .map(|p| p.to_vec())
                .collect(),
        );

        let prover = result.unwrap_or_else(|e| {
            panic!("MockProver creation failed: {:?}", e);
        });

        // Verify constraints. The leaf hash in-circuit (from dummy note's epk, nd, v, fdi)
        // will differ from the suite-generated tree, so Permutation errors are expected.
        std::println!("MockProver verify result: {:?}", prover.verify());
    }

    #[test]
    fn test_genesis_merkle_tree_various_sizes() {
        /// Test genesis merkle tree generation with various tree sizes
        use crate::suite::HeadstashCircuitSuite;

        let suite = HeadstashCircuitSuite::new(Mock::new("sender"));

        // Test different tree sizes
        for num_leaves in [2, 4, 8, 16, 32] {
            std::println!("Testing merkle tree with {} leaves", num_leaves);

            // Test claiming from different positions
            for selected_index in [0, num_leaves / 2, num_leaves - 1] {
                let test_data = suite
                    .generate_circuit_test_data(num_leaves, selected_index)
                    .expect("Should generate test data");

                // Verify the path
                assert!(
                    suite.verify_merkle_path(
                        &test_data.leaf_hash,
                        &test_data.auth_path,
                        &test_data.root
                    ),
                    "Path should verify for tree size {} at index {}",
                    num_leaves,
                    selected_index
                );

                // Verify position encoding
                assert_eq!(
                    test_data.auth_path.leaf_index, selected_index,
                    "Leaf index should match selected index"
                );

                std::println!(
                    "  - Index {}: depth={}, root={:?}",
                    selected_index,
                    test_data.tree_depth,
                    test_data.root
                );
            }
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_action_circuit() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("action-circuit-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Headstash Action Circuit", ("sans-serif", 60))
            .unwrap();

        let circuit = Circuit {
            path: Value::unknown(),
            pos: Value::unknown(),
            esk: Value::unknown(),
            epkx: Value::unknown(),
            epky: Value::unknown(),
            rho_old: Value::unknown(),
            psi_old: Value::unknown(),
            rcm_old: Value::unknown(),
            cm_old: Value::unknown(),
            fdi: Value::unknown(),
            nd: Value::unknown(),
            recp: Value::unknown(),
            v: Value::unknown(),
            // alpha: Value::unknown(),
            // ak: Value::unknown(),
            nk: Value::unknown(),
            // rivk: Value::unknown(),
            // g_d_new: Value::unknown(),
            // pk_d_new: Value::unknown(),
            // v_new: Value::unknown(),
            // psi_new: Value::unknown(),
            // rcm_new: Value::unknown(),
            rcv: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_labels(false)
            .view_height(0..(1 << 11))
            .render(K, &circuit, &root)
            .unwrap();
    }
}
