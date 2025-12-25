//! The Orchard Action circuit implementation.
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use alloc::vec::Vec;

use group::Curve;
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{
        self, Advice, Column, Constraints, Expression, Instance as InstanceColumn, Selector,
        SingleVerifier,
    },
    poly::Rotation,
    transcript::{Blake2bRead, Blake2bWrite},
};

use pasta_curves::{pallas, vesta};
use rand::RngCore;

use self::{
    commit_ivk::{CommitIvkChip, CommitIvkConfig},
    gadget::{
        add_chip::{AddChip, AddConfig},
        assign_free_advice,
    },
    note_commit::{NoteCommitChip, NoteCommitConfig},
};
use crate::{
    address::RecpAddr,
    builder::SpendInfo,
    circuit::gadget::secp256k1_chip::{Secp256k1Chip, Secp256k1Config, Secp256k1Fp, Secp256k1Fq},
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
        HashDomain,
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
const K: u32 = 17;

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

    pub(crate) fn from_action_context_unchecked(
        spend: SpendInfo,
        output_note: Note,
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
            nd: Value::known(nd.to_pallas()),
            recp: Value::known(recp.to_pallas()),
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

        // Secp256k1 curve paring config.TODO: ensure we define advice colums available to these accurately and document (3 each)
        let secp256k1 = Secp256k1Config::configure(
            meta,
            [advices[0], advices[1], advices[2]],
            [advices[3], advices[4], advices[5]],
            range_check.clone(),
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

        // hashdomain Merkle path validity check
        // Compute epk_sum

        // derive current note leaf
        let (leaf, rs) = gadget::derive_leaf(
            layouter.namespace(|| "derive leaf"),
            &config.sinsemilla_chip_1(),
            &ecc_chip,
            epk_crt,
            fdi.clone(),
            v.clone(),
            nd.clone(),
        )?;

        // constrain path to headstash genesis root
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
            // merkle_inputs.calculate_root(layouter.namespace(|| "Genesis merkle path"), leaf.x())?
        };

        // commitdomain Merkle path validity check. This is a headstash genesis sinsemilla hashdomain merkle tree.
        let root = {
            let path = self
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.pos,
                path,
            );
            let leaf = cm_old.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
        };

        // constrain hashCommit root to public input
        layouter.constrain_instance(root.cell(), config.primary, ANCHOR)?;

        // Nullifier integrity (https://p.z.cash/ZKS:action-nullifier-integrity).
        let nf_old = {
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

    /// Constructs an [`Instance`] from its constituent parts in bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        const THREETWO: usize = 32;
        const EIGHT: usize = 8;

        const TOTAL_SIZE: usize = (5 * THREETWO) + EIGHT;

        let mut offset = 0;
        // Parse anchor (32 bytes)
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
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(168);

        bytes.extend_from_slice(&self.anchor.to_bytes());
        bytes.extend_from_slice(&self.nd.as_bytes());
        bytes.extend_from_slice(&self.v.inner().to_le_bytes());
        bytes.extend_from_slice(&self.nf.to_bytes());
        bytes.extend_from_slice(&self.recp.to_bytes());
        bytes.extend_from_slice(&self.cmx.to_bytes());

        bytes
    }

    fn to_halo2_instance(&self) -> [[vesta::Scalar; 9]; 1] {
        let mut instance = [vesta::Scalar::zero(); 9];

        instance[ANCHOR] = self.anchor.inner();
        instance[HS_ND] = self.nd.to_pallas();
        instance[HS_V] = self.v.inner().into();
        instance[RECP] = self.recp.to_pallas();
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

    // /// Adds this proof to the given batch for verification with the given instances.
    // ///
    // /// Use this API if you want more control over how proof batches are processed. If you
    // /// just want to batch-validate Orchard bundles, use [`bundle::BatchValidator`].
    // ///
    // /// [`bundle::BatchValidator`]: crate::bundle::BatchValidator
    // pub fn add_to_batch(&self, batch: &mut BatchVerifier<vesta::Affine>, instances: Vec<Instance>) {
    //     let instances = instances
    //         .iter()
    //         .map(|i| {
    //             i.to_halo2_instance()
    //                 .into_iter()
    //                 .map(|c| c.into_iter().collect())
    //                 .collect()
    //         })
    //         .collect();

    //     batch.add_proof(instances, self.0.clone());
    // }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;

    use halo2_proofs::{circuit::Value, dev::MockProver};
    use pasta_curves::pallas;
    use rand::{rngs::OsRng, RngCore};

    use super::{Circuit, Instance, Proof, ProvingKey, VerifyingKey, K};
    use crate::{
        address::RecpAddr,
        circuit::gadget::secp256k1_chip::{Secp256k1Fp, Secp256k1Fq},
        keys::{EligibleSk, SpendValidatingKey},
        note::{Note, Rho},
        tree::MerklePath,
        value::{NoteDenom, NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };

    fn generate_circuit_instance<R: RngCore>(mut rng: R) -> (Circuit, Instance) {
        let (_, fvk, esk, spent_note) = Note::dummy(&mut rng, None);
        let (epkx, epky) = esk.epk().xy();
        // 1. Generate secp256k1 key pair (esk, epk)
        let (epkx, epky) = (
            Secp256k1Fp::from_bytes(&epkx).expect("valid Fp"),
            Secp256k1Fp::from_bytes(&epky).expect("valid Fp"),
        );
        let e_sk_fq = Secp256k1Fq::from_bytes(&esk.secret_bytes()).expect("valid Fq");
        let sender_address = spent_note.recipient();
        let nk = *fvk.nk();
        let nf = spent_note.nullifier();
        let rho = Rho::from_nf_old(nf);

        // let rivk = fvk.rivk(fvk.scope_for_address(&spent_note.recipient()).unwrap());
        // let ak: SpendValidatingKey = fvk.into();
        // let alpha = pallas::Scalar::random(&mut rng);
        // let rk = ak.randomize(&alpha);
        // let vsum = spent_note.value() - output_note.value();
        // let cv_net = ValueCommitment::derive(vsum, rcv.clone());
        // let rcv = ValueCommitTrapdoor::random(&mut rng);

        let cmx = spent_note.commitment().into();
        let nd = spent_note.nd();
        let v = spent_note.value();
        let recp = spent_note.recipient();

        let path = MerklePath::dummy(&mut rng);
        let anchor = path.root(spent_note.commitment().into());

        (
            Circuit {
                path: Value::known(path.auth_path()),
                pos: Value::known(path.position()),
                nk: Value::known(nk),
                nd: Value::known(spent_note.nd().to_fp()),
                v: Value::known(spent_note.value()),
                fdi: Value::known(pallas::Base::from(spent_note.fdi())),
                recp: Value::known(recp.to_pallas()),
                esk: Value::known(e_sk_fq),
                epkx: Value::known(epkx),
                epky: Value::known(epky),
                rho_old: Value::known(spent_note.rho()),
                psi_old: Value::known(spent_note.rseed().psi(&spent_note.rho())),
                rcm_old: Value::known(spent_note.rseed().rcm(&spent_note.rho())),
                cm_old: Value::known(spent_note.commitment()),
                // alpha: Value::known(alpha),
                // ak: Value::known(ak),
                // nk: Value::known(nk),
                // rivk: Value::known(rivk),
                // g_d_new: Value::known(output_note.recipient().g_d()),
                // pk_d_new: Value::known(*output_note.recipient().pk_d()),
                // v_new: Value::known(output_note.value()),
                // psi_new: Value::known(output_note.rseed().psi(&output_note.rho())),
                // rcm_new: Value::known(output_note.rseed().rcm(&output_note.rho())),
                // rcv: Value::known(rcv),
            },
            Instance {
                anchor,
                nd,
                v,
                recp,
                nf,
                cmx,
                // rk,
                // enable_spend: true,
                // enable_output: true,
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
            assert_eq!(
                format!("{:#?}\n", vk.vk.pinned()),
                include_str!("circuit_description").replace("\r\n", "\n")
            );
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

    #[test]
    fn serialized_proof_test_case() {
        use std::io::{Read, Write};

        let vk = VerifyingKey::build();

        fn write_test_case<W: Write>(
            mut w: W,
            instance: &Instance,
            proof: &Proof,
        ) -> std::io::Result<()> {
            w.write_all(&instance.anchor.to_bytes())?;
            w.write_all(&instance.nd.as_bytes())?;
            w.write_all(&instance.v.to_bytes())?;
            w.write_all(&instance.recp.to_bytes())?;
            w.write_all(&instance.nf.to_bytes())?;
            w.write_all(&instance.cmx.to_bytes())?;
            // w.write_all(&<[u8; 32]>::from(instance.rk.clone()))?;
            // w.write_all(&[
            //     u8::from(instance.enable_spend),
            //     u8::from(instance.enable_output),
            // ])?;

            w.write_all(proof.as_ref())?;
            Ok(())
        }

        fn read_test_case<R: Read>(mut r: R) -> std::io::Result<(Instance, Proof)> {
            let read_8_bytes = |r: &mut R| {
                let mut ret = [0u8; 8];
                r.read_exact(&mut ret).unwrap();
                ret
            };
            let read_32_bytes = |r: &mut R| {
                let mut ret = [0u8; 32];
                r.read_exact(&mut ret).unwrap();
                ret
            };
            let read_bool = |r: &mut R| {
                let mut byte = [0u8; 1];
                r.read_exact(&mut byte).unwrap();
                match byte {
                    [0] => false,
                    [1] => true,
                    _ => panic!("Unexpected non-boolean byte"),
                }
            };

            let anchor = crate::Anchor::from_bytes(read_32_bytes(&mut r)).unwrap();
            let v = NoteValue::from_bytes(read_8_bytes(&mut r));
            let nd = NoteDenom::new_for_proof(&hex::encode(&read_32_bytes(&mut r)));
            let nf_old = crate::note::Nullifier::from_bytes(&read_32_bytes(&mut r)).unwrap();
            let recp = RecpAddr::new(read_32_bytes(&mut r));
            let cmx =
                crate::note::ExtractedNoteCommitment::from_bytes(&read_32_bytes(&mut r)).unwrap();

            let instance = Instance::from_parts(anchor, nd, v, recp, nf_old, cmx);

            let mut proof_bytes = vec![];
            r.read_to_end(&mut proof_bytes)?;
            let proof = Proof::new(proof_bytes);

            Ok((instance, proof))
        }

        if std::env::var_os("ORCHARD_CIRCUIT_TEST_GENERATE_NEW_PROOF").is_some() {
            let create_proof = || -> std::io::Result<()> {
                let mut rng = OsRng;

                let (circuit, instance) = generate_circuit_instance(OsRng);
                let instances = &[instance.clone()];

                let pk = ProvingKey::build();
                let proof = Proof::create(&pk, &[circuit], instances, &mut rng).unwrap();
                assert!(proof.verify(&vk, instances).is_ok());

                let file = std::fs::File::create("circuit_proof_test_case.bin")?;
                write_test_case(file, &instance, &proof)
            };
            create_proof().expect("should be able to write new proof");
        }

        // Parse the hardcoded proof test case.
        let (instance, proof) = {
            let test_case_bytes = include_bytes!("circuit_proof_test_case.bin");
            read_test_case(&test_case_bytes[..]).expect("proof must be valid")
        };
        assert_eq!(proof.0.len(), 4992);

        assert!(proof.verify(&vk, &[instance]).is_ok());
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
