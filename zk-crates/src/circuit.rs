use self::gadget::add_chip::{AddChip, AddConfig};
use group::Curve;

use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp as Secp256k1Fp, Fq as Secp256k1Fq};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarFixedShort, ScalarVar,
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

use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{self, Advice, Column, Instance as InstanceColumn},
};
use pasta_curves::pallas;

use crate::{
    circuit::{
        gadget::{
            assign_free_advice,
            secp256k1_chip::{Secp256k1Chip, Secp256k1Config},
        },
        note_commit::{NoteCommitChip, NoteCommitConfig},
    },
    constants::{
        fixed_bases::HeadstashFixedBases as HFixedBases,
        sinsemilla::HeadstashCommitDomains as HCommitDomains, HeadstashHashDomains as HashDomains,
        MERKLE_DEPTH_HEADSTASH,
    },
    keys::NullifierDerivingKey,
    note::{NoteCommitment, Rho},
    tree::MerkleHashHeadstash,
};

// Absolute offsets for public inputs.
const ANCHOR: usize = 0;
const CV_NET_X: usize = 1;
const CV_NET_Y: usize = 2;
const NF: usize = 3;
const RK_X: usize = 4;
const RK_Y: usize = 5;
const CMX: usize = 6;

pub mod gadget;
mod note_commit;

#[derive(Clone, Debug)]
pub struct HeadstashConfig {
    primary: Column<InstanceColumn>,
    advices: [Column<Advice>; 10],
    add_config: AddConfig,
    ecc_config: EccConfig<HFixedBases>,
    secp256k1: Secp256k1Config,
    poseidon_cfg: PoseidonConfig<pallas::Base, 3, 2>,
    merkle_cfg: MerkleConfig<HashDomains, HCommitDomains, HFixedBases>,
    sinsemilla_cfg: SinsemillaConfig<HashDomains, HCommitDomains, HFixedBases>,
    nc_cfg: NoteCommitConfig,
}

/// The Headstash Action circuit.
#[derive(Clone, Debug, Default)]
pub struct Circuit {
    // Merkle path witnesses
    pub(crate) path: Value<[MerkleHashHeadstash; MERKLE_DEPTH_HEADSTASH]>,
    pub(crate) pos: Value<u32>,

    // Note randomness
    pub(crate) psi: Value<pallas::Base>,
    pub(crate) rho: Value<Rho>,
    pub(crate) cm: Value<NoteCommitment>,

    // Secp256k1 key pair (foreign field) - represented as 3x88-bit limbs in circuit
    pub(crate) e_sk: Value<Secp256k1Fq>, // Eligible secret key (scalar field)
    pub(crate) e_pk_x: Value<Secp256k1Fp>, // Eligible public key x-coordinate (base field)
    pub(crate) e_pk_y: Value<Secp256k1Fp>, // Eligible public key y-coordinate (base field)

    // Nullifier deriving key (derived from e_sk via HKDF outside circuit)
    pub(crate) nk: Value<NullifierDerivingKey>,

    // Fixed denomination index (private)
    pub(crate) fdi: Value<pallas::Base>,

    // Public inputs
    pub(crate) v: Value<pallas::Base>,    // Note value
    pub(crate) nd: Value<pallas::Base>,   // Note denomination (blake3 hash)
    pub(crate) recp: Value<pallas::Base>, // Recipient address
}

impl plonk::Circuit<pallas::Base> for Circuit {
    type Config = HeadstashConfig;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        // Current allocation (from circuit.rs:93-104):
        // advices[0-9] = 10 columns total
        // advices[5] = Poseidon partial_sbox
        // advices[6-8] = Poseidon state
        // advices[0-4] = Sinsemilla (5 columns)
        // advices[6] = Sinsemilla message
        // advices[9] = Range check column

        // Proposed allocation for Secp256k1:
        // fp_advices = [advices[0], advices[1], advices[2]]
        // fq_advices = [advices[3], advices[4], advices[5]]
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
        // six, so we could choose to configure them in parallel. However, we use two
        // Poseidon invocation, one  and we have the rows to accommodate it serially.
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
        let rcfg10 = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config =
            EccChip::<HFixedBases>::configure(meta, advices, lagrange_coeffs, rcfg10.clone());

        // Configuration for the Poseidon hash.
        let poseidon_cfg = PoseidonChip::configure::<poseidon::P128Pow5T3>(
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
        let (sinsemilla_cfg, merkle_cfg) = {
            let sinsemilla_cfg = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                rcfg10,
                false,
            );
            let merkle_cfg = MerkleChip::configure(meta, sinsemilla_cfg.clone());

            (sinsemilla_cfg, merkle_cfg)
        };

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_new.
        let nc_cfg = NoteCommitChip::configure(meta, advices, sinsemilla_cfg.clone());

        // Secp256k1 curve paring config.TODO: ensure we define advice colums available to these accurately and document (3 each)
        let secp256k1 = Secp256k1Config::configure(
            meta,
            [advices[0], advices[1], advices[2]],
            [advices[3], advices[4], advices[5]],
            rcfg10.clone(),
        );
        HeadstashConfig {
            primary,
            advices,
            add_config,
            secp256k1,
            ecc_config,
            poseidon_cfg,
            merkle_cfg,
            sinsemilla_cfg,
            nc_cfg,
        }
    }

    // TODO: complete implement headstash circuit synthesisation
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_cfg.clone(), &mut layouter)?;

        // // Construct the ECC chip.
        let ecc_chip = config.ecc_chip();

        // // Witness private inputs that are used across multiple checks.
        let (psi, rho, nk, cm, fdi, v, nd, recp) = {
            // Witness psi
            let psi = assign_free_advice(
                layouter.namespace(|| "witness psi"),
                config.advices[0],
                self.psi,
            )?;
            // Witness rho
            let rho = assign_free_advice(
                layouter.namespace(|| "witness rho"),
                config.advices[0],
                self.rho.map(|rho| rho.into_inner()),
            )?;
            // Witness nk.
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.nk.map(|nk| nk.inner()),
            )?;

            // Witness cm
            let cm = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness cm"),
                self.cm.as_ref().map(|cm| cm.inner().to_affine()),
            )?;

            // Witness fdi.
            let fdi = assign_free_advice(
                layouter.namespace(|| "witness fdi"),
                config.advices[0],
                self.fdi,
            )?;
            // Witness v.
            let v = assign_free_advice(
                layouter.namespace(|| "witness v"),
                config.advices[0],
                self.v,
            )?;
            // Witness nd.
            let nd = assign_free_advice(
                layouter.namespace(|| "witness nd"),
                config.advices[0],
                self.nd,
            )?;
            // Witness recp.
            let recp = assign_free_advice(
                layouter.namespace(|| "witness recp"),
                config.advices[0],
                self.recp,
            )?;

            (psi, rho, nk, cm, fdi, v, nd, recp)
        };

        // 1. CONSTRAINT: Foreign-field (secp256k1) key pairing
        // Prove e_pk = e_sk * G_secp256k1 using CRT representation (3x88-bit limbs)
        let secp256k1_chip = Secp256k1Chip::construct(config.secp256k1.clone());
        let (e_sk_crt, (_e_pk_x_crt, _e_pk_y_crt)) = secp256k1_chip.prove_key_pairing(
            layouter.namespace(|| "secp256k1 key pairing: e_pk = e_sk * G"),
            self.e_sk,
            self.e_pk_x,
            self.e_pk_y,
        )?;

        // 2. Merkle path validity check (GENESIS DISTRIBUTION INCLUSION).
        let root = {
            let path = self
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip()],
                HashDomains::MerkleCrh,
                self.pos,
                path,
            );
            let leaf = cm.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
        };

        // 3. Nullifier integrity: constraint that hkdf nullifier is equal to known with public and private inputs
        let nf = {
            let nf_old = gadget::derive_nullifier(
                layouter.namespace(|| "nf = DeriveNullifier_nk(rho,psi,m)"),
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip.clone(),
                rho.clone(),
                &psi,
                &cm,
                nk,
            )?;

            // Constrain nf to equal public input
            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF)?;
            nf_old
        };

        // q: have we constrained `leaf` is derived from provided values?
        // q: have we constrained `leaf` is on tree with known instance `root`.
        // q: have we constrained `nk` is hash-derived from the provided values?
        // q: have we constrained the pairing of `(e_sk,e_pk)`?


        Ok(())
    }
}
