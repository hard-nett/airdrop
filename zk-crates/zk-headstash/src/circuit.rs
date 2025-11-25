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
    note::{ExtractedNoteCommitment, NoteCommitment, Nullifier, Rho},
    tree::{Anchor, MerkleHashHeadstash},
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

/// The Headstash Circuit Array
#[derive(Clone, Debug, Default)]
pub struct HeadstashCircuit {
    pub(crate) path: Value<[MerkleHashHeadstash; MERKLE_DEPTH_HEADSTASH]>,
    pub(crate) pos: Value<u32>,
    pub(crate) psi: Value<pallas::Base>,
    pub(crate) rho: Value<Rho>,
    pub(crate) cm: Value<NoteCommitment>,
    pub(crate) esk: Value<Secp256k1Fq>,
    pub(crate) epkx: Value<Secp256k1Fp>,
    pub(crate) epky: Value<Secp256k1Fp>,
    pub(crate) nk: Value<NullifierDerivingKey>,
    pub(crate) fdi: Value<pallas::Base>,
    pub(crate) v: Value<pallas::Base>,
    pub(crate) nd: Value<pallas::Base>,
    pub(crate) recp: Value<pallas::Base>,
}

impl plonk::Circuit<pallas::Base> for HeadstashCircuit {
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

    // Prove epk = esk * G_secp256k1 using CRT representation (3x88-bit limbs)
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        SinsemillaChip::load(config.sinsemilla_cfg.clone(), &mut layouter)?;
        let ecc_chip = config.ecc_chip();
        // 1. CONSTRAINT: Foreign-field (secp256k1) key pairing
        let secp256k1_chip = Secp256k1Chip::construct(config.secp256k1.clone());
        let (e_sk_crt, (_e_pk_x_crt, _e_pk_y_crt)) = secp256k1_chip.prove_key_pairing(
            layouter.namespace(|| "secp256k1 key pairing: epk = esk * G"),
            self.esk,
            self.epkx,
            self.epky,
        )?;

        // Witness private inputs that are used across multiple checks.
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
        // q: have we constrained the pairing of `(esk,epk)`?

        Ok(())
    }
}

/// Public inputs to the Orchard Action circuit.
#[derive(Clone, Debug)]
pub struct Instance {
    // pub(crate) cv_net: ValueCommitment,
    pub(crate) anchor: Anchor,
    pub(crate) nf_old: Nullifier,
    pub(crate) cmx: ExtractedNoteCommitment,
    // pub(crate) rk: VerificationKey<SpendAuth>,
    // pub(crate) enable_spend: bool,
    // pub(crate) enable_output: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::{Field, PrimeField};
    use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp as Secp256k1Fp, Fq as Secp256k1Fq};
    use halo2_proofs::{dev::MockProver, plonk::Circuit};
    use pasta_curves::pallas;
    use rand::rngs::OsRng;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use crate::{
        keys::{EligibleSk, NullifierDerivingKey},
        note::{NoteCommitment, Rho},
        tree::MerkleHashHeadstash,
        value::{NoteDenom, NoteValue},
    };

    /// Degree for testing (2^18 = 262,144 rows for foreign field ops)
    const K: u32 = 18;

    /// Helper to generate a valid circuit instance using Note template
    fn generate_valid_circuit() -> HeadstashCircuit {
        use crate::{
            address::RecpAddr,
            keys::{EligiblePk, EligibleSk},
            note::{Note, RandomSeed},
        };
        use cosmwasm_std::{testing::mock_dependencies, Api};
        use ff::FromUniformBytes;

        // 1. Generate secp256k1 key pair (esk, epk)
        let e_sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let e_sk_secp = SecretKey::from_slice(&e_sk_bytes).expect("valid secret key");
        let esk = EligibleSk::from(e_sk_secp);

        // 2. Generate randomness (rho, rseed, psi)
        let mut randomness_64 = [0; 64];
        blake3::Hasher::new()
            .update(&[0u8; 32]) // deterministic for testing
            .finalize_xof()
            .fill(&mut randomness_64);

        let rho =
            Rho::from_bytes(&pallas::Base::from_uniform_bytes(&randomness_64).to_repr()).unwrap();
        let rseed = RandomSeed::from_bytes([1u8; 32], &rho).unwrap();

        // 3. Note parameters
        let v = NoteValue::from_raw(100);
        let nd = NoteDenom::new_for_proof("TEST_DENOM");
        let fdi = 0u64;

        // 4. Create recp address
        let mock_deps = mock_dependencies();
        let recp = RecpAddr::try_from(
            mock_deps
                .api
                .addr_canonicalize(
                    &mock_deps
                        .api
                        .addr_make(&format!("test{}", hex::encode(rho.into_inner().to_repr())))
                        .to_string(),
                )
                .unwrap(),
        )
        .unwrap();

        // 5. Create Note - this derives nk, cm, nullifier automatically
        let note = Note::from_parts(recp, v, nd, fdi, esk, rho, rseed).unwrap();

        // 6. Extract secp256k1 coordinates for circuit
        let secp = Secp256k1::new();
        let e_pk_secp = PublicKey::from_secret_key(&secp, &e_sk_secp);
        let e_pk_bytes = e_pk_secp.serialize_uncompressed();
        let e_pk_x_bytes: [u8; 32] = e_pk_bytes[1..33].try_into().unwrap();
        let e_pk_y_bytes: [u8; 32] = e_pk_bytes[33..65].try_into().unwrap();

        let e_sk_fq = Secp256k1Fq::from_repr(e_sk_bytes).expect("valid Fq");
        let epkx = Secp256k1Fp::from_repr(e_pk_x_bytes).expect("valid Fp");
        let epky = Secp256k1Fp::from_repr(e_pk_y_bytes).expect("valid Fp");

        // 7. Derive nk using HKDF
        let nk = NullifierDerivingKey::derive_from(esk, rho);

        let mut sin_root = pallas::Base::from_repr(
            hex::decode("8638de243d78472519d9d163872694dcc7343658a0199e3a67b390c1bdbc7300")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .expect("field conversion error");

        // let path = MerkleHashHeadstash::from(crate::tree::MerkleHashHeadstash(sin_root));
        // 8. Create dummy Merkle path (for testing)
        let path = [MerkleHashHeadstash::from_cmx(
            &ExtractedNoteCommitment::from_bytes(&sin_root.to_repr())
                .expect("sinsemilla headstash tree root derivation error"),
        ); MERKLE_DEPTH_HEADSTASH];
        let pos = 0u32;

        HeadstashCircuit {
            path: Value::known(path),
            pos: Value::known(pos),
            psi: Value::known(note.rseed().psi(&rho)),
            rho: Value::known(rho),
            cm: Value::known(note.commitment()),
            esk: Value::known(e_sk_fq),
            epkx: Value::known(epkx),
            epky: Value::known(epky),
            nk: Value::known(nk),
            fdi: Value::known(pallas::Base::from(fdi)),
            v: Value::known(v.to_fp_pallas()),
            nd: Value::known(crate::spec::nd_to_fp(&nd)),
            recp: Value::known(note.recp().to_pallas()),
        }
    }

    #[test]
    fn test_valid_headstash_circuit() {
        let circuit = generate_valid_circuit();
        println!("✓ Generated HeadstashCircuit, running MockProver...");
        // Run MockProver
        let prover = MockProver::run(K, &circuit, vec![vec![]]).expect("prover should run");

        // Verify
        match prover.verify() {
            Ok(()) => println!("✓ Valid Headstash circuit verified successfully"),
            Err(e) => {
                eprintln!("✗ Circuit verification failed:");
                for err in e.iter() {
                    eprintln!("  - {:1?}", err);
                }
                panic!("Valid circuit should verify");
            }
        }
    }

    #[test]
    #[should_panic(expected = "should verify")]
    fn test_invalid_key_pairing_fails() {
        let mut circuit = generate_valid_circuit();

        // Tamper with public key
        let secp = Secp256k1::new();
        let wrong_sk = SecretKey::from_byte_array([42u8; 32]).unwrap();
        let wrong_pk = PublicKey::from_secret_key(&secp, &wrong_sk);

        let wrong_pk_bytes = wrong_pk.serialize_uncompressed();
        let wrong_pk_x_bytes: [u8; 32] = wrong_pk_bytes[1..33].try_into().unwrap();
        let wrong_pk_y_bytes: [u8; 32] = wrong_pk_bytes[33..65].try_into().unwrap();

        circuit.epkx = Value::known(Secp256k1Fp::from_repr(wrong_pk_x_bytes).unwrap());
        circuit.epky = Value::known(Secp256k1Fp::from_repr(wrong_pk_y_bytes).unwrap());

        let prover = MockProver::run(K, &circuit, vec![vec![]]).expect("prover should run");
        prover.verify().expect("should verify");
    }

    #[test]
    fn test_circuit_without_witnesses() {
        let circuit = generate_valid_circuit();
        let circuit_no_witnesses = circuit.without_witnesses();

        let prover = MockProver::run(K, &circuit_no_witnesses, vec![vec![]]);
        assert!(
            prover.is_ok(),
            "Circuit without witnesses should be constructable"
        );
    }

    #[test]
    fn test_circuit_configuration() {
        use halo2_proofs::plonk::ConstraintSystem;
        let mut cs = ConstraintSystem::<pallas::Base>::default();
        let config = HeadstashCircuit::configure(&mut cs);

        println!("Circuit configuration:");
        println!("  - Advice columns: {}", config.advices.len());
        assert_eq!(config.advices.len(), 10, "Should have 10 advice columns");
    }

    #[test]
    fn test_circuit_cost() {
        use halo2_proofs::dev::CircuitCost;
        use pasta_curves::vesta;

        let circuit = generate_valid_circuit();
        let cost = CircuitCost::<vesta::Point, _>::measure(K, &circuit);

        println!("\nCircuit cost:");
        println!("  Degree: 2^{} = {} rows", K, 1 << K);
        // println!("  Proof size (1 instance): {} bytes", cost.proof_size(1));

        let proof_size = usize::from(cost.proof_size(1));
        assert!(proof_size > 0, "Proof size should be non-zero");
        println!(" proof_size: {}", proof_size);
    }
}
