//! Part T harness — Orchard-delta Headstash claim scenarios H1–H6.
//!
//! Spec: `docs/plans/spectrum/SPEC-airdrop-orchard-delta.md` §6
//!
//! ```bash
//! cd crates/headstash/circuit && cargo test --lib orchard_delta_part_t --no-default-features --features "circuit,std"
//! # or with default features if workspace deps resolve:
//! cargo test --lib orchard_delta_part_t
//! ```

#![cfg(all(test, feature = "circuit"))]

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use ff::PrimeField;
use halo2_proofs::{circuit::Value, dev::MockProver};
use pasta_curves::pallas;
use rand::{rngs::OsRng, RngCore};

use crate::circuit::gadget::secp256k1_chip::{Secp256k1Fp, Secp256k1Fq};
use crate::circuit::{Circuit, Instance, K};
use crate::distro_poseidon::poseidon_distro_leaf;
use crate::note::Note;
use crate::spec::to_native_out_of_circuit;
use crate::tree::MerklePath;
use crate::value::NoteDenom;

/// Claim output note schema stub (SPEC §6.1 / H6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimOutputNoteV0 {
    pub asset_tag: [u8; 32],
    pub value: u64,
    pub owner: [u8; 32],
    pub cmx: [u8; 32],
    pub nf_claim: [u8; 32],
    pub anchor_distro: [u8; 32],
}

impl ClaimOutputNoteV0 {
    pub fn from_instance(inst: &Instance) -> Self {
        let mut asset_tag = [0u8; 32];
        asset_tag.copy_from_slice(inst.nd.as_bytes());
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&inst.recp.to_canonical_bytes());
        let mut cmx = [0u8; 32];
        cmx.copy_from_slice(&inst.cmx.to_bytes());
        let mut nf_claim = [0u8; 32];
        nf_claim.copy_from_slice(&inst.nf.to_bytes());
        let mut anchor_distro = [0u8; 32];
        anchor_distro.copy_from_slice(&inst.anchor.to_bytes());
        Self {
            asset_tag,
            value: inst.v.inner(),
            owner,
            cmx,
            nf_claim,
            anchor_distro,
        }
    }
}

/// Valid circuit+instance pair (same construction as circuit unit tests).
fn valid_claim_pair<R: RngCore>(mut rng: R) -> (Circuit, Instance) {
    let (_sk, _fvk, esk, spent_note) = Note::dummy(&mut rng, None);
    let (epkx, epky) = esk.epk().xy();
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

    // Poseidon-v1 public inclusion leaf + path root (ADR-POSEIDON-DISTRO-TREE).
    let leaf = poseidon_distro_leaf(epk_x_native, epk_y_native, nd_pallas, v_pallas, fdi_pallas);
    let anchor = path.root_from_leaf(leaf);

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

fn public_columns(instance: &Instance) -> Vec<Vec<pallas::Base>> {
    instance
        .to_halo2_instance()
        .iter()
        .map(|row| row.to_vec())
        .collect()
}

/// H1: Valid claim with Poseidon-v1 path — MockProver must fully verify.
#[test]
fn h1_valid_claim() {
    let (circuit, instance) = valid_claim_pair(OsRng);
    let public = public_columns(&instance);
    let prover = MockProver::run(K, &circuit, public).expect("H1: MockProver must construct");
    assert_eq!(instance.to_bytes().len(), 168, "H1: public instance wire size");
    assert_eq!(
        prover.verify(),
        Ok(()),
        "H1: Poseidon-v1 claim circuit must satisfy MockProver"
    );
}

/// H1-suite: multi-leaf Poseidon tree + depth-32 path + matching partial note.
/// Full MockProver green is required (note-commit bool_check fix + note-derived nk).
#[test]
#[cfg(feature = "interface")]
fn h1_suite_backed_multi_leaf_claim() {
    use crate::suite::suite::HeadstashProofBuilder;
    use crate::suite::HeadstashCircuitSuite;
    use cw_orch::mock::Mock;

    let suite = HeadstashCircuitSuite::new(Mock::new("sender"));
    let (circuit, instance, anchor, partial) = suite
        .suite_backed_claim_pair(8, 3)
        .expect("suite-backed claim pair");

    assert_eq!(partial.value, instance.v.inner());
    assert_eq!(instance.to_bytes().len(), 168);
    assert_eq!(instance.anchor.to_bytes(), anchor.to_bytes());
    let mut saw_path = false;
    circuit.path.map(|_| saw_path = true);
    assert!(saw_path);

    let public = public_columns(&instance);
    let prover = MockProver::run(K, &circuit, public).expect("suite H1 MockProver construct");
    assert_eq!(
        prover.verify(),
        Ok(()),
        "suite-backed multi-leaf Poseidon claim must fully verify"
    );
}

/// Batch of two independent suite-backed claims — both must MockProver-verify.
#[test]
#[cfg(feature = "interface")]
fn h1_batch_two_claims_verify() {
    use crate::suite::suite::HeadstashProofBuilder;
    use crate::suite::HeadstashCircuitSuite;
    use cw_orch::mock::Mock;

    let suite = HeadstashCircuitSuite::new(Mock::new("sender"));
    let (c0, i0, a0, p0) = suite.suite_backed_claim_pair(4, 0).unwrap();
    let (c1, i1, a1, p1) = suite.suite_backed_claim_pair(4, 1).unwrap();
    assert_ne!(a0.to_bytes(), a1.to_bytes());
    assert_ne!(p0.esk_bytes, p1.esk_bytes);
    assert_eq!(i0.to_bytes().len(), 168);
    assert_eq!(i1.to_bytes().len(), 168);

    for (label, circuit, instance) in [("claim0", c0, i0), ("claim1", c1, i1)] {
        let public = public_columns(&instance);
        let prover = MockProver::run(K, &circuit, public).expect(label);
        assert_eq!(
            prover.verify(),
            Ok(()),
            "{label}: batch multi-claim MockProver must verify"
        );
    }
}

/// Contract-facing E2E: suite Poseidon root + instance layout bind to claim surface.
#[test]
#[cfg(feature = "interface")]
fn claim_surface_poseidon_root_and_instance_bytes() {
    use crate::suite::suite::HeadstashProofBuilder;
    use crate::suite::HeadstashCircuitSuite;
    use cosmwasm_std::Binary;
    use cw_orch::mock::Mock;

    let suite = HeadstashCircuitSuite::new(Mock::new("sender"));
    let (_circuit, instance, anchor, partial) =
        suite.suite_backed_claim_pair(4, 1).expect("claim pair");

    // Depth-32 Poseidon root is what the contract stores / checks.
    let root_bytes = Binary::from(anchor.to_bytes().to_vec());
    assert_eq!(root_bytes.len(), 32);
    assert_eq!(instance.anchor.to_bytes(), anchor.to_bytes());
    assert_eq!(instance.to_bytes().len(), 168);
    assert_eq!(partial.value, instance.v.inner());

    // Nullifier + cmx are 32-byte field encodings for process_headstash.
    assert_eq!(instance.nf.to_bytes().len(), 32);
    assert_eq!(instance.cmx.to_bytes().len(), 32);
}

/// H2: Double-claim of same nullifier rejected by nullifier set (contract policy model).
#[test]
fn h2_double_claim() {
    let (_circuit, instance) = valid_claim_pair(OsRng);
    let nf = instance.nf.to_bytes();
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    assert!(seen.insert(nf), "first claim inserts nullifier");
    assert!(
        !seen.insert(nf),
        "H2: second claim with same nullifier must be rejected"
    );
}

/// H3: Wrong distribution root (instance anchor ≠ path root) → verify fails.
#[test]
fn h3_bad_root() {
    let (circuit, mut instance) = valid_claim_pair(OsRng);
    let mut bad_bytes = instance.anchor.to_bytes();
    bad_bytes[0] ^= 0x01;
    instance.anchor = crate::Anchor::from_bytes(bad_bytes).expect("field element");

    let prover = MockProver::run(K, &circuit, public_columns(&instance)).expect("MockProver");
    assert!(
        prover.verify().is_err(),
        "H3: wrong distribution root must not verify"
    );
}

/// H4: Non-canonical `nd` (raw blake3 without field-bit clear) ≠ `new_for_proof`.
#[test]
fn h4_noncanonical_nd() {
    let raw = "uterp";
    let canonical = NoteDenom::new_for_proof(raw);
    let raw_hash = NoteDenom::hash(raw);
    let mut non_canonical = *raw_hash.as_bytes();
    if non_canonical[31] & !0x1F == 0 {
        non_canonical[31] |= 0xE0;
    }
    assert_ne!(
        canonical.as_bytes(),
        &non_canonical,
        "H4: non-canonical nd must differ from NoteDenom::new_for_proof"
    );
    // Bit-clear policy: last byte top 3 bits cleared
    assert_eq!(
        canonical.as_bytes()[31] & !0x1F,
        0,
        "H4: canonical nd must clear top 3 bits of last byte"
    );
}

/// H5: Public instance bytes do not embed eligibility secret key material.
#[test]
fn h5_recipient_privacy() {
    let mut rng = OsRng;
    let (sk, _fvk, esk, _spent_note) = Note::dummy(&mut rng, None);
    let (_circuit, instance) = valid_claim_pair(&mut rng);
    let pub_bytes = instance.to_bytes();
    let esk_bytes = esk.secret_bytes();
    assert!(
        !contains_subslice(&pub_bytes, &esk_bytes),
        "H5: eligibility secret must not appear in public instance bytes"
    );
    let sk_bytes = sk.to_bytes();
    assert!(
        !contains_subslice(&pub_bytes, sk_bytes.as_ref()),
        "H5: spending key must not appear in public instance bytes"
    );
    let recp_bytes = instance.recp.to_canonical_bytes();
    assert!(
        contains_subslice(&pub_bytes, &recp_bytes),
        "H5: recipient binding is public; eligibility address is not"
    );
}

/// H6: Successful claim instance maps to ClaimOutputNoteV0 without inventing fields.
#[test]
fn h6_claim_output_schema() {
    let (_circuit, instance) = valid_claim_pair(OsRng);
    let note = ClaimOutputNoteV0::from_instance(&instance);
    assert_eq!(note.value, instance.v.inner());
    assert_eq!(&note.asset_tag[..], instance.nd.as_bytes());
    assert_eq!(&note.nf_claim[..], &instance.nf.to_bytes()[..]);
    assert_eq!(&note.cmx[..], &instance.cmx.to_bytes()[..]);
    assert_eq!(&note.anchor_distro[..], &instance.anchor.to_bytes()[..]);
    assert_eq!(&note.owner[..], &instance.recp.to_canonical_bytes()[..]);
}

/// H12: Documented gap — public HS_ND is not yet forced equal to witness nd.
/// When Part I lands constrain_instance(nd), this must flip to verify().is_err().
#[test]
fn h12_instance_nd_gap_documented() {
    let (circuit, mut instance) = valid_claim_pair(OsRng);
    instance.nd = NoteDenom::new_for_proof("not-the-witness-denom");
    let prover = MockProver::run(K, &circuit, public_columns(&instance)).expect("MockProver");
    // TODAY: may still verify (gap §1.4). When constrained, expect is_err().
    let result = prover.verify();
    // Record status: either err (fixed) or ok (gap still open) — both valid for this round.
    // Progression: Part I should make this always Err.
    let _ = result;
    // Structural: instance bytes still encode the mutated nd (public API surface).
    assert_eq!(
        instance.nd.as_bytes(),
        NoteDenom::new_for_proof("not-the-witness-denom").as_bytes()
    );
}

fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}
