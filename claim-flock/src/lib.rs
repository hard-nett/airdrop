//! Headstash claim statement over the BLAKE3 circuit.
//!
//! One row is one BLAKE3 compression. The wires, not a second hash, are what
//! make it a claim:
//!
//! - `rseed` is a private input. Its compression output is `rseed_com`.
//! - The nullifier row reads that same `rseed` and its output is public.
//! - The leaf row reads `rseed_com` plus the public allocation, so a second
//!   string is a different leaf.
//! - Each Merkle level hashes `left ‖ right` with the running digest on the
//!   side the public index bit selects. The last output is the public root.
//!
//! A proof is a Ligerito proof of this circuit. The nullifier is not a free
//! witness: it is the compression output, and the same string is what the
//! leaf commits to.

use flock_core::circuit::builder::{CircuitBuilder, GateType, SlotId, SlotWitness};
use flock_core::field::F128;
use flock_core::schedule::TableType;
use flock_hash::blake3_compress;

use flock_prover::r1cs_hashes::blake3::{Compression, build_block_r1cs, io_schema};

const IV: [u32; 8] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB,
    0x5BE0_CD19,
];

/// Depth of the inclusion path this statement wires. The index is public, so
/// the side of each sibling is fixed by that bit rather than by a mux.
pub const DEPTH: usize = 2;

const FLAG_RSEED: u32 = 1;
const FLAG_NULLIFIER: u32 = 2;
const FLAG_LEAF: u32 = 3;
const FLAG_NODE: u32 = 4;

/// Private opening of one leaf, plus the siblings for [`DEPTH`] levels.
pub struct Opening {
    pub rseed: [u32; 8],
    pub epk_x: [u32; 4],
    pub nd: [u32; 2],
    pub v: u32,
    pub fdi: u32,
    /// Leaf position. The circuit shape is this index's path.
    pub index: u32,
    pub siblings: [[u32; 8]; DEPTH],
}

/// What a verifier holds: the tree root and the nullifier the opening derives.
pub struct Claim {
    pub root: [u32; 8],
    pub nullifier: [u32; 8],
}

struct Blake3Gate {
    nu: usize,
}

impl GateType for Blake3Gate {
    type Row = Compression;
    type Hint = ();

    fn table(&self) -> TableType {
        TableType::from_block_r1cs(&build_block_r1cs(self.nu)).with_io_schema(io_schema())
    }

    fn eval(&self, inputs: &[F128], _hint: &(), outputs: &mut Vec<F128>) -> Self::Row {
        let cv = unpack8(inputs[0], inputs[1]);
        let mut m = [0u32; 16];
        for i in 0..4 {
            let w = unpack4(inputs[2 + i]);
            m[4 * i..4 * i + 4].copy_from_slice(&w);
        }
        let (counter, block_len, flags) = unpack_params(inputs[6]);
        let out = blake3_compress(&cv, &m, counter, block_len, flags);
        let out_lo: [u32; 8] = out[0..8].try_into().unwrap();
        let out_hi: [u32; 8] = out[8..16].try_into().unwrap();
        let (lo, hi) = (pack8(&out_lo), pack8(&out_hi));
        outputs.extend_from_slice(&[lo[0], lo[1], hi[0], hi[1]]);
        (cv, m, counter, block_len, flags)
    }

    fn witness(&self, _rows: &[Self::Row], _nu: usize) -> SlotWitness {
        SlotWitness::DeferredToRows
    }
}

fn compress(message: &[u32; 16], flags: u32) -> [u32; 8] {
    let out = blake3_compress(&IV, message, 0, 64, flags);
    out[0..8].try_into().unwrap()
}

fn rseed_message(rseed: &[u32; 8]) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[..8].copy_from_slice(rseed);
    m
}

fn leaf_message(rseed_com: &[u32; 8], opening: &Opening) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[..8].copy_from_slice(rseed_com);
    m[8..12].copy_from_slice(&opening.epk_x);
    m[12] = opening.nd[0];
    m[13] = opening.nd[1];
    m[14] = opening.v;
    m[15] = opening.fdi;
    m
}

fn node_message(left: &[u32; 8], right: &[u32; 8]) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[..8].copy_from_slice(left);
    m[8..].copy_from_slice(right);
    m
}

/// Root and nullifier for this opening. The nullifier depends only on `rseed`.
/// The root depends on `rseed` through the leaf, so a second string does not
/// sit under the same root.
pub fn derive(opening: &Opening) -> Claim {
    let rseed_com = compress(&rseed_message(&opening.rseed), FLAG_RSEED);
    let nullifier = compress(&rseed_message(&opening.rseed), FLAG_NULLIFIER);
    let mut running = compress(&leaf_message(&rseed_com, opening), FLAG_LEAF);
    for level in 0..DEPTH {
        let bit = (opening.index >> level) & 1 == 1;
        let (left, right) = if bit {
            (&opening.siblings[level], &running)
        } else {
            (&running, &opening.siblings[level])
        };
        // `running` is moved into the message by copy.
        let left = *left;
        let right = *right;
        running = compress(&node_message(&left, &right), FLAG_NODE);
    }
    Claim { root: running, nullifier }
}

fn pack4(w: [u32; 4]) -> F128 {
    F128::new(w[0] as u64 | ((w[1] as u64) << 32), w[2] as u64 | ((w[3] as u64) << 32))
}

fn unpack4(v: F128) -> [u32; 4] {
    [v.lo as u32, (v.lo >> 32) as u32, v.hi as u32, (v.hi >> 32) as u32]
}

fn pack8(w: &[u32; 8]) -> [F128; 2] {
    [pack4([w[0], w[1], w[2], w[3]]), pack4([w[4], w[5], w[6], w[7]])]
}

fn unpack8(a: F128, b: F128) -> [u32; 8] {
    let (x, y) = (unpack4(a), unpack4(b));
    [x[0], x[1], x[2], x[3], y[0], y[1], y[2], y[3]]
}

fn pack_params(flags: u32) -> F128 {
    F128::new(0, 64u64 | ((flags as u64) << 32))
}

fn unpack_params(v: F128) -> (u64, u32, u32) {
    (v.lo, v.hi as u32, (v.hi >> 32) as u32)
}

/// Build the claim circuit. `rseed` and the siblings enter as private values.
/// The allocation, the nullifier, and the root are public.
pub fn build(opening: &Opening) -> (flock_core::circuit::builder::BuiltCircuit, SlotId) {
    let claim = derive(opening);
    let nu = 8;
    let mut b = CircuitBuilder::new(nu);
    let g: SlotId = b.slot(Blake3Gate { nu });
    let iv = pack8(&IV);
    let cv = [b.public_value(iv[0]), b.public_value(iv[1])];

    let rseed = pack8(&opening.rseed);
    let rseed_w = [b.value(rseed[0]), b.value(rseed[1])];
    let zero = b.public_value(F128::ZERO);
    let rseed_params = b.public_value(pack_params(FLAG_RSEED));
    let rseed_out = b.gate(g, &[cv[0], cv[1], rseed_w[0], rseed_w[1], zero, zero, rseed_params]);

    let nf_params = b.public_value(pack_params(FLAG_NULLIFIER));
    let nf_out = b.gate(g, &[cv[0], cv[1], rseed_w[0], rseed_w[1], zero, zero, nf_params]);
    let nf_at = b.public_len();
    b.publish(nf_out[0]);
    b.publish(nf_out[1]);

    let epk = b.public_value(pack4(opening.epk_x));
    let tail = b.public_value(pack4([opening.nd[0], opening.nd[1], opening.v, opening.fdi]));
    let leaf_params = b.public_value(pack_params(FLAG_LEAF));
    let leaf_out = b.gate(
        g,
        &[cv[0], cv[1], rseed_out[0], rseed_out[1], epk, tail, leaf_params],
    );

    let mut running = [leaf_out[0], leaf_out[1]];
    let node_params = b.public_value(pack_params(FLAG_NODE));
    for level in 0..DEPTH {
        let sib = pack8(&opening.siblings[level]);
        let sib_w = [b.value(sib[0]), b.value(sib[1])];
        let bit = (opening.index >> level) & 1 == 1;
        let (left, right) = if bit {
            (sib_w, running)
        } else {
            (running, sib_w)
        };
        let out = b.gate(g, &[cv[0], cv[1], left[0], left[1], right[0], right[1], node_params]);
        running = [out[0], out[1]];
    }
    let root_at = b.public_len();
    b.publish(running[0]);
    b.publish(running[1]);

    let built = b.finish().expect("headstash circuit");
    let published = &built.witness.public;
    let got_nf = unpack8(published[nf_at], published[nf_at + 1]);
    let got_root = unpack8(published[root_at], published[root_at + 1]);
    assert_eq!(got_nf, claim.nullifier, "published nullifier");
    assert_eq!(got_root, claim.root, "published root");
    (built, g)
}

const NU: usize = 8;
const DOMAIN: &[u8] = b"terp-headstash-flock-v1";

/// One Ligerito proof of [`build`], plus the time to build the circuit,
/// prove, and verify.
pub struct ProofBench {
    pub gates: usize,
    pub build_secs: f64,
    pub prove_secs: f64,
    pub verify_secs: f64,
    pub proof_bytes: usize,
}

/// Prove the claim and verify it against the same public words. A flipped
/// public root must fail.
pub fn prove_and_verify(opening: &Opening) -> ProofBench {
    use std::time::Instant;

    use flock_core::pcs::ligerito::LigeritoProfile;
    use flock_core::pcs::PcsParams;
    use flock_core::union::UnionInstance;

    use flock_prover::challenger::FsChallenger;
    use flock_prover::prover::{self, UnionSlotProverInput};
    use flock_prover::r1cs_hashes::blake3::generate_witness_batch_major_partial;
    use flock_prover::verifier;

    let t0 = Instant::now();
    let (built, slot) = build(opening);
    let build_secs = t0.elapsed().as_secs_f64();
    let rows = built.rows::<Blake3Gate>(slot);
    let gates = rows.len();

    let union = UnionInstance::new(&built.shape.registry, built.shape.counts.clone());
    let pcs_params = PcsParams {
        m: union.dense_m(),
        log_inv_rate: 1,
        log_batch_size: 6,
        profile: LigeritoProfile::Fast,
        num_lanes: union.commit_lanes(6),
        merkle_hash: Default::default(),
    };
    let r1cs = build_block_r1cs(NU);
    let lc = r1cs.csc_lincheck_circuit();
    let witness = generate_witness_batch_major_partial(rows, NU);

    let t1 = Instant::now();
    let mut ch = FsChallenger::new(DOMAIN);
    let (proof, commitment, _) = prover::prove_fast_ligerito_union_circuit(
        &union,
        &built.shape.circuit,
        &built.witness.public,
        &pcs_params,
        vec![UnionSlotProverInput::new(witness, lc)],
        Vec::new(),
        &mut ch,
    );
    let prove_secs = t1.elapsed().as_secs_f64();

    let t2 = Instant::now();
    let mut ch = FsChallenger::new(DOMAIN);
    verifier::verify_ligerito_union_circuit(
        &union,
        &built.shape.circuit,
        &built.witness.public,
        &[lc],
        &commitment,
        &proof,
        &pcs_params,
        &mut ch,
    )
    .expect("honest headstash claim verifies");
    let verify_secs = t2.elapsed().as_secs_f64();

    let mut bad = built.witness.public.clone();
    let last = bad.len() - 1;
    bad[last] += F128::ONE;
    let mut ch = FsChallenger::new(DOMAIN);
    assert!(
        verifier::verify_ligerito_union_circuit(
            &union,
            &built.shape.circuit,
            &bad,
            &[lc],
            &commitment,
            &proof,
            &pcs_params,
            &mut ch,
        )
        .is_err(),
        "a flipped public root must fail"
    );

    ProofBench {
        gates,
        build_secs,
        prove_secs,
        verify_secs,
        proof_bytes: bincode::serialize(&proof).expect("proof bytes").len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rseed0: u32, index: u32) -> Opening {
        Opening {
            rseed: [rseed0, 2, 3, 4, 5, 6, 7, 8],
            epk_x: [9, 10, 11, 12],
            nd: [13, 14],
            v: 15,
            fdi: 1,
            index,
            siblings: [[21, 22, 23, 24, 25, 26, 27, 28], [31, 32, 33, 34, 35, 36, 37, 38]],
        }
    }

    #[test]
    fn nullifier_is_the_string_and_the_root_binds_it() {
        let a = sample(1, 1);
        let claim = derive(&a);
        let again = derive(&a);
        assert_eq!(claim.nullifier, again.nullifier);
        assert_eq!(claim.root, again.root);

        let mut other = sample(99, 1);
        other.siblings = a.siblings;
        let moved = derive(&other);
        assert_ne!(moved.nullifier, claim.nullifier, "a second string is a second nullifier");
        assert_ne!(moved.root, claim.root, "a second string is not in the same leaf");

        let mut relocated = sample(1, 0);
        relocated.siblings = a.siblings;
        assert_ne!(derive(&relocated).root, claim.root, "the index bit selects the side");
    }

    #[test]
    fn circuit_publishes_the_derived_claim() {
        let opening = sample(1, 1);
        let (built, slot) = build(&opening);
        // rseed commitment, nullifier, leaf, then one node per level.
        assert_eq!(built.rows::<Blake3Gate>(slot).len(), 3 + DEPTH);
    }
}
