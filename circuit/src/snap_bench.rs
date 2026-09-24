//! Host timing for one Headstash Halo2 claim — same `Proof::create` the snap
//! calls from `gen_proof_witness`.
//!
//! MetaMask Snap workers (`@metamask/snaps-execution-environments`) are one SES
//! compartment per snap. They do not set `crossOriginIsolated` or hand the snap
//! `SharedArrayBuffer`, so `wasm-bindgen-rayon` `initThreadPool` cannot add OS
//! threads inside the snap. The execution environment parallelizes **across
//! snaps** (one worker each), not inside one K=18 IPA prove.
//!
//! This bench is **native release** (`halo2_proofs/multicore`). It is not a WASM
//! timing. Full K=18 prove in snap WASM is not viable here: `host-crypto` pulls
//! libsecp C, and a single-thread WASM prove would be several times slower than
//! the native number below.

use std::time::Instant;

use cw_orch::prelude::Mock;

use crate::circuit::{Proof, ProvingKey};
use crate::suite::suite::HeadstashProofBuilder;
use crate::suite::HeadstashCircuitSuite;

#[test]
#[ignore = "K=18 keygen+prove; cargo test -p zk-headstash --release --lib snap_bench -- --ignored --nocapture"]
fn bench_one_claim_proof_native() {
    let suite = HeadstashCircuitSuite::new(Mock::new("snap-bench"));
    let t_key = Instant::now();
    let pk = ProvingKey::build();
    let keygen_secs = t_key.elapsed().as_secs_f64();

    let (circuit, instance, _anchor, _partial) = suite
        .suite_backed_claim_pair(4, 1)
        .expect("suite claim");
    let instance_for_verify = instance.clone();

    let mut rng = crate::os_rng();
    let t_prove = Instant::now();
    let proof = Proof::create(&pk, &[circuit], &[instance], &mut rng).expect("prove");
    let prove_secs = t_prove.elapsed().as_secs_f64();

    let t_ver = Instant::now();
    proof
        .verify(&pk.vk(), &[instance_for_verify])
        .expect("verify");
    let verify_secs = t_ver.elapsed().as_secs_f64();

    let report = serde_json::json!({
        "halo2": "zakura-halo2-proofs",
        "floor_planner": "V1+floor-planner-v1-legacy-pdqsort",
        "runtime": "native-release",
        "threads": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1),
        "k": crate::circuit::K,
        "scalar_mul": "glv-128",
        "dropped": "q_orchard selector and action cv/enable gates (never enabled)",
        "keygen_secs": keygen_secs,
        "prove_secs": prove_secs,
        "verify_secs": verify_secs,
        "proof_bytes": proof.as_ref().len(),
        "wasm_snap": {
            "measured": false,
            "reason": "Snap SES worker is single-threaded; host-crypto is not a wasm32 guest. initThreadPool is a no-op unless the execution environment exposes SharedArrayBuffer, which snaps-execution-environments does not.",
        },
    });
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../artifacts/snap-proof-bench.json");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    std::eprintln!("{report}");
    std::eprintln!("wrote {}", path.display());
}
