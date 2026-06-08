use std::path::Path;

use cw_orch::mock::Mock;
use zk_headstash::suite::HeadstashCircuitSuite;
use zk_headstash::suite::{suite::CircuitKeysGenerator, *};
use zk_test_press::BoxError;

/// # create headstash circuit keys
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```sh
///  # run with parallelization: RAYON_NUM_THREADS=4 cargo run -p zk-headstash --bin gen_headstash_keys --features multicore.
///  cargo run -- --bin gen_headtash_keys0
/// ```
fn main() -> Result<(), BoxError> {
    HeadstashCircuitSuite::new(Mock::new("sender"))
        .gen_headstash_circuit_keys(Path::new("artifacts"))?;
    Ok(())
}
