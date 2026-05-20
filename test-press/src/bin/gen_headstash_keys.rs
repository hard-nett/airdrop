use std::path::Path;

use zk_headstash::suite::HeadstashSuite;
use zk_headstash::suite::{suite::CircuitKeysGenerator, *};
use zk_test_press::BoxError;

/// # create headstash circuit keys
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```sh
///  # run with parallelization: RAYON_NUM_THREADS=4 cargo run -p zk-headstash --bin gen_headstash_keys --features multicore.
///  cargo run -- --bin gen_headtash_keys0
/// ```
fn main() -> Result<(), BoxError> {
    HeadstashSuite::new().gen_headstash_circuit_keys(Path::new("data/testkeys"))?;
    Ok(())
}
