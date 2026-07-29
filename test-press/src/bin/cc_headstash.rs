use cw_orch::prelude::*;

//TODO: default implement TestDataGenerator for for circuits to build keys 
use zk_test_press::suites::headstash::HeadstashSuite;
/// # create headstash circuit keys
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```sh
///  # run with parallelization: RAYON_NUM_THREADS=4 cargo run -p zk-headstash --bin gen_headstash_keys --features multicore.
///  cargo run -- --bin gen_headtash_keys0
/// ```
fn main() -> Result<(), zk_test_press::BoxError> {
    env_logger::init();
    let terp = Daemon::builder(cw_orch::daemon::networks::TERP_TESTNET.clone()).mnemonic("tuna harbor jacket regular net athlete quarter very wave jewel observe voice evolve pass bamboo liberty write dentist just before pipe envelope bid matrix").build()?;
    let hs = HeadstashSuite::new(terp.clone());
    hs.circuit.build_keys()?;
    Ok(())
}
