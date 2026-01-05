use std::path::Path;

use zk_test_press::HeadstashSuite;
use zk_test_press::suite::{BoxError, HeadstashLaunchpadInstance};

/// # logic to create & verify circuit and proofs for testing in zk-wasmvm integrations.
/// - generates default testing circuits [VerifyingKey] and [ProvingKey]
/// used as a part of verifiable deployments of headstashes
/// ```sh
///  cargo run --bin create_test_circuit_data
/// ```q
// Generate test circuit keys for all example circuits
fn main() -> Result<(), BoxError> {
    let path = Path::new("./data/test_keys");

    let proofs = zk_cosmwasm::TestPressLaunchpadInstance::gen_test_circuit_keys(
        &zk_cosmwasm::suite::TestPressSuite::new(),
        path,
        None,
        vec![],
    )?; // vec![("randy".to_string(), "rick".to_string())];
    eprintln!("\n🎉 All circuit keys generated successfully!");
    // println!("{:#?}", proofs);
    Ok(())
}
