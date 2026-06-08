use std::path::Path;

use cw_orch::mock::Mock;
use zk_test_press::BoxError;

use zk_test_press::TestPressSuite;

/// # logic to create & verify circuit and proofs for testing in zk-wasmvm integrations.
/// - generates default testing circuits [VerifyingKey] and [ProvingKey]
/// used as a part of verifiable deployments of headstashes
/// ```sh
///  cargo run --bin create_test_circuit_data
/// ```q
// Generate test circuit keys for all example circuits
fn main() -> Result<(), BoxError> {
    let path = Path::new("./artifacts");
    // TODO: MockBase: ZkTxHandler
    // let proofs = TestPressSuite::new(Mock::new("sender")); // vec![("randy".to_string(), "rick".to_string())];
    // eprintln!("\n🎉 All circuit keys generated successfully!");
    // // println!("{:#?}", proofs);
    Ok(())
}
