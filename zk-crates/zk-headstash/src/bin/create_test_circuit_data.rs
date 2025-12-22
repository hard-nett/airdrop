use std::path::Path;
use zk_headstash::deploy::suite::*;

/// # create test circuits verifying keys & test data
/// - generates default testing circuits [VerifyingKey] and [ProvingKey]
/// used as a part of verifiable deployments of headstashes
/// ```sh
///  cargo run --bin create_test_circuit_data
/// ```
fn main() -> Result<(), BoxError> {
    eprintln!("🚀 Starting test circuit key generation...\n");
    let suite = HeadstashSuite::new();
    // Generate test circuit keys for all example circuits
    suite.gen_test_circuit_keys(Path::new("./data/test_keys"))?;
    eprintln!("\n🎉 All circuit keys generated successfully!");
    eprintln!("📂 Main circuit keys: ./data/keys/");
    eprintln!("📂 Test circuit keys: ./data/test_keys/");
    Ok(())
}
