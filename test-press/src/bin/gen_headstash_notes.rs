use cw_orch::mock::Mock;
use zk_headstash::suite::{HeadstashCircuitSuite, suite::HeadstashSinsemillaTree};
use zk_test_press::BoxError;

/// ## `create_headstash_notes`
///  **Sinsemilla HashDomain** generates default note using poseidon hashing algo & Fixed-Denomination Notes
/// ```
///  cargo run -- --bin gen_headstash_notes ./data/genesis_sinsemilla.json 0x0000000000000000000000000000000000000000
/// ```
fn main() -> Result<(), BoxError> {
    let s = HeadstashCircuitSuite::new(Mock::new("sender"));
    s.create_headstash_notes()?;
    let output_path = std::path::Path::new("./artifacts").join("merkle_output.json");
    let root_hex =
        HeadstashCircuitSuite::new(Mock::new("sender")).gen_headstash_tree(output_path)?;
    println!("🌳 Merkle Root: {}", root_hex);
    Ok(())
}
