use zk_headstash::deploy::suite::*;

/// ## `create_headstash_notes`
///  **Sinsemilla HashDomain** generates default note using poseidon hashing algo & Fixed-Denomination Notes
/// ```
///  cargo run -- --bin gen_headstash_notes ./data/genesis_sinsemilla.json 0x0000000000000000000000000000000000000000
/// ```
fn main() -> Result<(), BoxError> {
    HeadstashSuite::new().create_headstash_notes()?;
    let output_path = std::path::Path::new("./data").join("merkle_output.json");
    let root_hex = HeadstashSuite::new().gen_headstash_tree(output_path)?;
    println!("🌳 Merkle Root: {}", root_hex);
    Ok(())
}
