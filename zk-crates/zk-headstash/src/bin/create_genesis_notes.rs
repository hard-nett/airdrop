use zk_headstash::deploy::suite::*;

/// # create geneisis notes: Sinsemilla HashDomain
/// - generates default note using posiedon hashing algo & Fixed-Denomination Notes
/// - loads all balances,
/// - creates genesis Fixed-Denomination Notes, containing
///     -  tuple of static value: (1_000_000_000,100_000_000,10_000_000,1_000_000, ..) & index (multiple of notes an key is allocated per static value)\
///
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
