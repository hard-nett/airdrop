use zk_headstash::deploy::suite::*;

/// # create headstash circuit keys
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```
///  cargo run -- --bin gen_headtash_keys
/// ```
fn main() -> Result<(), BoxError> {
    HeadstashSuite::new().gen_headstash_keys()?;
    Ok(())
}
