use commonware_runtime::Runner;
use zk_headstash::deploy::suite::*;
/// # create headstash circuit proof from a note.
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```
///  cargo run -- --bin create_headstash_proof
/// ```
/// See <https://docs.rs/commonware_runtime> for traits/details.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Runner::default().start(|_| HeadstashSuite::new().create_headstash_proof())?;
    Ok(())
}
