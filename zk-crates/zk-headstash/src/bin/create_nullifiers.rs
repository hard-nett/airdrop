use zk_headstash::deploy::suite::*;

fn main() -> Result<(), BoxError> {
    HeadstashSuite::new().gen_note()?;
    Ok(())
}
