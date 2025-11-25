use zk_crates::deploy::suite::*;

fn main() -> Result<(), BoxError> {
    TerpHeadstash::new().gen_note_nullifier()?;
    Ok(())
}
