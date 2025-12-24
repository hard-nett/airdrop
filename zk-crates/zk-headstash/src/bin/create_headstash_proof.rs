// use commonware_runtime::tokio::Runner;
// use commonware_runtime::Runner as _;
use zk_headstash::address::RecpAddr;
use zk_headstash::deploy::suite::*;
use zk_headstash::keys::EligibleSk;
use zk_headstash::tree::{MerkleHashOrchard, MerklePath};
use zk_headstash::value::{HeadstashValue, NoteDenom};
use zk_headstash::Anchor;
/// # create headstash circuit proof from a note.
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```
///  cargo run -- --bin create_proof
/// ```
/// See <https://docs.rs/commonware_runtime> for traits/details.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Runner::default()
    //     .start(|_| async move {
    //         let a = Anchor::empty_tree();
    //         let mp =
    //             MerklePath::from_parts(0, [MerkleHashOrchard::from_bytes(&[69; 32]).unwrap(); 32]);
    //         let esk = EligibleSk::from_bytes([42u8; 32]);
    //         let recp = RecpAddr::new([42; 32]);
    //         let hv = HeadstashValue::new(100.into(), NoteDenom::new_for_proof("uterp"), 6);
    //         HeadstashSuite::new()
    //             .create_headstash_proof(a, mp, esk, recp, hv)
    //             .await
    //     })
    //     .map_err(|e| e as Box<dyn std::error::Error>)?;
    Ok(())
}
