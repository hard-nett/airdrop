use zk_headstash::circuit::Circuit;

/// # create headstash circuit proof from a note.
/// - generates default Headstash [VerifyingKey] and [ProvingKey]
/// ```
///  cargo run -- --bin create_proof
/// ```
/// See <https://docs.rs/commonware_runtime> for traits/details.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Circuit::default();
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
