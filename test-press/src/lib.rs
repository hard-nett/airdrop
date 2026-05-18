//! spec: `docs/zk-headstash/suite.md`
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod circuits;
pub mod suite;
pub mod suites;
pub mod traits;
pub mod unit;

#[cfg(feature = "interface")]
pub use suite::TestPressSuite;

/// BoxError
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// get_cli_args
pub fn get_cli_args() -> Result<(String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("flag format: {} <input-file> <address>", args[0]);
        std::process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone()))
}
