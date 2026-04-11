//! spec: `docs/zk-headstash/suite.md`
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod circuits;
pub mod suite;
pub mod suites;
pub mod unit;

#[cfg(feature = "interface")]
pub use suite::TestPressSuite;
#[cfg(feature = "interface")]
pub use suites::{
    headstash::{HeadstashDeployData, HeadstashSuite, ZkDeployError},
    no_rick::NoRickSuite,
};
