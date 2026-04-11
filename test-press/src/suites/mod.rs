/// One `TerpVmSuite` implementation per ZK test circuit.
#[cfg(feature = "interface")]
pub mod no_rick;

/// Unified suite composing both CosmWasm contracts and all circuit suites.
#[cfg(feature = "interface")]
pub mod headstash;
#[cfg(feature = "interface")]
pub use headstash::HeadstashSuite;
