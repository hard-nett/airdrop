/// One `TerpVmSuite` implementation per ZK test circuit.
#[cfg(feature = "interface")]
pub mod no_rick;

/// Unified suite composing both CosmWasm contracts and all circuit suites.
#[cfg(feature = "interface")]
pub mod headstash;

mod interface {

    #[cw_orch::circuit_interface(id = "headstash")]
    pub struct HeadstashCircuitSuite;
    
    #[cw_orch::circuit_interface(id = "no_rick")]
    pub struct NoRickCircuitSuite;
}
