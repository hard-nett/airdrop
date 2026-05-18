//! main DeployData implementations for suites in test
#[cfg(feature = "interface")]
use crate::suites::headstash::HeadstashDeployData;
use cw_no_rick::interface::NoRickDeployData;
#[cfg(feature = "multicore")]
use rayon::prelude::*;

use cosmwasm_std::Addr;
use cw_orch::environment::{CwEnv, ZkCwEnv};

#[derive(Debug, thiserror::Error)]
pub enum ZkDeployError {
    #[error("cw-orch error: {0}")]
    CwEnv(#[from] cw_orch::prelude::CwOrchError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("deploy error: {0}")]
    Other(String),
}

/// Deploy configuration for the ZK headstash system.
pub struct TestPressDeployData {
    pub no_rick: NoRickDeployData,
    pub headstash: HeadstashDeployData,
}

impl TestPressDeployData {
    pub fn local_default(admin: Addr, genesis_root: &[u8], keys_dir: std::path::PathBuf) -> Self {
        Self {
            no_rick: NoRickDeployData {},
            headstash: HeadstashDeployData::local_default(admin, genesis_root )
                .expect("oooooohhh"),
        }
    }
}
// ── TestPressSuite ────────────────────────────────────────────────────────────

/// Composed suite of **all** test-press circuit suites.
///
/// Retains every method from the headstash helpers (via the same trait blanket
/// impls) and adds one `TerpVmSuite`-compatible field per test circuit.
///
/// # Feature gating
/// The circuit-suite fields (`no_rick`, …) are only present when the
/// `interface` feature is enabled (pulls in ict-rs).  The struct is still
/// usable without that feature — it is then just a zero-sized wrapper that
/// provides all the `HeadstashBitwiseInstance` / tree / IPFS / launchpad
/// helpers.
///
/// # Layout (keys dir)
/// ```text
/// <keys_base>/
///   no_rick/
///     params.bin
///     proving_key.bin
///     verifying_key.bin
/// ```
pub struct TestPressSuite<Chain: ZkCwEnv> {
    /// No-Rick circuit: key management, prove, verify, on-chain deploy.
    #[cfg(feature = "interface")]
    pub no_rick: crate::suites::no_rick::NoRickSuite<Chain>,
    /// Headstash Orchard circuit: production spend-proof circuit.
    #[cfg(feature = "interface")]
    pub headstash: crate::suites::headstash::HeadstashSuite<Chain>,
    // sinsemilla merkle tree
    // zk-hashmerchant (proove know mirrored tree root path )
    // plonky3
    // groth16
    // cario
    // zk-tls
}

/// TerpHeadstashConfig
#[derive(Debug)]
pub struct TerpHeadstashConfig {}

// // All stateless circuit-utility traits are delegated with default impls.
// impl<Chain: CwEnv> HeadstashBitwiseInstance for TestPressSuite<Chain> {}
// impl<Chain: CwEnv> HeadstashSinsemillaTree for TestPressSuite<Chain> {}
// impl<Chain: CwEnv> HeadstashIpfsInstance for TestPressSuite<Chain> {}
// impl<Chain: CwEnv> HeadstashLaunchpadInstance for TestPressSuite<Chain> {}
