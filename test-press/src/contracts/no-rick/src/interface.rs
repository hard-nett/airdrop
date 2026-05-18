use crate::*;
use cosmwasm_std::Empty;
use cw_orch::prelude::*;

#[cw_orch::interface(InstantiateMsg, ExecuteMsg, QueryMsg, Empty, id = "no_rick")]
pub struct NoRickContractSuite;

impl<Chain: CwEnv> Uploadable for NoRickContractSuite<Chain> {
    /// Path to the compiled wasm artifact (used with Daemon).
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        artifacts_dir_from_workspace!()
            .find_wasm_path_from_crates_label("no_rick")
            .unwrap()
    }

    /// CosmWasm contract wrapper for cw-multi-test environments.
    fn wrapper() -> Box<dyn MockContract<Empty>> {
        Box::new(ContractWrapper::new_with_empty(execute, instantiate, query))
    }
}

pub struct NoRickDeployData {}
