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

impl<Chain: CwEnv> Deploy<Chain> for NoRickContractSuite<Chain> {
    type Error = CwOrchError;
    type DeployData = NoRickDeployData;

    fn store_on(_chain: Chain) -> Result<Self, Self::Error> {
        todo!()
    }

    fn get_contracts_mut(&mut self) -> Vec<Box<&mut dyn ContractInstance<Chain>>> {
        todo!()
    }

    fn load_from(_chain: Chain) -> Result<Self, Self::Error> {
        todo!()
    }
}
#[derive(Clone, Debug)]
pub struct NoRickDeployData {}
