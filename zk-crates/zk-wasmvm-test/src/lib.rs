use cosmwasm_schema::{QueryResponses, cw_serde};
use cosmwasm_std::Checksum;
use cosmwasm_std::StdError;
use cosmwasm_std::VerificationError;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, to_json_binary};
use cw_storage_plus::Item;
use cw2::set_contract_version;
use thiserror::Error;

#[cw_serde]
pub struct Config {
    /// words we are prooving a privte instance does not contain
    pub words: Vec<String>,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const MOCK_DATA: Item<Vec<u8>> = Item::new("mock_data");

const CONTRACT_NAME: &str = "crates.io:cw-cadence";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cw_serde]
pub struct InstantiateMsg {
    words: Vec<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    Proove { word_id: usize, proof: Vec<u8> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Checksum)]
    VkChecksum {},
    #[returns(Vec<String>)]
    WordList {},
}

#[derive(Error, Debug)]
pub enum Never {}


#[cw_serde]
pub enum SudoMsg {}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    VerificationError(#[from] VerificationError),
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    CONFIG.save(deps.storage, &Config { words: msg.words })?;

    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let c = CONFIG.load(deps.storage)?;
    match msg {
        ExecuteMsg::Proove { word_id, proof } => {
            let instance = c.words[word_id].as_bytes();
            deps.api.halo2_proof_instance_verify(&proof, instance)?;
        }
    }

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VkChecksum {} => unimplemented!(),
        QueryMsg::WordList {} => to_json_binary(&CONFIG.load(deps.storage)?.words),
    }
}

// sudo msg
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, _env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

// #[test]
// fn test_gas_consumption() -> StdResult<()> {
//     #![cfg(not(target_arch = "wasm32"))]
//     let mut deps = cosmwasm_std::testing::mock_dependencies();
//     MOCK_DATA.save(&mut deps.storage, &vec![])?;
//     CONFIG.save(&mut deps.storage, &Config { val: 2 })?;

//     increment(deps.as_mut())?;

//     let data = MOCK_DATA.load(&deps.storage)?;
//     let byte_count = data.len();

//     println!("Byte count: {}", byte_count);

//     Ok(())
// }
