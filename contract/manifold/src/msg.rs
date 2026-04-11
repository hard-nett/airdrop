use cosmwasm_schema::{QueryResponses, cw_serde};
use cosmwasm_std::{Addr, Binary, Uint128, Uint256};
use cw_headstash::msg::InstantiateMsg as HeadstashInstantiateMsg;

#[cw_serde]
pub struct InstantiateMsg {
    pub owner: Option<String>,
    pub headstash_code_id: u64,
}

#[cfg_attr(feature = "interface", derive(cw_orch::ExecuteFns))]
#[cw_serde]
pub enum ExecuteMsg {
    UpdateOwnership(cw_ownable::Action),
    CreateHeadstash {
        instantiate_msg: HeadstashInstantiateMsg,
        label: Option<String>,
        funding: Option<FundingInfo>,
    },
}

#[cw_serde]
pub struct FundingInfo {
    pub amount: Uint256,
    pub token: FundingToken,
}

#[cw_serde]
pub enum FundingToken {
    Native { denom: String },
    Cw20 { contract_addr: String },
}

#[cfg_attr(feature = "interface", derive(cw_orch::QueryFns))]
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(cw_ownable::Ownership<Addr>)]
    Ownership {},

    #[returns(Vec<HeadstashContract>)]
    ContractsByInstantiator {
        instantiator: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },

    #[returns(HeadstashContract)]
    Contract { address: String },
}

#[cw_serde]
pub struct HeadstashContract {
    pub address: Addr,
    pub instantiator: Addr,
    pub genesis_root: Binary,
    pub funding: Option<FundingInfo>,
}

#[cw_serde]
pub struct MigrateMsg {}
