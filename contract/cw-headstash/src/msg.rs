use super::*;

#[cw_serde]
pub struct InstantiateMsg {
    pub genesis_root: Binary,
    pub token_strategy: TokenStrategy,
    pub wavs: WavsProofOfOwnership,
}

#[cfg_attr(feature = "interface", derive(cw_orch::ExecuteFns))]
#[cw_serde]
pub enum ExecuteMsg {
    // RotateKey { keys: Vec<String> },
    ProcessHeadstash {
        claims: Vec<HeadstashNote>,
    },
    LoadVk {
        vk: Binary,
    },
    Mint {
        to_address: String,
        amount: Uint128,
    },
    Burn {
        from_address: String,
        amount: Uint128,
    },
}

#[cfg_attr(feature = "interface", derive(cw_orch::QueryFns))]
#[cw_ownable::cw_ownable_query]
#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// check if a nullifier exists
    #[returns(bool)]
    Nullifer { null: String },
    /// Retrieve all nullifiers
    #[returns(Vec<String>)]
    Nullifiers {
        start_after: Option<String>,
        limit: Option<u32>,
    },
}
