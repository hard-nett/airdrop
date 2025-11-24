use cosmwasm_schema::{QueryResponses, cw_serde};
use cosmwasm_std::{Binary, Coin};

use crate::wavs::WavsObject;

#[cw_serde]
pub struct HeadstashObject {
    // genesis distribution merkle tree root.
    pub nullifier: Binary,
    // public address token are sent to
    pub recipient: String,
    // amount of funds to send
    pub amount: Coin,
}

#[cw_serde]
pub struct InstantiateMsg {
    /// genesis distribution merkle tree root.
    pub genesis_root: Binary,
    /// object containing data that validates initial wavs opreator paramters.
    pub wavs: WavsObject,
}

#[cw_serde]
pub enum ExecuteMsg {
    RotateKey { keys: Vec<String> },
    ProcessHeadstash { claims: Vec<HeadstashObject> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(bool)]
    Nullifer { null: String },
    #[returns(Vec<String>)]
    Nullifiers {
        start_after: Option<String>,
        limit: Option<u32>,
    },
}
