pub mod headstash;
pub mod smartaccount;
pub mod tokenfactory;
pub mod wavs;

use crate::{
    headstash::*,
    // tokenfactory::{FactoryStrategy, TokenParams, create_denom_msg, mint_tokens_msg},
    wavs::{WavsOperatorSet, WavsOpsAuthMsg},
};

use cosmwasm_schema::{QueryResponses, cw_serde};
use cosmwasm_std::{
    Addr, AnyMsg, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Order,
    Response, StdError, StdResult, Storage, from_json, to_json_binary,
};
use serde::{Deserialize, Serialize};
use token_bindings::TokenFactoryMsg;

pub const WAVS_OPERATORS: Map<u64, Vec<String>> = Map::new("wavs_operators");
pub const HEADSTASH_CFG: Item<HeadstashCfg> = Item::new("headstash_params");
pub(crate) const GENESIS_TREE_ROOT: Item<Binary> = Item::new("root_gen_tree");
pub(crate) const COMMITMENT_TREE_ROOT: Item<Binary> = Item::new("root_cm_tree");
pub(crate) const NULLIFIERS: Map<String, ()> = Map::new("nullifiers");

use cosmwasm_schema::serde;
use cw_storage_plus::{Bound, Bounder, Item, KeyDeserialize, Map};

#[cw_serde]
pub struct InstantiateMsg {
    /// genesis distribution merkle tree root.
    pub sinsemilla_hash_root: Binary,
    /// headstash distribution params
    // pub tokenfactory: TokenParams,
    /// operator set key params
    pub wavs: WavsParams,
}

#[cw_serde]
pub struct WavsParams {
    pub keys: Vec<wavs::OperatorAuth>,
    pub msg: WavsOpsAuthMsg,
}

#[cw_serde]
pub enum ExecuteMsg {
    RotateKey { keys: Vec<String> },
    ProcessHeadstash { claims: Vec<HeadstashNote> },
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwHeadstashStructs {}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwHeadstash {}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, StdError> {
    let keys = &msg.wavs.keys;
    if keys.len() != msg.wavs.msg.total_operators {
        return Err(StdError::msg("incorrect operator key config"));
    }
    let response = Response::default();
    // let response = init_token_strategy(
    //     deps.as_ref(),
    //     &info.sender,
    //     &env.contract.address,
    //     &msg.tokenfactory,
    // )?;

    // register singleton contract as authenticator for itself
    let msg_auth = btsg_auth::MsgAddAuthenticator {
        sender: env.contract.address.to_string(),
        authenticator_type: "CosmwasmAuthenticatorV1".into(),
        data: to_json_binary(&btsg_auth::CosmwasmAuthenticatorInitData {
            contract: env.contract.address.to_string(),
            params: to_json_binary(&WavsOperatorSet {
                address: env.contract.address.to_string(),
                keys: keys.to_vec(),
                msg: msg.wavs.msg,
            })?
            .to_vec(),
        })?
        .to_vec(),
    };

    // Sinsemilla HashDomain Merkle Tree Root
    GENESIS_TREE_ROOT.save(deps.storage, &msg.sinsemilla_hash_root)?;
    Ok(response.add_message(AnyMsg {
        type_url: "/terp.smartaccount.v1beta1.MsgAddAuthenticator".to_owned(),
        value: to_json_binary(&msg_auth)?,
    }))
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    // TODO: allowlist for writing to nullifier tree
    match msg {
        ExecuteMsg::ProcessHeadstash { claims } => {
            crate::headstash::process_headstash(deps, env, claims)
        }
        ExecuteMsg::RotateKey { keys } => {
            crate::headstash::rotate_key(deps, info.sender, env, keys)
        }
    }
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Nullifer { null } => Ok(to_json_binary(
            &NULLIFIERS.may_load(deps.storage, null)?.is_some(),
        )?),
        QueryMsg::Nullifiers { start_after, limit } => {
            headstash::query_nullifiers(deps, start_after, limit)
        }
    }
}

impl btsg_account::traits::default::BtsgAccountTrait for CwHeadstash {
    type InstantiateMsg = InstantiateMsg;
    type ExecuteMsg = ExecuteMsg;
    type QueryMsg = QueryMsg;
    type SudoMsg = btsg_auth::AuthSudoMsg;
    type ContractError = StdError;
    type AuthMethodStructs = Binary;
    type AuthProcessResult = Result<Response, Self::ContractError>;

    fn process_sudo_auth(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &Self::SudoMsg,
    ) -> Self::AuthProcessResult {
        match req {
            btsg_auth::AuthSudoMsg::OnAuthAdded(req) => Self::on_auth_added(deps, env, req),
            btsg_auth::AuthSudoMsg::OnAuthRemoved(req) => Self::on_auth_removed(deps, env, req),
            btsg_auth::AuthSudoMsg::Authenticate(req) => Self::on_auth_request(deps, env, req),
            btsg_auth::AuthSudoMsg::Track(req) => Self::on_auth_track(deps, env, req),
            btsg_auth::AuthSudoMsg::ConfirmExecution(req) => Self::on_auth_confirm(deps, env, req),
        }
    }

    fn extended_authenticate(
        deps: cosmwasm_std::DepsMut,
        auth: Self::AuthMethodStructs,
    ) -> Self::AuthProcessResult {
        // allow wavs aservie to also broadcast batched proof claims during this step 
        todo!()
    }

    /// 1. verify aggregated key-set registration (via aggregated G1,G2)
    /// 2. verify proof-of-possession for each key
    fn on_auth_added(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &btsg_auth::OnAuthenticatorAddedRequest,
    ) -> Self::AuthProcessResult {
        let auth = &req.authenticator_params;
        // assert threshold key ownership proofs
        let wavs: WavsOperatorSet =
            match from_json(auth.clone().expect("headstash aggregation keys required")) {
                Ok(w) => w,
                Err(e) => return Err(e),
            };
        wavs.proof_of_possesion(deps.api)?;
        // initialize token specific parameters
        // store params to state
        todo!()
    }

    fn on_auth_removed(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &btsg_auth::OnAuthenticatorRemovedRequest,
    ) -> Self::AuthProcessResult {
        // remove params from state
        todo!()
    }

    fn on_auth_request(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &Box<btsg_auth::AuthenticationRequest>,
    ) -> Self::AuthProcessResult {
        // verify aggregated-signature: deps.api.bls12_381_pairing_equality(ps, qs, r, s)
        todo!()
    }

    fn on_auth_track(
        _deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &btsg_auth::TrackRequest,
    ) -> Self::AuthProcessResult {
        // noop
        Ok(Response::default())
    }

    fn on_auth_confirm(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &btsg_auth::ConfirmExecutionRequest,
    ) -> Self::AuthProcessResult {
        // verifies circuit proofs, reverts any stateful change if errors.
        Self::extended_authenticate(
            deps,
            req.authenticator_params.clone().expect("cw-auth params"),
        )
    }

    fn on_hooks(deps: cosmwasm_std::DepsMut, env: cosmwasm_std::Env) -> Self::AuthProcessResult {
        todo!()
    }
}

/// Map nonce -> indexList of wav operator bls12-381
/// we want to be able to query:
/// - the list of operators given an array of their positions in the index
/// - the list of operators at a given nonce
/// Stores: nonce -> list of operator indices (e.g., positions in validator set)

// -  merkle tree must be fixed length, meaning once buffer is full from specific tree,
// - we must create new one and be able to have users reference the head/where existing is to prevent expensive use

/// Generic function for paginating a list of (K, V) pairs in a
/// CosmWasm Map.
pub fn paginate_map<'a, 'b, K, V, R: 'static>(
    deps: Deps,
    map: &Map<K, V>,
    start_after: Option<K>,
    limit: Option<u32>,
    order: Order,
) -> StdResult<Vec<(R, V)>>
where
    K: Bounder<'a> + KeyDeserialize<Output = R> + 'b,
    V: serde::de::DeserializeOwned + serde::Serialize,
{
    let (range_min, range_max) = match order {
        Order::Ascending => (start_after.map(Bound::exclusive), None),
        Order::Descending => (None, start_after.map(Bound::exclusive)),
    };

    let items = map.range(deps.storage, range_min, range_max, order);
    match limit {
        Some(limit) => Ok(items
            .take(limit.try_into().unwrap())
            .collect::<StdResult<_>>()?),
        None => Ok(items.collect::<StdResult<_>>()?),
    }
}
