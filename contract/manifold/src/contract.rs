use cosmwasm_std::{
    Addr, Binary, CosmosMsg, Deps, DepsMut, Env, Event, MessageInfo, Reply, Response, StdResult,
    SubMsg, WasmMsg, entry_point, to_json_binary,
};
use cw_ownable::initialize_owner;
use cw_storage_plus::Bound;

use crate::error::{ContractError, ContractResult};
use crate::msg::{
    ExecuteMsg, FundingInfo, FundingToken, HeadstashContract, InstantiateMsg, QueryMsg,
};
use crate::state::{HEADSTASH_CODE_ID, contracts};
use cw_headstash::msg::InstantiateMsg as HeadstashInstantiateMsg;

// Temporary storage for instantiation data during reply
pub const PENDING_INSTANTIATION: cw_storage_plus::Item<PendingInstantiation> =
    cw_storage_plus::Item::new("pending_instantiation");

#[cosmwasm_schema::cw_serde]
pub struct PendingInstantiation {
    pub instantiator: Addr,
    pub genesis_root: Binary,
    pub funding: Option<FundingInfo>,
}

const INSTANTIATE_HEADSTASH_REPLY_ID: u64 = 1;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> ContractResult<Response> {
    let owner = msg
        .owner
        .as_deref()
        .map_or(Ok(info.sender.clone()), |o| deps.api.addr_validate(o))?;

    initialize_owner(deps.storage, deps.api, Some(&owner.to_string()))?;
    HEADSTASH_CODE_ID.save(deps.storage, &msg.headstash_code_id)?;

    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("owner", owner)
        .add_attribute("headstash_code_id", msg.headstash_code_id.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> ContractResult<Response> {
    match msg {
        ExecuteMsg::UpdateOwnership(action) => {
            cw_ownable::update_ownership(deps, &env.block, &info.sender, action)?;
            Ok(Response::new())
        }
        ExecuteMsg::CreateHeadstash {
            instantiate_msg,
            label,
            funding,
        } => execute_create_headstash(deps, env, info, instantiate_msg, label, funding),
    }
}

fn execute_create_headstash(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    instantiate_msg: HeadstashInstantiateMsg,
    label: Option<String>,
    funding: Option<FundingInfo>,
) -> ContractResult<Response> {
    // Check that only the owner can create headstash contracts
    cw_ownable::assert_owner(deps.storage, &info.sender)?;

    // Validate funding if provided
    if let Some(ref funding_info) = funding {
        validate_funding(&deps, &info, funding_info)?;
    }

    let code_id = HEADSTASH_CODE_ID.load(deps.storage)?;

    // Store pending instantiation data for the reply handler
    let pending = PendingInstantiation {
        instantiator: info.sender.clone(),
        genesis_root: instantiate_msg.genesis_root.clone(),
        funding: funding.clone(),
    };
    PENDING_INSTANTIATION.save(deps.storage, &pending)?;

    let label = label.unwrap_or_else(|| format!("headstash-{}", info.sender));

    let instantiate = WasmMsg::Instantiate {
        admin: Some(info.sender.to_string()),
        code_id,
        msg: to_json_binary(&instantiate_msg)?,
        funds: vec![], // Funding handled separately
        label,
    };

    let msg = SubMsg::reply_on_success(instantiate, INSTANTIATE_HEADSTASH_REPLY_ID);

    let event = Event::new("create_headstash")
        .add_attribute("instantiator", info.sender.to_string())
        .add_attribute("funding", funding.is_some().to_string());

    Ok(Response::new()
        .add_submessage(msg)
        .add_event(event)
        .add_attribute("action", "create_headstash"))
}

fn validate_funding(
    deps: &DepsMut,
    info: &MessageInfo,
    funding: &FundingInfo,
) -> ContractResult<()> {
    match &funding.token {
        FundingToken::Native { denom } => {
            let coin = info
                .funds
                .iter()
                .find(|c| c.denom == *denom && c.amount >= funding.amount.into())
                .ok_or(ContractError::InvalidFundingToken {})?;
            if coin.amount < funding.amount.into() {
                return Err(ContractError::InvalidFundingToken {});
            }
        }
        FundingToken::Cw20 { contract_addr } => {
            let _contract = deps.api.addr_validate(contract_addr)?;
            // CW20 funding validation would be handled in the headstash contract
        }
    }
    Ok(())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _msg: crate::msg::MigrateMsg,
    _info: cosmwasm_std::MigrateInfo,
) -> ContractResult<Response> {
    Ok(Response::new().add_attribute("action", "migrate"))
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, Binary};

    use crate::contract::instantiate;
    use crate::msg::InstantiateMsg;

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&Addr::unchecked("creator"), &[]);

        let msg = InstantiateMsg {
            owner: Some("creator".to_string()),
            headstash_code_id: 1,
        };

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 0); // No messages on instantiate
        assert_eq!(res.attributes.len(), 2); // owner and code_id attributes
    }
}

fn handle_instantiate_reply(deps: DepsMut, msg: Reply) -> ContractResult<Response> {
    // In CosmWasm v3, we extract the contract address from the reply result
    let response = msg
        .result
        .into_result()
        .map_err(|_| ContractError::InstantiationFailed {})?;
    let contract_addr_str = response
        .events
        .iter()
        .find(|e| e.ty == "instantiate")
        .and_then(|e| e.attributes.iter().find(|a| a.key == "_contract_address"))
        .map(|a| a.value.clone())
        .ok_or(ContractError::InstantiationFailed {})?;
    let contract_addr = deps.api.addr_validate(&contract_addr_str)?;

    // Load the pending instantiation data
    let pending = PENDING_INSTANTIATION.load(deps.storage)?;

    let contract = HeadstashContract {
        address: contract_addr.clone(),
        instantiator: pending.instantiator,
        genesis_root: pending.genesis_root,
        funding: pending.funding,
    };

    contracts().save(deps.storage, &contract_addr, &contract)?;

    // Clean up pending data
    PENDING_INSTANTIATION.remove(deps.storage);

    Ok(Response::new()
        .add_attribute("action", "register_headstash")
        .add_attribute("contract_address", contract_addr))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Ownership {} => to_json_binary(&cw_ownable::get_ownership(deps.storage)?),
        QueryMsg::ContractsByInstantiator {
            instantiator,
            start_after,
            limit,
        } => query_contracts_by_instantiator(deps, instantiator, start_after, limit),

        QueryMsg::Contract { address } => query_contract(deps, address),
    }
}

fn query_contracts_by_instantiator(
    deps: Deps,
    instantiator: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Binary> {
    let instantiator_addr = deps.api.addr_validate(&instantiator)?;
    let start = start_after
        .map(|s| deps.api.addr_validate(&s))
        .transpose()?
        .map(Bound::exclusive);

    let contracts_list = contracts()
        .idx
        .instantiator
        .prefix(instantiator_addr)
        .range(deps.storage, start, None, cosmwasm_std::Order::Ascending)
        .take(limit.unwrap_or(30) as usize)
        .map(|item| item.map(|(_, contract)| contract))
        .collect::<StdResult<Vec<_>>>()?;

    to_json_binary(&contracts_list)
}

fn query_contract(deps: Deps, address: String) -> StdResult<Binary> {
    let addr = deps.api.addr_validate(&address)?;
    let contract = contracts().load(deps.storage, &addr)?;
    to_json_binary(&contract)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, msg: Reply) -> ContractResult<Response> {
    match msg.id {
        INSTANTIATE_HEADSTASH_REPLY_ID => handle_instantiate_reply(deps, msg),
        _ => Err(ContractError::UnknownReplyId { id: msg.id }),
    }
}
