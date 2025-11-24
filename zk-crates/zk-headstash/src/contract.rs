use std::{collections::HashMap, fmt, marker::PhantomData};

use cosmwasm_std::{
    BankMsg, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
    Storage, coins, to_json_binary,
};

use crate::{
    msg::{ExecuteMsg, HeadstashObject, InstantiateMsg, QueryMsg},
    state::{GENESIS_TREE_ROOT, HEADSTASH_PARAMS, HeadstashParams, NULLIFIERS, paginate_map},
};

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, StdError> {
    // verify inital proof of ownership of wavs operator set.
    msg.wavs.proof_of_possesion(deps.api)?;
    // set distribution merkle root
    GENESIS_TREE_ROOT.save(deps.storage, &msg.genesis_root)?;
    HEADSTASH_PARAMS.save(
        deps.storage,
        &HeadstashParams {
            wavs: deps.api.addr_validate(&msg.wavs.address)?,
            nonce: 1u64,
        },
    )?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Nullifer { null } => Ok(to_json_binary(
            &NULLIFIERS.may_load(deps.storage, null)?.is_some(),
        )?),
        QueryMsg::Nullifiers { start_after, limit } => query_nullifiers(deps, start_after, limit),
    }
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, StdError> {
    let params = HEADSTASH_PARAMS.load(deps.storage)?;
    if info.sender != params.wavs {
        return Err(StdError::generic_err("not authorized"));
    }
    match msg {
        ExecuteMsg::ProcessHeadstash { claims } => process_headstash(deps, env, claims),
        ExecuteMsg::RotateKey { keys } => todo!(),
    }
}

/// Validates nullifiers uniqueness & distribute funds
fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashObject>,
) -> Result<Response, StdError> {
    let mut tokens = HashMap::new();
    for claim in claims {
        verify_nullifier(deps.storage, claim.nullifier.to_string())?;
        tokens.insert(claim.amount.denom, (claim.amount.amount, claim.recp));
    }

    // ensure balance exists in contract
    let cosmos_msgs: Result<Vec<CosmosMsg>, StdError> = tokens
        .iter()
        .map(|(denom, (amount, recp))| {
            let balance = deps
                .querier
                .query_balance(env.contract.address.to_string(), denom)?
                .amount;

            if balance.lt(amount) {
                return Err(StdError::generic_err(
                    "insufficient balance for token: ".to_string() + denom,
                ));
            }

            let msg = BankMsg::Send {
                to_address: recp.to_string(),
                amount: coins(amount.u128(), denom),
            };

            Ok(msg.into())
        })
        .collect();

    Ok(Response::default().add_messages(cosmos_msgs?))
}

// verifies a nullifier does not exist in the map, and will save to map if it does not
fn verify_nullifier(storage: &mut dyn Storage, nullifier: String) -> Result<(), StdError> {
    NULLIFIERS.update(storage, nullifier, |n| match n {
        Some(_) => {
            return Err(StdError::generic_err("nullifier already exists"));
        }
        None => Ok(()),
    })?;
    Ok(())
}

pub fn query_nullifiers(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<Binary> {
    to_json_binary(&paginate_map(
        deps,
        &NULLIFIERS,
        start_after,
        limit,
        cosmwasm_std::Order::Descending,
    )?)
}
