use super::*;
use cosmwasm_std::Addr;
use std::collections::HashMap;

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCfg {
    pub wavs: WavsOperatorSet,
    // pub token_cfg: TokenParams,
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashNote {
    // genesis distribution merkle tree root.
    pub null: Binary,
    // public address token are sent to
    pub recp: String,
    // amount of funds to send
    pub coin: Coin,
}

pub fn rotate_key(
    deps: DepsMut,
    sender: Addr,
    env: Env,
    keys: Vec<String>,
) -> Result<Response, StdError> {
    let params = HEADSTASH_CFG.load(deps.storage)?;
    if sender.to_string() != params.wavs.address {
        return Err(StdError::msg("not authorized"));
    }
    Ok(Response::default())
}

/// Validates nullifiers uniqueness & distribute funds
pub fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashNote>,
) -> Result<Response, StdError> {
    let mut tokens = HashMap::new();
    for claim in claims {
        verify_nullifier(deps.storage, claim.null.to_string())?;
        tokens.insert(claim.coin.denom, (claim.coin.amount, claim.recp));
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
                return Err(StdError::msg(
                    "insufficient balance for token: ".to_string() + denom,
                ));
            }

            let msg = BankMsg::Send {
                to_address: recp.to_string(),
                amount: vec![Coin::new(*amount, denom)],
            };

            Ok(msg.into())
        })
        .collect();

    Ok(Response::default().add_messages(cosmos_msgs?))
}

// verifies a nullifier does not exist in the map, and will save to map if it does not
pub fn verify_nullifier(storage: &mut dyn Storage, nullifier: String) -> Result<(), StdError> {
    NULLIFIERS.update(storage, nullifier, |n| match n {
        Some(_) => {
            return Err(StdError::msg("nullifier already exists"));
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
    to_json_binary(&crate::paginate_map(
        deps,
        &NULLIFIERS,
        start_after,
        limit,
        cosmwasm_std::Order::Descending,
    )?)
}
