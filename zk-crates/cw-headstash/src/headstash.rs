use crate::tokenfactory::TokenStrategy;

use super::*;
use cosmwasm_std::{Addr, Uint256};
use std::collections::HashMap;

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCfg {
    pub gr: Binary,
    pub ts: Vec<TokenStrategy>,
    pub w: WavsOperatorSet,
    // pub created_at: u64,
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

/// Allows key rotation
pub fn rotate_key(
    deps: DepsMut,
    sender: Addr,
    env: Env,
    keys: Vec<String>,
) -> Result<Response<TokenFactoryMsg>, StdError> {
    let params = HEADSTASH_CFG.load(deps.storage)?;
    if sender.to_string() != params.w.c {
        return Err(StdError::msg("not authorized"));
    }
    Ok(Response::default())
}

/// Validates nullifiers uniqueness & distribute funds
pub fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashNote>,
) -> Result<Response<TokenFactoryMsg>, StdError> {
    let cfg = HEADSTASH_CFG.load(deps.storage)?;

    let mut tokens = HashMap::new();
    // Aggregate amount per (denom, recipient)
    for claim in &claims {
        let denom = &claim.coin.denom;
        // verify denom is supported for this token strategy
        if !cfg
            .ts
            .iter()
            .any(|e| &e.denom(&env.contract.address) == denom)
        {
            return Err(StdError::msg("incorrect token denom"));
        }
        // verify headstash proof

        // verify nullifier does note exist in headstash instance
        verify_nullifier(deps.storage, claim.null.to_string())?;
        // increment allcoation going to user if multiple proofs are being claimed
        *tokens
            .entry((claim.coin.denom.clone(), claim.recp.clone()))
            .or_insert(claim.coin.amount) += claim.coin.amount;
    }

    let mut response: Response<TokenFactoryMsg> = Response::new();

    for tech in cfg.ts {
        // Manifold dispatch: mint or send
        let denom = tech.denom(&env.contract.address);
        let mut denom_entries: Vec<((String, String), Uint256)> = tokens
            .iter()
            .filter(|((d, _), _)| d == &denom)
            .map(|(k, &v)| (k.clone(), v))
            .collect();
        match tech {
            TokenStrategy::NewFungible(d) => {
                // Mint one message per recipient (batched amount)
                for ((_, recipient), amount) in denom_entries {
                    response = response.add_message(TokenFactoryMsg::MintTokens {
                        denom: denom.to_string(),
                        amount: amount.try_into().unwrap(),
                        mint_to_address: recipient,
                    });
                }
            }
            TokenStrategy::ExistingFungible(d) => {
                // Sum total required for this denom
                let total_required: Uint256 = denom_entries.iter().map(|(_, amount)| *amount).sum();
                // Escrow: check balance first
                let balance = deps
                    .querier
                    .query_balance(&env.contract.address, denom)?
                    .amount;

                if balance < total_required {
                    return Err(StdError::msg("insuffiecient balance"));
                }

                for ((_, recipient), amount) in denom_entries {
                    response = response.add_message(BankMsg::Send {
                        to_address: recipient,
                        amount: vec![Coin::new(amount, &d)],
                    });
                }
            }
        }
    }
    // }

    Ok(response.add_attribute("action", "process_headstash"))
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
