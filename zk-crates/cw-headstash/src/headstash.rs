use crate::tokenfactory::TokenStrategy;

use super::*;
use cosmwasm_std::{Addr, Uint128};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::Fp;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

// Groth16 proof structure (192 bytes)
#[cosmwasm_schema::cw_serde]
struct Groth16Proof {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}
impl Groth16Proof {
    pub fn validate(&self) -> bool {
        self.a.len() > 48 || self.b.len() > 96 || self.c.len() > 48
    }
}
// Verifying Key (alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1[])
#[cosmwasm_schema::cw_serde]
struct VerifyingKey {
    alpha_g1: Vec<u8>,
    beta_g2: Vec<u8>,
    gamma_g2: Vec<u8>,
    delta_g2: Vec<u8>,
    ic: Vec<u8>, // one per public input
}

impl VerifyingKey {
    pub fn validate(&self) -> bool {
        self.alpha_g1.len() > 48
            || self.beta_g2.len() > 96
            || self.gamma_g2.len() > 96
            || self.delta_g2.len() > 96
            || self.ic.len() > 48
    }
    fn from_binary(data: Binary) -> StdResult<Self> {
        let bytes = data.as_slice();
        // Format: [48|96|96|96|48*N] where N = number of public inputs
        // Minimum size: alpha_g1 (48) + beta_g2 (96) + gamma_g2 (96) + delta_g2 (96) = 336
        if bytes.len() < 336 {
            return Err(StdError::msg("Verifying key too short"));
        }

        let mut offset = 0;

        // Extract fixed-size points
        let (alpha_g1, rest) = bytes.split_at(48);
        let (beta_g2, rest) = rest.split_at(96);
        let (gamma_g2, rest) = rest.split_at(96);
        let (delta_g2, rest) = rest.split_at(96);
        let mut ic = rest;
        Ok(VerifyingKey {
            alpha_g1: alpha_g1.to_vec(),
            beta_g2: beta_g2.to_vec(),
            gamma_g2: gamma_g2.to_vec(),
            delta_g2: delta_g2.to_vec(),
            ic: ic.to_vec(),
        })
    }
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCoin {
    pub v: u64,
    pub nd: Binary,
}
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
    pub root: Binary,
    // witness proof.
    pub proof: Binary,
    // nullifer genreated client side out of circuit
    pub null: Binary,
    // public address token are sent to
    pub recp: String,
    // amount of funds to send
    pub coin: HeadstashCoin,
}

/// Validates nullifiers uniqueness & distribute funds
pub fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashNote>,
) -> Result<Response<TokenFactoryMsg>, StdError> {
    let cfg = HEADSTASH_CFG.load(deps.storage)?;

    let mut seen_nullifiers = HashSet::new();
    let mut tokens = HashMap::new();
    for claim in &claims {
        // verify no nullifier duplicates
        if !seen_nullifiers.insert(claim.null.clone()) {
            return Err(StdError::msg(format!("null: {}", hex::encode(&claim.null))));
        }
        verify_nullifier_stateful(deps.storage, claim.null.to_string())?;

        // verify denom is supported for this token strategy
        if !cfg
            .ts
            .iter()
            .any(|e| &e.proof_representation() == &claim.coin.nd)
        {
            return Err(StdError::msg("incorrect token denom"));
        }

        // verify headstash proof

        //  Deserialize proof
        let proof = {
            let mut proof_vec = claim.proof.clone();
            if proof_vec.len() != 96 {
                // typical Groth16 proof size
                return Err(StdError::msg("invalid proof length"));
            }
            proof_vec
        };

        //  Reconstruct public inputs (must match circuit order!)
        let public_inputs = vec![
            // Order MUST match your circuit's assigned public inputs
            Fp::from_repr(claim.root.to_array()?).expect("genesis root"),
            Fp::from_repr(claim.null.to_array()?).expect("note nullifier"),
            Fp::from_repr(
                claim
                    .recp
                    .as_bytes()
                    .try_into()
                    .expect("recipient represenation bytes length"),
            )
            .expect("recipient addr representation"),
            Fp::from_u128(Uint128::from_str(&claim.coin.v.to_string())?.u128()),
            Fp::from_repr(claim.coin.nd.to_array()?).expect("note-denomination representation"),
        ];

        // 5. Accumulate IC * public_input
        let mut acc = [0u8; 48];

        // 6. Final Groth16 pairing check
        // let valid = deps.api.bls12_381_pairing_equality(
        //     // e(A, B) == e(alpha, beta)
        //     &proof.a,
        //     &proof.b,
        //     &vk.alpha_g1,
        //     &vk.beta_g2,
        // )? && deps.api.bls12_381_pairing_equality(
        //     // e(C, delta) == e(acc, gamma)
        //     &proof.c,
        //     &vk.delta_g2,
        //     &acc,
        //     &vk.gamma_g2,
        // )?;

        // if !valid {
        //     return Err(StdError::generic_err("invalid proof"));
        // }

        // increment allcoation going to user if multiple proofs are being claimed
        *tokens
            .entry((claim.coin.nd.clone(), claim.recp.clone()))
            .or_insert(claim.coin.v) += claim.coin.v;
    }

    let mut response: Response<TokenFactoryMsg> = Response::new();

    for tech in cfg.ts {
        // Manifold dispatch: mint or send
        let denom = tech.denom(&env.contract.address);
        let mut denom_entries: Vec<((Binary, String), u64)> = tokens
            .iter()
            .filter(|((_, d), _)| d == &denom)
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
                let total_required: u64 = denom_entries.iter().map(|(_, amount)| *amount).sum();
                // Escrow: check balance first
                let balance = deps
                    .querier
                    .query_balance(&env.contract.address, denom)?
                    .amount;

                if balance < Uint128::new(total_required as u128).into() {
                    return Err(StdError::msg("insuffiecient balance"));
                }

                for ((_, recipient), amount) in denom_entries {
                    response = response.add_message(BankMsg::Send {
                        to_address: recipient,
                        amount: vec![Coin::new(amount, &d.raw)],
                    });
                }
            }
        }
    }
    // }

    Ok(response.add_attribute("action", "process_headstash"))
}

// verifies a nullifier does not exist in the map, and will save to map if it does not
pub fn verify_nullifier_stateless(
    storage: &dyn Storage,
    nullifier: String,
) -> Result<Option<()>, StdError> {
    NULLIFIERS.may_load(storage, nullifier)?;
    Ok(Some(()))
}

// verifies a nullifier does not exist in the map, and will save to map if it does not
pub fn verify_nullifier_stateful(
    storage: &mut dyn Storage,
    nullifier: String,
) -> Result<(), StdError> {
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
