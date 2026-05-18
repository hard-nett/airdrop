use crate::tokenfactory::TokenStrategy;

use super::*;
use cosmwasm_std::{CanonicalAddr, Uint128};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use zk_headstash::address::RecpAddr;
use zk_headstash::note::{ExtractedNoteCommitment, Nullifier};
use zk_headstash::value::{NoteDenom, NoteValue};

use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor};

use zk_headstash::circuit::{Instance, VerifyingKey};
use zk_headstash::{Anchor, Proof};

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCfg {
    // cid: circuit-id of stored circuit in vm
    pub cid: u64,
    // gr: genesis tree root
    pub gr: Binary,
    // ts: token strategies
    pub ts: Vec<TokenStrategy>,
    // w: wavs operator set
    pub w: WavsOperatorSet,
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashNote {
    // i: instances
    pub i: HeadstashInstances,
    // p: proof
    pub p: Binary,
    // r: raw recipient of headstash. CanonicalAddr
    pub rr: Binary,
}

impl HeadstashNote {
    // verifies a nullifier does not exist in the map, and will save to map if it does not
    fn verify_recp_posiedon_hash(&self) -> Result<(), StdError> {
        match pallas::Base::from_repr(self.rr.as_slice().try_into()?)
            .expect("proof has been verified")
            == RecpAddr::try_from(self.i.recp.as_slice())?.to_fp()
        {
            true => Ok(()),
            false => Err(StdError::msg("recipient addr not represented in proof ")),
        }
    }
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashInstances {
    pub anchor: Binary,
    pub nd: Binary,
    pub v: u64,
    pub nf: Binary,
    pub recp: Binary,
    pub cmx: Binary,
}

/// Implement CosmWasm Instance as a Halo2 Circuit Instance Struct
impl Into<Instance> for HeadstashInstances {
    fn into(self) -> Instance {
        Instance::from_parts(
            Anchor::from_bytes(
                self.anchor
                    .as_slice()
                    .try_into()
                    .expect("Invalid anchor bytes"),
            )
            .expect("bad anchor"),
            NoteDenom::from(self.nd.to_array().expect("nd bytes")),
            NoteValue::from(self.v),
            RecpAddr::try_from(self.recp.as_slice()).expect("recp bytes"),
            Nullifier::from_bytes(
                self.nf
                    .as_slice()
                    .try_into()
                    .expect("Invalid nullifier bytes"),
            )
            .expect("darn"),
            ExtractedNoteCommitment::from_bytes(&self.cmx.to_array().expect("cmx bytes"))
                .expect("ExtractedNoteCommitment"),
        )
    }
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCoin {
    /// v: value
    pub v: u64,
    /// nd: token denom in circuit pre-input specification
    pub nd: Binary,
}

/// Validates nullifiers uniqueness & distribute funds
pub fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashNote>,
) -> Result<Response, StdError> {
    let cfg = HEADSTASH_CFG.load(deps.storage)?;
    let mut n = HashSet::new();
    let mut cts = HashMap::new();

    for claim in &claims {
        // verify no nullifier duplicates at once.
        if !n.insert(claim.i.nf.clone()) {
            return Err(StdError::msg(format!("null: {}", &claim.i.nf.to_hex())));
        }
        // verify nullifier is new. adds nullifier to map if so
        verify_nullifier_stateful(deps.storage, claim.i.nf.to_hex())?;

        // verify denom is supported for this token strategy
        if !cfg
            .ts
            .iter()
            .any(|e| &e.proof_representation() == &claim.i.nd)
        {
            return Err(StdError::msg("incorrect token denom"));
        }

        // verify headstash proof
        deps.api.halo2_proof_instance_verify(
            cfg.cid.into(),
            &claim.p.to_vec(),
            &<HeadstashInstances as Into<Instance>>::into(claim.i.clone()).to_bytes(),
        )?;

        // verify recp integrity
        claim.verify_recp_posiedon_hash()?;

        // increment allcoation going to user if multiple proofs are being claimed
        *cts.entry((claim.i.nd.clone(), claim.rr.clone()))
            .or_insert(claim.i.v) += claim.i.v;
    }

    let mut res: Response = Response::new();

    // TODO(hard-nett): implement multi-token support
    for t in cfg.ts {
        let td = t.denom(&env.contract.address);

        let mut denom_entries: Vec<_> = cts
            .iter()
            .filter(|((_, d), _)| d == &t.proof_representation())
            .map(|(k, &v)| (k.clone(), v))
            .collect();

        match t {
            TokenStrategy::NewFungible(d) => {
                // TODO: Implement token minting using cw_tokenfactory_types
                // Mint one message per recipient (batched amount)
                for ((_, r), amount) in denom_entries {
                    let ra = deps.api.addr_humanize(&CanonicalAddr::from(r))?;
                    // res = res.add_message(...); // Commented out for now
                }
            }
            TokenStrategy::ExistingFungible(d) => {
                // Sum total required for this denom
                let total_required: u64 = denom_entries.iter().map(|(_, amount)| *amount).sum();
                // Escrow: check balance first
                if deps
                    .querier
                    .query_balance(&env.contract.address, td)?
                    .amount
                    < Uint128::new(total_required as u128).into()
                {
                    return Err(StdError::msg("insuffiecient balance"));
                }

                for ((_, r), amount) in denom_entries {
                    let ra = deps.api.addr_humanize(&CanonicalAddr::from(r))?;
                    res = res.add_message(BankMsg::Send {
                        to_address: ra.into(),
                        amount: vec![Coin::new(amount, &d.raw)],
                    });
                }
            }
        }
    }

    Ok(res.add_attribute("action", "process_headstash"))
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
