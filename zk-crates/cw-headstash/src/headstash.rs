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
use std::str::FromStr;
use zk_headstash::circuit::{Instance, VerifyingKey};
use zk_headstash::{Anchor, Proof};

/// lazily load the dedicated headstash circuit key to smart contract params
pub static VK: LazyLock<VerifyingKey> = LazyLock::new(|| {
    VerifyingKey::load_cosmwasm(include_bytes!("../../../data/keys/proving_key.bin"))
});

// Helper function to skip VK bytes (reads through VK without storing)
fn skip_vk_bytes<R: io::Read>(reader: &mut R) -> io::Result<()> {
    // Version byte
    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;

    // Fixed commitments
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let fixed_commitments_len = u32::from_le_bytes(len_bytes) as usize;
    for _ in 0..fixed_commitments_len {
        let mut commitment_bytes = [0u8; 64]; // Adjust based on your curve
        reader.read_exact(&mut commitment_bytes)?;
    }

    // Skip permutation bytes (implement based on permutation::VerifyingKey::write)
    // ...

    // Skip selectors
    reader.read_exact(&mut len_bytes)?;
    let selectors_len = u32::from_le_bytes(len_bytes) as usize;
    // Skip the actual selector bytes...

    Ok(())
}

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCfg {
    // gr: genesis tree root hash
    pub gr: Binary,
    // ts: token strategies
    pub ts: Vec<TokenStrategy>,
    // w: wavs operator set
    pub w: WavsOperatorSet,
    // pub created_at: u64,
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
            == RecpAddr::try_from(self.i.recp.as_slice())?.to_pallas()
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
            NoteDenom::from(self.nd),
            NoteValue::from(self.v),
            RecpAddr::from(self.recp),
            Nullifier::from_bytes(
                self.nf
                    .as_slice()
                    .try_into()
                    .expect("Invalid nullifier bytes"),
            )
            .expect("darn"),
            ExtractedNoteCommitment::from(self.cmx),
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
pub fn set_verifying_key(
    deps: DepsMut,
    env: Env,
    vk: Binary,
) -> Result<Response<TokenFactoryMsg>, StdError> {
    // ensure sender is this contract owner (or this contract)
    // hash & save vk

    let mut r: Response<TokenFactoryMsg> = Response::new();
    Ok(r)
}
/// Validates nullifiers uniqueness & distribute funds
pub fn process_headstash(
    deps: DepsMut,
    env: Env,
    claims: Vec<HeadstashNote>,
) -> Result<Response<TokenFactoryMsg>, StdError> {
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
        Proof::new(claim.p.to_vec()).verify(&VK, &[claim.i.clone().into()])?;
        // verify recp integrity
        claim.verify_recp_posiedon_hash()?;

        // increment allcoation going to user if multiple proofs are being claimed
        *cts.entry((claim.i.nd.clone(), claim.rr.clone()))
            .or_insert(claim.i.v) += claim.i.v;
    }

    let mut res: Response<TokenFactoryMsg> = Response::new();

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
                // Mint one message per recipient (batched amount)
                for ((_, r), amount) in denom_entries {
                    let ra = deps.api.addr_humanize(&CanonicalAddr::from(r))?;
                    res = res.add_message(TokenFactoryMsg::MintTokens {
                        denom: td.to_string(),
                        amount: amount.try_into().unwrap(),
                        mint_to_address: ra.into(),
                    });
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
    // }

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
