use crate::distro::{self, DistroHashDomain, GENESIS_ROOT_ID};
use crate::tokenfactory::TokenStrategy;

use super::*;
use cosmwasm_std::{CanonicalAddr, Uint128};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use std::collections::{HashMap, HashSet};
use zk_headstash::Anchor;
use zk_headstash::address::RecpAddr;
use zk_headstash::circuit::Instance;
use zk_headstash::note::{ExtractedNoteCommitment, Nullifier};
use zk_headstash::value::{NoteDenom, NoteValue};

#[cosmwasm_schema::cw_serde]
pub struct HeadstashCfg {
    // cid: circuit-id of stored circuit in vm
    pub cid: u64,
    // gr: genesis tree root (also stored under eligibility root_id = 0)
    pub gr: Binary,
    /// Default / genesis public-inclusion hash domain (`poseidon-v1` for new drops).
    #[serde(default)]
    pub distro_hash_domain: DistroHashDomain,
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
    // rr: raw recipient of headstash. CanonicalAddr
    pub rr: Binary,
    /// Eligibility root this claim proves under. Default `0` = genesis set.
    /// Circuit public input `anchor` must match the registered root for this id
    /// once Poseidon-v1 inclusion proofs are live.
    #[serde(default)]
    pub root_id: u64,
}

impl HeadstashNote {
    // verifies a nullifier does not exist in the map, and will save to map if it does not
    // TODO: ffi api pasta curves
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
    // Batch-local keys are domain-separated by root_id so two claims under
    // different additive sets with the same nf encoding do not collide.
    let mut n = HashSet::new();
    let mut cts = HashMap::new();

    for claim in &claims {
        let root_id = claim.root_id;
        // Claim must reference a registered eligibility root (additive set).
        // Anchor must equal the registered root bytes (depth-32 Poseidon path root for new drops).
        let root_entry =
            distro::assert_claim_root(deps.storage, root_id, Some(&claim.i.anchor))?;
        // Default product path: only Poseidon-v1 inclusion roots (ADR).
        // Instantiation with `sinsemilla-legacy` genesis opts into recovery mode.
        if cfg.distro_hash_domain == DistroHashDomain::PoseidonV1 {
            distro::assert_claim_domain_poseidon_v1(&root_entry)?;
        }

        let nf_hex = claim.i.nf.to_hex();
        let nf_key = distro::nullifier_storage_key(root_id, &nf_hex);

        // verify no nullifier duplicates in this batch (same root scope).
        if !n.insert(nf_key.clone()) {
            return Err(StdError::msg(format!("null: {nf_hex} (root_id={root_id})")));
        }
        // verify nullifier is new. adds nullifier to map if so
        verify_nullifier_stateful(deps.storage, nf_key)?;

        // verify denom is supported for this token strategy
        if !cfg
            .ts
            .iter()
            .any(|e| &e.proof_representation() == &claim.i.nd)
        {
            return Err(StdError::msg("incorrect token denom"));
        }

        // verify headstash proof (requires cosmwasm-std `zk` + chain wasmvm export).
        // Guest builds omit that import so BridgeMintNote deploys on stock wasmd;
        // claim path is fail-closed unless built with zk host support.
        #[cfg(feature = "zk-api")]
        {
            let ok = deps
                .api
                .proof_instance_verify(
                    cfg.cid.into(),
                    &claim.p,
                    &<HeadstashInstances as Into<Instance>>::into(claim.i.clone()).to_bytes(),
                )
                .map_err(|e| StdError::msg(e.to_string()))?;
            if !ok {
                return Err(StdError::msg("invalid headstash proof"));
            }
        }
        #[cfg(not(feature = "zk-api"))]
        {
            let _ = (&cfg.cid, &claim.p, &claim.i);
            return Err(StdError::msg(
                "headstash claim proof verify requires zk-api feature + zk wasmvm (use BridgeMintNote for corridor)",
            ));
        }

        // verify recp integrity
        claim.verify_recp_posiedon_hash()?;

        // increment allcoation going to user if multiple proofs are being claimed
        *cts.entry((claim.i.nd.clone(), claim.rr.clone()))
            .or_insert(claim.i.v) += claim.i.v;
    }

    let mut res: Response = Response::new();

    for t in cfg.ts {
        let td = t.denom(&env.contract.address);

        let denom_entries: Vec<_> = cts
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

/// Owner registers an additive eligibility root (Poseidon-v1 policy).
pub fn register_eligibility_root(
    deps: DepsMut,
    info: MessageInfo,
    root: Binary,
    domain: Option<DistroHashDomain>,
    label: Option<String>,
) -> Result<Response, StdError> {
    cw_ownable::assert_owner(deps.storage, &info.sender)?;
    let cfg = HEADSTASH_CFG.load(deps.storage)?;
    let domain = domain.unwrap_or(cfg.distro_hash_domain);
    let entry = distro::register_eligibility_root(deps.storage, root, domain, label)?;

    Ok(Response::new()
        .add_attribute("action", "register_eligibility_root")
        .add_attribute("root_id", entry.root_id.to_string())
        .add_attribute("distro_hash_domain", entry.domain.as_str())
        .add_attribute("root", entry.root.to_string()))
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

pub fn query_distro_config(deps: Deps) -> StdResult<Binary> {
    let cfg = HEADSTASH_CFG.load(deps.storage)?;
    let next = NEXT_ROOT_ID.may_load(deps.storage)?.unwrap_or(1);
    to_json_binary(&crate::msg::DistroConfigResponse {
        default_domain: cfg.distro_hash_domain,
        default_domain_tag: cfg.distro_hash_domain.as_str().to_string(),
        next_root_id: next,
        genesis_root: cfg.gr,
    })
}

pub fn query_eligibility_root(deps: Deps, root_id: u64) -> StdResult<Binary> {
    to_json_binary(&distro::require_root(deps.storage, root_id)?)
}

pub fn query_eligibility_roots(
    deps: Deps,
    start_after: Option<u64>,
    limit: Option<u32>,
) -> StdResult<Binary> {
    let limit = limit.unwrap_or(30).min(100) as usize;
    let start = start_after.map(cw_storage_plus::Bound::exclusive);
    let roots: Vec<_> = distro::ELIGIBILITY_ROOTS
        .range(deps.storage, start, None, Order::Ascending)
        .take(limit)
        .map(|r| r.map(|(_, v)| v))
        .collect::<StdResult<_>>()?;
    to_json_binary(&roots)
}

/// Convenience for tests / callers: genesis root_id.
pub fn genesis_root_id() -> u64 {
    GENESIS_ROOT_ID
}
