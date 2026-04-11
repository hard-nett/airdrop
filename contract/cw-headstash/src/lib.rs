pub mod headstash;
pub mod msg;
pub mod tokenfactory;
pub mod wavs;

#[cfg(feature = "interface")]
pub mod interface;

use crate::{
    headstash::*,
    tokenfactory::TokenStrategy,
    wavs::{WavsOperatorSet, WavsProofOfOwnership},
};

use ark_ff::Zero;
use cosmwasm_schema::{QueryResponses, cw_serde, serde};
use cosmwasm_std::{
    Addr, AnyMsg, BLS12_381_G1_GENERATOR as G1, BLS12_381_G2_GENERATOR as G2, BankMsg, Binary,
    Coin, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Order, Reply, ReplyOn, Response, StdError,
    StdResult, Storage, SubMsg, Uint128, coins, from_json, to_json_binary,
};
use cw_storage_plus::{Bound, Bounder, Item, KeyDeserialize, Map};
pub use msg::*;

// use cw2::{ContractVersion, get_contract_version, set_contract_version};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwHeadstashStructs {}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CwHeadstash {}

// Version info for migration
const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

// Reply IDs
const CREATE_DENOM_REPLY_ID: u64 = 1;

// a historical set of wavs operator keys after rotated. once rotated we list of old keys iwith block height changed as key.
pub const WAVS_OPERATORS: Map<String, Vec<String>> = Map::new("wavs_operators");
pub const HEADSTASH_CFG: Item<HeadstashCfg> = Item::new("headstash_params");
pub(crate) const GENESIS_TREE_ROOT: Item<Binary> = Item::new("root_gen_tree");
pub(crate) const COMMITMENT_TREE_ROOT: Item<Binary> = Item::new("root_cm_tree");
pub(crate) const NULLIFIERS: Map<String, ()> = Map::new("nullifiers");
pub(crate) const DENOM: Item<String> = Item::new("denom");

// Allowance maps for minting and burning
pub const MINTER_ALLOWANCES: Map<Addr, Uint128> = Map::new("minter_allowances");
pub const BURNER_ALLOWANCES: Map<Addr, Uint128> = Map::new("burner_allowances");

// Hardcoded protobuf type URLs for tokenfactory messages
const MSG_CREATE_DENOM_TYPE_URL: &str = "/osmosis.tokenfactory.v1beta1.MsgCreateDenom";
const MSG_MINT_TYPE_URL: &str = "/osmosis.tokenfactory.v1beta1.MsgMint";
const MSG_BURN_TYPE_URL: &str = "/osmosis.tokenfactory.v1beta1.MsgBurn";

// Helper functions to create Stargate messages for tokenfactory operations
fn msg_create_denom(sender: String, subdenom: String) -> StdResult<CosmosMsg> {
    #[derive(serde::Serialize)]
    struct MsgCreateDenom {
        sender: String,
        subdenom: String,
    }

    let msg = MsgCreateDenom { sender, subdenom };
    let value = to_json_binary(&msg)?;

    Ok(CosmosMsg::Stargate {
        type_url: MSG_CREATE_DENOM_TYPE_URL.to_string(),
        value,
    })
}

fn msg_mint(sender: String, amount: Uint128, denom: String) -> StdResult<CosmosMsg> {
    #[derive(serde::Serialize)]
    struct Coin {
        denom: String,
        amount: String,
    }

    #[derive(serde::Serialize)]
    struct MsgMint {
        sender: String,
        amount: Coin,
        mint_to_address: String,
    }

    let coin = Coin {
        denom,
        amount: amount.to_string(),
    };

    let msg = MsgMint {
        sender: sender.clone(),
        amount: coin,
        mint_to_address: sender.clone(), // Mint to sender, then we'll send via BankMsg
    };

    let value = to_json_binary(&msg)?;

    Ok(CosmosMsg::Stargate {
        type_url: MSG_MINT_TYPE_URL.to_string(),
        value,
    })
}

fn msg_burn(
    sender: String,
    amount: Uint128,
    denom: String,
    burn_from_address: String,
) -> StdResult<CosmosMsg> {
    #[derive(serde::Serialize)]
    struct Coin {
        denom: String,
        amount: String,
    }

    #[derive(serde::Serialize)]
    struct MsgBurn {
        sender: String,
        amount: Coin,
        burn_from_address: String,
    }

    let coin = Coin {
        denom,
        amount: amount.to_string(),
    };

    let msg = MsgBurn {
        sender,
        amount: coin,
        burn_from_address,
    };

    let value = to_json_binary(&msg)?;

    Ok(CosmosMsg::Stargate {
        type_url: MSG_BURN_TYPE_URL.to_string(),
        value,
    })
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, StdError> {
    // set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Owner is the sender of the initial InstantiateMsg
    cw_ownable::initialize_owner(deps.storage, deps.api, Some(info.sender.as_str()))?;

    // validate initialization params
    msg.wavs.verify()?;
    msg.token_strategy.validate()?;

    let ts = msg.token_strategy;
    let c = env.contract.address.clone();

    match ts.clone() {
        tokenfactory::TokenStrategy::NewFungible(ref cfg) => {
            // Save config for reply handler to access initial mints
            let w = msg.wavs.proof_of_ownership(deps.api, &c)?;
            HEADSTASH_CFG.save(
                deps.storage,
                &HeadstashCfg {
                    gr: msg.genesis_root.clone(),
                    ts: vec![ts],
                    w,
                    cid: 0, // TODO: implement circuit ID
                },
            )?;

            Ok(Response::new()
                .add_attribute("action", "instantiate")
                .add_attribute("owner", info.sender)
                .add_attribute("subdenom", cfg.subdenom.raw.clone())
                .add_submessage(
                    // Create new denom, denom info is saved in the reply
                    SubMsg::reply_on_success(
                        msg_create_denom(
                            env.contract.address.to_string(),
                            cfg.subdenom.raw.clone(),
                        )?,
                        CREATE_DENOM_REPLY_ID,
                    ),
                ))
        }
        tokenfactory::TokenStrategy::ExistingFungible(ref denom) => {
            // check for prefunding of headstash
            if !info.funds.iter().any(|coin| coin.denom == denom.raw) {
                let balance = deps.querier.query_balance(&c, &denom.raw)?.amount;
                if balance.is_zero() {
                    return Err(StdError::msg(
                        "at least 1 token required for existing denom",
                    ));
                }
            }

            DENOM.save(deps.storage, &denom.raw)?;

            // Save config for existing tokens too
            let w = msg.wavs.proof_of_ownership(deps.api, &c)?;
            HEADSTASH_CFG.save(
                deps.storage,
                &HeadstashCfg {
                    gr: msg.genesis_root.clone(),
                    ts: vec![ts],
                    w,
                    cid: 0, // TODO: implement circuit ID
                },
            )?;

            Ok(Response::new()
                .add_attribute("action", "instantiate")
                .add_attribute("owner", info.sender)
                .add_attribute("denom", denom.raw.clone()))
        }
    }
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
        ExecuteMsg::LoadVk { vk } => crate::headstash::set_verifying_key(deps, env, vk),
        ExecuteMsg::Mint { to_address, amount } => {
            execute_mint(deps, env, info, to_address, amount)
        }
        ExecuteMsg::Burn {
            from_address,
            amount,
        } => execute_burn(deps, env, info, from_address, amount),
    }
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Ownership {} => to_json_binary(&cw_ownable::get_ownership(deps.storage)?),
        QueryMsg::Nullifer { null } => Ok(to_json_binary(
            &NULLIFIERS.may_load(deps.storage, null)?.is_some(),
        )?),
        QueryMsg::Nullifiers { start_after, limit } => {
            headstash::query_nullifiers(deps, start_after, limit)
        }
    }
}

pub fn execute_mint(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    to_address: String,
    amount: Uint128,
) -> Result<Response, StdError> {
    // Only allow current contract owner to mint
    cw_ownable::assert_owner(deps.storage, &info.sender)?;

    // Validate that to_address is a valid address
    deps.api.addr_validate(&to_address)?;

    // Don't allow minting of 0 coins
    if amount.is_zero() {
        return Err(StdError::msg("Zero amount"));
    }

    // Get token denom from contract
    let denom = DENOM.load(deps.storage)?;

    // Create tokenfactory MsgMint which mints coins to the contract address
    let mint_tokens_msg = msg_mint(env.contract.address.to_string(), amount, denom.clone())?;

    // Send newly minted coins from contract to designated recipient
    let send_tokens_msg = BankMsg::Send {
        to_address: to_address.clone(),
        amount: coins(amount.u128(), denom),
    };

    Ok(Response::new()
        .add_message(mint_tokens_msg)
        .add_message(send_tokens_msg)
        .add_attribute("action", "mint")
        .add_attribute("to", to_address)
        .add_attribute("amount", amount))
}

pub fn execute_burn(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    from_address: String,
    amount: Uint128,
) -> Result<Response, StdError> {
    // Only allow current contract owner to burn
    cw_ownable::assert_owner(deps.storage, &info.sender)?;

    // Don't allow burning of 0 coins
    if amount.is_zero() {
        return Err(StdError::msg("Zero amount"));
    }

    // Get token denom from contract config
    let denom = DENOM.load(deps.storage)?;

    // Create tokenfactory MsgBurn which burns coins from the contract address
    // NOTE: this requires the contract to own the tokens already
    let from_addr = deps.api.addr_validate(&from_address)?;
    let burn_tokens_msg = msg_burn(
        env.contract.address.to_string(),
        amount,
        denom,
        from_addr.to_string(),
    )?;

    Ok(Response::new()
        .add_message(burn_tokens_msg)
        .add_attribute("action", "burn")
        .add_attribute("burner", info.sender)
        .add_attribute("burn_from_address", from_addr.to_string())
        .add_attribute("amount", amount))
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, StdError> {
    match msg.id {
        CREATE_DENOM_REPLY_ID => {
            // Extract the new_token_denom from the reply data
            // In CosmWasm v3, the reply data contains the response from the submessage
            let response_data = msg
                .result
                .into_result()
                .map_err(|_| StdError::msg("Submessage failed"))?
                .data
                .ok_or_else(|| StdError::msg("No response data"))?;

            #[derive(serde::Deserialize)]
            struct MsgCreateDenomResponse {
                new_token_denom: String,
            }

            let response: MsgCreateDenomResponse = cosmwasm_std::from_json(&response_data)?;
            let new_token_denom = response.new_token_denom;

            DENOM.save(deps.storage, &new_token_denom)?;

            // Check if we need to do initial minting
            let cfg = HEADSTASH_CFG.may_load(deps.storage)?;
            if let Some(config) = cfg {
                if let Some(token_strategy) = config.ts.first() {
                    let initial_mints = token_strategy.get_initial_mints();
                    if !initial_mints.is_empty() {
                        let mut messages = vec![];
                        let initial_mint_count = initial_mints.len();
                        for mint in initial_mints {
                            let mint_msgs = token_strategy.mint_tokens(
                                &env.contract.address,
                                mint.amount,
                                &mint.to_address,
                            )?;
                            messages.extend(mint_msgs);
                        }
                        return Ok(Response::new()
                            .add_attribute("denom", new_token_denom)
                            .add_attribute("initial_mints", initial_mint_count.to_string())
                            .add_messages(messages));
                    }
                }
            }

            Ok(Response::new().add_attribute("denom", new_token_denom))
        }
        _ => Err(StdError::msg("Unknown reply id")),
    }
}

impl terp_auth::TerpAccountTrait for CwHeadstash {
    type InstantiateMsg = InstantiateMsg;
    type ExecuteMsg = ExecuteMsg;
    type QueryMsg = QueryMsg;
    type SudoMsg = terp_auth::AuthSudoMsg;
    type ContractError = StdError;
    type AuthMethodStructs = Binary;
    type AuthProcessResult = Result<Response, Self::ContractError>;

    fn process_sudo_auth(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &Self::SudoMsg,
    ) -> Self::AuthProcessResult {
        match req {
            terp_auth::AuthSudoMsg::OnAuthAdded(req) => Self::on_auth_added(deps, env, req),
            terp_auth::AuthSudoMsg::OnAuthRemoved(req) => Self::on_auth_removed(deps, env, req),
            terp_auth::AuthSudoMsg::Authenticate(req) => Self::on_auth_request(deps, env, req),
            terp_auth::AuthSudoMsg::Track(req) => Self::on_auth_track(deps, env, req),
            terp_auth::AuthSudoMsg::ConfirmExecution(req) => Self::on_auth_confirm(deps, env, req),
        }
    }

    fn extended_authenticate(
        _deps: cosmwasm_std::DepsMut,
        _auth: Self::AuthMethodStructs,
    ) -> Self::AuthProcessResult {
        Ok(Response::default())
    }

    fn on_auth_added(
        _deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &terp_auth::OnAuthenticatorAddedRequest,
    ) -> Self::AuthProcessResult {
        Ok(Response::default())
    }

    fn on_auth_removed(
        deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &terp_auth::OnAuthenticatorRemovedRequest,
    ) -> Self::AuthProcessResult {
        // prune state
        WAVS_OPERATORS.clear(deps.storage);
        HEADSTASH_CFG.remove(deps.storage);
        NULLIFIERS.clear(deps.storage);
        Ok(Response::default())
    }

    // - sign the hash of the proofs being verified per msgs. this lets us recreate the hash on-chain and verify actions,
    //   then recontstruct action values from proof inputs after verification (i.e coin amounts, auth params, etc.)
    // confirms wavs operator set authentication.
    // recomposes aggregated key and signature to enforce threshold minimums
    fn on_auth_request(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &Box<terp_auth::AuthenticationRequest>,
    ) -> Self::AuthProcessResult {
        let cfg = HEADSTASH_CFG.load(deps.storage)?;
        let agg_g2 = deps.api.bls12_381_aggregate_g2(&req.signature)?;
        let msg = to_json_binary(&req.tx_data.msgs)?;
        // reconstruct msg that was signed (hash of req.tx_data.msgs) (TODO: BENCHMARK)
        // `Hash-to-curve: H(msg) → G2`
        let qs = deps
            .api
            .bls12_381_hash_to_g2(cosmwasm_std::HashFunction::Sha256, &msg, &G2)?;

        if !cfg.w.msg.threshold.is_zero() {
            let w: WavsOperatorSet = cfg.w;
            let agg_g1 = hex::decode(&w.msg.aggregate_key)?;
            // e(agg_g1, qs) == e(G1, agg_g2)
            if !deps
                .api
                .bls12_381_pairing_equality(&agg_g1, &qs, &G1, &agg_g2)?
            {
                return Err(StdError::msg("auth_params"));
            };
        }

        Ok(Response::default())
    }

    fn on_auth_track(
        _deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &terp_auth::TrackRequest,
    ) -> Self::AuthProcessResult {
        Ok(Response::default())
    }

    fn on_auth_confirm(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &terp_auth::ConfirmExecutionRequest,
    ) -> Self::AuthProcessResult {
        let auth_data: wavs::BlsThresholdAuthData =
            from_json(&req.authenticator_params.clone().expect("cw-auth params"))?;

        // verifies circuit proofs, reverts any stateful change if errors.
        // Self::extended_authenticate(deps, params.clone())
        Ok(Response::default())
    }

    fn on_hooks(deps: cosmwasm_std::DepsMut, env: cosmwasm_std::Env) -> Self::AuthProcessResult {
        Ok(Response::default())
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

#[cfg(test)]
mod instantiate_tests {
    use crate::tokenfactory::*;

    use super::*;
    use crate::tokenfactory::{DenomUnit, Metadata};
    use ark_ff::UniformRand;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, Api, HashFunction, Uint128, coins};
    use rand_core::OsRng;

    #[test]
    fn minimal_test() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&deps.api.addr_make("creator"), &[]);

        let msg = InstantiateMsg {
            genesis_root: Binary::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap(),
            token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
                subdenom: HeadstashTokenObject {
                    proof: derive_nd("test"),
                    raw: "test".into(),
                },
                metadata: mock_metadata(),
                initial_mint: None,
                manager: None,
                minters: vec![],
            }),
            wavs: valid_wavs_proof(3),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();
        // println!("{:#?}", res);
        assert_eq!(res.messages.len(), 2);
    }

    // Helper: Create valid WAVS proof-of-ownership (matches your working tests)
    fn valid_wavs_proof(total_operators: usize) -> WavsProofOfOwnership {
        use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
        use ark_ec::AffineRepr;
        use ark_ff::UniformRand;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        use cosmwasm_std::testing::MockApi;
        use rand_core::OsRng;

        let api = MockApi::default();

        let mut poos = vec![];
        let mut agg_pk_projective = G1Projective::default();

        // Generate valid keypairs + proof-of-possession for each operator
        for _ in 0..total_operators {
            let sk = Fr::rand(&mut OsRng);
            let pk: G1Affine = (G1Affine::generator() * sk).into();

            let pk_bytes = {
                let mut buf = vec![];
                pk.serialize_compressed(&mut buf).unwrap();
                buf
            };

            // Hash pk → G2 point
            let pop_hash = api
                .bls12_381_hash_to_g2(HashFunction::Sha256, &pk_bytes, &G2)
                .unwrap();

            let h_point = G2Affine::deserialize_compressed(&pop_hash[..]).unwrap();

            // PoP signature: sig = sk * H(pk)
            let pop_sig: G2Affine = (h_point * sk).into();
            let mut sig_bytes = vec![];
            pop_sig.serialize_compressed(&mut sig_bytes).unwrap();

            poos.push(wavs::WavsOpAuth {
                key: hex::encode(&pk_bytes),
                poo: hex::encode(&sig_bytes),
            });

            // Accumulate public key for aggregate
            agg_pk_projective += pk;
        }

        let agg_pk: G1Affine = agg_pk_projective.into();
        let mut agg_pk_bytes = vec![];
        agg_pk.serialize_compressed(&mut agg_pk_bytes).unwrap();

        WavsProofOfOwnership {
            poos,
            msg: wavs::WavsAuthMetadata {
                aggregate_key: hex::encode(agg_pk_bytes),
                threshold: (total_operators * 2 / 3) + 1, // standard 2f+1
                total_operators,
                nonce: 0,
            },
        }
    }
    fn mock_metadata() -> Metadata {
        Metadata {
            description: Some("Test Token".into()),
            denom_units: vec![
                DenomUnit {
                    denom: "utest".into(),
                    exponent: 0,
                    aliases: vec![],
                },
                DenomUnit {
                    denom: "TEST".into(),
                    exponent: 6,
                    aliases: vec![],
                },
            ],
            base: Some("utest".into()),
            display: Some("TEST".into()),
            name: Some("Test Token".into()),
            symbol: Some("TEST".into()),
        }
    }

    #[test]
    fn instantiate_new_fungible_success() {
        let mut deps = mock_dependencies();
        let creator = deps.api.addr_make("creator");
        let alice = deps.api.addr_make("alice");
        let bob = deps.api.addr_make("bob");
        let env = mock_env();
        let info = message_info(&creator, &[]);

        let msg = InstantiateMsg {
            genesis_root: Binary::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .unwrap(),
            token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
                subdenom: HeadstashTokenObject {
                    proof: derive_nd(&"test"),
                    raw: "test".into(),
                },
                metadata: mock_metadata(),
                initial_mint: Some(vec![
                    InitialMint {
                        to_address: alice.to_string(),
                        amount: Uint128::new(1000),
                    },
                    InitialMint {
                        to_address: bob.to_string(),
                        amount: Uint128::new(500),
                    },
                ]),
                manager: None,
                minters: vec![],
            }),
            wavs: valid_wavs_proof(3),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        // Should have 1 submessage for CreateDenom (initial minting happens in reply)
        assert_eq!(res.messages.len(), 1);

        // Check that it's a SubMsg with reply_on_success
        match &res.messages[0] {
            SubMsg { msg, reply_on, .. } => {
                match msg {
                    CosmosMsg::Stargate { type_url, value } => {
                        // This should be the CreateDenom message
                        assert!(type_url.contains("tokenfactory"));
                    }
                    _ => panic!("Expected Stargate message for CreateDenom"),
                }
                assert_eq!(reply_on, &ReplyOn::Success);
            }
            _ => panic!("Expected SubMsg"),
        }

        // Config should be saved for new fungible tokens
        let cfg = HEADSTASH_CFG.load(&deps.storage).unwrap();
        assert_eq!(cfg.ts.len(), 1);
        assert!(matches!(cfg.ts[0], TokenStrategy::NewFungible(_)));
    }

    #[test]
    fn instantiate_existing_fungible_with_funds_success() {
        let mut deps = mock_dependencies();
        let creator = deps.api.addr_make("creator");
        let contract = deps.api.addr_make("contract");

        let env = mock_env();
        let info = message_info(&creator, &[Coin::new(Uint128::new(1000), "existing_token")]);

        let msg = InstantiateMsg {
            genesis_root: Binary::from([0u8; 32]),
            token_strategy: TokenStrategy::ExistingFungible(HeadstashTokenObject::new(
                "existing_token".to_string(),
            )),
            wavs: valid_wavs_proof(1),
        };

        let res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        assert_eq!(res.messages.len(), 1);

        // Config should be saved for existing fungible tokens
        let cfg = HEADSTASH_CFG.load(&deps.storage).unwrap();
        assert_eq!(cfg.ts.len(), 1);
        assert!(matches!(cfg.ts[0], TokenStrategy::ExistingFungible(_)));
    }

    #[test]
    fn instantiate_existing_fungible_no_funds_fails() {
        let mut deps = mock_dependencies();
        let creator = deps.api.addr_make("creator");

        // Balance = 0 for "existing_token"
        let env = mock_env();
        let info = message_info(&creator, &[]);

        let msg = InstantiateMsg {
            genesis_root: Binary::from([0u8; 32]),
            token_strategy: TokenStrategy::ExistingFungible(HeadstashTokenObject::new(
                "test".to_string(),
            )),
            wavs: valid_wavs_proof(1),
        };

        let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(
            err.to_string(),
            "kind: Other, error: at least 1 token required for existing denom"
        );
    }

    #[test]
    fn instantiate_invalid_operator_count_fails() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let creator = deps.api.addr_make("creator");

        let info = message_info(&creator, &[]);

        let wavs = valid_wavs_proof(3);
        let mut invalid_wavs = wavs.clone();
        invalid_wavs.msg.total_operators = 5; // mismatch

        let msg = InstantiateMsg {
            genesis_root: Binary::from([0u8; 32]),
            token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
                subdenom: HeadstashTokenObject::new("test".to_string()),
                metadata: mock_metadata(),
                initial_mint: None,
                manager: None,
                minters: vec![],
            }),
            wavs: invalid_wavs,
        };

        let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();

        assert!(
            err.to_string()
                .contains("invalid amount of operators defined")
        );
    }

    #[test]
    fn instantiate_invalid_proof_of_ownership_fails() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let creator = deps.api.addr_make("creator");

        let info = message_info(&creator, &[]);

        let mut wavs = valid_wavs_proof(1);
        wavs.poos[0].poo = "deadbeef".to_string(); // corrupt PoO

        let msg = InstantiateMsg {
            genesis_root: Binary::from([0u8; 32]),
            token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
                subdenom: HeadstashTokenObject::new("test".to_string()),
                metadata: mock_metadata(),
                initial_mint: None,
                manager: None,
                minters: vec![],
            }),
            wavs,
        };

        let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();
        // println!("{:#?}", err);
        // assert!(err.to_string().contains("proof of ownership failed"));
    }

    #[test]
    fn instantiate_stores_genesis_root_and_config() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let sender = deps.api.addr_make("sender");

        let info = message_info(&sender, &[]);

        let genesis_root = Binary::from_base64("YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=").unwrap();

        let msg = InstantiateMsg {
            genesis_root: genesis_root.clone(),
            token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
                subdenom: HeadstashTokenObject::new("test".to_string()),
                metadata: mock_metadata(),
                initial_mint: None,
                manager: None,
                minters: vec![],
            }),
            wavs: valid_wavs_proof(1),
        };

        instantiate(deps.as_mut(), env, info, msg).unwrap();

        let stored_root = GENESIS_TREE_ROOT.load(&deps.storage).unwrap();
        assert_eq!(stored_root, genesis_root);

        let cfg = HEADSTASH_CFG.load(&deps.storage).unwrap();
        assert_eq!(cfg.gr, genesis_root);
        assert_eq!(cfg.ts.len(), 1);
        assert!(cfg.w.msg.nonce == 0);
    }
}
