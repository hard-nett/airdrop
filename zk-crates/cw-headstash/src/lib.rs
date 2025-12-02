pub mod headstash;
pub mod smartaccount;
pub mod tokenfactory;
pub mod wavs;

use crate::{
    headstash::*,
    tokenfactory::TokenStrategy,
    wavs::{WavsOperatorSet, WavsParams, WavsProofOfOwnership},
};

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{
    from_json, to_json_binary, AnyMsg, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    MessageInfo, Order, Response, StdError, StdResult, Storage, BLS12_381_G1_GENERATOR,
    BLS12_381_G2_GENERATOR,
};
use serde::{Deserialize, Serialize};
use token_bindings::TokenFactoryMsg;

// a historical set of wavs operator keys after rotated. once rotated we list of old keys iwith block height changed as key.
pub const WAVS_OPERATORS: Map<String, Vec<String>> = Map::new("wavs_operators");
pub const HEADSTASH_CFG: Item<HeadstashCfg> = Item::new("headstash_params");
pub(crate) const GENESIS_TREE_ROOT: Item<Binary> = Item::new("root_gen_tree");
pub(crate) const COMMITMENT_TREE_ROOT: Item<Binary> = Item::new("root_cm_tree");
pub(crate) const NULLIFIERS: Map<String, ()> = Map::new("nullifiers");

use cosmwasm_schema::serde;
use cw_storage_plus::{Bound, Bounder, Item, KeyDeserialize, Map};

#[cw_serde]
pub struct InstantiateMsg {
    pub genesis_root: Binary,
    pub token_strategy: TokenStrategy,
    pub wavs: WavsProofOfOwnership,
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
) -> Result<Response<TokenFactoryMsg>, StdError> {
    // // Validate WAVS
    // if msg.wavs.poos.len() != msg.wavs.msg.total_operators {
    //     return Err(StdError::msg("total operators"));
    // }
    // let mut w = WavsOperatorSet::default();
    // // w.proof_of_ownership(deps.api, &msg.wavs)?;

    let mut r = Response::new();
    // let gr = msg.genesis_root.clone();
    // let ts = msg.token_strategy;
    // let c = env.contract.address.clone();
    // let d = ts.denom(&c);
    // w = WavsOperatorSet {
    //     c: c.to_string(),
    //     keys: msg.wavs.poos.iter().map(|e| e.key.clone()).collect(),
    //     msg: msg.wavs.msg.clone(),
    // };

    // if let Some(tfm) = ts.create_denom_msg(&c) {
    //     r = r.add_message(tfm);
    // }
    // r = r.add_messages(ts.initial_mint_msgs(&c)?);
    // // For ExistingFungible: check pre-funding
    // if ts.requires_prefund() {
    //     let balance = deps.querier.query_balance(&c, &d)?.amount;

    //     if balance.is_zero() {
    //         return Err(StdError::msg("at least 1 token"));
    //     }
    // }
    // let add_auth = btsg_auth::MsgAddAuthenticator {
    //     sender: c.to_string(),
    //     authenticator_type: "CosmwasmAuthenticatorV1".into(),
    //     data: to_json_binary(&btsg_auth::CosmwasmAuthenticatorInitData {
    //         contract: c.to_string(),
    //         params: to_json_binary(&w)?.to_vec(),
    //     })?
    //     .to_vec(),
    // };

    // HEADSTASH_CFG.save(
    //     deps.storage,
    //     &HeadstashCfg {
    //         gr,
    //         ts: vec![ts],
    //         w,
    //     },
    // )?;
    // GENESIS_TREE_ROOT.save(deps.storage, &msg.genesis_root)?;
    Ok(
        r.add_attribute("action", "instantiate_headstash"), // .add_message(CosmosMsg::Any(AnyMsg {
                                                            //     type_url: "/terp.smartaccount.v1beta1.MsgAddAuthenticator".to_string(),
                                                            //     value: to_json_binary(&add_auth)?,
                                                            // }))
    )
}

#[cfg_attr(not(feature = "library"), cosmwasm_std::entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<TokenFactoryMsg>, StdError> {
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
        _deps: cosmwasm_std::DepsMut,
        _auth: Self::AuthMethodStructs,
    ) -> Self::AuthProcessResult {
        // allow wavs service to also broadcast batched proof claims during this step
        Ok(Response::default())
    }

    fn on_auth_added(
        _deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &btsg_auth::OnAuthenticatorAddedRequest,
    ) -> Self::AuthProcessResult {
        Ok(Response::default())
    }

    fn on_auth_removed(
        deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &btsg_auth::OnAuthenticatorRemovedRequest,
    ) -> Self::AuthProcessResult {
        // prune state
        WAVS_OPERATORS.clear(deps.storage);
        HEADSTASH_CFG.remove(deps.storage);
        NULLIFIERS.clear(deps.storage);
        Ok(Response::default())
    }

    fn on_auth_request(
        deps: cosmwasm_std::DepsMut,
        env: cosmwasm_std::Env,
        req: &Box<btsg_auth::AuthenticationRequest>,
    ) -> Self::AuthProcessResult {
        match req.authenticator_params {
            Some(_) => {
                let cfg = HEADSTASH_CFG.load(deps.storage)?;
                let w: WavsOperatorSet = cfg.w;
                let auth_data: wavs::BlsThresholdAuthData =
                    from_json(&req.authenticator_params.clone().expect("auth_params"))?;
                let agg_g1 = hex::decode(&w.msg.aggregate_key)?;
                let agg_g2 = deps
                    .api
                    .bls12_381_aggregate_g2(&auth_data.aggregated_signature)?;

                // reconstruct msg that was signed (hash of req.tx_data.msgs ) (TODO: BENCHMARK)
                let msg = to_json_binary(&req.tx_data.msgs)?;

                //  Hash-to-curve: H(msg) → G2
                let qs = deps.api.bls12_381_hash_to_g2(
                    cosmwasm_std::HashFunction::Sha256,
                    &msg,
                    &BLS12_381_G2_GENERATOR,
                )?;

                // e(agg_pubkey, H(msg)) == e(G1, agg_sig)
                if !deps.api.bls12_381_pairing_equality(
                    &agg_g1,
                    &qs,
                    &BLS12_381_G1_GENERATOR,
                    &agg_g2,
                )? {
                    return Err(StdError::msg("auth_params"));
                };
            }
            None => return Err(StdError::msg("auth_params")),
        }

        Ok(Response::default())
    }

    fn on_auth_track(
        _deps: cosmwasm_std::DepsMut,
        _env: cosmwasm_std::Env,
        _req: &btsg_auth::TrackRequest,
    ) -> Self::AuthProcessResult {
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

// #[cfg(test)]
// mod instantiate_tests {
//     use crate::tokenfactory::*;

//     use super::*;
//     use ark_ff::UniformRand;
//     use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
//     use cosmwasm_std::{coins, Addr, Api, HashFunction, Uint128};
//     use rand_core::OsRng;
//     use token_bindings::{DenomUnit, Metadata};

//     // Helper: Create valid WAVS proof-of-ownership (matches your working tests)
//     fn valid_wavs_proof(total_operators: usize) -> WavsProofOfOwnership {
//         use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
//         use ark_ec::AffineRepr;
//         use ark_ff::UniformRand;
//         use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
//         use cosmwasm_std::testing::MockApi;
//         use rand_core::OsRng;

//         let api = MockApi::default();

//         let mut poos = vec![];
//         let mut agg_pk_projective = G1Projective::default();

//         // Generate valid keypairs + proof-of-possession for each operator
//         for _ in 0..total_operators {
//             let sk = Fr::rand(&mut OsRng);
//             let pk: G1Affine = (G1Affine::generator() * sk).into();

//             let pk_bytes = {
//                 let mut buf = vec![];
//                 pk.serialize_compressed(&mut buf).unwrap();
//                 buf
//             };

//             // Hash pk → G2 point
//             let pop_hash = api
//                 .bls12_381_hash_to_g2(HashFunction::Sha256, &pk_bytes, &BLS12_381_G2_GENERATOR)
//                 .unwrap();

//             let h_point = G2Affine::deserialize_compressed(&pop_hash[..]).unwrap();

//             // PoP signature: sig = sk * H(pk)
//             let pop_sig: G2Affine = (h_point * sk).into();
//             let mut sig_bytes = vec![];
//             pop_sig.serialize_compressed(&mut sig_bytes).unwrap();

//             poos.push(wavs::WavsOpAuth {
//                 key: hex::encode(&pk_bytes),
//                 poo: hex::encode(&sig_bytes),
//             });

//             // Accumulate public key for aggregate
//             agg_pk_projective += pk;
//         }

//         let agg_pk: G1Affine = agg_pk_projective.into();
//         let mut agg_pk_bytes = vec![];
//         agg_pk.serialize_compressed(&mut agg_pk_bytes).unwrap();

//         WavsProofOfOwnership {
//             poos,
//             msg: wavs::WavsAuthMetadata {
//                 aggregate_key: hex::encode(agg_pk_bytes),
//                 threshold: (total_operators * 2 / 3) + 1, // standard 2f+1
//                 total_operators,
//                 nonce: 0,
//             },
//         }
//     }
//     fn mock_metadata() -> Metadata {
//         Metadata {
//             description: Some("Test Token".into()),
//             denom_units: vec![
//                 DenomUnit {
//                     denom: "utest".into(),
//                     exponent: 0,
//                     aliases: vec![],
//                 },
//                 DenomUnit {
//                     denom: "TEST".into(),
//                     exponent: 6,
//                     aliases: vec![],
//                 },
//             ],
//             base: Some("utest".into()),
//             display: Some("TEST".into()),
//             name: Some("Test Token".into()),
//             symbol: Some("TEST".into()),
//         }
//     }

//     #[test]
//     fn instantiate_new_fungible_success() {
//         let mut deps = mock_dependencies();
//         let creator = deps.api.addr_make("creator");
//         let alice = deps.api.addr_make("alice");
//         let bob = deps.api.addr_make("bob");
//         let env = mock_env();
//         let info = message_info(&creator, &[]);

//         // let wavs = valid_wavs_proof(3);

//         let msg = InstantiateMsg {
//             genesis_root: Binary::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
//                 .unwrap(),
//             token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
//                 subdenom: "test".into(),
//                 metadata: mock_metadata(),
//                 initial_mint: Some(vec![
//                     InitialMint {
//                         to_address: alice.to_string(),
//                         amount: Uint128::new(1000),
//                     },
//                     InitialMint {
//                         to_address: bob.to_string(),
//                         amount: Uint128::new(500),
//                     },
//                 ]),
//                 manager: None,
//                 minters: vec![],
//             }),
//             wavs: WavsProofOfOwnership::default(),
//         };

//         let res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

// // Should have: CreateDenom + 2x MintTokens + AddAuthenticator
// assert_eq!(res.messages.len(), 4);

// // Check CreateDenom
// let create_msg = &res.messages[0];
// match &create_msg.msg {
//     CosmosMsg::Custom(TokenFactoryMsg::CreateDenom { subdenom, metadata }) => {
//         assert_eq!(subdenom, "test");
//         assert_eq!(
//             metadata.as_ref().unwrap().name.as_ref().unwrap(),
//             "Test Token"
//         );
//     }
//     _ => panic!("Expected CreateDenom"),
// }

// // Check MintTokens
// let expected_denom = format!("factory/{}/test", env.contract.address);
// let mint1 = &res.messages[1];
// let mint2 = &res.messages[2];
// match (&mint1.msg, &mint2.msg) {
//     (
//         CosmosMsg::Custom(TokenFactoryMsg::MintTokens {
//             denom: d1,
//             amount: a1,
//             mint_to_address: to1,
//         }),
//         CosmosMsg::Custom(TokenFactoryMsg::MintTokens {
//             denom: d2,
//             amount: a2,
//             mint_to_address: to2,
//         }),
//     ) => {
//         assert_eq!(d1, &expected_denom);
//         assert_eq!(d2, &expected_denom);
//         assert!(
//             (a1 == &Uint128::new(1000) && to1 == &alice.to_string())
//                 || (a1 == &Uint128::new(500) && to1 == &bob.to_string())
//         );
//         assert!(
//             (a2 == &Uint128::new(500) && to2 == &bob.to_string())
//                 || (a2 == &Uint128::new(1000) && to2 == &alice.to_string())
//         );
//     }
//     _ => panic!("Expected MintTokens"),
// }

// // Check AddAuthenticator
// let auth_msg = &res.messages[3];
// match &auth_msg.msg {
//     CosmosMsg::Any(any)
//         if any.type_url == "/terp.smartaccount.v1beta1.MsgAddAuthenticator" =>
//     {
//         let parsed: btsg_auth::MsgAddAuthenticator = from_json(&any.value).unwrap();
//         assert_eq!(parsed.sender.to_string(), env.contract.address.to_string());
//         assert_eq!(parsed.authenticator_type, "CosmwasmAuthenticatorV1");
//     }
//     _ => panic!("Expected AddAuthenticator"),
// }

// // State saved
// let cfg = HEADSTASH_CFG.load(&deps.storage).unwrap();
// assert_eq!(cfg.ts.len(), 1);
// assert!(matches!(cfg.ts[0], TokenStrategy::NewFungible(_)));
// }

// #[test]
// fn instantiate_existing_fungible_with_funds_success() {
//     let mut deps = mock_dependencies();
//     let creator = deps.api.addr_make("creator");

//     deps.querier.bank.update_balance(
//         CONTRACT_ADDR,
//         vec![Coin::new(Uint128::new(1000), "existing_token")],
//     );
//     let env = mock_env();
//     let info = message_info(&creator, &[]);

//     let msg = InstantiateMsg {
//         genesis_root: Binary::from([0u8; 32]),
//         token_strategy: TokenStrategy::ExistingFungible("existing_token".into()),
//         wavs: valid_wavs_proof(1),
//     };

//     let res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

//     assert_eq!(res.messages.len(), 1); // Only AddAuthenticator
//                                        // assert!(res.messages[0]
//                                        //     .msg
//                                        //     .to_string()
//                                        //     .contains("MsgAddAuthenticator"));
// }

// #[test]
// fn instantiate_existing_fungible_no_funds_fails() {
//     let mut deps = mock_dependencies();
//     let creator = deps.api.addr_make("creator");

//     // Balance = 0 for "existing_token"
//     let env = mock_env();
//     let info = message_info(&creator, &[]);

//     let msg = InstantiateMsg {
//         genesis_root: Binary::from([0u8; 32]),
//         token_strategy: TokenStrategy::ExistingFungible("existing_token".into()),
//         wavs: valid_wavs_proof(1),
//     };

//     let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();
//     assert_eq!(err.to_string(), "Generic error: at least 1 token");
// }

// #[test]
// fn instantiate_invalid_operator_count_fails() {
//     let mut deps = mock_dependencies();
//     let env = mock_env();
//     let creator = deps.api.addr_make("creator");

//     let info = message_info(&creator, &[]);

//     let wavs = valid_wavs_proof(3);
//     let mut invalid_wavs = wavs.clone();
//     invalid_wavs.msg.total_operators = 5; // mismatch

//     let msg = InstantiateMsg {
//         genesis_root: Binary::from([0u8; 32]),
//         token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
//             subdenom: "test".into(),
//             metadata: mock_metadata(),
//             initial_mint: None,
//             manager: None,
//             minters: vec![],
//         }),
//         wavs: invalid_wavs,
//     };

//     let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();
//     assert_eq!(err.to_string(), "Generic error: total operators");
// }

// #[test]
// fn instantiate_invalid_proof_of_ownership_fails() {
//     let mut deps = mock_dependencies();
//     let env = mock_env();
//     let creator = deps.api.addr_make("creator");

//     let info = message_info(&creator, &[]);

//     let mut wavs = valid_wavs_proof(1);
//     wavs.poos[0].poo = "deadbeef".to_string(); // corrupt PoO

//     let msg = InstantiateMsg {
//         genesis_root: Binary::from([0u8; 32]),
//         token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
//             subdenom: "test".into(),
//             metadata: mock_metadata(),
//             initial_mint: None,
//             manager: None,
//             minters: vec![],
//         }),
//         wavs,
//     };

//     let err = instantiate(deps.as_mut(), env, info, msg).unwrap_err();
//     assert!(err.to_string().contains("proof of ownership failed"));
// }

// #[test]
// fn instantiate_stores_genesis_root_and_config() {
//     let mut deps = mock_dependencies();
//     let env = mock_env();
//     let sender = deps.api.addr_make("sender");

//     let info = message_info(&sender, &[]);

//     let genesis_root = Binary::from_base64("YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=").unwrap();

//     let msg = InstantiateMsg {
//         genesis_root: genesis_root.clone(),
//         token_strategy: TokenStrategy::NewFungible(NewTokenConfig {
//             subdenom: "test".into(),
//             metadata: mock_metadata(),
//             initial_mint: None,
//             manager: None,
//             minters: vec![],
//         }),
//         wavs: valid_wavs_proof(1),
//     };

//     instantiate(deps.as_mut(), env, info, msg).unwrap();

//     let stored_root = GENESIS_TREE_ROOT.load(&deps.storage).unwrap();
//     assert_eq!(stored_root, genesis_root);

//     let cfg = HEADSTASH_CFG.load(&deps.storage).unwrap();
//     assert_eq!(cfg.gr, genesis_root);
//     assert_eq!(cfg.ts.len(), 1);
//     assert!(cfg.w.msg.nonce == 0);
// }
// }
