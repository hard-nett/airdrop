use cosmwasm_std::Uint128;
use token_bindings::{DenomUnit, Metadata, TokenFactoryMsg};

// #[cosmwasm_schema::cw_serde]
// pub struct TokenParams {
//     pub strategy: TokenStrategy,
// }

// #[cosmwasm_schema::cw_serde]
// pub enum TokenStrategy {
//     /// create token using tokenfactory middleware (instantiates middleware that creates token)
//     NewFungible(FactoryStrategy),
//     // /// using existing token.
//     ExistingFungible(ExistingFungible),
//     // NewNonFungible {},
//     // ExistingNonFungible {},
// }

// #[cosmwasm_schema::cw_serde]
// pub enum FactoryStrategy {
//     New(MsgNewHeadstashToken),
// }

// #[cosmwasm_schema::cw_serde]
// pub struct MsgNewHeadstashToken {
//     // the manager of the contract is the one who can transfer the admin to another address
//     // Typically this should be a multisig or a DAO (https://daodao.zone/)
//     // Default is the contract initializer
//     pub manager: Option<String>,
//     pub allowed_mint_addresses: Vec<String>,
//     // We can manage multiple denoms
//     // pub existing_denoms: Option<Vec<String>>, // ex: factory/terp1xxxx/test
//     pub new_denoms: Vec<NewDenom>,
// }

// #[cosmwasm_schema::cw_serde]
// pub struct ExistingFungible {
//     pub denom: String,
//     pub decimals: u32,
//     /// optional existing tokenfactory middleware contract managed by caller.
//     ///  Specified when user wants to have new token managed by token factory middleware contract
//     pub factory: Option<String>,
// }

// #[cosmwasm_schema::cw_serde]
// pub struct NewDenom {
//     pub name: String,
//     pub description: Option<String>,
//     pub symbol: String,
//     pub decimals: u32,
//     pub initial_balances: Option<Vec<InitialBalance>>,
// }

// #[cosmwasm_schema::cw_serde]
// pub struct InitialBalance {
//     pub address: String,
//     pub amount: Uint128,
// }

// // create tokenfactory middleware
// pub fn create_denom_msg(subdenom: String, full_denom: String, denom: NewDenom) -> TokenFactoryMsg {
//     TokenFactoryMsg::CreateDenom {
//         subdenom,
//         metadata: Some(Metadata {
//             name: Some(denom.name),
//             description: denom.description,
//             denom_units: vec![
//                 DenomUnit {
//                     denom: full_denom.clone(),
//                     exponent: 0,
//                     aliases: vec![],
//                 },
//                 DenomUnit {
//                     denom: denom.symbol.clone(),
//                     exponent: denom.decimals,
//                     aliases: vec![],
//                 },
//             ],
//             base: Some(full_denom),
//             display: Some(denom.symbol.clone()),
//             symbol: Some(denom.symbol),
//         }),
//     }
// }
// pub fn mint_tokens_msg(address: String, denom: String, amount: Uint128) -> TokenFactoryMsg {
//     TokenFactoryMsg::MintTokens {
//         denom,
//         amount,
//         mint_to_address: address,
//     }
// }

// pub fn init_token_strategy(
//     deps: Deps,
//     sender: &Addr,
//     me: &Addr,
//     cfg: &TokenParams,
// ) -> Result<Response<TokenFactoryMsg>, StdError> {
//     Ok(match &cfg.strategy {
//         tokenfactory::TokenStrategy::NewFungible(fs) => {
//             let mut denoms = Vec::new();
//             let mut new_denom_msgs = vec![];
//             let mut new_mint_msgs = vec![];

//             // Validate existing denoms.
//             let (admin, minters, new_denoms) = match fs {
//                 FactoryStrategy::New(new) => {
//                     (&new.manager, &new.allowed_mint_addresses, &new.new_denoms)
//                 }
//             };

//             if !new_denoms.is_empty() {
//                 for denom in new_denoms {
//                     let subdenom = denom.symbol.to_lowercase();
//                     let full_denom = format!("factory/{}/{}", me, subdenom);

//                     // Add creation message.
//                     new_denom_msgs.push(create_denom_msg(
//                         subdenom.clone(),
//                         full_denom.clone(),
//                         denom.clone(),
//                     ));
//                     // Add initial balance mint messages.
//                     if let Some(initial_balances) = &denom.initial_balances {
//                         if !initial_balances.is_empty() {
//                             // Validate addresses.
//                             for initial in initial_balances.iter() {
//                                 deps.api.addr_validate(&initial.address)?;
//                             }

//                             for b in initial_balances {
//                                 new_mint_msgs.push(mint_tokens_msg(
//                                     b.address.clone(),
//                                     full_denom.clone(),
//                                     b.amount,
//                                 ));
//                             }
//                         }
//                     }
//                     // Add to existing denoms.
//                     denoms.push(full_denom);
//                 }
//             } else {
//                 return Err(StdError::msg("cannot set empty new denoms"));
//             }

//             // if denoms.is_empty() {
//             //     return Err(ContractError::NoDenomsProvided {});
//             // }
//             let manager = match admin {
//                 Some(a) => &deps.api.addr_validate(&a)?,
//                 None => sender,
//             };

//             Response::new()
//                 .add_messages(new_denom_msgs)
//                 .add_messages(new_mint_msgs)
//         }

//         tokenfactory::TokenStrategy::ExistingFungible(existing_fungible) => Response::new(),
//     })
// }
