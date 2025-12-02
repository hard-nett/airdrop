// src/tokenfactory.rs
use cosmwasm_std::{Addr, Coin, Deps, Response, StdResult, Uint128};
use token_bindings::{DenomUnit, Metadata, TokenFactoryMsg};

#[cosmwasm_schema::cw_serde]
pub enum TokenStrategy {
    /// Create new token via TokenFactory
    NewFungible(NewTokenConfig),
    /// Use existing denom (must pre-fund contract)
    ExistingFungible(String), // denom only
}

#[cosmwasm_schema::cw_serde]
pub struct NewTokenConfig {
    pub subdenom: String,
    pub metadata: Metadata,
    pub initial_mint: Option<Vec<InitialMint>>, // optional pre-mint
    pub manager: Option<String>,                // admin of denom
    pub minters: Vec<String>,                   // who can mint later
}

#[cosmwasm_schema::cw_serde]
pub struct InitialMint {
    pub to_address: String,
    pub amount: Uint128,
}

impl TokenStrategy {
    pub fn denom(&self, contract_addr: &Addr) -> String {
        match self {
            TokenStrategy::NewFungible(cfg) => {
                format!("factory/{}/{}", contract_addr, cfg.subdenom)
            }
            TokenStrategy::ExistingFungible(denom) => denom.clone(),
        }
    }

    pub fn create_denom_msg(&self, contract_addr: &Addr) -> Option<TokenFactoryMsg> {
        match self {
            TokenStrategy::NewFungible(cfg) => Some(TokenFactoryMsg::CreateDenom {
                subdenom: cfg.subdenom.clone(),
                metadata: Some(cfg.metadata.clone()),
            }),
            TokenStrategy::ExistingFungible(_) => None,
        }
    }

    pub fn initial_mint_msgs(&self, contract_addr: &Addr) -> StdResult<Vec<TokenFactoryMsg>> {
        match self {
            TokenStrategy::NewFungible(cfg) => {
                let full_denom = self.denom(contract_addr);
                Ok(cfg
                    .initial_mint
                    .as_ref()
                    .map(|mints| {
                        mints
                            .iter()
                            .map(|m| TokenFactoryMsg::MintTokens {
                                denom: full_denom.clone(),
                                amount: m.amount,
                                mint_to_address: m.to_address.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default())
            }
            TokenStrategy::ExistingFungible(_) => Ok(vec![]),
        }
    }

    pub fn requires_prefund(&self) -> bool {
        matches!(self, TokenStrategy::ExistingFungible(_))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128};
    use token_bindings::{DenomUnit, Metadata};

    const CONTRACT_ADDR: &str = "cosmos2contractaddr1234567890abcdef";

    fn mock_metadata() -> Metadata {
        Metadata {
            description: Some("Headstash Token".to_string()),
            denom_units: vec![
                DenomUnit {
                    denom: "uhead".to_string(),
                    exponent: 0,
                    aliases: vec![],
                },
                DenomUnit {
                    denom: "HEAD".to_string(),
                    exponent: 6,
                    aliases: vec!["head".to_string()],
                },
            ],
            base: Some("uhead".to_string()),
            display: Some("HEAD".to_string()),
            name: Some("Headstash Token".to_string()),
            symbol: Some("HEAD".to_string()),
        }
    }

    #[test]
    fn test_denom_new_fungible() {
        let deps = mock_dependencies();
        let contract = Addr::unchecked(CONTRACT_ADDR);

        let strategy = TokenStrategy::NewFungible(NewTokenConfig {
            subdenom: "head".to_string(),
            metadata: mock_metadata(),
            initial_mint: None,
            manager: None,
            minters: vec![],
        });

        assert_eq!(
            strategy.denom(&contract),
            format!("factory/{}/head", CONTRACT_ADDR)
        );
    }

    #[test]
    fn test_denom_existing_fungible() {
        let contract = Addr::unchecked(CONTRACT_ADDR);
        let strategy = TokenStrategy::ExistingFungible("cosmos1abc...xyz".to_string());

        assert_eq!(strategy.denom(&contract), "cosmos1abc...xyz");
    }

    #[test]
    fn test_create_denom_msg_new_fungible() {
        let deps = mock_dependencies();
        let contract = Addr::unchecked(CONTRACT_ADDR);

        let strategy = TokenStrategy::NewFungible(NewTokenConfig {
            subdenom: "head".to_string(),
            metadata: mock_metadata(),
            initial_mint: None,
            manager: None,
            minters: vec![],
        });

        let msg = strategy.create_denom_msg(&contract).unwrap();
        match msg {
            TokenFactoryMsg::CreateDenom { subdenom, metadata } => {
                assert_eq!(subdenom, "head");
                assert_eq!(metadata.unwrap().name.unwrap(), "Headstash Token");
            }
            _ => panic!("Expected CreateDenom"),
        }
    }

    #[test]
    fn test_create_denom_msg_existing_returns_none() {
        let contract = Addr::unchecked(CONTRACT_ADDR);
        let strategy = TokenStrategy::ExistingFungible("existing_denom".to_string());

        assert!(strategy.create_denom_msg(&contract).is_none());
    }

    #[test]
    fn test_initial_mint_msgs_with_mints() {
        let contract = Addr::unchecked(CONTRACT_ADDR);

        let strategy = TokenStrategy::NewFungible(NewTokenConfig {
            subdenom: "head".to_string(),
            metadata: mock_metadata(),
            initial_mint: Some(vec![
                InitialMint {
                    to_address: "alice".to_string(),
                    amount: Uint128::new(1000),
                },
                InitialMint {
                    to_address: "bob".to_string(),
                    amount: Uint128::new(500),
                },
            ]),
            manager: None,
            minters: vec![],
        });

        let msgs = strategy.initial_mint_msgs(&contract).unwrap();
        assert_eq!(msgs.len(), 2);

        let expected_denom = format!("factory/{}/head", CONTRACT_ADDR);

        match &msgs[0] {
            TokenFactoryMsg::MintTokens { denom, amount, mint_to_address } => {
                assert_eq!(denom, &expected_denom);
                assert_eq!(*amount, Uint128::new(1000));
                assert_eq!(mint_to_address, "alice");
            }
            _ => panic!("Expected MintTokens"),
        }

        match &msgs[1] {
            TokenFactoryMsg::MintTokens { denom, amount, mint_to_address } => {
                assert_eq!(denom, &expected_denom);
                assert_eq!(*amount, Uint128::new(500));
                assert_eq!(mint_to_address, "bob");
            }
            _ => panic!("Expected MintTokens"),
        }
    }

    #[test]
    fn test_initial_mint_msgs_no_initial_mint() {
        let contract = Addr::unchecked(CONTRACT_ADDR);

        let strategy = TokenStrategy::NewFungible(NewTokenConfig {
            subdenom: "head".to_string(),
            metadata: mock_metadata(),
            initial_mint: None,
            manager: None,
            minters: vec![],
        });

        let msgs = strategy.initial_mint_msgs(&contract).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_initial_mint_msgs_existing_fungible_returns_empty() {
        let contract = Addr::unchecked(CONTRACT_ADDR);
        let strategy = TokenStrategy::ExistingFungible("existing".to_string());

        let msgs = strategy.initial_mint_msgs(&contract).unwrap();
        assert!(msgs.is_empty());
    }

    #[test]
    fn test_requires_prefund() {
        let contract = Addr::unchecked(CONTRACT_ADDR);

        let new_strategy = TokenStrategy::NewFungible(NewTokenConfig {
            subdenom: "head".to_string(),
            metadata: mock_metadata(),
            initial_mint: None,
            manager: None,
            minters: vec![],
        });

        let existing_strategy = TokenStrategy::ExistingFungible("existing".to_string());

        assert!(!new_strategy.requires_prefund());
        assert!(existing_strategy.requires_prefund());
    }

    #[test]
    fn test_full_denom_resolution_consistency() {
        let contract = Addr::unchecked("cosmos1qwerty");

        let cfg = NewTokenConfig {
            subdenom: "meme".to_string(),
            metadata: mock_metadata(),
            initial_mint: None,
            manager: None,
            minters: vec![],
        };

        let strategy = TokenStrategy::NewFungible(cfg);

        let from_denom = strategy.denom(&contract);
        let from_create = strategy.create_denom_msg(&contract).unwrap();

        if let TokenFactoryMsg::CreateDenom { subdenom, .. } = from_create {
            let expected = format!("factory/{}/{}", contract, subdenom);
            assert_eq!(from_denom, expected);
        } else {
            panic!("Wrong msg type");
        }
    }
}