#[cfg(feature = "wallet")]
pub mod client;
#[cfg(feature = "wallet")]
pub mod crypto;
#[cfg(feature = "wallet")]
pub mod wallet;
#[cfg(feature = "wallet")]
pub use wallet::*;

// Copyright 2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use serde::{Deserialize, Serialize};
use std::str::FromStr;
// use zcash_protocol::consensus::{self, Parameters};

/// Enum representing the network type
/// This is used instead of the `consensus::Network` enum so we can derive
/// custom serialization and deserialization and from string impls
#[derive(Copy, Clone, Debug, Default, Serialize, PartialEq, Deserialize)]
pub enum Network {
    #[default]
    MainNetwork,
    TestNetwork,
}

impl FromStr for Network {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "main" => Ok(Network::MainNetwork),
            "test" => Ok(Network::TestNetwork),
            _ => Err(Error::InvalidNetwork(s.to_string())),
        }
    }
}

// impl Parameters for Network {
//     fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
//         match self {
//             Network::MainNetwork => zcash_protocol::consensus::NetworkType::Main,
//             Network::TestNetwork => zcash_protocol::consensus::NetworkType::Test,
//         }
//     }

//     fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<consensus::BlockHeight> {
//         match self {
//             Network::MainNetwork => {
//                 zcash_primitives::consensus::Network::MainNetwork.activation_height(nu)
//             }
//             Network::TestNetwork => {
//                 zcash_primitives::consensus::Network::TestNetwork.activation_height(nu)
//             }
//         }
//     }
// }

// impl From<Network> for consensus::Network {
//     fn from(network: Network) -> Self {
//         match network {
//             Network::MainNetwork => consensus::Network::MainNetwork,
//             Network::TestNetwork => consensus::Network::TestNetwork,
//         }
//     }
// }

// feature gated library
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid network string given: {0}")]
    InvalidNetwork(String),
    #[cfg(feature = "keys")]
    #[cfg(feature = "req")]
    #[cfg(feature = "wallet")]
    #[error("Javascript error")]
    Js(wasm_bindgen::JsValue),
    // #[error("Invalid account id")]
    // AccountIdConversion(#[from] zcash_primitives::zip32::TryFromIntError),
    // #[error("Failed to derive key from seed")]
    // Derivation(#[from] zcash_keys::keys::DerivationError),
    #[error("Error attempting to decode key: {0}")]
    KeyDecoding(String),
    #[error("Failed to sign Pczt: {0}")]
    PcztSign(String),
    #[error("Error attempting to get seed fingerprint.")]
    SeedFingerprint,
    #[error("serde wasm-bindgen error")]
    SerdeWasmBindgen(#[from] serde_wasm_bindgen::Error),
}

// Implement Into<JsValue> for wasm-bindgen compatibility
impl From<Error> for wasm_bindgen::JsValue {
    fn from(err: Error) -> Self {
        wasm_bindgen::JsValue::from_str(&err.to_string())
    }
}

// impl From<indexed_db_futures::web_sys::DomException> for Error {
//     fn from(e: indexed_db_futures::web_sys::DomException) -> Self {
//         Self::DomException {
//             name: e.name(),
//             message: e.message(),
//             code: e.code(),
//         }
//     }
// }

// impl From<zcash_client_backend::scanning::ScanError> for Error {
//     fn from(e: zcash_client_backend::scanning::ScanError) -> Self {
//         Self::Scan(e)
//     }
// }

// impl<A, B, C> From<zcash_client_backend::sync::Error<A, B, C>> for Error
// where
//     A: Display,
//     B: Display,
//     C: Display,
// {
//     fn from(e: zcash_client_backend::sync::Error<A, B, C>) -> Self {
//         Self::Sync(e.to_string())
//     }
// }
