use cosmwasm_schema::cw_serde;
use cosmwasm_std::Empty;
use cw_storage_plus::{Item, Map};

use crate::msg::CeremonyStatus;

#[cw_serde]
pub struct Config {
    pub admin: Option<String>,
    pub max_nullifiers_per_mark: u32,
}

#[cw_serde]
pub struct Ceremony {
    pub domain: String,
    pub status: CeremonyStatus,
    pub registration_open: bool,
    pub anchor_policy: Option<String>,
}

pub const CONFIG: Item<Config> = Item::new("config");

/// ceremonies[session_id] → Ceremony
pub const CEREMONIES: Map<&str, Ceremony> = Map::new("ceremony");

/// registrations[session_id][addr] → Empty
pub const REGISTRATIONS: Map<(&str, &str), Empty> = Map::new("reg");

/// spent[domain][session_id][nullifier] → Empty (presence = spent)
/// Namespace `"spent"` is stable for raw-query ante (V2).
pub const SPENT: Map<(&str, &str, &[u8]), Empty> = Map::new("spent");

pub fn spent_key<'a>(
    domain: &'a str,
    session_id: &'a str,
    nullifier: &'a [u8],
) -> (&'a str, &'a str, &'a [u8]) {
    (domain, session_id, nullifier)
}
