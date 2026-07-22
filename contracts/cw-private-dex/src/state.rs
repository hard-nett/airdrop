use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;
use cw_storage_plus::{Item, Map};

use crate::msg::{Pool, PoolStatus};

#[cw_serde]
pub struct Config {
    /// Lab dual-path: when true, mock accept non-empty proofs after seam checks.
    pub mock_verify: bool,
    /// Circuit id for `proof_instance_verify` (x/wasm registry).
    pub zkid: Option<u64>,
    /// Optional single allowed root (v1 stub window).
    pub allowed_root: Option<Binary>,
    pub next_pool_id: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");

/// pool_id → virtual pool (public reserves).
pub const POOLS: Map<u64, Pool> = Map::new("pools");

/// Spent pool-spend nullifiers (32-byte keys as Binary).
pub const NULLIFIERS: Map<&[u8], bool> = Map::new("nullifiers");

/// Tree leaf counter (stub; real IMT later).
pub const TREE_LEAVES: Item<u64> = Item::new("tree_leaves");

impl Config {
    pub fn default_new(mock_verify: bool, zkid: Option<u64>, allowed_root: Option<Binary>) -> Self {
        Self {
            mock_verify,
            zkid,
            allowed_root,
            next_pool_id: 1,
        }
    }
}

pub fn pool_active(status: &PoolStatus) -> bool {
    matches!(status, PoolStatus::Active)
}
