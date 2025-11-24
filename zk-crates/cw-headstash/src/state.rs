use cosmwasm_schema::serde;
use cosmwasm_std::{Addr, Binary, Deps, Order, StdResult};
use cw_storage_plus::{
    Bound, Bounder, Index, IndexList, IndexedMap, Item, KeyDeserialize, Map, MultiIndex,
    SnapshotItem, SnapshotMap, Strategy,
};

#[cosmwasm_schema::cw_serde]
pub struct HeadstashParams {
    pub wavs: Addr,
    pub nonce: u64,
}

/// Map nonce -> indexList of wav operator bls12-381
/// we want to be able to query:
/// - the list of operators given an array of their positions in the index
/// - the list of operators at a given nonce
/// Stores: nonce -> list of operator indices (e.g., positions in validator set)
pub const WAVS_OPERATORS: Map<u64, Vec<String>> = Map::new("wavs_operators");
pub const HEADSTASH_PARAMS: Item<HeadstashParams> = Item::new("headstash_params");

// binary encoded Fp
pub(crate) const GENESIS_TREE_ROOT: Item<Binary> = Item::new("root_gen_tree");
pub(crate) const COMMITMENT_TREE_ROOT: Item<Binary> = Item::new("root_cm_tree");
// Ox hex encoded Fp nullifer in
pub(crate) const NULLIFIERS: Map<String, ()> = Map::new("nullifiers");

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
