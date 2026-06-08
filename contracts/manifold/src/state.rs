use cosmwasm_std::Addr;
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};

use crate::msg::HeadstashContract;

pub const HEADSTASH_CODE_ID: Item<u64> = Item::new("headstash_code_id");

// Indexes for tracking contracts
pub struct ContractIndexes<'a> {
    pub instantiator: MultiIndex<'a, Addr, HeadstashContract, Addr>,
}

impl<'a> IndexList<HeadstashContract> for ContractIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<HeadstashContract>> + '_> {
        let v: Vec<&dyn Index<HeadstashContract>> = vec![&self.instantiator];
        Box::new(v.into_iter())
    }
}

pub fn contracts<'a>() -> IndexedMap<&'a Addr, HeadstashContract, ContractIndexes<'a>> {
    let indexes = ContractIndexes {
        instantiator: MultiIndex::new(
            |_pk: &[u8], d: &HeadstashContract| d.instantiator.clone(),
            "contracts",
            "contracts__instantiator",
        ),
    };
    IndexedMap::new("contracts", indexes)
}
