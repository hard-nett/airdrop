# Mesh-API

A Verifiable Service mesh of nodes acting an a proxy for broadcasting proofs on chain unlocks a number of UX benefits:

## Features

- verifiable api powered by WAVS
- opt-in data provisioning for headstash instances metadata (ipfs wrapper compaitible)
- makes use of network and mesh design of ergors nodes for tick-like network consensus on actions.
- keep client server lightweight, define server query and msg as one server in proto file
- out of bounds for wavs runtime verification for cosmos-chain web-socket with rpc node for stateful updates to db (for recording new headstash instances and performing stateful updates when contracts are funded)
- dedicated API for broadcasting claims
- minimizing fee-grants
- delayed claiming support

### WAVS

### IPFS Compatible

Node operators are able to enable an ipfs server wrapper around their nodes, and participate in providing storage of the headstash instance metadata files and other extended markets.

### Mesh Consensus

### Lightweight Client Server Interface

### Cosmos-Indexer

- Allows subscription of specific events for cosmos node
- Ensure we are always in sync with latests blocks via peer check of other rpc nodes
- fallback/retry on different peer via reuqesting for previous blocks

### Delayed Write Buffer Market

Allow users to particiapte in enchancing privacy by delay between network call and transaction settlement without compromise integrity of privacy during claim pending

### FeeGrant Market

- x402 api for feegrant provisioning. Non deterministic, programmable per api-node, unless requesting feegrant from authenticator node

- cosmos-sdk cosmwasm MaxCalls feegrant 

/// MaxCallsLimit limited number of calls to the contract. No funds transferable.
/// Since: wasmd 0.30
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, Copy, PartialEq, ::prost::Message)]
pub struct MaxCallsLimit {
    /// Remaining number that is decremented on each execution
    #[prost(uint64, tag = "1")]
    pub remaining: u64,
}
impl ::prost::Name for MaxCallsLimit {
    const NAME: &'static str = "MaxCallsLimit";
    const PACKAGE: &'static str = "cosmwasm.wasm.v1";
    fn full_name() -> ::prost::alloc::string::String {
        "cosmwasm.wasm.v1.MaxCallsLimit".into()
    }
    fn type_url() -> ::prost::alloc::string::String {
        "/cosmwasm.wasm.v1.MaxCallsLimit".into()
    }
}