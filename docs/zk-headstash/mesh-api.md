# Mesh-API

we are tasked to implement a group of new features to our node. These features
  introduce new server api routes, and are described at a high level here[Pasted text
  #1 +111 lines]. lets start with the proof verification. in
  packages/cw-ho/src/headstash/claim.rs ive defined the method that will verify proofs
  and then save them to storage to be processed if valid. we expect ethe proto defined
  MsgClaimHeadstash to be used that carries the proof public inputs and the proof
  itself being verified, and we expect the proof circuiit keys to be accessable in our
  nodes storage. This means headstashes had to have been registered to the node before
  proofs can be claimed. lets implement functions that register a new headsatsh
  instance into our storage node and perform all of the actions needed when a new
  headstash is registered. specifically, we will need to query an ipfs cid that will
  contain the verifying keys and metadata about the headstash, and then save a
  reference to a headstash by the contract addr 

  
 *A Verifiable Service mesh of nodes acting an a proxy for broadcasting proofs and other data.*

- verifiable api powered by WAVS
- opt-in data provisioning for headstash instances metadata (ipfs wrapper compaitible)
- makes use of network and mesh design of ergors nodes for tick-like network consensus on actions.
- keep client server lightweight, define server query and msg as one server in proto file
- out of bounds for wavs runtime verification for cosmos-chain web-socket with rpc node for stateful updates to db (for recording new headstash instances and performing stateful updates when contracts are funded)
- dedicated API for broadcasting claims
- minimizing fee-grants
- delayed claiming support

## WAVS

### Verifiable Proof Verification

Cosmwasm cant perform pallas curve ops on-chain effeciently, so we validate proof in wavs, and then bind wavs-operator set msg to proofs via hashing so we pair a wavs action with a set of stateful events the wavs operator set authorizes each block.

`validate-proofs --> sign-hash of set of nullifier,msg tuples --> verify-in contract --> stateful events`

- mempool that allows for pre-verification/storage of proof verification and nullifier preparation

## Headstash Storage + IPFS Compatible

Node operators are able to enable an ipfs server wrapper around their nodes, and participate in providing storage of the headstash instance metadata files and other extended markets.

- API definition for uploading files to store for headstashes
- API definition for granting users access to upload files to store (default to anyone able to access api)
- feature to pin to ipfs gateway & respond with metadata

new storage layers:

    - headstash metadata classification 
    - pending headstashes to claim 
    - 

### Mesh Consensus

commonware network for node identity and communication

## Vote-Extension Server

*we are going to doing something fun.*

were going to make use of a side-car service that will allow any validator to participate in enhancing the censorship resistant to tx settlement of claiming headsatshes, by operating vote-extension servers that create binding hashes via blake3 of the nullifiers and msgs to be verified on chain much more effeciently.

*because we are using a wavs service, this proof verification can be done off-chain without worry that the verifcation process was corrupted*

### Design

- oracle connected to validator and curates the voteExtension containing sets of nullifiers to submit to headstash contracts
- allows smart-contracts to be designed for async-claiming *(provide proof via vote-extension, claim via authentication channel/manual smart-contract claim)*

### `ExtendVoteHandler`

`ExtendVoteHandler` returns a handler that extends a vote with the sidecars
pending nullifiers to store. In the case where oracle data is unable to be fetched
or correctly marshalled, the handler will return an empty vote extension to
ensure liveness.

```rs
// `abci/ve/vote_extension.go`: `ExtendVoteHandler() `

```

### `VerifyVoteExtensionHandler`

`VerifyVoteExtensionHandler` returns a handler that verifies the vote extension provided by
a validator is valid. In the case when the vote extension is empty, we return ACCEPT. This means
that the validator may have been unable to fetch nullifiers from the oracle and is voting an empty vote extension.

### Lightweight Client Server Interface

### Cosmos-Indexer

- Allows subscription of specific events for cosmos node
- Ensure we are always in sync with latests blocks via peer check of other rpc nodes
- fallback/retry on different peer via reuqesting for previous blocks

### Delayed Write Buffer Market

Allow users to particiapte in enchancing privacy by delay between network call and transaction settlement without compromise integrity of privacy during claim pending

<!-- 
### FeeGrant Market

- x402 api for feegrant provisioning. Non deterministic, programmable per api-node, unless requesting feegrant from authenticator node
- cosmos-sdk cosmwasm MaxCalls feegrant

```
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
``` -->
