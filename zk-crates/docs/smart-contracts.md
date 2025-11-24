# Zk-Headstash

- nursery: registry & launchpad for new headstash instances
- headstash: distribution contract

## Launchpad x Instance Framework

Single smart contract for creating multiple headstash contract instances.

- trustlessness parameters:
  - distribution csv hash (ipfs cid, hash etc)
  - governance parameters
  - proof verification parameters (verifying key, constants)
- minting methods (new/existing)
  - new: tokenfactory integration
  - existing: ensure contract has balance dedicated to user
- acts as registry for headstash to query:
  - filter by creators, name, tokens, parameters, etc.
- smart-account authentication support: wire in authenticator for DAOs and accounts

### Creating New Headstash

- preparing public allocations:
  - holder distribution snapshots, public key scraping tooling, merkle tree generation access, ipfs storage and preparation, token branding image & metadata preparartion
- creating new smart contract instance: authorize via wallet, propose via DAO

## Headstash Instance

- created by nursery, main contraint maintaining token state, nullifier trees and params
