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
- smart-account authentication support: wire in authenticator for DAOs and accounts to register

### Creating New Headstash

- preparing public allocations:
  - holder distribution snapshots, public key scraping tooling, merkle tree generation access, ipfs storage and preparation, token branding image & metadata preparartion
- creating new smart contract instance: authorize via wallet, propose via DAO

## Headstash Instance

- created by nursery, main contraint maintaining token state, nullifier trees and params

## On-Chain Verification

⏺ Excellent review! This is a detailed analysis of your circuit performance. Let me explain what "hash the inputs into one" means and
   how to fix it:

  The Problem: 254 Instance Columns (Public Inputs)

  The (13, 10, 254) configuration means:

- 13 advice columns (private witness data)
- 10 fixed columns (constants/lookup tables)
- 254 instance columns (public inputs that are visible to everyone)

  Why is this bad?

  Each instance column becomes a public input to your circuit. When verifying on-chain (Ethereum):

- Each public input requires operations like load, add, mul in Solidity
- 254 public inputs = ~1000+ EVM opcodes
- Gas cost skyrockets: ~700k+ gas just to verify

  The Solution: Hash All Public Inputs Into One

  Instead of having 254 separate public inputs, you:

  1. Take all 254 values you want to make public
  2. Hash them together (using Keccak, Poseidon, or Blake3)
  3. Output only the hash as your single public input
  4. Inside the circuit, prove that the 254 private values hash to that public hash

  This way:

- Instance columns: 254 → 1
- Proof size: still ~5KB (no change)
- Gas cost: 700k → ~150k gas (75% reduction!)

  How to Apply This to Your Circuit

  Looking at your circuit in src/circuit.rs, you currently have multiple public inputs like:

- ANCHOR
- CV_NET_X, CV_NET_Y
- NF (nullifier)
- RK_X, RK_Y
- CMX

  Instead of exposing these individually, you should:

  // OLD WAY (bad - 7 public inputs):
  layouter.constrain_instance(anchor.cell(), config.primary, ANCHOR)?;
  layouter.constrain_instance(nf.cell(), config.primary, NF)?;
  layouter.constrain_instance(cmx.cell(), config.primary, CMX)?;
  // ... etc for all 7 values

  // NEW WAY (good - 1 public input):
  // 1. Collect all values you want to make public
  let public_values = vec![anchor, nf, cmx /*...etc...*/];

  // 2. Hash them inside the circuit using Poseidon
  let poseidon_chip = config.poseidon_chip();
  let hash = poseidon_chip.hash(
      layouter.namespace(|| "hash public inputs"),
      public_values.as_slice(),
  )?;

  // 3. Expose only the hash
  layouter.constrain_instance(hash.cell(), config.primary, 0)?;

  Then outside the circuit (in your verifier), you:

  1. Take the 254 values
  2. Hash them the same way
  3. Compare the hash with the single public input

  This makes your circuit mainnet-ready with 75% less gas cost for on-chain verification!

  Would you like me to show you how to implement this specifically for your Headstash circuit?
