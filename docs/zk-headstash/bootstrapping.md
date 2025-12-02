# Bootstrapping A Headstash

## HeadstashAPI

- allows headstash data to be registered and uploaded after generated

### 1. Genesis Distribution Tree Construction

First, the tree is constructed by separating separating all distributions into the smallest amount of fixed denomination notes, for each token allocated (The Headstash Airdrop distributes TERP & THIOL, so there is a set of leaves for each address due to their allocation including 2 tokens.). We generate leaves in an non-interactive manner using the pre-known public information available:

### Step 2: Deploy Verifiable Proxy Service

This steps involves deploying the verifiable service used to route claiming actions on-chain for proof validation,nullifier & note commitment storage, and also token distributions.

#### Upload/Instantiate Zk-Headstash Contract

#### Create/Seed Tokens To Distribute

#### Register Service Owned Address w/ Smart-Account

The proxy service must control an on-chain account, in order to register the zk-headstash contract as its on-chain authenticator.

- **single feegrant/payment address**: Instead of allocating feegrants to each public address claiming headstashes, we can allocate a single feegrant to the services owned account.

- **granularizes sequence of operations**: authenticators require specific steps of a tx broadcasted to be performed within the scope defined by the x/smart-account authentication module. This allows us to separate the signature verification coming from the off-chain service from the users proof verification sequence.

### Step 3: Eligible Addresses Generate Proofs for claiming

In the proof circuit, the user generates a proof that essentially encodes the following statements:

- They own `addr_eligible` via `epk` `esk` pairing.
- The note being spent corresponds to an unclaimed entry in the genesis Merkle tree.
- The nullifier for the note being spent has been accurately defined to this note.

### Step 4: Claim Spent Note By Contract Call

A user will broadcast their proof generated to the verifiable service, which has feegrants registered under an account it controls to cover gas cost to broadcast to a chain state. The smart contract will enforce that a nullifier doesnt yet exist
