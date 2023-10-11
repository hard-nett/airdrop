# Airdrop - Cannabis Culture Projects

## The Goal
**Allocate ownership to those pre-invested in web3 & cannabis communities.**

This event has been pre-organized by community members, and will be voted on via the terp network governance process.

It is believed that those who are owners of existing cannabis brands & communities tokens that are using blockchain technology are not just acquiring ownership of these projects tokens for the brands potential fiscal return, but more broadly due to the nature of the benefit’s these technologies provide, specifically in permissionless sovereignty.    

## Process
### 1. Data Collection
First, any community to potentially be included in the airdrop must have their token holders data exported and provided in the [holders](./holders/) folder, with the timestamp of the snapshot taken. If you would like to suggest a community to be included in the airdrop, please open a new PR on this repo. 

### 2. Point Allocation
Once the holder information has been aggregated and added to this repository, we can utilize a piecewise linear function to find a [fair-tiered distribution](./points/) of token holders within each community. 

A piecewise liner curve was used to generalize ranges in each community, to which we then allocated points. This was used as a data point helping to determine a fair point distribution between communities and the range of how invested various token holders are. 

Piecewise linear curves also help minimize over-allocating ownership to massive whales & project owners.


### 4. Eth to Terp Wallet Address Conversion

A UI for users to connect to & verify their airdrop allocation will be available, and will utilize the Metamask Snap Functionality now available thanks to a number of teams in the cosmos! 

To determine the public address associated with an existing address, there are a number of tools to handle [bech32](https://github.com/atmoner/cosmos-bech32) & [address converters](https://www.npmjs.com/package/@evmos/address-converter).

### 5. TODO: Smart Contract? Gov Prop?

### 6. Verify Consensus
This is when all data and steps can be verified using the on-chain governance procedure. To learn more, check our [Governance Proposal Framework](https://docs.terp.network/overview/governance).
