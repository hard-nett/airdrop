# Airdrop - Cannabis Culture Projects

## Introduction 
An airdrop to the token holders of projects focused on web-3 & cannabis culture infusion is an action that directly aligns with a project rooted in progressive decentralization.

This public repository contains all of the data aggregated from various blockchain ecosystem of the point system, wallet addresses, allocations, and processes that collectively makes up the second leg of Terp Network airdrop cycle.

## Process
### 1. Data Collection
First, any community to potentially be included in the airdrop must have their token holders data exported and provided in the [holders](./holders/) folder, with the timestamp of the snapshot taken. If you would like to suggest a community to be included in the airdrop, please open a new PR on this repo. 

### 2. Point Allocation
Once the holder information has been aggregated and added to this repository, we can utilize a piecewise linear function to find a fair-tiered distribution of token holders within each community. 


### 3. Point to Token Conversion
For this next airdrop cycle, the TerpNET Foundation DAO will propose to allocate 15% (63 Million) of the total supply of TERP & THIOL between the token holders included. 

This can make a fair point distribution to be found by normalizing data between communities included in the airdrop, by diving the expected number of tokens to a specific community, by the total points allocated to that community. 

This creates a ratio between each community that can be compared and modified relative to the number of token holders, in a way that will be deemed fair by consnesus of the community.

### 4. Eth to Evmos Wallet Address Conversion

Evmos is an EVM chain in the cosmos, which has native metamask support. To learn more about the wallet compatibility of Evmos, click [here](https://docs.evmos.org/use/wallet).

For this step, all eth public wallet addresses must be converted to their evmos counterparts. Converted data must be available in the [addresses](./addresses/) folder, and will include the points & token conversion data as well.

### 5. Prepare Smart Contract Creation Plan
This step is where the escrow smart contract will planned and mapped out, to be included in the next step. 

### 6. Verify Consensus
This is when all data and steps can be verified using the on-chain governance procedure. To learn more, check our [Governance Proposal Framework](https://docs.terp.network/overview/governance).

### 7. Airdrop/Escrow Smart Contract Developed
If we have consensus of the parameters of the second airdrop cycle, then the smart contract that will power this airdrop will be deployed and contain the final parameters of the airdrop.

## Next Steps
