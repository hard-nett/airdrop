# Headstash Airdrop: Cannabis Culture Projects

## The Goal

**Allocate ownership to those pre-invested in web3 & cannabis communities.**

This event has been pre-organized by community members, and will be voted on via the terp network governance process.

> We believe that those who are owners of existing cannabis brands & communities tokens that are using blockchain technology are not only just acquiring ownership of these projects tokens for the brands potential fiscal return, but more broadly due to recognizing nature of the benefit’s these technologies provide, specifically in permissionless sovereignty. **Choosing to have ownership of specific digital assets is an extension of free-speech, though consensual actions.**. We want to show our respect to those leading the way, having skin-in-the-game, and contributing to the ecosystem that emerges around the cannabis plant.

Our awareness is not omnipotent, so there certainly are projects and communities that resonate with the statement above, but are not included in this distribution. We ask those communities not included to make use of Terp Network none-the-less, and contirbute to a free-market through contributions as we progress.

## Process

### 1. Data Collection

First, any community to potentially be included in the airdrop must have their token holders data exported and provided in the [holders](./holders/) folder, with the timestamp of the snapshot taken. If you would like to suggest a community to be included in the airdrop, please open a new PR on this repo.

### 2. Point Allocation

Once the holder information has been aggregated and added to this repository, we can utilize a piecewise linear function to find a [fair-tiered distribution](./points/) of token holders within each community.

 A piecewise liner curve was used to generalize ranges in each community, to which we then allocated points. This was used as a data point helping to determine a fair point distribution between communities and the range of how invested various token holders are.

 > Point allocations for the percentile ranges were normallized such that when an address was eligilbe for multiple communities, we can simply sum the points between each community together, greatly simplifying the resulting allocation calculation.

**Piecewise linear curves also help minimize over-allocating ownership to massive whales & project owners.**

### 4. Governance, Deploying & Claiming

#### The Problem

We initally proposed a vanilla cosmwasm smart contract to power the distribution and claiming of tokens on Terp Network. We recognized once deployed that this did not respect the privacy of the individuals who would like to participate, as claiming tokens require a signed message by the eligilbe wallet, containing the address of the wallet claiming. This creates an on-chain association graph between the wallets, and since we can avoid this, we belive it is worth the extra effort to do just that.

#### Possible Solution #1: Secret Network + IBC-Cosmwasm

Our solution was to make use of IBC & Secret Networks 'privacy preserving VM layer' to make use of encrypted smart contract state to obfuscate these signatures claiming tokens, however after experimentation & reflection, our position is that broadcasting these signatures permanently onto another networks state still does not fully align with the intention of respecting the eligible claimers privacy, especially as we move towards a post-quantum world.

> more details on the idea behind this step can be found in our [commonwealth post here.](https://common.xyz/terp-network/discussion/24629-secret-headstash-airdrop-workflow)

#### Possible Solution #2: Ephemeral TEE + Zk-Snarks + DA (for redundancy/recovery)

Now, our current solution is to make use of **verifiable, ephemeral, Trusted-Execution-Environments** for claiming and redemption of tokens. This design is similar to the design of using Secret Network, however this method will make use of a completely sovereign side-car of a TEE, a Cosmwasm VM, and also a framework making use of zk-snarks for recoverable/rotatable TEE instances!

> This is our current experimentation step, and is well, experimental. We will stand on the shoulders of giants (our ecosystem peers) to curate a product suitable for these needs ::)
