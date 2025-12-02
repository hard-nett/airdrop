# TODO

## Testing Suite

- implmenet overall testing suite structure for all crates in workspace

## Headstash Indexer/API

- we need to store host, and retrieve data related to headstash distributions. Use cnardium + commonware node for storage and api (see ergors)
- canonical workflow for a pubkey to search for any headstashes they are eligible for (used when snap-pugin syncs on first install and any time plugin request to sync)

## Snap-n-pull - MVP

- refactor msg and proof input building logic with use of the HeadstashSuite orchestration client that has the headstash traits implemented (we are replacing the zcash specification that exists due tto this being a fork of an existing metamask-snap for zcash, but we are going to use it for our purposes)

- broadcast msgs to network using the dedicated smart-account authenticator (using non_crititcal_tx_extension) (uses headstash contract address as authenticator)

## HeadstashSuite

- implement grpc request for headstash api 
- sync with headstash api
