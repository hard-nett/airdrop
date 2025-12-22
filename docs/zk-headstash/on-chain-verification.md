
# On-Chain Verification

## Option 1: Custom WasmVM




## Option 2: Vote-Extension + Custom Module

- x/headstash
  - interface with wasm module + vote extensions
  - stored headstash contract proofs recorded by vote-extensions to state, accessable by cosmwasm contract queries
  - calls sudo entrypoint for headstash contract to process claims each block

headstash-api:

- api service performing proof validation and signature aggreagation.

headstsah-sidecar:

- lightweight runtime validators use that communicates with headstash-api aggregates proof claims , includes and
