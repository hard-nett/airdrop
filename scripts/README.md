# Scripts

This script checks for and sums any duplicate allocation together to generate a csv file that does not contain duplicate addresses.

| Command   | Description| 
|------------|----------|
| `node main.js -1 `| Process solana nft holder distribution (used for SAC)  | 
| `node main.js -2 `| Encode Processed data from `-1` into encoded format (cw-headstash requires sol addr and offline signature as base64 encoded) | 
| `node main.js -3 `| Process genesis allocations based on points & percentiles  | 
| `node main.js -4 `| Process headstash allocations based on points & percentiles  | 
| `node main.js -5 `| Process distribution from an exported state   | 

|----------|----------|----------| |


## Adding A New Community For Headstash (EVM based)
## Adding A New Community For Headstash (Solana based)