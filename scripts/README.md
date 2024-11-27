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

### Step 1: Distribution Snapshot 
- Date snapshot was taken
- .csv file with `addr,amount` as headers
- create new folder in `../headstash/communities/<new-community>`

### Step 2: Percentile Distribution Calculation 
- calculate points for percentile range
- calculate token per point (propose total allocation for community)
### Step 3: Addition To Scripts

```js
    {
        csv: "../headstash/communities/<new-community>/<distribution>.csv", 
        points: [
            { points: 1, min: 1, max: 1 },   // 1st - nth percentile
            { points: 2, min: 2, max: 9 }, // n+1 - m percentile
            { points: 3, min: 10, max: 10 } // m+1 - 100th percentile
        ], 
        tpp: 1660.079051 // calculated token per point
    },
```

## Adding A New Community For Headstash (Solana based)