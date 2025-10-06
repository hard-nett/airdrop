# Scripts

These are helping scripts for un
This script checks for and sums any duplicate allocation together to generate a csv file that does not contain duplicate addresses.

| Command   | Description|Files Created |
|------------|----------| -- |
| `node main.js -1`| Processes data from eligible projects holder distributions, based on expected distribution parameters defined.|
| `node main.js -2`| Process genesis allocations (BCNA & ATOM) based on points & percentiles |
| `node main.js -3`| Process headstash allocations based on points & percentiles  |
| `node main.js -4`| Process distribution from an exported state   |
 

|----------|----------|----------| |

## Adding A New Community For Headstash (EVM based)

### Step 1: Distribution Snapshot

- Date snapshot was taken
- .csv file with `addr,amount` as headers
- create new folder in `../headstash/communities/<new-community>`

### Step 2: Percentile Distribution Calculation

- calculate desired points for percentile range & desired token per point

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
