# Genesis Distribution Patch 

It has been noticed that the genesis distribution proposed and deployed to morocco-1 was not accurated distributed. The intended distribution ratio was the following:
- Cosmos Hub Holders:  `6.11 % of 420 Million TERP`
- Bitcanna Holders:  `1.911 % of 420 Million TERP`
- Terp Og participants: `53,508 TERP`
- Scavenger Hunt participants: `53,508 TERP`
- Terp Network Foundation: `16% of 420 Million TERP`

There are now scripts located in this repository that will calucate an accurate distribution rate for these values, and compare the orignial genesis distribution to determine the additional allocations to set these values to be much more accurate to where we have aimed to be originally.

### Step 1: Process Genesis Distribution 

running the following command:
```sh
node main.js -3
```
Will take the snapshot distributions `gaia.csv` & `bcna_delegators.csv`, and determine the allocations to be recieved, printing the results into `scripts-data/final_output.csv`. A `points_distribution.csv` file will be generated during this function, which displays the points allocated for each projects percentile range. Also, a `total-points.csv` file is generated that gives us a count of the total points, tokens per point based on desired % of supply, and the total amount of tokens actually to be distributed.

### Step 2: Analyze step-1 data with live data from `morocco-1`

We can obtain an export of the data from a full node of Terp Network via `terpd export`. This will let us then compare the discrepencies from what acutally was distributed, to what should be distributed. Run the following:
```sh
node main.js -5
```
This will take the exported state, and sort the accounts by whether or not they have submitted atleast 1 transaction on-chain, `updated_greater_zero_sequence_accounts.json` & `updated_zero_sequence_accounts.json`. With these files, we can now calculate the differences between the original amount allocated on block height 1 of Terp Network, with our new more accurate calculation,  via:
```sh 
node main.js -7
```
This will create a new file `patched-distribution.csv` that contains the accurate distribution. Now we can determine the amount of additional (or excess) tokens to be distributed to holders. run:
```sh
node main.js -11
```
Note that if a wallet address has been allocated an excess tokens originally, we will not propose to clawback these tokens on behalf of our mistake for this circumstance.
