# Point Allocations


## Step 1: Piecewise Linear Function

Each projects percentile range will either be allocated 1,2, or 3 points.

This gives us for each project:

- total # of points
- total # of holders

## Step 2: Multi-Community Fairness Normalization

We then want to normalize the distribution points between all of the projects, so that we have a fair allocation of tokens to distribute between each project. Note that fair is defined soley as a reflection of the distribution of holders within each project. No other metrics were taken into account.

we experimented with various normalization methods:

- **BaseAllocation**: Total pool of points (or tokens) available for distribution to all projects.
- **HolderCount**: # of holders within a specific project
- **AllHolderCounts**: # of all projects holders


1. Square Root Scaling Normalization

```math
ProjectPoints = BaseAllocation × √(HolderCount) / Σ(√(AllHolderCounts))
```

2. Logarithmic Scaling

```math
ProjectPoints = BaseAllocation × log(HolderCount + 1) / Σ(log(AllHolderCounts + 1))
```

*After experimenting, its seems that the square root scaling reflects more accurately the totaly % allocated to porjects based on the hodler size. This is a bias that we wanbt to propose influences the distribution, as the large holder projects we consider are more decentralized in token ownership.*


## Step 3: Governance Proposal
