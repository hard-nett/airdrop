# Airdrop - Terp Network
## Overview: Inital Token Distribution
The current suggested genesis file for Terp Network includes a mixture of [**ATOM delegators**](./interchain/gaia.csv),[**BCNA**](./interchain/bcna_delegators.csv),[**TERP OG Participants**](./points/terp-og.md), [**Scavenger Hunt Participants**](./points/scavenger-hunt.md), **Genesis Validators**, and **Protocol Treasury Tokens**.

Each inital account with TERP (excluding Protocol Treasury & 1 Terp for each Genesis Validator) will be vesting until `1697803200` UNIX time (Oct, 20th, 2023).


### Genesis Distribution Details
| Project                     | Points     | # of addresses | Total Tokens (TERP & THIOL)  | TPP (Token per point)
|-----------------------------|------------|----------------|---------------|-----|
| ATOM                        | `1`          | `114,846`        | `13,276,409.490870` | `115.601845`
| ATOM                        | `2`          | `40,877`         | `9,450,913.236130`  | `115.601845`
| ATOM                        | `3`          | `8,147`          | `2,825,424.701792`  | `115.601845`
| ATOM + BCNA                 | `4`          | `1,443 `         | `8,013,565.901289`  | `1,388.351680`
| ATOM + BCNA                 | `5`          | `264`            | `1,496,618.262216`  | `1,133.8017138`
| ATOM + BCNA                 | `6`          | `79`             | `451,199.612292`    | `951.897916`
| BCNA                        | `6`          | `100`            | `1,087,560.976`     | `1,812.601626`
| ATOM + BCNA                 | `7`          | `4`              | `43,964.846400`     | `1,570.173085`
| ATOM + BCNA                 | `8`          | `4`              | `33,320.440350`     | `1,041.263760`
| ATOM + BCNA                 | `9`          | `4`              | `44,889.661160`     | `1,246.935032`
| BCNA                        | `9`          | `4`              | `65,253.658520`     | `1,812.601625`
| TERP OG & SCAVENGER HUNT    | `1 - 1.34`   | `43`             | `111,913.879345`    | ~`2,263.172484`
| GENTX                       | `1`          | `4`              | `4`                 | `1`
| **TOTAL**                   | -          |  **`165,819`**     | **`36,901,038.666364`** | -

### Genesis Distribution Normalization
To normalize the TPP for each type of token holder, we can use the following formula to calculate how many additional tokens should be distirbuted to holders in each category 

$NewTokenPerPoint = (TotalTokens + Y) ÷  NumAddrs ÷ Points$

where we can calcluate the additional tokens by:

$Y = (NewTokenPerPoint * NumAddrs * Points) - TotalTokens$


Leaving us with the following additional tokens to distribute to each category of genesis addrs:
| Project                  |Points   | Additional Tokens  | New Total | New Token Per Addr  | New TPP | Diff in TPP (Token per point)
|-----------------------------|---|------------|----------------|---------------|-----| --- |
| ATOM                      | -  | -        | -      | - | - |
| ATOM                      | -  |-        | -       | - | - |
| ATOM                      | -  |-        | -         | - | - |
| ATOM + BCNA               | -  |-        | -       | -  | - | - |
| ATOM + BCNA               |`5` | `336,005.955384`|`1,832,624.2176`| `6,941.7584`| `1,388.351680` |`254.549966`|
| ATOM + BCNA               |`6` |`206,879.084028`|`658,078.69632`|`8,330.11008`|`1,388.351680`| `436.453764`|
| BCNA                      | -  | - | - | - | - |
| ATOM + BCNA               |`7` | `10,024.850788`| `53,989.697188` | `13,497.424297` | `1,928.203471`|`358.030386` |
| ATOM + BCNA               |`8` | `28,382.070722`|`61,702.511072` |`15,425.627768`|`1,928.203471` | `886.939711` |
| ATOM + BCNA               |`9` | `24,525.663796`| `69,415.324956`| `17,353.831239`| `1,928.203471` | `681.268439` |
| BCNA                      | -  | - | -   | - | 
| TERP OG & SCAVENGER HUNT  | -  | - | -  | - | 
| GENTX                     | -  | - | - | - |
| **TOTAL**                 | -  | `605,817.624718`| - | - | - |


## Airdrop Cycle 2: Cannabis Culture Communities 



| Project                                           | Unique Addresses  | Date Of Snapshot   | Total Tokens Allocated | Average Token Per Point |
|---------------------------------------------------|-------------------|-------------------|-------------------| -------------------| 
| [Chronic Token](./eth/communities/cht.csv)        | 1,256             | Oct 11th, 2022    | 7,615,897.44 TERP & THIOL |
| [Crypto Canna Club](./eth/communities/ccc.csv)    | 4,405             | Oct 11th, 2022    | 12,706,127.17 TERP & THIOL |
| [MonsterBuds](./eth/communities/the-buds.csv)     | 3,385             | Oct 11th, 2022    | 5,746,617.43  TERP & THIOL |
| [Hippie Life Krew](./eth/communities/hlk.csv)     | 342               | June 16th, 2023   | 807,361.96  TERP & THIOL |
| [N8 Free Mint Holders](./eth/communities/n8.csv)  | 316               | Oct 11th, 2022    | 735000.000000   TERP & THIOL |
| [Secret Sesh](./eth/communities/sesh.csv)         | 779               | Oct 11th, 2022    | 4200000.000000  TERP & THIOL |
| [Galaktic Gang](./eth/communities/gg.csv)         | 2566              | Oct 11th, 2022    | 6,306,752.41  TERP & THIOL |
| [Buddah Bears](./eth/communities/bb.csv)          | 2453              |  <>               | 6,300,000.00  TERP & THIOL |
| [Re-Bud](./eth/communities/rebud.csv)             | 585               | <>                | 927,127.66  TERP & THIOL |
| [Stoned Ape Club](./eth/communities/rebud.csv)    | 2059              | Oct 24th, 2024    | 927,127.66  TERP & THIOL |

### Check [here](./eth/README.md) to learn about the parameters for the airdrop to token holders of projects supporting the vision of web-3 + cannabis culture.


## Todo
- scripts: create scripts that calculate genesis distribution for accuracy
- scripts: create scripts to determine additional allocation for genesis distribution that balances inital distribution ratio
- scripts: create scripts that form accurate final distribution file to use for deployment of adding eligilbe addrs to headstash
- docs: calculate expected tokens for airdrop, including additional random rewards