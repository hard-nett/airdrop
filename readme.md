# Airdrop - Terp Network
## Overview: Inital Token Distribution
The current suggested genesis file for Terp Network includes a mixture of [**ATOM delegators**](./interchain/gaia.csv),[**BCNA**](./interchain/bcna_delegators.csv),[**TERP OG Participants**](./points/terp-og.md), [**Scavenger Hunt Participants**](./points/scavenger-hunt.md), **Genesis Validators**, and **Protocol Treasury Tokens**.

Each inital account with TERP (excluding Protocol Treasury & 1 Terp for each Genesis Validator) will be vesting until `1697803200` UNIX time (Oct, 20th, 2023).


### Genesis Distribution Details
| Project | Max Tokens in Percentile Range | Points     | # of addresses | Total Tokens (TERP & THIOL)  | TPP (Token per point) | Tokens 
|---------------------------|------|------------|----------------|---------------|-----| --- |
| ATOM  |   `56.290873`     | `1`  | `114,846`  | `13,276,409.490870` | `115.601845` | `115.601845` |
| ATOM  |   `581.059663`    | `2`  | `40,877`   | `9,450,913.236130`  | `115.601845` | `231.203690` |
| ATOM  |`11,695,142.809644`|`3`| `8,147` | `2,825,424.701792`    | `115.601845` | `346.805536` |
| BCNA  | `56.104789`   | `3`  | `1073`      | `5,834,764.634094` | `1,812.601626`|  `5,437.804878` | 
| ATOM(1) + BCNA(3)    |  -      | `4`| `1,443` * *`342`*| `8,013,565.901289`  | `1,388.351680` | `5,553.40672` |
| ATOM(2) + BCNA(3)    | -      | `5`| `264`| `1,496,618.262216`  | `1,133.8017138` |`5,669.008569` |
| ATOM(3) + BCNA(3)    | -     | `6`          | `79`             | `451,199.612292`    | `951.897916` |`5,784.610414` |
| BCNA | `3,835.224107`| `6`          | `100`            | `1,087,560.976`     | `1,812.601626` | `10,875.609760` |
| ATOM(1) + BCNA(6)  | -        | `7`          | `4`  * *`264`*             | `43,964.846400`     | `1,570.173085` | -|
| ATOM(2) + BCNA(6)  | -        | `8`          | `4`              | `33,320.440350`     | `1,041.263760` | - |
| ATOM(3) + BCNA(6) | -           | `9`          | `4`              | `44,889.661160`     | `1,246.935032` | - |
| BCNA   |`32,910,049.646754` | `9`          | `4`              | `65,253.658520`     | `1,812.601625` | - |
| TERP OG & SCAVENGER HUNT | -  | `1 - 1.34`   | `43`             | `111,913.879345`    | ~`2,263.172484` | - |
| GENTX         |              | `1`          | `4`              | `4`                 | `1` | - |
| **TOTAL**                   | -          |  **`165,819`**     | **`36,901,038.666364`** | - | - | -| 

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



| Project                                           | Unique Addresses  | Date Of Snapshot   | Est. Total TERP | Average Token Per Point |
|---------------------------------------------------|-------------------|-------------------|-------------------| -------------------| 
| [Chronic Token](./headstash/communities/chronic-token/cht.csv)        | 1,256             | Oct 11th, 2022    | 7,615,897.44 TERP & THIOL |
| [Crypto Canna Club](./headstash/communities/crypto-canna-club/ccc.csv)| 4,405             | Oct 11th, 2022    | 12,706,127.17 TERP & THIOL |
| [MonsterBuds](./headstash/communities/monster-buds/the-buds.csv)      | 3,385             | Oct 11th, 2022    | 5,746,617.43  TERP & THIOL |
| [Hippie Life Krew](./headstash/communities/hippie-life-krew/hlk.csv)  | 342               | June 16th, 2023   | 807,361.96  TERP & THIOL |
| [Secret Sesh](./headstash/communities/secret-sesh/sesh.csv)           | 779               | Oct 11th, 2022    | 4,200,000.000000  TERP & THIOL |
| [Galaktic Gang](./headstash/communities/galacktic-gang/gg.csv)        | 2566              | Oct 11th, 2022    | 6,306,752.41  TERP & THIOL |
| [Buddah Bears](./headstash/communities/buddah-bears/bb.csv)           | 2453              | June 17th, 2023   | 6,300,000.00  TERP & THIOL |
| [Re-Bud](./headstash/communities/rebud/rebud.csv)                     | 585               | Jan 23rd,2024     | 927,127.66  TERP & THIOL |
| [Stoned Ape Club](./headstash/communities/stoned-ape-club/sac.csv)    | 2059              | Oct 24th, 2024    | 927,127.66  TERP & THIOL |
| [Wake-And-Bake](./headstash/communities/wake-and-bake/wab.csv)        | 154               | Nov 18th, 2024     | -  TERP & THIOL |
| [Cannabuddies](./headstash/communities/cannabuddies/cb.csv)           | 238               | Nov 18th, 2024     | -  TERP & THIOL |
| [Special-K](./headstash/communities/special-k/cb.csv)                 | 46                | Nov 18th, 2024     | -  TERP & THIOL |
| [CryptoWizards](./headstash/communities/cryptowizards/cb.csv)         | 55                | Nov 18th, 2024     | -  TERP & THIOL |
| [N8](./headstash/communities/n8/cb.csv)                               | 316               | June 17th, 2023    | -  TERP & THIOL |
| [Heady Pipe society](./headstash/communities/heady-pipe-society/cb.csv)| 23               | Nov 18th, 2024     | -  TERP & THIOL |
| [Carta: Beta Gang](./headstash/communities/carta-beta-gang/cb.csv)    | 157 | Nov 19th, 2024  | -  TERP & THIOL |
| [The Shurlok Holms Collection](./headstash/communities/shurlok/shurlok.csv)| 33 | Nov 26th, 2024  | -  TERP & THIOL |

### Check [here](./headstash/README.md) to learn about the parameters for the airdrop to token holders of projects supporting the vision of web-3 + cannabis culture.


## Todo
__~~- scripts: create scripts that calculate genesis distribution for accuracy~~__\
__~~- scripts: create scripts that form accurate headstash final distribution file~~__\
__- scripts: create scripts taking network export, compare genesis holders balance with expected balance form new scripts__\
__- scripts: create scripts to determine additional allocation for genesis distribution that balances inital distribution ratio__\
__- docs: calculate expected tokens for airdrop, including additional random rewards, improve details regarding headstash airdrop__\
