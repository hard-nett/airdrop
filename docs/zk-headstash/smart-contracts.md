# **Cw-Headstash – on-chain manifold

**A modular, BLS12-381 threshold-authenticated smart contract authenticator on a custom Cosmos SDK chain using CosmWasm Authenticators (AnteHandler extension)**

### Core Purpose

- off-chain service operator set signature authentication
- proof verification
- headstash instance nullifier set storage medium
- token factory middleware for escrow and distribution

---

### Architecture Overview

```
[CosmWasm Authenticator] ←─── Custom AnteHandler (x/authenticator)
        │
        ├── BLS12-381 Threshold Signature Verification: Off-chain proof verification
        ├── Proof verification
        └── State Management (nullifiers, roots, aggregated keys)
[Headstash Instance] ←─── Instantiated per distribution campaign
        ├── Genesis Merkle Root (SinsemillaHashDomain)
        ├── Nullifier Set (double-spend prevention)
        ├── Token Strategy: New (TokenFactory) or Existing denom
        └── Funds held or minted on-demand

```

---

### Key Features & Precise Behavior

#### 1. CosmWasm Authenticator Lifecycle (Modular Authentication)

The contract implements the full `btsg_account::traits::BtsgAccountTrait` (or equivalent `CosmWasmAuthenticator` interface) and responds to these sudo callbacks:

| Callback                  | Purpose                                                                                     | Implementation Detail |
|---------------------------|---------------------------------------------------------------------------------------------|-----------------------|
| `OnAuthenticatorAdded`    | Register new BLS aggregate keyset + proof-of-possession                                     | Validates each operator's PoP, stores `WavsOperatorSet` |
| `OnAuthenticatorRemoved`  | Clean up params on removal                                                                  | Clears state |
| `Authenticate`            | **Fast path**: Verify BLS12-381 aggregate signature over tx messages                        | Uses `bls12_381_aggregate_g1/g2` + pairing check |
| `Track`                   | No-op (can be used for analytics)                                                           | Returns OK |
| `ConfirmExecution`        | **Slow path**: Execute + verify zk-proof batch (nullifier claims)                           | Calls `extended_authenticate` → verifies Halo2/Plonk proofs + nullifiers |

> This enables **dual-mode authentication**: simple txs use fast BLS, private claims use zk + BLS.

#### 2. BLS12-381 Aggregated Threshold Key Management

- Uses **non-programmable aggregation** (simple sum in G1) – sufficient for known operator sets.
- Each operator submits:  
  - `pubkey ∈ G1` (hex-encoded compressed)  
  - `proof_of_possession = sk · H(pk)` in G2
- On rotation: requires **signed message by current threshold** approving new keyset + new PoPs.
- `WavsOperatorSet` stored immutably per nonce → supports **key rotation with versioning**.

#### 3. Token Strategy: New vs Existing (Fully Enforced)

```rust
#[cw_serde]
pub enum TokenStrategy {
    NewFungible(NewTokenConfig),      // Uses TokenFactory → creates + mints
    ExistingFungible(String),         // Uses pre-existing denom → must pre-fund
}
```

**Strict Enforcement at Instantiate & Claim Time**:

| Strategy           | Instantiate Behavior                                      | Claim-Time Checks                                      |
|--------------------|-----------------------------------------------------------|---------------------------------------------------------|
| `NewFungible`      | Emits `CreateDenom` + `MintTokens` via TokenFactory msgs | No balance check needed (mints on demand)              |
| `ExistingFungible` | Requires contract pre-funded with exact denom             | `query_balance(contract, denom) >= total_claim_amount` |

→ **Fails early** if insufficient balance for `ExistingFungible` before processing any claims.

#### 4. Privacy-Preserving Distribution (Headstash Core)

Each `HeadstashNote` contains:

```rust
pub struct HeadstashNote {
    pub nullifier: Binary,      // zk-SNARK nullifier (prevents double claim)
    pub recipient: String,      // bech32 address to receive funds
    pub amount: Coin,           // amount + denom
    pub proof: Binary,          // Halo2/Plonk proof (groth16 or ultra-plonk)
    pub public_inputs_hash: Binary,  // Recommended: single Poseidon/Keccak hash of all public inputs
}
```

**Execution Flow in `ProcessHeadstash` / `ConfirmExecution`**:

1. For each claim:
   - Verify nullifier not in `NULLIFIERS` map → insert atomically
   - (Optional) Verify Merkle inclusion proof against `GENESIS_TREE_ROOT`
   - Verify zk-proof using pre-loaded verifying key (stored in contract or passed)
   - **Critical**: Use **single hashed public input** (see optimization below)
2. Aggregate all `BankMsg::Send` or `TokenFactoryMsg::MintTokens`
3. Revert entire tx on any failure (nullifier duplicate, bad proof, insufficient balance)

#### 5. On-Chain Verification Optimization (Mandatory for Mainnet)

**Problem**: Original circuit had 254+ public inputs → ~700k–1M gas per verification  
**Solution**: Hash all public inputs into **one** → reduces to ~120–180k gas

**Recommended Public Inputs Hash (inside circuit)**:

```rust
let public_inputs = [
    genesis_root,
    nullifier,
    commitment,
    recipient_commitment,
    amount,
    token_denom_hash,
    merkle_path_hint,
    // ... all other public values
];

let public_hash = poseidon_hash(public_inputs);  // or keccak256
layouter.constrain_instance(public_hash.cell(), primary, 0)?;
```

→ Contract verifies only **one** public input = hash of all values  
→ Off-chain verifier reconstructs and re-hashes to validate correctness

**75–80% gas reduction** → enables mainnet-scale private airdrops.

#### 6. Smart Account & DAO Integration

- Contract self-registers as authenticator in `instantiate()` via:

  ```rust
  MsgAddAuthenticator {
      authenticator_type: "CosmwasmAuthenticatorV1",
      data: CosmwasmAuthenticatorInitData { contract: self, params: WavsOperatorSet }
  }
  ```

- Any DAO or smart account can now use **BLS threshold signatures** instead of EOAs.
- Supports **AllOf(passkey, wallet, DAO vote)** composite authenticators via macro injection.

### Proving Keys

We store the viewing keys of a headstash circuit inside a cosmwasm contract for proof verification.
