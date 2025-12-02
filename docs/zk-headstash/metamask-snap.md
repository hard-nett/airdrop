# Snap-n-Pull: MetaMask Snap Plugin for Headstash Interaction

"A good UX does not require the user to learn anything they do not already know." Powered by this principle, we can make use of a metamask snap plugin to power the hkdf & note management steps:

- download/import/store pubkeys eligible notes from headstash registry: download entire set once, discard non-related notes
- free will derived entropy generation
- perform hkdf + nullifier generation
- broadcast to sc/verifiable service mesh/smart-contract

Wires in our verifiable wasm binaries to a metamask snap plugin. THis lets us pack up our functions to generate note nullifiers and return them with an encrypted spent note.

```

- keep things flexible and organized in grids that react to window format


- use authenticators: iframe window/prewired application extensions/windows for authenticator support:
  - smart-account powered tx signing via non_crititical_extension preparation and injection ( x/402 authentication,webauthn / passkey / bls12-381 / etc)

- user actions should have hooks: since we expect to have stateful things happening when user clicks on instance (like stateful queries spefici to results of actions chosen), we can wire in query hooks to the client middleware for retrival of data related to spefic instance, and also use caching for storage of this data and extremely effecieve applicatoin

- main view shows verified deployed contract instances, search bar for manual contract input and saving to localstorage. once contract instance is selected query for retrieving active market objects to display in list occurs, render infusion instances for users to select to interact with
- tab for displaying registered authenticators for an account (indexerquery,chainfallback)
- tab for registering authenticator (via known ones, or manually via known tx steps take (instantiate+register || upload+instanitate+register))
- tab for using authenticator: (calling smart contract state genericlly)
# human notes
- queries headstash registry for list of all active headstsh (indexer priority chain contract callback)
- Current headstash: table grid wired into queries of all current headstashes
- Create headstash: tab with form to register new headstash
- Interacting with headstash: viewed when selected a headstash, dedicated information regarding global headtash metrics, specific to wallet connected as well, actions for interacting with headsatsh
- bluetooth / 2fa / passkey / auth app support
- penumbra wallet view and client sdk implementati9on
```

**Location**: `zk-crates/snap-n-pull/`

IMPORTANT: this defines the previous existing specification for interacing with ZCASH, so keep this in context when reading theis specification as we are going to replace these with functions,logic and definitions to be specific to

## Overview

The `snap-n-pull` crate is a WebAssembly-based MetaMask Snap plugin that enables secure, client-side interaction with Headstash instances. It provides key management, cryptographic operations, transaction building, and wallet synchronization capabilities within the MetaMask browser extension environment.

**Key Characteristics**:

- **WASM-first**: Compiled to WebAssembly for browser execution
- **Security-focused**: Key operations isolated within MetaMask's secure snap environment
- **Feature-gated**: Modular architecture with optional components
- **Parallel-capable**: Leverages rayon for concurrent operations in WASM

---◊

## Architecture

### Crate Type

```toml
crate-type = ["cdylib", "rlib"]
```

- **cdylib**: For WASM binary generation via wasm-pack
- **rlib**: For use as Rust library dependency

### Feature Flags

| Feature | Description | Status |
|---------|-------------|--------|
| `default` | Enables all features (wasm, common, keys, req, wallet) | Active |
| `wasm` | Enables wasm-bindgen for JavaScript interop | Active |
| `common` | Error types and network configuration | Active |
| `keys` | Cryptographic key operations | Active |
| `req` | Transaction request handling | Active |
| `wallet` | Full wallet functionality | Active |

---

## Module Structure

### Core Modules

```
snap-n-pull/
├── src/
│   ├── lib.rs                    # Root module, feature gates, Network enum
│   ├── keys/
│   │   ├── mod.rs                # Key management module exports
│   │   ├── keys.rs               # UnifiedSpendingKey, UFVK, SeedFingerprint
│   │   └── pczt_sign.rs          # PCZT signing operations
│   ├── req/
│   │   ├── mod.rs                # Request module exports
│   │   ├── requests.rs           # TransactionRequest, PaymentRequest (commented)
│   │   └── error.rs              # SnapReqErr error type
│   └── wallet/
│       ├── mod.rs                # Wallet module root
│       ├── init.rs               # Wallet initialization utilities
│       ├── wallet.rs             # Core Wallet struct and implementation
│       └── bindgen/
│           ├── mod.rs            # WASM bindgen exports
│           ├── wallet.rs         # WebWallet WASM bindings
│           └── proposal.rs       # Proposal WASM bindings
```

---

## Core Types and Structures

### Network Configuration

**Location**: `lib.rs:27`

```rust
pub enum Network {
    MainNetwork,
    TestNetwork,
}
```

**Purpose**: Network-agnostic operations supporting both mainnet and testnet environments

**Features**:

- Implements `FromStr` for parsing from strings ("main", "test")
- Serializable via Serde for cross-boundary communication
- Default: `MainNetwork`

---

### Error Handling

**Location**: `lib.rs:75`

```rust
pub enum Error {
    InvalidNetwork(String),
    SnapReqError(SnapReqErr),
    Js(wasm_bindgen::JsValue),
    KeyDecoding(String),
    PcztSign(String),
    SeedFingerprint,
}
```

**Purpose**: Unified error type for all snap-n-pull operations

**Error Categories**:

- Network configuration errors
- Request processing errors
- JavaScript interop errors
- Cryptographic key errors
- PCZT signing errors

---

## Module Specifications

### 1. Keys Module

**Purpose**: Cryptographic key management, derivation, and PCZT signing within secure snap environment

#### Key Types (Currently Commented Out)

| Type | Purpose | Status | Location |
|------|---------|--------|----------|
| `SeedFingerprint` | Blake2b hash of seed for key derivation tracking | TODO | keys.rs:17 |
| `UnifiedSpendingKey` | ZIP-32 spending key for account operations | TODO | keys.rs:83 |
| `UnifiedFullViewingKey` | View-only key for balance queries | TODO | keys.rs:135 |
| `ProofGenerationKey` | Sapling proof generation key | TODO | keys.rs:63 |

#### Functions

| Function | Signature | Purpose | Status | Location |
|----------|-----------|---------|--------|----------|
| `generate_seed_phrase()` | `() -> String` | Generate 24-word BIP39 mnemonic | TODO | keys.rs:178 |
| `pczt_sign()` | `(network: &str, pczt: Pczt, usk: USK, seed_fp: SeedFingerprint) -> Result<Pczt, Error>` | Sign PCZT with spending key | TODO | pczt_sign.rs:23 |
| `pczt_sign_inner()` | See impl | Internal PCZT signing logic for Orchard/Sapling/Transparent | TODO | pczt_sign.rs:39 |

**PCZT Signing Flow**:

1. Verify PCZT structure and extract spends
2. Match spends to account indices via seed fingerprint
3. Derive appropriate keys per protocol (Orchard/Sapling/Transparent)
4. Sign each spend with corresponding key
5. Return fully signed PCZT

---

### 2. Request Module

**Purpose**: ZIP-321 payment request handling and transaction construction

#### Types (Currently Commented Out)

| Type | Purpose | Status | Location |
|------|---------|--------|----------|
| `TransactionRequest` | ZIP-321 compliant transaction request | TODO | requests.rs:13 |
| `PaymentRequest` | Individual payment within transaction request | TODO | requests.rs:70 |

#### TransactionRequest Methods

| Method | Purpose | Status | Location |
|--------|---------|--------|----------|
| `new(payments: Vec<PaymentRequest>)` | Construct from payment list | TODO | requests.rs:19 |
| `from_uri(uri: &str)` | Parse from "zcash:" URI | TODO | requests.rs:58 |
| `to_uri()` | Encode as URI string | TODO | requests.rs:63 |
| `total()` | Sum payment values | TODO | requests.rs:42 |
| `payment_requests()` | Get payment list | TODO | requests.rs:32 |

#### PaymentRequest Methods

| Method | Purpose | Status | Location |
|--------|---------|--------|----------|
| `new(...)` | Construct payment with memo/metadata | TODO | requests.rs:76 |
| `simple_payment(addr, amount)` | Quick payment without memo | TODO | requests.rs:103 |
| `recipient_address()` | Get encoded address | TODO | requests.rs:112 |
| `amount()` | Get payment value | TODO | requests.rs:117 |
| `memo()` | Get optional memo bytes | TODO | requests.rs:122 |
| `label()` / `message()` | Get metadata fields | TODO | requests.rs:130 |

---

### 3. Wallet Module

**Purpose**: Complete wallet management including account creation, synchronization, and transaction building

#### Core Wallet Structure

**Location**: `wallet/wallet.rs:85`

```rust
pub struct Wallet<W> {
    db: Arc<RwLock<W>>,
    network: Network,
    min_confirmations: NonZeroU32,
    target_note_count: usize,
    min_split_output_value: u64,
}
```

**Generic Parameter**: `W` - Database backend (e.g., `MemoryWalletDb`)

**Fields**:

- `db`: Thread-safe wallet database for accounts/transactions/blocks
- `network`: Network configuration
- `min_confirmations`: Required confirmations before finality
- `target_note_count`: Note management for change splitting
- `min_split_output_value`: Minimum value for split outputs

---

#### WebWallet WASM Bindings

**Location**: `wallet/bindgen/wallet.rs:98`

```rust
#[wasm_bindgen]
pub struct WebWallet {
    inner: MemoryWallet<tonic_web_wasm_client::Client>,
}
```

**Purpose**: JavaScript-accessible wallet interface for browser environments

---

#### Account Management

| Method | Signature | Purpose | Status | Location |
|--------|-----------|---------|--------|----------|
| `create_account()` | `(&self, name: &str, seed: &str, hd_index: u32, birthday: Option<u32>) -> Result<AccountId, Error>` | Create account from seed phrase | TODO | wallet.rs:176 |
| `import_ufvk()` | `(&self, name: &str, ufvk: &UFVK, purpose: AccountPurpose, birthday: Option<u32>) -> Result<AccountId, Error>` | Import view-only account | TODO | wallet.rs:205 |
| `import_account_ufvk()` | Internal helper for UFVK imports | TODO | wallet.rs:217 |

**Account Creation Flow**:

1. Decode BIP39 mnemonic and derive USK
2. Generate UFVK from USK
3. Query chain tip or use provided birthday height
4. Fetch tree state at birthday - 1 (leaks birthday to server)
5. Import account into database

---

#### Synchronization

| Method | Signature | Purpose | Status | Location |
|--------|-----------|---------|--------|----------|
| `sync()` | `(&self) -> Result<(), Error>` | Sync wallet with blockchain via gRPC | TODO | wallet.rs:275 |
| `suggest_scan_ranges()` | `(&self) -> Result<Vec<BlockRange>, Error>` | Get recommended block ranges to scan | TODO | wallet.rs:261 |

**Sync Strategy**:

- Uses `MemBlockCache` for temporary block storage
- Batch size: 10,000 blocks
- Delegates to background worker to prevent main thread blocking
- Updates wallet database with scanned transactions

---

#### Transaction Building (Standard Flow)

| Method | Signature | Purpose | Status | Location |
|--------|-----------|---------|--------|----------|
| `propose_transfer()` | `(&self, account_id: AccountId, to: ZcashAddress, value: u64) -> Result<Proposal, Error>` | Create transaction proposal | TODO | wallet.rs:303 |
| `create_proposed_transactions()` | `(&self, proposal: Proposal, usk: &USK) -> Result<NonEmpty<TxId>, Error>` | Prove and sign proposal | TODO | wallet.rs:356 |
| `send_authorized_transactions()` | `(&self, txids: &NonEmpty<TxId>) -> Result<(), Error>` | Broadcast transactions | TODO | wallet.rs:383 |
| `transfer()` | Helper combining all three steps | TODO | wallet.rs:415 |

**Proposal Configuration**:

- Input selector: Greedy (selects notes greedily)
- Fee rule: ZIP-317 standard fees
- Change strategy: Multi-output with note splitting
- Dust policy: Default (configurable minimum)
- Split policy: Target `target_note_count` outputs

---

#### PCZT Transaction Flow

**Purpose**: Separate transaction construction, signing, and proving for multi-party or hardware wallet scenarios

| Method | Signature | Purpose | Status | Location |
|--------|-----------|---------|--------|----------|
| `pczt_create()` | `(&self, account_id: AccountId, to: ZcashAddress, value: u64) -> Result<Pczt, Error>` | Create unsigned PCZT | TODO | wallet.rs:498 |
| `pczt_shield()` | `(&self, account_id: AccountId) -> Result<Pczt, Error>` | Create shielding PCZT | TODO | wallet.rs:435 |
| `pczt_prove()` | `(&self, pczt: Pczt, sapling_pgk: Option<ProofGenerationKey>) -> Result<Pczt, Error>` | Generate proofs | TODO | wallet.rs:555 |
| `pczt_send()` | `(&self, pczt: Pczt) -> Result<(), Error>` | Extract, verify, store, and broadcast | TODO | wallet.rs:613 |
| `pczt_combine()` | `(&self, pczts: Vec<Pczt>) -> Result<Pczt, Error>` | Combine multiple PCZTs | TODO | wallet.rs:635 |

**PCZT Flow**:

1. **Create**: `pczt_create()` generates proposal and unsigned PCZT
2. **Sign**: `pczt_sign()` (keys module) signs with USK in secure environment
3. **Prove**: `pczt_prove()` generates zkSNARK proofs using LocalTxProver
4. **Send**: `pczt_send()` extracts transaction, verifies, stores, and broadcasts

**Shielding Threshold**: 100,000 zatoshis (0.001 ZEC)

---

#### Query Methods

| Method | Signature | Purpose | Status | Location |
|--------|-----------|---------|--------|----------|
| `get_wallet_summary()` | `(&self) -> Result<Option<WalletSummary>, Error>` | Get account balances and sync status | TODO | wallet.rs:292 |
| `db_to_bytes()` | `(&self) -> Result<Vec<u8>, Error>` | Serialize wallet database | TODO | wallet.rs:113 |

**WalletSummary Fields**:

- `account_balances`: Per-account Sapling/Orchard/Transparent balances
- `chain_tip_height`: Latest known block
- `fully_scanned_height`: Fully synced height
- `next_sapling_subtree_index` / `next_orchard_subtree_index`: Merkle tree indices

---

## WebWallet WASM API

**Purpose**: Browser-accessible wallet interface with WebWorker support for expensive operations

### Constructor

```rust
#[wasm_bindgen(constructor)]
pub fn new(
    network: &str,
    lightwalletd_url: &str,
    min_confirmations: u32,
    db_bytes: Option<Box<[u8]>>,
) -> Result<WebWallet, Error>
```

**Parameters**:

- `network`: "main" or "test"
- `lightwalletd_url`: gRPC endpoint (e.g., "<https://zcash-mainnet.chainsafe.dev>")
- `min_confirmations`: Transaction finality threshold
- `db_bytes`: Optional serialized database for session restoration

**Status**: TODO (wallet.rs:130)

---

### Async Operations via WebWorkers

| Operation | Worker Usage | Purpose | Location |
|-----------|--------------|---------|----------|
| `sync()` | Spawns "sync" worker | Long-running blockchain sync | wallet.rs:269 |
| `create_proposed_transactions()` | Spawns "create_proposed_transaction" worker | Expensive zkSNARK proving | wallet.rs:351 |

**WebWorker Pattern**:

- Prevents main thread blocking
- Uses `wasm-thread` for worker management
- Rayon for parallel proving within worker
- Safe concurrent database access via `Arc<RwLock<Db>>`

---

### Address Retrieval

| Method | Purpose | Status | Location |
|--------|---------|--------|----------|
| `get_current_address(account_id: u32)` | Get unified address | TODO | wallet.rs:433 |
| `get_current_address_transparent(account_id: u32)` | Extract transparent component | TODO | wallet.rs:519 |

---

### gRPC Lightwalletd Methods

| Method | Purpose | Status | Location |
|--------|---------|--------|----------|
| `get_latest_block()` | Query current chain height | TODO | wallet.rs:535 |

---

## Constants and Configuration

### Pruning Depth

**Location**: `wallet/mod.rs:17`

```rust
pub const PRUNING_DEPTH: usize = 100;
```

**Purpose**: Maximum checkpoints stored in shard-tree for wallet history

---

### Batch Processing

**Location**: `wallet/wallet.rs:60` (commented)

```rust
const BATCH_SIZE: u32 = 10000;
```

**Purpose**: Block batch size for synchronization

---

### Shielding Threshold

**Location**: `wallet/wallet.rs:64` (commented)

```rust
const SHIELDING_THRESHOLD: Zatoshis = 100000;
```

**Purpose**: Minimum transparent balance to trigger auto-shielding proposal

---

## Headstash Integration Points

### Current State

The snap-n-pull crate is currently based on Zcash libraries and patterns. To integrate with Headstash:

### Required Adaptations

1. **Replace Zcash Types**:
   - `ZcashAddress` → Headstash-compatible address format
   - `Zatoshis` → Generic value type for multiple denoms
   - `TxId` → Headstash transaction identifiers

2. **Key Derivation**:
   - Adapt `UnifiedSpendingKey` for secp256k1 → Pallas decomposition (see `HeadstashBitwiseInstance::derive_esk`)
   - Integrate `EligibleSk`, `NullifierDerivingKey` from zk-headstash

3. **Note Management**:
   - Replace Orchard/Sapling note tracking with Headstash `Note` structure
   - Implement `list_unspent_notes()` / `list_spent_notes()` from `HeadstashInstance`

4. **Synchronization**:
   - Replace lightwalletd gRPC with Headstash-API client
   - Sync against Merkle tree commitments instead of blockchain state
   - Implement `find_new_headstashes()` discovery

5. **Transaction Building**:
   - Adapt PCZT flow to Headstash claim/harvest operations
   - Integrate `prepare_and_harvest_note()` from HeadstashInstance
   - Wire in circuit proving via `zk-headstash` proving key

---

## Development Status

### Implemented

- ✅ Feature-gated module structure
- ✅ Error type hierarchy
- ✅ Network configuration
- ✅ WASM compilation infrastructure
- ✅ Core `Wallet<W>` generic structure

### In Progress (Commented Out)

- 🔄 All key management functions
- 🔄 ZIP-321 request handling
- 🔄 WebWallet WASM bindings
- 🔄 PCZT signing implementation
- 🔄 Synchronization logic
- 🔄 Transaction building

### TODO

- ❌ Headstash-specific adaptations
- ❌ Integration with `HeadstashInstance` trait
- ❌ MetaMask Snap manifest and permissions
- ❌ Browser testing harness
- ❌ Documentation for MetaMask Snap API
- ❌ Production cryptographic randomness verification

---

## Usage Context

This specification serves as the **primary router for snap-n-pull codebase navigation**. For detailed implementation:

- **Headstash Integration**: See `docs/zk-headstash/suite.md` for HeadstashSuite trait specifications
- **Cryptographic Primitives**: `zk-crates/zk-headstash/src/spec.rs`
- **Note Structure**: `zk-crates/zk-headstash/src/note/`
- **WASM Compilation**: Use `wasm-pack build --target web` with features
- **MetaMask Snap**: Follow [MetaMask Snaps documentation](https://docs.metamask.io/snaps/)

---

## Security Considerations

1. **Seed Phrase Handling**: Never expose seed phrases to JavaScript; keep within snap sandbox
2. **Randomness**: Current `generate_seed_phrase()` may not use secure randomness in browser
3. **Birthday Leakage**: Querying tree state at birthday - 1 leaks birthday to server
4. **Key Storage**: Leverage MetaMask's encrypted storage for persistent keys
5. **PCZT Verification**: Always verify proofs before broadcasting transactions

---

## References

- **Copyright**: Based on ChainSafe Systems' Zcash WebWallet (Apache-2.0, MIT)
- **ZIP-32**: [Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- **ZIP-316**: [Unified Addresses and Unified Viewing Keys](https://zips.z.cash/zip-0316)
- **ZIP-321**: [Payment Request URIs](https://zips.z.cash/zip-0321)
- **PCZT**: Partially Constructed Zcash Transaction format
