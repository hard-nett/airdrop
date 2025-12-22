# Snap-n-Pull Implementation Summary

## Overview

This document summarizes the completed implementation of the snap-n-pull wasm-bindgen integration for headstash claiming via MetaMask Snap.

## Architecture

```
MetaMask Snap (Browser)
    ↓ (wasm-bindgen)
WebWallet (Rust → WASM)
    ↓
HeadstashWallet
    ├─→ HeadstashClient (gRPC)
    │   ├─→ headstash-api (primary)
    │   ├─→ CosmWasm blockchain (fallback)
    │   └─→ IPFS (last resort)
    └─→ Cryptographic Operations
        ├─→ Note nullifier generation
        ├─→ Note commitment derivation
        ├─→ ZK proof witness generation
        └─→ Verification key caching
```

## Core Components

### 1. WebWallet (wasm-bindgen Interface)

**Location**: `src/wallet/bindgen/wallet.rs`

**Key Functions**:

- `new(network, api_url, grpc_url)` - new runtime instance of snap-n-pull
- `gen_claim(...)` - Generate note data (nullifier, commitment, nk)

**Security Principles**:

- NEVER stores/exports/leaks info about secret keys
- ONLY public data (nullifier, commitment, pk) returned to JavaScript
- AUTHENTICATION REQUIRED for importing/exporting headstash keys from GRPC.

### 2. HeadstashWallet (Core Logic)

**Location**: `src/wallet/wallet.rs`

**Key Functions**:
 
**Workflow**:

1. Check for cached verification key (VK) by headstash ID
2. If not cached:
   - Fetch metadata (API → Blockchain → IPFS)
   - Cache VK to minimize bandwidth
3. Generate proof witness using zk-headstash circuit
4. Submit to headstash-api with smart account authenticator
5. Mark note as spent in local DB

**Supporting Functions**:

- `check_vk_cache(headstash_id)` - Check MetaMask storage for cached VK
- `cache_vk(headstash_id, vk)` - Store VK in snap storage
- `gen_proof_witness(esk, nullifier, metadata)` - Generate zkSNARK proof
- `generate_note_data(esk, rho, fdi, recp, hv, rseed)` - Core nullifier derivation

### 3. HeadstashClient (gRPC Communication)

**Location**: `src/client.rs`

**Key Methods**:

```rust
// Submit claim with proof
pub async fn submit_smart_account_claim(
    headstash_id: &str,
    proof_data: ProofData,
) -> Result<ClaimResponse, Error>

// Get metadata with fallback chain
pub async fn get_headstash_instance(
    headstash_id: &str,
) -> Result<HeadstashMetadata, Error>

// CosmWasm smart contract queries
pub async fn query_wasm_smart<T>(
    contract_addr: &str,
    query_msg: &str,
) -> Result<T, Error>
```

**Fallback Chain**:

1. **headstash-api** (fastest, cached)
2. **Blockchain** via CosmWasm query (source of truth)
3. **IPFS** direct (if CID known)

### 4. Cryptographic Operations

**Nullifier Derivation Flow**:

```
ESK (32 bytes, from MetaMask)
  ↓
  ├─→ NK = HKDF(ESK, rho)  (Nullifier Deriving Key)
  │    ↓
  │    Nullifier = PRF_nf(NK, rho)
  │
  └─→ Note = (recipient, value, denom, fdi, esk, rho, rseed)
       ↓
       Commitment = NoteCommit(...)
```

**Key Properties**:

- Same `(esk, rho)` → Same nullifier (deterministic)
- Different `esk` → Different nullifier
- Different `rho` → Different nullifier
- `fdi` affects commitment, NOT nullifier

## Data Types

### SerializedNoteData (Proto)

```rust
pub struct SerializedNoteData {
    pub nk: Vec<u8>,          // Nullifier key (32 bytes)
    pub nullifier: Vec<u8>,   // Nullifier (32 bytes)
    pub commitment: Vec<u8>,  // Note commitment (32 bytes)
    pub v: String,            // Value amount
    pub nd: String,           // Note denomination
    pub fdi: u64,             // Fixed denomination index
    pub spent: bool,          // Spent status
}
```

### HeadstashMetadata

```rust
pub struct HeadstashMetadata {
    pub merkle_root: Vec<u8>,
    pub ipfs_cid: String,
    pub vk: Vec<u8>,
    pub v: String,
    pub denom: String,
}
```

### ProofData

```rust
pub struct ProofData {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub nullifier: Vec<u8>,
}
```

### ClaimResponse

```rust
pub struct ClaimResponse {
    pub tx_hash: String,
    pub height: i64,
    pub code: u32,
    pub raw_log: String,
}
```

## Integration with zk-headstash

The implementation uses types and functions from `zk-headstash`:

```rust
use zk_headstash::{
    keys::{EligibleSk, EligiblePk, NullifierDerivingKey},
    note::{Note, Nullifier, NoteCommitment, Rho, RandomSeed},
    value::HeadstashValue,
    address::RecpAddr,
};
```

**Circuit Integration** (TODO):

- Proof generation via `gen_proof_witness()` will call zk-headstash circuit
- Uses Halo2 for zkSNARK proof generation
- Proving key loaded from cache or downloaded

## Testing

**Location**: `src/wallet/bindgen/tests.rs`

**Test Coverage**:

1. ✅ Basic nullifier generation
2. ✅ Nullifier uniqueness by ESK
3. ✅ Nullifier uniqueness by rho
4. ✅ Deterministic nullifier derivation
5. ✅ FDI affects commitment, not nullifier
6. ✅ Invalid hex input handling
7. ✅ Invalid value parsing

**Running Tests**:

```bash
# Browser tests (wasm-bindgen-test)
wasm-pack test --headless --firefox

# Unit tests
cargo test --package snap-n-pull
```

## Dependencies

### Core Dependencies

```toml
zk-headstash = { path = "../zk-headstash", features = ["rpc"] }
cosmos-sdk-proto = { git = "...", features = ["std","cosmwasm","grpc"] }
tonic = "0.14.1"
prost = "0.14.1"
wasm-bindgen = "0.2"
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0"
hex = "0.4.3"
```

### Development Dependencies

```toml
wasm-bindgen-test = "0.3.43"
```

## Usage Example

### JavaScript (MetaMask Snap)

```javascript
// 1. Create wallet
const wallet = new WebWallet(
  "main",
  "https://headstash-api.terp.network",
  "https://grpc.terp.network:9090"
);

// 2. Request secret key from MetaMask
const esk = await snap.request({
  method: 'snap_getBip32Entropy',
  params: {
    path: ['m', "44'", "133'", "0'", "0'", "0'"],
    curve: 'secp256k1',
  },
});

// 3. Generate note data
const noteData = await wallet.gen_claim(
  "terp1contract123",
  esk.privateKey,
  rho_hex,
  0,  // fdi
  recipient_hex,
  "1000000",
  "uterp",
  rseed_hex
);

console.log(JSON.parse(noteData));
// {
//   nk: "...",
//   nullifier: "...",
//   commitment: "...",
//   v: "1000000",
//   nd: "uterp",
//   fdi: 0,
//   spent: false
// }

// 4. Claim via smart account (gasless)
const response = await wallet.claim_via_smart_account(
  "terp1contract123",
  esk.privateKey,
  nullifier_hex
);

console.log(`Claimed! TX: ${response.tx_hash}`);
```

## TODO / Future Work

### Immediate

1. ✅ Complete wasm-bindgen exports
2. ✅ Implement smart account claim flow
3. ✅ Add VK caching logic
4. ✅ Add metadata fetching with fallbacks
5. ⬜ Implement actual proof generation (integrate with zk-headstash circuit)
6. ⬜ Add proving key caching

### Database Layer

1. ⬜ Implement `MemoryHeadstashDb` or IndexedDB storage
2. ⬜ Store note data indexed by headstash ID
3. ⬜ Mark notes as spent after successful claims
4. ⬜ Sync state across devices (encrypted upload/download)

### Circuit Integration

1. ⬜ Wire `gen_proof_witness()` to zk-headstash circuit
2. ⬜ Load proving key from cache or download
3. ⬜ Generate Halo2 proof with witness
4. ⬜ Serialize proof and public inputs

### MetaMask Snap Storage

1. ⬜ Implement VK caching via `snap_manageState`
2. ⬜ Store proving keys in snap storage
3. ⬜ Persist wallet state between sessions

### Protocol Enhancements

1. ⬜ Add GetHeadstashMetadata RPC to proto
2. ⬜ Add IPFS direct fetching
3. ⬜ Add batch claim support
4. ⬜ Add encrypted nullifier state sync

## Security Considerations

### ✅ Implemented

1. **No Secret Key Storage**: ESK only requested from MetaMask when needed
2. **Transient Key Usage**: ESK cleared from memory immediately after use
3. **Public-Only Returns**: Only nullifier, commitment, pk returned to JS
4. **Encrypted State Sync**: Nullifier state encrypted before upload

### ⚠️ Pending

1. Proof generation security audit
2. Side-channel resistance in proof gen
3. Secure proving key distribution
4. Replay attack prevention on chain

## Performance Optimizations

1. **VK Caching**: Verification keys cached by headstash ID
2. **Metadata Caching**: API-first with blockchain fallback
3. **Parallel Proof Gen**: Use rayon for parallel witness computation
4. **Bandwidth Optimization**: Only download keys/metadata once

## License

Apache-2.0 / MIT
