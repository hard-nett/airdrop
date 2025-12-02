# HeadstashSuite: singular, highly efficient manifold for interacting with Headstashes

**Location**: `zk-crates/zk-headstash/src/deploy/suite.rs`

## Overview

The HeadstashSuite provides a comprehensive framework for client-side interaction with headstash airdrops. It is organized into three core traits that separate concerns by functionality and use case:

1. **HeadstashInstance** - Client-side operations for discovering, querying, and claiming from existing headstashes
2. **HeadstashBitwiseInstance** - Low-level bitwise operations and cryptographic primitives
3. **HeadstashLaunchpadInstance** - Complete client-side headstash creation and tree generation

## Primary Implementation

### HeadstashSuite

The canonical implementation that combines all three trait interfaces.

```rust
pub struct HeadstashSuite {}
impl HeadstashInstance for HeadstashSuite
impl HeadstashBitwiseInstance for HeadstashSuite
impl HeadstashLaunchpadInstance for HeadstashSuite
```

**Constructor**: `HeadstashSuite::new() -> Self`

---

## Trait Definitions

### HeadstashInstance

**Purpose**: Client-side interactions with deployed headstashes - discovery, querying state, managing notes, and claiming allocations.

**Associated Types**:

- `type HsErr` - Error type for headstash operations

**Functions**:

| Function | Purpose | Status | Location |
|----------|---------|--------|----------|
| `find_new_headstashes()` | Query headstash market contract for new instances | TODO | suite.rs:56 |
| `list_headstash_info()` | Retrieve headstash config from IPFS | TODO | suite.rs:61 |
| `list_unspent_notes()` | Read local folder and display unspent notes with FDI counts | TODO | suite.rs:66 |
| `list_spent_notes()` | Read local folder and display spent notes | TODO | suite.rs:71 |
| `prepare_and_harvest_note()` | Select unspent notes, move to spent folder, generate proof (wasm/cargo/bash) | TODO | suite.rs:77 |
| `headstash_action()` | Execute headstash action transaction | TODO | suite.rs:81 |

---

### HeadstashBitwiseInstance

**Purpose**: Low-level cryptographic operations, field arithmetic, and bitwise transformations for note commitments, nullifiers, and Merkle operations.

**Functions**:

| Function | Signature | Purpose | Location |
|----------|-----------|---------|----------|
| `derive_m()` | `(&self, esk: &[u8; 32], fdi: u64, v: u64, nd: &str) -> Result<pallas::Base, BoxError>` | Derive the `m` value using PRF over esk, fdi, v, nd | suite.rs:87 |
| `derive_esk()` | `(&self, sk: [u8; 32]) -> [Fp; 3]` | Decompose secp256k1 secret key into 3×88-bit Pallas limbs | suite.rs:102 |
| `derive_epk()` | `(&self, pk: [u8; 32]) -> [Fp; 3]` | Decompose secp256k1 public key into 3×88-bit Pallas limbs | suite.rs:111 |
| `derive_v()` | `(&self, v: u64) -> [u8; 8]` | Convert value to little-endian bytes | suite.rs:119 |
| `derive_fdi()` | `(&self, fdi: u64) -> [u8; 8]` | Convert FDI (leaf index) to little-endian bytes | suite.rs:123 |
| `derive_nk()` | `(&self, esk: &[u8; 32], rho: Rho) -> NullifierDerivingKey` | Derive nullifier key from secret and rho | suite.rs:126 |
| `bytes_to_bits_le()` | `(bytes: &[u8]) -> impl Iterator<Item = bool>` | Convert bytes to LSB-first bit iterator | suite.rs:133 |
| `derive_secp256k1_limbs_sum_const_time()` | `(&self, bytes: &[Fp; 3]) -> Fp` | Sum 3×88-bit limb representation to single field element | suite.rs:140 |
| `derive_nd()` | `(&self, raw_nd: &str) -> [u8; 32]` | Blake3 hash of token denomination string | suite.rs:147 |
| `extend_with_base_field_bits()` | `(bits: &mut Vec<bool>, a: pallas::Base)` | Append 250-bit field element to bit vector | suite.rs:154 |

---

### HeadstashLaunchpadInstance

**Purpose**: Complete client-side headstash creation pipeline - from community snapshots to Merkle tree generation to contract deployment.

**Trait Bounds**: Requires `HeadstashBitwiseInstance` implementation

**Functions**:

| Function | Signature | Purpose | Status | Location |
|----------|-----------|---------|--------|----------|
| `create_new_headstash()` | `() -> Result<(), BoxError>` | Full pipeline: select communities, query holders, configure distribution, generate tree, deploy contracts | TODO | suite.rs:165 |
| `get_input_path()` | `(&self) -> Result<String, BoxError>` | Parse CLI args for input file path | Implemented | suite.rs:176 |
| `derive_leaf()` | `(&self, addr: &str, token: &str, total: u64) -> Result<(Vec<(u64,usize,String)>, Vec<Fp>), BoxError>` | Parallel generation of all leaves for address+token allocation | Implemented | suite.rs:187 |
| `gen_headstash_tree()` | `(&self, output: PathBuf) -> Result<String, BoxError>` | Generate complete Merkle tree from allocations JSON | Implemented | suite.rs:251 |
| `tree_root_from_leaves()` | `(&self, leaves: Vec<pallas::Base>) -> Vec<pallas::Base>` | Build Merkle tree from leaf vector | Implemented | suite.rs:338 |
| `merkle_crh()` | `(layer: u32, left: pallas::Base, right: pallas::Base) -> pallas::Base` | Merkle CRH hash: H(layer \|\| left \|\| right) | Implemented | suite.rs:364 |
| `leaf_hash()` | `(&self, epk: &[u8], nd: &[u8], v: &[u8], fdi: &[u8]) -> Result<pallas::Base, BoxError>` | Compute leaf hash for (epk, nd, v, fdi) tuple | Implemented | suite.rs:388 |
| `create_headstash_notes()` | `(&self) -> Result<(), BoxError>` | Generate note files for specific address from tree | Implemented | suite.rs:410 |
| `gen_headstash_my_notes()` | `(&self, input: PathBuf, output: PathBuf) -> Result<(), BoxError>` | Query headstash API, retrieve tree, generate notes client-side | TODO | suite.rs:503 |
| `print_tree()` | `(&self, input: &mut Value, output: Value, path: &Path) -> Result<(), BoxError>` | Write tree and Merkle output to files | Implemented | suite.rs:507 |
| `find_fdi()` | `(input_path: &str, token: &str, amount: &str) -> Result<u64, BoxError>` | Find FDI for first note matching token and amount | Implemented | suite.rs:526 |
| `get_note_path()` | `() -> Result<(String, String, String), BoxError>` | Parse CLI args for note lookup (path, denom, amount) | Implemented | suite.rs:557 |
| `gen_note()` | `(&self) -> Result<(), BoxError>` | Derive nullifier from esk and note data | TODO | suite.rs:585 |
| `rho_from_secure_random()` | `() -> Rho` | Generate cryptographically secure random rho value | Implemented | suite.rs:589 |

---

## Helper Functions

### Standalone Utilities

| Function | Signature | Purpose | Location |
|----------|-----------|---------|----------|
| `get_cli_args()` | `() -> Result<(String, String), Box<dyn Error>>` | Parse CLI args for (input_file, address) | suite.rs:26 |

---

## Data Structures

### TerpHeadstashConfig

Empty config struct (placeholder for future configuration)
**Location**: suite.rs:34

### BoxError

Type alias for `Box<dyn Error + Send + Sync>`
**Location**: suite.rs:24

---

## Implementation Notes

### Parallelization

- `derive_leaf()` uses Rayon for parallel leaf generation (suite.rs:225)
- `tree_root_from_leaves()` uses parallel chunk processing for Merkle CRH (suite.rs:348)

### Cryptographic Constants

- **LEAF_PERSONALIZATION**: Sinsemilla domain for leaf hashing
- **MERKLE_CRH_PERSONALIZATION**: Sinsemilla domain for Merkle tree nodes
- **FIXED_AMOUNTS**: Predefined denomination values for note splitting

### Input/Output Formats

- **Input**: JSON with structure `{ "address": [{ "name": "token", "amount": "123" }] }`
- **Output**: Merkle tree JSON + notes JSON per address
- **Notes Format**: `{ "token": [{ "m": "", "esk": "", "fdi": 0, "amount": "", ... }] }`

---

## Outstanding Work (TODOs)

1. **HeadstashInstance** - All client-facing functions need implementation
2. **Launchpad** - `create_new_headstash()` full pipeline
3. **Launchpad** - `gen_headstash_my_notes()` API integration
4. **Launchpad** - `gen_note()` implementation
5. **Accuracy** - Note commitment derivation verification (suite.rs:601)
6. **Accuracy** - Nullifier derivation verification (suite.rs:602)
7. **Documentation** - DST & hashing algorithm constants (suite.rs:603)
8. **Feature Flag** - Parallelization toggle for tree generation (suite.rs:162)

---

## Testing

### Test Coverage

| Test | Purpose | Location |
|------|---------|----------|
| `test_note_accuracy()` | Verify generated notes sum to original allocations | suite.rs:617 |
| `test_input_data_accuracy()` | Ensure input JSON schema compatibility | suite.rs:693 |

**Test Data**: `./data/genesis_sinsemilla.json`
**Test Notes**: `./data/notes/0x0000000000000000000000000000000000000000.json`

---

## Usage Context

This suite serves as the **primary router for agentic codebase navigation**. For detailed type definitions, function inputs, and implementation specifics, refer to:

- **Type Members**: See trait definitions in source
- **Cryptographic Primitives**: `zk-crates/zk-headstash/src/spec.rs`
- **Note Structure**: `zk-crates/zk-headstash/src/note/`
- **Constants**: `zk-crates/zk-headstash/src/constants/`
