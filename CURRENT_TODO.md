# Refactor snap-n-pull to use HeadstashSuite

## Objective

Refactor the `snap-n-pull` MetaMask Snap wallet implementation to integrate with the HeadstashSuite trait system, replacing Zcash-specific types and operations with Headstash-compatible equivalents.

## Context

- **Current State**: snap-n-pull is based on Zcash libraries (ZcashAddress, Zatoshis, Orchard/Sapling protocols)
- **Target State**: Use HeadstashSuite traits (HeadstashInstance, HeadstashBitwiseInstance, HeadstashLaunchpadInstance)
- **Reference Documentation**:
  - HeadstashSuite specification: `docs/zk-headstash/suite.md`
  - MetaMask Snap specification: `docs/zk-headstash/metamask-snap.md`
  - Implementation location: `zk-crates/snap-n-pull/`
  - Suite implementation: `zk-crates/zk-headstash/src/deploy/suite.rs`

## Tasks

### 1. Type System Migration
<!-- 

#### 1.1 Replace Zcash Address Types

- **Current**: `ZcashAddress` (ZIP-316 unified addresses)
- **Target**: Headstash-compatible address format (secp256k1 public keys)
- **Files**:
  - `src/wallet/wallet.rs`
  - `src/wallet/bindgen/wallet.rs`
  - `src/req/requests.rs`
- **Action**:
  - Create `HeadstashAddress` wrapper for secp256k1 public keys
  - Support both hex (0x-prefixed) and base64 encoding (per suite.rs:215-222)
  - Update all `ZcashAddress::try_from_encoded()` calls

#### 1.2 Replace Value Types

- **Current**: `Zatoshis` (Zcash atomic units)
- **Target**: Multi-denomination support (uterp, IBC tokens, tokenfactory)
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Create `HeadstashValue { v: u64, nd: NoteDenom }` struct
  - Replace all `Zatoshis::from_u64()` calls
  - Update proposal/transaction methods to accept denomination parameter -->

### 2. Key Management Integration
<!-- 
#### 2.1 Adapt Key Derivation

- **Current**: `UnifiedSpendingKey::from_seed()` (ZIP-32)
- **Target**: secp256k1 → Pallas limb decomposition
- **Files**:
  - `src/keys/keys.rs`
  - `src/wallet/wallet.rs` (usk_from_seed_str)
- **Action**:
  - Implement `EligibleSk::from(SecretKey::from_byte_array())` (suite.rs:127-130)
  - Use `HeadstashBitwiseInstance::derive_esk()` for 3×88-bit decomposition (suite.rs:102-109)
  - Use `derive_epk()` for public key decomposition (suite.rs:111-118)

#### 2.2 Nullifier Key Derivation

- **Current**: N/A (Zcash uses different nullifier system)
- **Target**: `NullifierDerivingKey::derive_from(esk, rho)`
- **Files**: `src/keys/keys.rs`
- **Action**:
  - Implement `derive_nk()` wrapper (suite.rs:126-131)
  - Generate `Rho` via `rho_from_secure_random()` (suite.rs:589-597)

#### 2.3 Update PCZT Signing

- **Current**: Signs Orchard/Sapling/Transparent spends
- **Target**: Sign Headstash note claims, creating spent note data ready for broadcasting.
- **Files**: `src/keys/pczt_sign.rs`
- **Action**:
  - Refactor `pczt_sign_inner()` to work with Headstash note structure
  - Replace protocol-specific signing with generating spent note values, requireing derivation from secret-key -->

### 3. Wallet Database Integration
<!-- #### 3.1 Note Management

- **Current**: `MemoryWalletDb` tracking Orchard/Sapling notes
- **Target**: Track Headstash `Note` instances (unspent/spent)
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Implement `HeadstashInstance::list_unspent_notes()` (suite.rs:66-68)
  - Implement `HeadstashInstance::list_spent_notes()` (suite.rs:71-73)
  - Store note-file & save spent-notes via standard metamask-storage plugin specification: MetaMask recommends using the `snap_manageState` API method to persist up to 100 MB of data to the user's disk. This is their recommended approach for long-term data storage in Snaps.By default, `snap_manageState` automatically encrypts data using a Snap-specific key before storing it on the user's disk, and automatically decrypts it when retrieved.

Example:

```javascript
// Store data (encrypted by default)
await snap.request({
  method: "snap_manageState",
  params: {
    operation: "update",
    newState: { hello: "world" },
  },
});

// Retrieve data
const persistedData = await snap.request({
  method: "snap_manageState",
  params: { operation: "get" },
});
```

**Unencrypted Storage Option**
If you don't need encryption, you can set `encrypted: false`:

```javascript
await snap.request({
  method: "snap_manageState",
  params: {
    operation: "update",
    newState: { hello: "world" },
    encrypted: false,
  },
});
``` -->
<!-- 
### Important Considerations

1. **Permission Required**:

You must request the `snap_manageState` permission in your Snap's manifest file

3. **Encrypted Access**: Accessing encrypted state requires MetaMask to be unlocked

This approach provides flexibility for both sensitive and non-sensitive data storage needs in your Snap.

#### 3.2 Headstash Discovery

- **Current**: N/A (direct blockchain sync)
- **Target**: Query headstash market contract
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Implement `HeadstashInstance::find_new_headstashes()` (suite.rs:56-58)
  - Add gRPC client for headstash market contract queries
  - Cache discovered headstash instances

#### 3.3 Configuration Retrieval

- **Current**: N/A
- **Target**: Fetch headstash config from IPFS
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Implement `HeadstashInstance::list_headstash_info()` (suite.rs:61-63)
  - Add IPFS client integration
  - Parse and cache headstash configuration -->

### 4. Synchronization Refactor
<!-- 
#### 4.1 Replace Blockchain Sync

- **Current**: `sync()` via lightwalletd compact blocks
- **Target**: Sync against Headstash Merkle tree commitments
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Remove `MemBlockCache` and block scanning logic
  - Query Headstash-API for tree roots and note inclusion proofs
  - Update `suggest_scan_ranges()` to suggest headstash instances to check
  - Use Snap Cron Service to query api for new note ipfs location

#### 4.2 Note Generation

- **Current**: N/A (receives notes from blockchain)
- **Target**: Client-side note generation from tree
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - generate notes using known suite functions and pre-input prepartaitons defined the headstash suite
  -  -->

### 5. Transaction Building Refactor
<!-- 
#### 5.1 Replace propose_transfer()

- **Current**: Creates Zcash transaction proposal
- **Target**: Select notes for headstash claim
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Refactor to select unspent notes matching claim criteria
  - Remove `GreedyInputSelector`, `MultiOutputChangeStrategy`
  - Return simple note building function that defines how to build the note nullifier and commitments 
#### 5.2 Replace create_proposed_transactions()

- **Current**: Proves and signs Zcash transaction
- **Target**: Prepare and harvest notes (generate proof)
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Implement wrapper for `HeadstashInstance::prepare_and_harvest_note()` (suite.rs:77-79)
  - Integrate circuit proving (wasm-bindgen, cargo script, or bash)
  - Generate proof for note claim
  - Move claimed notes to spent folder

#### 5.3 Replace send_authorized_transactions()

- **Current**: Broadcasts Zcash transactions via lightwalletd
- **Target**: Submit headstash action to chain
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Implement `HeadstashInstance::headstash_action()` (suite.rs:81-83)
  - Submit proof + nullifier to headstash contract
  - Return action result

#### 5.4 Remove PCZT Flow (Optional - Future Work)

- **Current**: Full PCZT support for multi-party transactions
- **Target**: Consider if PCZT pattern applies to headstash claims
- **Files**: `src/wallet/wallet.rs`
- **Action**:
  - Evaluate if PCZT separation (create/sign/prove/send) is useful
  - If yes, adapt for headstash; if no, remove methods
  - Document decision in specification -->

### 6. WebWallet WASM Bindings Update

- **Files**: `src/wallet/bindgen/wallet.rs`
- implment mvp function integration
- implement wasm-bindgen calls into egui front end wasm
- zk-packages::snap - make sure we document api functions access via wasm-bindgen rpc call
<!-- 
#### 6.1 Constructor Update

- **Current**: `new(network, lightwalletd_url, min_confirmations, db_bytes)`
- **Target**: `new(network, headstash_api_url, min_confirmations, db_bytes)`
- **Action**:
  - Replace `lightwalletd_url` with `headstash_api_url`
  - Update `Client::new()` to point to headstash gRPC endpoint
  - Update JSDoc comments

#### 6.2 API Method Updates

- **Action**:
  - Update `propose_transfer()` signature to accept denomination
  - Update `create_proposed_transactions()` to `claim_notes()`
  - Add `discover_headstashes()` method
  - Add `fetch_headstash_config()` method
  - Update return types to match Headstash structures

#### 6.3 WalletSummary Update

- **Current**: Sapling/Orchard/Transparent balances
- **Target**: Per-denomination balances across all headstashes
- **Action**:
  - Update `AccountBalance` to `HeadstashBalance { denom: String, amount: u64 }`
  - Change `account_balances` to `headstash_balances: Vec<(String, Vec<HeadstashBalance>)>`
  - Remove Sapling/Orchard indices -->

### 7. Testing and Validation
<!-- 
#### 7.1 Unit Tests

- **Files**: All refactored modules
- **Action**:
  - Add tests for key derivation (esk, epk, nk)
  - Test note selection logic
  - Test note file management (unspent → spent)
  - Test denomination parsing

#### 7.2 Integration Tests

- **Files**: `tests/` directory
- **Action**:
  - Create mock Headstash-API server
  - Test full claim flow (discover → fetch config → generate notes → claim)
  - Test multi-denomination scenarios
  - Verify proof generation integration

#### 7.3 WASM Build Verification

- **Action**:
  - Run `wasm-pack build --target web` with all features
  - Verify generated TypeScript bindings
  - Test in browser environment with MetaMask Snap -->

### 8. Documentation Updates
<!-- 
#### 8.1 Update metamask-snap.md

- **Files**: `docs/zk-headstash/metamask-snap.md`
- **Action**:
  - Update "Headstash Integration Points" section with completed work
  - Move items from "Required Adaptations" to "Implemented"
  - Update method signatures in specification tables
  - Add new sections for headstash-specific features

#### 8.2 Add Usage Examples

- **Files**: `docs/zk-headstash/metamask-snap.md` or new `USAGE.md`
- **Action**:
  - Add JavaScript examples for MetaMask Snap API
  - Document headstash discovery flow
  - Document note claiming flow
  - Add troubleshooting section

#### 8.3 Update suite.md Cross-References

- **Files**: `docs/zk-headstash/suite.md`
- **Action**:
  - Add references to MetaMask Snap integration
  - Link to specific WASM bindings for each trait method -->

## Implementation Order
<!--   -->

## Success Criteria

- [ ] All Zcash-specific types replaced with Headstash equivalents
- [ ] HeadstashSuite traits successfully integrated
- [ ] WASM builds without errors with all features enabled
- [ ] Can discover headstashes via market contract
- [ ] Can generate notes client-side from tree
- [ ] Can claim notes and submit headstash actions
- [ ] MetaMask Snap loads in browser
- [ ] All unit tests pass
- [ ] Integration test covers full claim flow
- [ ] Documentation reflects current implementation

## Notes

- Maintain backward compatibility during refactor by feature-flagging old code
- Consider creating `feature = "headstash"` flag during transition
- Keep PCZT signing logic commented until decision on applicability
- Prioritize security review of key derivation changes
- Verify cryptographic randomness in WASM environment for `rho_from_secure_random()`

## References

- HeadstashSuite: `zk-crates/zk-headstash/src/deploy/suite.rs`
- Suite Spec: `docs/zk-headstash/suite.md`
- Snap Spec: `docs/zk-headstash/metamask-snap.md`
- Current Implementation: `zk-crates/snap-n-pull/`
