# Snap-n-Pull: MetaMask Snap Plugin for Headstash Interaction

**Version:** 2.0
**Status:** Production Implementation
**Last Updated:** 2025-01-20

## Overview

The `snap-n-pull` MetaMask Snap plugin provides secure, client-side nullifier generation for Headstash airdrop claims. It enables users to prove ownership of eligible addresses and claim allocations without revealing their private keys or creating on-chain associations between eligible and recipient addresses.

**Core Principle:** "A good UX does not require the user to learn anything they do not already know."

### Key Capabilities

✅ **Nullifier Generation** - Generate note nullifiers from private keys without revealing them
✅ **Note Commitment** - Create cryptographic commitments to notes
✅ **Public Key Derivation** - Derive public keys for verification
✅ **Zero Private Key Storage** - Private keys are NEVER stored, only used transiently
✅ **MetaMask Integration** - Seamless integration with MetaMask's secure environment
✅ **WASM-Powered** - Rust cryptographic core compiled to WebAssembly

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    dApp (Frontend)                           │
│  - User selects headstash to claim                          │
│  - Provides public note inputs (recp, nd, v, fdi, rho, rseed)│
│  - Calls snap via window.ethereum.request()                 │
└───────────────────────────────┬─────────────────────────────┘
                                 │
                                 │ JSON-RPC: generateNullifier
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                MetaMask Snap Plugin (Isolated)               │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ index.tsx (RPC Handler)                               │  │
│  │  - Validates requests                                 │  │
│  │  - Initializes WASM                                   │  │
│  │  - Routes to gn() handler                             │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                            │                                 │
│                            ▼                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ rpc/gn.tsx (Generate Nullifier)                       │  │
│  │  1. Show user confirmation dialog                     │  │
│  │  2. Request user approval                             │  │
│  │  3. Call getSk() to retrieve private key              │  │
│  └────────────────────────┬──────────────────────────────┘  │
│                            │                                 │
│                            ▼                                 │
│             ┌──────────────────────────────┐                 │
│             │ getSk() (BIP-32 Derivation)  │                 │
│             │  - snap_getBip32Entropy()    │                 │
│             │  - Path: m/44'/133'/0'/0'/0' │                 │
│             │  - Returns: 32-byte esk      │                 │
│             └──────────┬───────────────────┘                 │
│                        │                                     │
│                        │ esk (TRANSIENT - never stored!)     │
│                        │                                     │
│             ┌──────────▼───────────────────┐                 │
│             │ getPk(esk)                   │                 │
│             │  - Derives secp256k1 pubkey  │                 │
│             │  - Returns: 33-byte pk (hex) │                 │
│             └──────────┬───────────────────┘                 │
│                        │                                     │
│                        │ pk (PUBLIC - safe to reveal)        │
│                        │                                     │
│             ┌──────────▼────────────────────────────────┐    │
│             │ generateNullifier(wasm, esk, noteInputs)  │    │
│             │                                           │    │
│             │ Sequential Derivation (esk is root):     │    │
│             │  1. nk = HKDF(esk, rho)                   │    │
│             │  2. nullifier = PRF_nf(nk, rho, psi)      │    │
│             │  3. commitment = NoteCommit(esk, ...)     │    │
│             └──────────┬────────────────────────────────┘    │
│                        │                                     │
│                        ▼                                     │
│             ┌────────────────────────────┐                   │
│             │ WASM Module (snap-n-pull)  │                   │
│             │  - Rust cryptographic core │                   │
│             │  - HeadstashWallet         │                   │
│             │  - generate_note_data()    │                   │
│             └────────────┬───────────────┘                   │
│                          │                                   │
│                          ▼                                   │
│                   ┌──────────────┐                           │
│                   │ esk.fill(0)  │                           │
│                   │ Clear secret │                           │
│                   │ from memory  │                           │
│                   └──────────────┘                           │
└───────────────────────────────┬─────────────────────────────┘
                                 │
                                 │ Returns: { nullifier, commitment, pk }
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    dApp (Frontend)                           │
│  - Receives nullifier + commitment + pk                      │
│  - Generates ZK proof (separate step)                        │
│  - Broadcasts claim transaction to chain                     │
└─────────────────────────────────────────────────────────────┘
```

**Critical Security Note:** The secret key (esk) is the root of all cryptographic operations. It must be obtained first from MetaMask's BIP-32 derivation, then used to derive both the nullifier and commitment sequentially. The key is never stored and is cleared from memory immediately after use.

---

## Core Components

### 1. MetaMask Snap Package (`zk-packages/snap`)

**Location:** `zk-packages/snap/src/`

#### File Structure

```
zk-packages/snap/src/
├── index.tsx                 # RPC entry point, WASM initialization
├── rpc/
│   └── gn.tsx                # generateNullifier RPC handler
├── utils/
│   ├── getSk.tsx             # BIP-32 key retrieval from MetaMask
│   ├── getPk.tsx             # Public key derivation
│   ├── nullifier.tsx         # Nullifier generation via WASM
│   └── initialiseWasm.ts     # WASM module initialization
└── package.json              # Snap manifest
```

#### Key Functions

**`index.tsx` - RPC Router**

```typescript
export const onRpcRequest: OnRpcRequestHandler = async ({ request, origin }) => {
  const wasmModule = await ensureWasmInitialized();

  switch (request.method) {
    case 'generateNullifier': {
      // Validate params
      const params = request.params as GenerateNullifierParams;
      // Generate nullifier
      return await gn(wasmModule, params, origin);
    }
    default:
      throw new Error(`Method not found: ${request.method}`);
  }
};
```

**`rpc/gn.tsx` - Nullifier Generation Handler**

```typescript
export async function gn(
  wasm: InitOutput,
  params: GenerateNullifierParams,
  origin: string,
): Promise<GenerateNullifierResponse> {
  // 1. Show confirmation dialog
  const approved = await snap.request({ method: 'snap_dialog', ... });
  if (!approved) throw new Error('User rejected');

  // 2. Retrieve secret key (TRANSIENT)
  const sk = await getSk();

  // 3. Derive public key
  const pk = await getPk(sk);

  // 4. Generate nullifier and commitment
  const nullifierData = await generateNullifier(wasm, sk, noteInputs);

  // 5. Clear secret key from memory
  sk.fill(0);

  // 6. Return only public data
  return {
    nullifier: nullifierData.nullifier,
    commitment: nullifierData.commitment,
    pk, // Public key - safe to reveal
  };
}
```

**`utils/getSk.tsx` - Secret Key Retrieval**

Uses `snap_getBip32Entropy` as per [MetaMask Snaps API Reference](https://docs.metamask.io/snaps/reference/snaps-api/#snap_getbip32entropy):

```typescript
export async function getSk(): Promise<Uint8Array> {
  // Request BIP-32 entropy from MetaMask
  const entropyResult = await snap.request({
    method: 'snap_getBip32Entropy',
    params: {
      path: ['m', "44'", "133'", "0'", "0'", "0'"],
      curve: 'secp256k1',
    },
  });

  // Convert hex to bytes
  const privateKeyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    privateKeyBytes[i] = parseInt(entropyResult.privateKey.substr(i * 2, 2), 16);
  }

  return privateKeyBytes;
}
```

**Path Explanation:** `m/44'/133'/0'/0'/0'`

- `44'` - BIP-44 purpose
- `133'` - Zcash coin type (placeholder for Terp Network)
- `0'` - Account index
- `0'` - Change index
- `0'` - Address index

**`utils/getPk.tsx` - Public Key Derivation**

```typescript
export async function getPk(sk: Uint8Array): Promise<string> {
  const { secp256k1 } = await import('@noble/curves/secp256k1');
  const publicKey = secp256k1.getPublicKey(sk, true); // compressed
  return Buffer.from(publicKey).toString('hex');
}

export async function pkToAddress(pk: string): Promise<string> {
  const { secp256k1 } = await import('@noble/curves/secp256k1');
  const { keccak_256 } = await import('@noble/hashes/sha3');

  // Get uncompressed public key
  const pkBytes = Buffer.from(pk, 'hex');
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pkBytes).toRawBytes(false);

  // Keccak256 hash (Ethereum-style)
  const hash = keccak_256(uncompressed.slice(1));

  // Take last 20 bytes
  const address = hash.slice(-20);
  return '0x' + Buffer.from(address).toString('hex');
}
```

**`utils/nullifier.tsx` - Nullifier Generation**

```typescript
export async function generateNullifier(
  wasm: InitOutput,
  esk: Uint8Array,
  noteInputs: NoteInputs,
): Promise<NullifierData> {
  const eskHex = Buffer.from(esk).toString('hex');
  const { WebWallet } = wasm;

  // Create temporary wallet instance
  const wallet = await WebWallet.new('test', 'http://localhost:8080', null, null);

  // Store note (triggers generation)
  await wallet.gen_claim(
    'temp_headstash_id',
    eskHex,
    noteInputs.rho,
    noteInputs.fdi,
    noteInputs.recp,
    noteInputs.v.toString(),
    noteInputs.nd,
    noteInputs.rseed,
  );

  // Retrieve generated note data
  const notesJson = await wallet.list_unspent_notes('temp_headstash_id');
  const notes = JSON.parse(notesJson);
  const note = notes[0];

  return {
    nullifier: note.nullifier,
    commitment: note.commitment,
    nk: note.nk,
  };
}
```

---

### 2. WASM Cryptographic Core (`zk-crates/snap-n-pull`)

**Location:** `zk-crates/snap-n-pull/src/`

#### Module Structure

```
zk-crates/snap-n-pull/src/
├── lib.rs                    # Root module, Network enum
├── wallet/
│   ├── mod.rs                # Wallet module exports
│   ├── wallet.rs             # HeadstashWallet implementation
│   ├── headstash.rs          # NoteData, HeadstashApiDbInstance
│   └── bindgen/
│       ├── mod.rs
│       └── headstash.rs      # WebWallet WASM bindings
├── client.rs                 # HeadstashClient (gRPC)
└── crypto.rs                 # Encryption/decryption for nullifier sync
```

#### Core Types

**`HeadstashWallet<W>` - Main Wallet Structure**

```rust
pub struct HeadstashWallet<W> {
    /// Internal database for note data
    pub(crate) db: Arc<RwLock<W>>,
    /// Network configuration
    pub(crate) network: Network,
    /// gRPC client for headstash API
    pub(crate) client: Option<HeadstashClient>,
}

impl<W: HeadstashApiDbInstance> HeadstashWallet<W> {
    /// Generate nullifier and commitment for a note
    pub fn generate_note_data(
        &self,
        esk: EligibleSk,
        rho: Rho,
        fdi: u64,
        recp: &[u8],
        hv: HeadstashValue,
        rseed: [u8; 32],
    ) -> Result<(NullifierDerivingKey, Nullifier, NoteCommitment), Error> {
        // Derive nullifier key: nk = HKDF(esk, rho)
        let nk = NullifierDerivingKey::derive_from(esk, rho);

        // Create note
        let recp = RecpAddr::try_from(recp)?;
        let rseed = RandomSeed::from_bytes(rseed, &rho)?;
        let (v, nd) = hv.into_parts();
        let note = Note::from_parts(recp, v, nd, fdi, esk, rho, rseed)?;

        // Derive nullifier and commitment
        let nullifier = note.nullifier();
        let commitment = note.commitment();

        Ok((nk, nullifier, commitment))
    }
}
```

**`WebWallet` - WASM Bindings**

```rust
#[wasm_bindgen]
pub struct WebWallet {
    inner: HeadstashWallet<MemoryHeadstashDb>,
}

#[wasm_bindgen]
impl WebWallet {
    #[wasm_bindgen(constructor)]
    pub async fn new(
        network: &str,
        headstash_api_url: &str,
        cosmos_grpc_url: Option<String>,
        db_bytes: Option<Box<[u8]>>,
    ) -> Result<WebWallet, Error> { ... }

    /// Store note and generate nullifier/commitment
    pub async fn gen_claim(
        &self,
        headstash_id: String,
        esk_hex: String,
        rho_hex: String,
        fdi: u64,
        recp_hex: String,
        value_amount: u64,
        value_denom: String,
        rseed_hex: String,
    ) -> Result<(), Error> { ... }

    /// List unspent notes (includes nullifiers)
    pub async fn list_unspent_notes(&self, headstash_id: String) -> Result<String, Error> { ... }
}
```

**`NoteData` - Note Information**

```rust
#[derive(Debug, Clone)]
pub struct NoteData {
    /// Nullifier deriving key
    pub nk: NullifierDerivingKey,
    /// The nullifier
    pub nullifier: Nullifier,
    /// The note commitment
    pub commitment: NoteCommitment,
    /// The value
    pub hv: HeadstashValue,
    /// Fixed denomination index
    pub fdi: u64,
    /// Spent status
    pub spent: bool,
}
```

---

## Cryptographic Flow

### Sequential Derivation (Critical Security Property)

**The secret key (esk) must be used FIRST to derive all other values:**

```
esk (secret key - 32 bytes from BIP-32)
  │
  │ ← MUST obtain esk before any derivations
  │
  ├─────────────────────────────────────┐
  │                                     │
  ▼                                     ▼
getPk(esk)                    generateNullifier(esk, ...)
  │                                     │
  │                                     │ ← esk is input to both paths
  │                                     │
  │                                     ▼
  │                          nk = HKDF(esk, rho)
  │                                     │
  │                                     │  (Poseidon-based HKDF)
  │                                     │
  │                                     ▼
  │                          nullifier = PRF_nf(nk, rho, psi)
  │                                     │
  │                                     │  (Poseidon PRF)
  │                                     │
  ▼                                     ▼
pk (public key)              commitment = NoteCommit(esk, fdi, nd, v, recp, rho, rseed)
  │                                     │
  │                                     │  (Sinsemilla CommitDomain)
  │                                     │
  └─────────────┬───────────────────────┘
                │
                ▼
          esk.fill(0)  ← Clear secret key from memory
                │
                ▼
    Return: { nullifier, commitment, pk }
```

### Key Derivations

**1. Nullifier Deriving Key (nk)**

```rust
// HKDF using Poseidon
nk = hdkf_pallas(esk_to_base(&esk), rho.into_inner())
```

**2. Nullifier**

```rust
// PRF using Poseidon
nullifier = prf_nf(nk.inner(), rho.into_inner(), psi)
```

**3. Note Commitment**

```rust
// Sinsemilla CommitDomain
commitment = SinsemillaCommitDomain::commit(
    recp, v, nd, fdi, esk, rho, rseed, rcm
)
```

**Important:** Both nullifier and commitment depend on `esk`. The secret key must be retrieved once and used for both derivations, not retrieved separately for each.

---

## API Reference

### JSON-RPC Methods

#### `generateNullifier`

Generate note nullifier and commitment for a headstash claim.

**Request:**

```typescript
{
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@terpnetwork/headstash-snap',
    request: {
      method: 'generateNullifier',
      params: {
        headstashId: string,
        noteInputs: {
          recp: string,      // Recipient address (hex)
          nd: string,        // Denomination (e.g., "uterp")
          v: string,         // Value amount
          fdi: number,       // Fixed denomination index
          rho: string,       // Randomness (32 bytes hex)
          rseed: string      // Random seed (32 bytes hex)
        }
      }
    }
  }
}
```

**Response:**

```typescript
{
  nullifier: string,   // Note nullifier (32 bytes hex)
  commitment: string,  // Note commitment (32 bytes hex)
  pk: string          // Public key (33 bytes hex) - SAFE TO REVEAL
}
```

**Example:**

```javascript
const response = await window.ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId: 'npm:@terpnetwork/headstash-snap',
    request: {
      method: 'generateNullifier',
      params: {
        headstashId: 'terp1contract123...',
        noteInputs: {
          recp: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
          nd: 'uterp',
          v: '1000000',
          fdi: 42,
          rho: 'a1b2c3d4e5f6...', // 64 hex chars (32 bytes)
          rseed: 'f1e2d3c4b5a6...', // 64 hex chars (32 bytes)
        },
      },
    },
  },
});

// response = { nullifier, commitment, pk }
```

---

## Security Guarantees

### What the Snap NEVER Does

❌ **Store the secret key** - Keys are only requested when needed
❌ **Log the secret key** - No logging of sensitive material
❌ **Return the secret key** - Only public outputs returned
❌ **Transmit the secret key** - Never sent over network
❌ **Store the seed phrase** - Managed by MetaMask only
❌ **Persist keys to disk** - All operations in-memory
❌ **Reveal the secret key in note records** - Only public key is stored

### What the Snap DOES

✅ **Request key transiently** - Only when generating nullifiers
✅ **Use key temporarily** - For cryptographic operations only
✅ **Clear key immediately** - `esk.fill(0)` after use
✅ **Return public outputs** - nullifier, commitment, pk only
✅ **Show user confirmation** - Before every operation
✅ **Derive public key** - For verification purposes only
✅ **Store only public key** - In spent note records for verification

### Privacy Properties

**Unlinkability:** The nullifier reveals nothing about:

- The eligible address (epk)
- The secret key (esk)
- Other nullifiers generated by the same user
- The recipient address (recp) - binding happens via proof

**Double-Spend Prevention:** Each note has a unique nullifier:

- Derived deterministically from esk + note data
- Impossible to alter inputs and reuse a nullifier
- Tracked on-chain in spent-nullifier list

**No On-Chain Association:** The claiming transaction reveals:

- Nullifier (unlinkable to epk)
- Commitment (unlinkable to note details)
- Public key (unlinkable to epk)
- Recipient (recp) - intentionally public

But does NOT reveal:

- Eligible address (epk)
- Secret key (esk)
- Which specific allocation is being claimed
- Link between multiple claims by the same user

---

## Workspace Integration

### Cohesive Product Suite

The MetaMask Snap is part of a larger workspace providing complete headstash interaction:

```
┌─────────────────────────────────────────────────────────────┐
│                    HEADSTASH PRODUCT SUITE                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 1. ZK-Headstash Circuit (zk-crates/zk-headstash)     │  │
│  │    - Halo2 circuit implementation                     │  │
│  │    - Key pairing verification (esk, epk)              │  │
│  │    - HKDF derivation (nk from esk + rho)              │  │
│  │    - Nullifier generation (PRF_nf)                    │  │
│  │    - Note commitment (Sinsemilla)                     │  │
│  │    - Merkle tree inclusion proofs                     │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            │ proving key, verification key    │
│                            │                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 2. Snap-n-Pull WASM (zk-crates/snap-n-pull)          │  │
│  │    - Rust cryptographic core                          │  │
│  │    - HeadstashWallet                                  │  │
│  │    - Note management                                  │  │
│  │    - Nullifier generation (without proof)             │  │
│  │    - wasm-bindgen exports for browser use             │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            │ WebWallet API                    │
│                            │                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 3. MetaMask Snap (zk-packages/snap)                   │  │
│  │    - TypeScript snap implementation                   │  │
│  │    - BIP-32 key derivation via snap_getBip32Entropy   │  │
│  │    - User confirmation dialogs                        │  │
│  │    - WASM integration                                 │  │
│  │    - JSON-RPC interface (generateNullifier)           │  │
│  └───────────────────────────────────────────────────────┘  │
│                            │                                 │
│                            │ snap API                         │
│                            │                                 │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 4. Frontend Dashboard (egui/web)                      │  │
│  │    - Headstash marketplace                            │  │
│  │    - Wallet connection (Keplr, MetaMask)              │  │
│  │    - Smart account authentication                     │  │
│  │    - Claim interface                                  │  │
│  │    - Transaction broadcasting                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 5. Headstash Smart Contract (Rust/CosmWasm)           │  │
│  │    - Merkle root storage                              │  │
│  │    - Spent nullifier tracking                         │  │
│  │    - Proof verification                               │  │
│  │    - Token distribution                               │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 6. Headstash API (Verifiable Service)                 │  │
│  │    - Merkle tree queries                              │  │
│  │    - Note discovery                                   │  │
│  │    - Nullifier state sync                             │  │
│  │    - Fee grant support                                │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Integration Flow

**1. User discovers eligible headstash (Frontend)**

- Query headstash API for available instances
- Check merkle tree for eligible allocations
- Display claimable notes

**2. User initiates claim (Frontend → Snap)**

- Frontend calls `generateNullifier` RPC method
- Provides public note inputs (recp, nd, v, fdi, rho, rseed)

**3. Snap generates nullifier (Snap → WASM)**

- Retrieves esk from MetaMask BIP-32 derivation
- Calls WASM `generate_note_data()`
- Returns nullifier, commitment, pk

**4. Frontend generates proof (Frontend → Circuit)**

- Uses nullifier/commitment as public inputs
- Generates ZK proof of ownership and merkle inclusion
- Proof verifies: knows esk for epk, note is in tree

**5. Frontend broadcasts claim (Frontend → Chain)**

- Submits: nullifier, commitment, proof, publicInputs
- Smart contract verifies proof
- Contract checks nullifier uniqueness
- Contract distributes tokens to recp

---

## Build and Deploy

### Prerequisites

- Node.js 18+
- Yarn or npm
- wasm-pack
- Rust toolchain

### Build WASM Module

```bash
cd zk-crates/snap-n-pull
wasm-pack build --target web --out-dir ../../zk-packages/snap/wasm
```

### Build Snap

```bash
cd zk-packages/snap
yarn install
yarn build
```

### Test Locally

```bash
# Serve snap locally
yarn serve

# In another terminal, run test dApp
cd examples/test-dapp
yarn dev
```

### Deploy to npm

```bash
# Update version in package.json
yarn version --new-version 1.0.0

# Publish
yarn publish --access public
```

---

## References

**Documentation:**

- [MetaMask Snaps API](https://docs.metamask.io/snaps/)
- [BIP-32 Entropy API](https://docs.metamask.io/snaps/reference/snaps-api/#snap_getbip32entropy)
- [Headstash Spec](./spec.md)
- [Frontend Guide](./frontend.md)

**Research:**

- [Zcash Orchard Protocol](https://zips.z.cash/protocol/protocol.pdf#orchard)
- [ZK-ECDSA (0xPARC)](https://0xparc.org/blog/zk-ecdsa-1)
- [Stealthdrop](https://github.com/stealthdrop/stealthdrop)
- [Halo2 ECC](https://github.com/axiom-crypto/halo2-lib)

**Copyright:** Based on ChainSafe Systems' Zcash WebWallet (Apache-2.0, MIT)

---

**Version History:**

- **v2.0** (2025-01-20) - Complete rewrite for Headstash integration with actual implementation
- **v1.0** (2024) - Initial Zcash-based specification (deprecated)
