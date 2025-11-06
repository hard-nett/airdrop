
# Headstash Circuit

```text
  Circuit Component Dependencies

  Secp256k1 Key Pairing (pk = sk * G)
  ├─ Requires: FpChip, FqChip from halo2-ecc
  ├─ Requires: RangeChip for limb bounds
  └─ Requires: EccChip for point multiplication

   HKDF + Signature Verification
  ├─ Requires: Poseidon on Pallas (already configured)
  ├─ Inputs: elig_sk (u64), DST (32 bytes)
  └─ Output: pk/sk (Pallas)

   Nullifier Derivation
  ├─ Requires: Poseidon on Pallas (already configured)
  ├─ Inputs: fdi (u64), v (u64), nd (32 bytes), elig_sk (32 bytes)
  └─ Output: nullifier (Pallas::Base)

   Note Commitment
  ├─ Requires: PRF expansion (psi, rcm from rseed)
  ├─ Requires: Poseidon on Pallas (already configured)
  └─ Inputs: recp, v, rho, psi, rcm

   Merkle Verification
  ├─ Genesis tree: Sinsemilla HashDomain (configured)
  └─ Note tree: Sinsemilla CommitDomain (configured)

    Major Implementation Challenges

  1. Integrating halo2-lib with halo2-gadgets: The halo2-lib chips use a different architecture (FlexGate, RangeChip abstractions) than halo2-gadgets
  (traditional Chip trait). You'll need to bridge these or standardize on one approach.


  3. Hash-to-Curve In-Circuit: The PLUME signature requires h = HTC([m, sec1(pk)]) computed in-circuit. The halo2-ecc/secp256k1/hash_to_curve module should
  provide this.
  4. Fixed-Base vs Variable-Base Multiplication: For pk = sk * G (fixed base), you can use optimized fixed-base scalar mult. For PLUME point operations, you'll need variable-base.

  Recommended Implementation Order

  The todo list I created follows this priority:

 

```

## Circuits Curve & Field Elements

Our circuit primary curve is pallas. We have a need to make use of multiple curves, as expected elements of our circuit inputs are related to curves other than pallas.

| Chip     | Field       | Curve|   Value | |
|----------|-------------|--------------------------------------|--------------------------------------|------------|
| **Sinsemilla**| **Base(`Fp`)** | **Pallas**  | `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`| — |
| **Sinsemilla**| **Scalar(`Fq`)** | **Pallas**  | `q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`| — |
| **Sinsemilla**| **Point(`Ep`)** | **Pallas**  |  - | — |
| **Plume_Fp**| **Base(`Fp`)** |**Secp256k1**  | `p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`| — |
| **Plume_Fq**| **Scalar(`Fq`)** | **Secp256k1**  |`q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`| — |
<!-- | **Plume_Fr**| **Scalar(`Fr`)** | **Bn254**  |`r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`| — |
| **Plume_Point**| **Scalar(`Fr`)** | **Bn254**  |`r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`| — |
| **Plume_Posiedon_Hash**| **Scalar(`Fr`)** | **Bn254**  |`r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`| — | -->

## Foreign-Field Related Chips

### PallasLookupRangeCheck

The `RangeChip` is the foundation for foreign field arithmetic in our Pallas-based circuit. It provides lookup tables for efficient range checking of limb values, ensuring that our BigInt representations don't overflow when emulating non-native field arithmetic.

#### Limb Parameters

**Secp256k1 → Pallas:**

- **limb_bits:** 88
- **num_limbs:** 3
- **Total bits:** 264 (covers 256-bit secp256k1 fields with 8-bit overflow buffer)
- **Lookup bits:** 17 (lookup table size = 2^17 = 131,072 entries)
- **Rationale:** 88-bit limbs fit comfortably within Pallas field capacity while minimizing the number of limbs needed
- The RangeChip enforces: 0 ≤ limb_i < 2^88 via lookup tables

<!-- **BN254 → Pallas:**

- **limb_bits:** 88
- **num_limbs:** 3
- **Total bits:** 264 (covers 254-bit BN254::Fr)
- **Lookup bits:** 17
- **Rationale:** Same configuration as secp256k1 for consistency -->

<!-- ```
BN254::Fr = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 ≈ 2^254

Using same 88-bit × 3 limb strategy provides adequate coverage
``` -->

**Key Configuration Constants:**

```rust
// From halo2-ecc/configs/secp256k1/ecdsa_circuit.config
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const LOOKUP_BITS: usize = 17;
const DEGREE: u32 = 18; // Circuit size: 2^18 rows
```

### Field Elements (Fp,Fq,Fr)

In our circuit, we need to represent and operate on field elements from three different curves within the Pallas native field. This requires careful handling of **non-native field arithmetic** using the Chinese Remainder Theorem (CRT) representation.

#### CRT Integer Representation

Each foreign field element is represented as a `ProperCrtUint<F>` where `F = Pallas::Base`:

```rust
pub struct ProperCrtUint<F> {
    // Limb representation: value = Σ(limb[i] * 2^(limb_bits * i))
    pub truncation: OverflowInteger<F>,
    // Native field representation: value mod modulus::<F>()
    pub native: AssignedValue<F>,
    // Maximum limb value
    pub max_limb_bits: usize,
}
```

**How It Works:**

1. **Limb decomposition:** A 256-bit foreign field element is split into 3 × 88-bit limbs
2. **Native reduction:** The value is also stored as `value mod Pallas::Fq` in native representation
3. **Dual representation:** Both representations are constrained to be equivalent, enabling efficient operations

#### Constraining Foreign Fields in Circuit

**Operation Flow:**

1. Load foreign field element as witness:\
   `FpChip::load_private( secp_value) → ProperCrtUint<Pallas::Base>`

2. Perform operations in CRT representation:
   - Addition: add limbs element-wise, check for carries
   - Multiplication: mul limbs, reduce modulo foreign field prime
   - Reduction: carry_mod ensures result < foreign_modulus

3. Range check all limbs:\
   RangeChip::range_check( limb, LIMB_BITS) → ensures limb < 2^88

4. Verify CRT consistency:
   Constrain: native_value ≡ Σ(limb[i] *2^(88*i)) (mod Pallas::Fq)

**Critical Constraints:**

1. **Limb Bounds:** Each limb must be < 2^88 (enforced by RangeChip lookups)
2. **Modular Reduction:** After operations, values must be reduced mod foreign_prime
3. **Native Consistency:** `native ≡ Σ limbs (mod Pallas::Fq)`
4. **Carry Propagation:** Multi-limb arithmetic must handle carries correctly

### Ecc (Secp256k1 chip)

The `EccChip` performs elliptic curve operations over `secp256k1` using foreign field arithmetic. It's essential for both key pairing verification (`pk = sk·G`) and HKDF constraints.

#### Key Operations

**1. Fixed-Base Scalar Multiplication** (for `pk = sk·G`)

```rust
// G is the secp256k1 generator (fixed base point)
// sk is the secret key (scalar in Fq)
// Result: pk = sk·G

pub fn fixed_base_scalar_mult(
    &self,
    sk: ProperCrtUint<F>,  // sk ∈ Secp256k1::Fq
    base: &EcPoint<F, FpChip<F>>,  // G (generator)
) -> EcPoint<F, FpChip<F>>  // pk ∈ secp256k1 curve
```

**Optimization:** Fixed-base multiplication uses precomputed multiples of G (windowed method) to reduce constraints compared to variable-base.

**2. Variable-Base Scalar Multiplication** (for PLUME operations)

```rust
// For computing g^s, h^s, pk^c, nul^c in PLUME verification
pub fn scalar_mult(
    &self,
    point: EcPoint<F, FpChip<F>>,
    scalar: ProperCrtUint<F>,
) -> EcPoint<F, FpChip<F>>
```

**Algorithm:** Uses windowed non-adjacent form (wNAF) with window size 4, requiring ~256/4 = 64 point additions/doubles.

**3. Point Addition** (for `g^s·pk^(-c)`)

```rust
pub fn add_unequal(
    &self,
    P: EcPoint<F, FpChip<F>>,
    Q: EcPoint<F, FpChip<F>>,
) -> EcPoint<F, FpChip<F>>
```

**Constraint:** Uses incomplete addition formula assuming P ≠ Q, P ≠ -Q. Requires ~10 Fp multiplications per addition.

**4. Point Negation** (for `-c` in PLUME)

```rust
pub fn negate(
    &self,
    point: EcPoint<F, FpChip<F>>,
) -> EcPoint<F, FpChip<F>>
```

**Implementation:** Simply negates y-coordinate: `(x, y) → (x, -y mod p)`

#### Secp256k1 Curve Equation

The chip enforces points lie on the curve: `y² = x³ + 7 (mod p)`

**On-Curve Check:**

```rust
pub fn assert_on_curve(
    &self,
    point: &EcPoint<F, FpChip<F>>,
) {
    let y_sq = fp_chip.mul( point.y, point.y);
    let x_sq = fp_chip.mul( point.x, point.x);
    let x_cu = fp_chip.mul( x_sq, point.x);
    let x_cu_plus_b = fp_chip.add_constant( x_cu, SECP_B); // SECP_B = 7
    fp_chip.assert_equal( y_sq, x_cu_plus_b);
}
```

### Poseidon (for Pallas-native operations)

Poseidon is a ZK-friendly hash function used for nullifier derivation, note commitments. Our circuit uses two Poseidon configurations:

1. **Poseidon on Pallas::Base (for Nullifiers & Note Commitments)**

```rust
// Already configured in circuit.rs:139-147
let poseidon_config_1 = PoseidonChip::configure::<poseidon::P128Pow5T3>(
    meta,
    advices[6..9].try_into().unwrap(),  // 3 state columns
    advices[5],                          // partial_sbox column
    rc_a,                                // Round constants
    rc_b,
);
```

**Parameters:**

- **State width:** 3 (t=3)
- **Rate:** 2 (can hash 2 field elements per permutation)
- **Full rounds:** 8
- **Partial rounds:** 56
- **S-box:** x^5 (AlphaInv for Pallas)

**Usage for Nullifiers (from spec.md:251-266):**

```rust
// nul = Poseidon(fdi, v, h_nd, h_elig)
// where:
//   h_nd = Poseidon(DST_N || nd)
//   h_elig = Poseidon(DST_N || elig_sk)

let h_nd = poseidon_chip.hash( &[dst_n, nd])?;
let h_elig = poseidon_chip.hash( &[dst_n, elig_sk])?;
let nul = poseidon_chip.hash( &[fdi, v, h_nd, h_elig])?;
```

**Usage for Note Commitments (from spec.md:320-327):**

```rust
// cm = Poseidon(recp, v, rho, psi, rcm)
let cm = poseidon_chip.hash( &[recp, v, rho, psi, rcm])?;
```

2. **HKDF-Derived Pallas Signatures (Optimized Ownership Proof)**

**Strategy:**

1. **Prove secp256k1 key ownership** (1 foreign field scalar mult - ~20K constraints)
2. **Derive Pallas keypair via HKDF** from secp256k1 secret (native - ~150 constraints)
3. **Sign message on Pallas curve** via Schnorr (native - ~2.5K constraints)
4. **Generate deterministic nullifier** from derived key (native - ~150 constraints)

### In-Circuit Constraint Flow

**Step 1: Secp256k1 Key Pairing (Foreign Field)**

```rust
// CONSTRAINT: Prove elig_sk corresponds to elig_pk
let sk = fq_chip.load_private(ctx, elig_sk);     // Private witness
let pk_input = ecc_chip.load_private(ctx, elig_pk); // Private witness
let pk_computed = ecc_chip.fixed_base_scalar_mult(ctx, sk, G_SECP);
ecc_chip.assert_equal(ctx, pk_computed, pk_input);
// ✅ Circuit enforces: elig_pk = elig_sk * G_secp
// ✅ Proves ownership of secp256k1 key
// Cost: ~20,000 constraints (foreign field)
```

**Step 2: HKDF Derivation (Native - In-Circuit!)**

```rust
// CONSTRAINT: Derive Pallas secret key deterministically
// Use Poseidon-based KDF (much cheaper than HMAC-SHA256)

// Convert secp256k1 scalar to Pallas field element
let elig_sk_native = fq_chip.to_native(ctx, sk); // ∈ Pallas::Base

// Derive Pallas scalar
let pallas_sk = poseidon_chip.hash(ctx, &[
    DST,              // Domain separator (constant)
    elig_sk_native,   // secp256k1 sk as Pallas::Base
    m,                // Message hash (binds to note)
])?;
// ✅ Circuit enforces: pallas_sk = Poseidon(DST, elig_sk, m)
// ✅ Deterministic: same inputs → same pallas_sk
// ✅ Unlinkable: different m → different pallas_sk
// Cost: ~150 constraints (native Poseidon)
```

**Step 3: Pallas Keypair Derivation (Native)**

```rust
// CONSTRAINT: Compute Pallas public key from derived secret
let pallas_pk = ecc_chip_pallas.fixed_base_scalar_mult(
    ctx,
    pallas_sk,  // From HKDF above
    G_PALLAS    // Pallas generator
);
// ✅ Circuit enforces: pallas_pk = pallas_sk * G_pallas
// Cost: ~1,000 constraints (native curve)
```

**Step 4: Schnorr Signature Verification (Native - In-Circuit!)**

```rust
// Private inputs: signature components (R, s)
let R = ecc_chip_pallas.load_private(ctx, sig_R);  // Signature point
let s = load_private(ctx, sig_s);                   // Signature scalar

// CONSTRAINT: Compute challenge
let e = poseidon_chip.hash(ctx, &[
    R.x, R.y,           // Signature nonce point
    pallas_pk.x, pallas_pk.y,  // Derived public key
    m                    // Message
])?;
// e ∈ Pallas::Scalar

// CONSTRAINT: Verify Schnorr equation: R == s*G - e*pallas_pk
let sG = ecc_chip_pallas.fixed_base_scalar_mult(ctx, s, G_PALLAS);
let e_pk = ecc_chip_pallas.scalar_mult(ctx, pallas_pk, e);
let e_pk_neg = ecc_chip_pallas.negate(ctx, e_pk);
let R_check = ecc_chip_pallas.add(ctx, sG, e_pk_neg);

ecc_chip_pallas.assert_equal(ctx, R, R_check);
// ✅ Circuit enforces: Valid Schnorr signature
// ✅ Proves: HKDF-derived key signed the message
// ✅ Binds: elig_sk → pallas_sk → signature → message
// Cost: ~2,500 constraints (2 scalar mults + 1 hash)
```

**Step 5: Deterministic Nullifier (Native)**

```rust
// CONSTRAINT: Generate deterministic nullifier from derived key
let nul = poseidon_chip.hash(ctx, &[
    pallas_sk,  // From HKDF (step 2)
    m,          // Message (binds to note)
    fdi,        // Fixed denomination index
    v,          // Note value
    h_nd,       // Hash of denomination
])?;
// ✅ Circuit enforces: Nullifier correctly derived
// ✅ Deterministic: same (elig_sk, note) → same nullifier
// ✅ Prevents double-spend
// ✅ Unlinkable to elig_pk (HKDF breaks linkage)
// Cost: ~150 constraints (native Poseidon)
```

### Message Construction

The message `m` is deterministic and binds to the note being claimed:

```rust
// Out of circuit (witness generation):
let m = Poseidon::hash([
    recp,     // Recipient address (binds destination)
    v,        // Note value
    nd,       // Note denomination
    fdi,      // Fixed denomination index
]);

// This ensures:
// 1. Message uniquely identifies the note
// 2. Signature binds to specific destination (recp)
// 3. Cannot reuse signature for different claim
// 4. Different notes → different pallas_sk (via HKDF)
```

### Security Properties

**✅ Ownership Proof:**

- Circuit constrains: `elig_pk = elig_sk * G_secp`
- Prover must know valid secp256k1 private key

**✅ Authorization Proof:**

- Circuit constrains: `pallas_sk = HKDF(elig_sk, m)`
- Circuit verifies: Schnorr signature valid for (pallas_sk, m)
- Message binds to recipient address

**✅ Double-Spend Prevention:**

- Nullifier: `nul = Hash(pallas_sk, m, fdi, v, nd)`
- Same note + same key → same nullifier
- On-chain nullifier set prevents reuse

**✅ Privacy:**

- `elig_pk` never revealed (private witness)
- `pallas_sk` derived via one-way function (HKDF)
- No linkage between `elig_pk` and on-chain data

### Constraint Cost Comparison

| Approach | Foreign Field Ops | Native Ops | Total Constraints | Proof Time (est.) |
|----------|-------------------|------------|-------------------|-------------------|
| **Full PLUME (secp256k1)** | 6-8 scalar mults | Minimal | ~150,000 | ~8-10s |
| **HKDF + Pallas (this approach)** | 1 scalar mult | 3 scalar mults + 3 hashes | ~24,000 | **~2-3s** |
| **Savings** | -87% foreign field | +3 native (cheap) | **-84%** | **-70%** |

### Circuit Interface

**Public Inputs (exposed to verifier):**

```rust
pub struct PublicInputs {
    genesis_root: pallas::Base,      // Genesis merkle root (constant)
    nul: pallas::Base,               // Nullifier (prevents double-spend)
    cm: pallas::Base,                // Note commitment (output)
    nd: pallas::Base,                // Note denomination (public)
    v: pallas::Base,                 // Note value (public)
    recp: pallas::Base,              // Recipient address (destination)
}
// Note: No secp256k1 keys or signatures exposed!
// Total: 6 public inputs
```

**Private Witnesses (only prover knows):**

```rust
pub struct PrivateWitnesses {
    // Secp256k1 key pair (ownership proof)
    elig_sk: secp256k1::Fq,          // Eligible secret key
    elig_pk: secp256k1::Affine,      // Eligible public key

    // Note identification
    fdi: u64,                        // Fixed denomination index
    merkle_path: [pallas::Base; 32], // Path to genesis root

    // Note commitment components
    rseed: [u8; 32],                 // Random seed for PRF
    rho: pallas::Base,               // Unique note identifier
    psi: pallas::Base,               // PRF output
    rcm: pallas::Scalar,             // Commitment randomness

    // Schnorr signature on Pallas (authorization)
    sig_R: pallas::Affine,           // Signature nonce point
    sig_s: pallas::Scalar,           // Signature scalar
}
// Total: 11 private witnesses
```

**Derived Values (computed in-circuit):**

```rust
// Message binding note to recipient
let m = poseidon_hash([recp, v, nd, fdi]);

// HKDF-derived Pallas keypair
let pallas_sk = poseidon_hash([DST, elig_sk_native, m]);
let pallas_pk = pallas_sk * G_pallas;

// Schnorr challenge
let e = poseidon_hash([sig_R.x, sig_R.y, pallas_pk.x, pallas_pk.y, m]);
```

### Implementation Notes

- Implement `fq_chip.to_native()` for field element conversion
- Use existing Pallas ECC chip from halo2_gadgets (already in circuit.rs:7-10)
- Implement Schnorr verification in `src/circuit/gadget/schnorr_chip.rs`
- HKDF uses Poseidon (reuse `poseidon_config_1`)
- Domain separator: `DST = "HEADSTASH_HKDF_PALLAS_V1"`
- Estimated circuit size: **2^15 to 2^16 rows** (~24K constraints)

### FpChip (Secp256k1::Fp)

**Purpose:** Represents and operates on secp256k1 base field elements within the Pallas circuit.

**Type Signature:**

```rust
pub type FpChip<'range, F> = fp::FpChip<'range, F, Secp256k1::Fp>;
// where F = Pallas::Base (our native field)
```

**Construction:**

```rust
let fp_chip = FpChip::<Pallas::Base, Secp256k1::Fp>::new(
    range,      // RangeChip for lookup tables
    88,         // limb_bits
    3,          // num_limbs
);
```

**Core Operations:**

- `load_private( value)` - Load Fp element as witness
- `load_constant( value)` - Load Fp constant
- `mul( a, b)` - Multiply two Fp elements
- `add( a, b)` - Add two Fp elements
- `sub( a, b)` - Subtract Fp elements
- `assert_equal( a, b)` - Constrain equality
- `enforce_less_than_p( a)` - Ensure a < secp256k1_p

**Used For:**

- Public key x, y coordinates
- Elliptic curve point arithmetic
- Hash-to-curve outputs

### FqChip (Secp256k1::Fq)

**Purpose:** Represents and operates on secp256k1 scalar field elements (the curve order).

**Type Signature:**

```rust
pub type FqChip<'range, F> = fp::FpChip<'range, F, Secp256k1::Fq>;
```

**Construction:** Same as FpChip but parameterized with `Secp256k1::Fq`

**Used For:**

- Secret key `sk`
- PLUME signature scalars `r, s, c`
- Scalar multiplication exponents

**Critical Difference from FpChip:**

- Modulus is `Secp256k1::Fq` (curve order) not `Secp256k1::Fp` (base field)
- Used for scalars, not point coordinates
- Operations are mod `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`

## merkle tree spec: Sinsemilla

Sinsemilla is a ZK-friendly hash function designed specifically for Pallas/Vesta curves. We use it for both genesis distribution tree (HashDomain) and note commitment tree (CommitDomain).

### PallasLookupRangeCheck (for Sinsemilla)

Sinsemilla operations require range checks on bit decompositions and intermediate values. The same `LookupRangeCheckConfig` used for foreign field arithmetic is shared with Sinsemilla.

**Configuration (from circuit.rs:131):**

```rust
let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
```

**Shared Usage:**

- **Foreign field:** Range checks on 88-bit limbs
- **Sinsemilla:** Range checks on 10-bit chunks during message decomposition

**Optimization:** Sharing lookup tables across chips reduces circuit overhead by ~15% compared to separate configs.

### FixedPoints (Pallas Curve)

Fixed points are precomputed generators used in Sinsemilla hashing and commitment schemes. They're defined in `src/constants/fixed_bases.rs`.

- **MerkleHashCrh:** Generator for Sinsemilla hash function in merkle trees
- **NoteCommitR:** Generator for blinding factor in pedersen commitments
- Window tables enable efficient fixed-base scalar multiplication

### HashDomains (Genesis Distribution Tree)

`HashDomains` define the Sinsemilla hash function parameters for different contexts. We use this for the **genesis merkle tree** (non-hiding hashes).

**Key Properties:**

1. **Hiding:** Given `cm`, cannot determine `recp, v, rho, psi` without knowing `rcm`
2. **Binding:** Cannot find two different preimages that produce the same `cm`
3. **Additively Homomorphic:** `Commit(m1, r1) + Commit(m2, r2) = Commit(m1+m2, r1+r2)`
