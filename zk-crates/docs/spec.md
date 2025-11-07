
# Spec: Zk-Airdrop Claiming
>
> **GOAL: Allow eligible headstash members to use zk-proofs to claim partial amounts of their rewards over time.**

## Context

Our current airdrop framework, `The Headstash Contract` powers distribution by mapping ECDSA addresses not native to the chain (ETH,SOL,etc) as eligible to claim a specific list of tokens. In order to claim, users need to verify they are owners of any eligible addresses secret key `elig_sk`. This is done by generating a signature with `elig_sk`, from a message that includes the address native to the chain that the user will use to broadcast the message to claim their allocations `recp`.

```math
\sigma = \text{Sign}_{\text{elig}_{\text{sk}}}\big( H(m) \big), \quad \text{where } \text{recp} \in m
```

**This creates an on-chain association between the eligible account `elig_pk`, and the claiming address `recp`, which we want to prevent.**

In order to prevent this association between verifying ownership & claiming tokens, there are 3 major obstacles:

### Q: How Does Someone Prove They Own An Eligible Wallet Without Revealing Their Signature?

**A: proof of ownership**: A circuit can provide certainty that an individual knows the private key paired with their public key of an eligible account, by use of the deterministic capabilities of a hash-based key deriving function (hkdf).

### Q: How can someone prevent leaking where their claimed funds end up, if the total amount & distributions allocated are public?

**A: Fixed Denomination Notes**: notes function as private UTXOs (Unspent Transaction Outputs) that represent claims to portions of the airdropped tokens. Each note contains sensitive data that must remain private, except for certain public components used for verification and transaction processing.

A predetermined set of notes for users are generated based on initial allocations, classified by fixed-denomination amounts. Partial claims of genesis allocations are then possible, and allows eligble claimers to designate unique addresses for receiving allocations over a span of time rather than immediately.

### Q: How are users prevented from claiming more funds then they are allocated?

**A:nullifiers**: Deriving from private data within a note, collision-resistant nullifiers paired with note-commitments will prevent notes from being double-spent.note nullifiers derive from completely deterministic sources, such that it is impossible to alter one of the PRF inputs, that will result in the ability to reuse a note that has been spent.

> **Notes About Design**
> These obstacles are not unique to our requirements, and have been solved concretely by multiple teams, one for example is the zcash's sprout, sapling, and orchard protocols. We are designing our protocol for private airdrops so that we can leverage a large majority of the work done by the cypherpunk community, however there are some discrepancies we need to design around. Specifically:
>
> **1. Actions will be sending tokens to destination on a transparent ledger**
> When someone is claiming, they will be revealing how much and to whom the claimed tokens are going to *(along with the other crucial components like nullifiers & note commitments)*.
>
> **2. Viewing key magic is very limited**
> We do not use diversifiers, viewing-keys & spending-keys as defined in multiple Zcash protocols, which is how note-commitments and nullifiers are
> derived. We instead implement a simplified implementation of this that satisfies our requirements, without sacraficing any of the privacy
> guarantees that are available with use of halo2 circuits.
>
## Requirements

- **Keys: Self-Custody Key Management Systems**
- **Randomness Generators**
- **Private Proof Of Ownership - PLUME + key pairing**
- **Sinsemilla Merkle Trees**
- **Nullifier & Note Commitments**
- **Verifiable Service in TEE**
- **On-Chain Smart Contract**
- **Metamask Snap Support**

___

## Keys, Curves & Fields

We have 3 main types of keys involved in this process.

1. **Eligible Keys:**  *the keys that has a public allocation set for them, and is what we must keep any signature or hash derived from private, in order to retain privacy.*
2. **Redemption Keys:** *the keys that will be recieving the public allocations claimed by the eligible keys*
3. **HKDF keys:** *the keys that are deterministically derived from private inputs of a circuit*

> HKDF keys are specifically used to make our proof of ownership step effecient & feasable in-circuit.

| # | Key type         | Curve used | Primary crate | Public / Private usage | Typical Rust type (example) | Key‑derivation notes |
|---|------------------|------------|--------------|------------------------|-----------------------------|----------------------|
| 1 | **Eligible Key** | `secp256k1`  | `k256` (or `secp256k1`) | Public key is **published** in the allocation; **private key + any signatures / hashes must stay secret** to preserve privacy. | `k256::ecdsa::SigningKey` / `k256::ecdsa::VerifyingKey` | - |
| 2 | **Redemption Key** | secp256k1 | `k256` (or `secp256k1`) | Public key is **the recipient** of the claimed allocation; private key is used only to sign the redemption proof. | Same as Eligible (`SigningKey`/`VerifyingKey`) | May be pre‑generated or created on‑the‑fly; no HKDF involved. |
| 3 | **HKDF‑derived Key** |  `pallas` | - | Private key **only**; the corresponding public key is *not* exposed – it is used inside the circuit for proof‑of‑ownership. |   | Deterministically derived via posiedon based HKDF from circuit‑private inputs (e.g., a seed, a note commitment, a nullifier). The derived scalar is mapped to a pallas point using the crate’s `generator` |

> NOTE: zcash orchard protocol implements very complex (but useful) key derivation for viewing, authorization, and privacy retention purposes. Our scope does not require the use of viewing or authorization keys, as the end results of tokens claimed will be public. A large portion of the modifications from the orchard protocol altering how note-commitments & nullifiers are derived, as they rely heavily on the use of the key structure used by zcash orchard protocol.

### Circuit Curve

Our circuit primary curve is pallas. We have a need to make use of multiple curves, as expected elements of our circuit inputs are related to curves other than pallas.

| Chip     | Field       | Curve|   Value | |
|----------|-------------|--------------------------------------|--------------------------------------|------------|
| **Sinsemilla**| **Base(`Fp`)** | **Pallas**  | `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`| — |
| **Sinsemilla**| **Scalar(`Fq`)** | **Pallas**  | `q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`| — |
| **Sinsemilla**| **Point(`Ep`)** | **Pallas**  |  - | — |
| **Plume_Fp**| **Base(`Fp`)** |**Secp256k1**  | `p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`| — |
| **Plume_Fq**| **Scalar(`Fq`)** | **Secp256k1**  |`q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`| — |

### Circuit Field Elements

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

## Randomness Generation

In order to make it impossible to retroatively derive randomness used during the note-commitment generation (which in theory would be possible if an adversary had access to a device, the timestamp of when randomness was generated, its theoretically possible to recreate the randomness source), we want to enable user-derived input as an additional seed to the PRNG process.

> <center> DEMO: our script used to generate randomness can be invoked via :
>
> `cargo run --package zk-crates --bin generate_randomness`</center>

## Ownership Verification: Pairing

Its crucial that our circuit has an feasable way to verify that the owner of the `elig_pk` is authorizing the spend of a specific note. Normal signature verification for secp256k1 curves are computationally heavy, & generate extremely large proof sizes not compatible with on-chain gas limits & a nice UX.

**Instead, users can prove they know this `elig_sk` by providing it and `elig_pk` as private inputs when generating their proofs.** The circuit will then make use of the known curve equation & generator points to constrain that the two keys are either mathematically paired together or not.

| **Aspect** | **Explanation** |
|------------|-----------------|
| **Private inputs** | `elig_pk` (public key) and `elig_sk` (secret key) must both be provided as **private** witnesses to the circuit. |
| **Arithmetic required** | The circuit needs **foreign‑field arithmetic** to operate over the secp256k1 scalar field (different from the base field of the halo2 proof system). |
| **Core constraint** |  $pk \;=\; sk \;\cdot\; G$, where `G` is the generator point of the secp256k1 curve. |

> **Reference implementation:**  <https://github.com/axiom-crypto/halo2-lib/blob/community-edition/halo2-ecc/src/secp256k1/tests/ecdsa.rs>

The constraint equation is:

```math
\begin{aligned}
\textbf{Private witnesses} &\qquad
\begin{cases}
\mathsf{sk}\in\mathbb{F}_{\ell}      &\text{(secret scalar)}\\[2pt]
\mathsf{pk}= (X_{\mathsf{pk}},Y_{\mathsf{pk}})\in\mathbb{F}_{p}^{\,2}
                                       &\text{(corresponding public point)}
\end{cases}
\\[8pt]
\textbf{Constants} &\qquad
\begin{cases}
G   = (G_{x},G_{y})                     &\text{(generator point)}\\
G_{x}= \texttt{GENERATOR\_X}            &\\
G_{y}= \texttt{GENERATOR\_Y}            &\\
\ell = \texttt{CURVE\_ORDER}            &\text{(sub‑group order)}
\end{cases}
\end{aligned}
```

```math
\boxed{
\begin{aligned}
&0 \;<\; \mathsf{sk} \;<\; \ell
   &&\text{(range‑check that the secret is a canonical scalar)}\\[6pt]
&\mathsf{pk}\;=\;\mathsf{sk}\,\cdot\,G
   &&\text{(fixed‑base elliptic‑curve multiplication)}
\end{aligned}}
```

```math
\text{Component‑wise this is equivalent to}
\qquad
\begin{cases}
X_{\mathsf{pk}} = X\!\bigl(\mathsf{sk}\,\cdot\,G\bigr) \\[4pt]
Y_{\mathsf{pk}} = Y\!\bigl(\mathsf{sk}\,\cdot\,G\bigr)
\end{cases}
```

## Headstash Destination Authorization: HKDF STEPS

Specifically, we aim derive a keypair on the pallas curve from the `elig_sk`.  This derivation process is implmented such that we generate a `hkdf_sk` that is deterministic of its inputs, which lets us constrain the derivation in circuit. By involving the unique and also random inputs from a note, this step lets us accomplish a number of requirements for our circuit to be able to have proofs generated accurately that satisfy our requirements. Specifically

- b. nullifier generation: each key derived via hkdf will be unique due to the composition of its inputs, allowing us to use the `hkdf_pk` as a nullifier
- c. destination & allocation integrity: the destination & amount of funds being spent in a note are public inputs to the hkdf, ensuring that there is no possible way for an man-in-the-middle attack on altering where funds destinations are to be.

### Hashing Function

For effeciency of in-circuit hashing, we are using Posiedon as the hkdf hashing algorithm. Poseidon is a ZK-friendly hash function used for nullifier derivation, note commitments. Our circuit uses two Poseidon configurations:

### Derivation Inputs

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `NOTE_NULLIFIER_PERSONALIZATION`      |    |                                      | **Constant**                         |   |
| `elig_sk`| Eligible secret key             | `bytes[32]`                          | **Private**                          | — |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**                          | *fully padded u64* |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**                           | *blake3 Hash + top 3 bits |
| `psi`    | Note Randomness                 | ` `                                  | **Private**                          ||

> **q: do we damage the blinding of the rest of the inputs to the hashing function due to some being public and some being private?**
>
> a: no! thanks to the hardness of hashing functions, its unfeasable to retroactively derive the private inputs given all of the public inputs and the output hash.

### Nullifiers

To prevent double-spends, each note must have a unique, deterministic nullifier derivable only by the owner. This ensures the nullifier is:

- Unique per note.
- Unlinkable to the eligible address.
- Only computable by the note owner.

```math
\begin{array}{lcl}
\textbf{Private witnesses} &
\begin{cases}
\mathsf{fdi}      \in \mathbb{F}_p      &\text{(fully padded u64 of fixed denomination index }fdi\text{)}\\[2pt]
\mathsf{hkdf\_sk}  \in \{0,1\}^{256}   &\text{(32‑byte secret-key of Pallas curve key derived from eligible secret key)}\\[2pt]
\mathsf{psi}        \in \{0,1\}^{256}   &\text{(32‑byte entropy generated by user)}\\
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\\[10pt]
\textbf{Public inputs} &
\begin{cases}
\mathsf{v}\in \mathbb{F}_p      &\text{(fully padded u64 of value being spent in note)}\\[2pt]
\mathsf{nd}^{\ast}\in \mathbb{F}_p      &\text{(Posiedon Hash of notes token denomination }nd\text{)}\\[2pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\\[10pt]
\textbf{Constants} &
\begin{cases}
\mathtt{DST}_{\!N}= \texttt{NOTE\_NULLIFIER\_PERSONALIZATION}
    &\text{(domain‑separation tag)}\\[2pt]
\mathbb{F}_p &\text{base field of the Pallas curve}
\end{cases}
\end{array}
```

```math
\begin{aligned}
%--- intermediate hashes -------------------------------------------------
h_{\mathsf{nd}}   &:= \text{Poseidon}_{\mathbb{F}_p}
                     \bigl(\,\mathtt{DST}_{\!N}\;\|\;\mathsf{nd}\,\bigr)
                     \;\in\; \mathbb{F}_p \\[4pt]
h_{\mathsf{elig}} &:= \text{Poseidon}_{\mathbb{F}_p}
                     \bigl(\,\mathtt{DST}_{\!N}\;\|\;\mathsf{elig\_sk}\,\bigr)
                     \;\in\; \mathbb{F}_p \\[6pt]
%--- final nullifier ----------------------------------------------------
\boxed{
\mathsf{nul}
   = \text{Poseidon}_{\mathbb{F}_p}
     \bigl(\,\mathsf{fdi},\;\mathsf{v},\;h_{\mathsf{nd}},\;h_{\mathsf{elig}}\,\bigr)
   \in \mathbb{F}_p
}
\end{aligned}
```

### Note Commitments

Note Commitments `cm` are what is disclosed publicly during claiming, by appending to the Note Commitment Tree. They are derived from the private and public inputs of a note, allowing the origin of the claiming address to be private. note commitments are derived from both deterministic and non-deterministic inputs of a note, as we do not use note-commitments for preventing double spends (this is what nullifiers are for).

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `recp`   | Recipient Address               | `bytes[32]`                          | **Public**                           | — |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* |
| `rho`    |                                 |                                      | **Private**                          | - |
| `psi`    |                                 |                                      | **Private**                          |   |
| `rcm`    |                                 |                                      | **Private**                           |   |
| `rseed`  |                                 |                                      | **Private**                           |   |

Constraining the derivation of the note commitment `cm` requires the following inputs:

> note: in order to derive `psi` & `rcm`, we have a `rseed` that is a randomness source in a PRF, that expends into each.

The constraint equation is:

```math
\begin{array}{lcl}
\textbf{Public inputs} &
\begin{cases}
\mathsf{recp}   \in \mathbb{F}_p & \text{recipient address} \\[4pt]
v               \in \mathbb{F}_p & \text{value} \\[4pt]
\rho            \in \mathbb{F}_p & \text{note randomness}
\end{cases}

\\[10pt]
\textbf{Private witnesses} &
\begin{cases}
\mathsf{rseed} \in \{0,1\}^{256} & \text{PRF seed} \\[4pt]
\psi^{\ast}    \in \mathbb{F}_p   & \text{derived via } \text{PRF}_{\text{PSI}} \\[4pt]
\mathsf{rcm}^{\ast} \in \mathbb{F}_p & \text{derived via } \text{PRF}_{\text{RCM}}
\end{cases}
\end{array}
```

```math
\begin{aligned}
\psi      &:= \text{PRF}_{\text{PSI}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[4pt]
\mathsf{rcm} &:= \text{PRF}_{\text{RCM}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[6pt]
\boxed{%
\mathsf{cm}\;:=\;
\text{Poseidon}_{\mathbb{F}_p}\!\bigl(
\mathsf{recp},\,
v,\,\rho,\,\psi,\,\mathsf{rcm}
\bigr)
}
\end{aligned}
```

### Fixed-Denomination-Index

 we need to ensure that note-commitments and nullifiers are impossible to be doublespent, given that we are not using nullifier-keys. specifically, our genesis merkle tree is created by generating leaves for each eligible address total possible fixed denominations. We included an index for all duplicate fixed denomination amounts (ie; if there was 4 1000 TERP fixed denomnination, each leaf without an index would have an identical hash). This will ensure with certainty that nullifiers cannot be forged for resuse.

___

## Sinsemilla Merkle Trees: Inclusion Constraints

Sinsemilla is a ZK-friendly hash function designed specifically for Pallas/Vesta curves. We use it for both genesis distribution tree (HashDomain) and note commitment tree (CommitDomain).

### 1. Genesis Distribution Tree: `HashDomain`

**This is the static, starting state of the headstash before any claims happen.**
Its purpose is to allow a user to prove a specific address `elig_pk` is eligible to claim a certain allocation `v` without revealing which specific address it is. Each leaf is a commitment to the `HashDomain`,that is public & binding an eligible recipients balance for a single token balance. A leaf is computed using the sinsemilla hashing function as:

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `elig_pk`| Eligible public key             | `bytes[32]`                          | **Private**                          | — |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**                          | *fully padded u64* |
| `root`   | Genesis Distribution Tree Root  | `u64`                                | **Constant**                          | *sinsemilla::HashDomain*  |
| `leaf`   | Note Leaf                       | `bytes[32]`                          | **Private**                          | *sinsemilla::HashDomain* |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**                           | *blake3 Hash + top 3 bits cleared* |

> - **Denomination hashing** – Since the length of a denomination is unknown, we hash `nd` with **blake3** to obtain a 32‑byte digest. *Sinsemilla* expects a
> 253‑bit domain, so we simply clear the top three bits of the digest. The denomination is public, so smart contracts can map `nd` → `blake3(nd) &
> 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` in O(1) time.
>
> - **Padding for `v` and `fdi`** – Both values are `u64` (max 160 bits when concatenated). For table look‑ups we left‑pad each to the byte length required by
> the hashDomain of Sinsemilla (e.g., 32 bytes). This ensures the inputs line up with the fixed‑size field elements used inside the circuit.
>
> - **`elig_pk` handling for Sinsemilla compatibility** – `elig_pk` is a 32‑byte public‑key representation. The value is interpreted as a field element; any
> bits that fall outside the field size are cleared (i.e., the top‑most bits are masked) before it is used as input to the Sinsemilla hash. **The Full key is
> required in‑circuit,**Even though `elig_pk` is private for the prover, the circuit must receive the entire key as  we need to enforce the relationship of the
> `hkd_sk` being derived from a `elig_sk` thyat is paired with an `elig_pk`. This guarantees that the HKDF‑derived key used in the protocol is indeed tied to
> the secret key `elig_sk`.
>

```math
\begin{aligned}
\text{Leaf}_{i,j}
   &= H_{\text{leaf}}\!\Bigl(
        \underbrace{\text{addr}_{i}}_{\text{public address}}
        \;\parallel\;
        \underbrace{\text{denom}_{j}}_{\text{token identifier}}
        \;\parallel\;
        \underbrace{\text{amount}_{i,j}}_{\text{amount for addr}_{i}}
        \;\parallel\;
        \underbrace{\text{fdi}_{j}}_{\text{fixed\_denom\_index}}
      \Bigr) \\[6pt]
\text{Root}
   &= H_{\text{root}}\!\Bigl(
        \{\,\text{Leaf}_{i,j}\mid
          \text{addr}_{i}\in\text{Elig},
          \text{token\_name}_{j}\in\mathcal{T}\,\}
      \Bigr)
\end{aligned}
```

<center>

| Symbol | Meaning |
|--------|---------|
| $$\text{Elig}$$ | Set of all public addresses receiving tokens |
| $$\mathcal{T}$$ | Set of token names being distributed |
| $$\text{addr}_{i}$$ | The *i*‑th address in `Elig` |
| $$\text{denom}_{j}$$ | The *j*‑th token name in $\mathcal{T}$ |
| $$\text{amount}_{i,j}$$ | Amount of token *j* sent to address *i* |
| $$\text{fdi}_{j}$$ | Fixed denomination index for token *j* |
| $$H_{\text{leaf}}$$ | Hash function that creates a leaf from the concatenated fields |
| $$H_{\text{root}}$$ | (Merkle‑tree) hash that aggregates all leaves into the root |

</center>

> <center>  DEMO: our script used to generate this is invokable via the command:
>
> `cargo run --bin create_merkle -- data/sinsemilla_json.json`</center>

### 2. Note Commitment Tree: `CommitDomain`

>
> q: how can we actually implement a note-commitment tree given our specification, and taking into account possible discrepencies with
> note-commitment generation timing between multiple parties?\
> a: user maintains their own note-commitment tree. This is only used when genesis notes are split into sub-notes, which is not in spec for the inital MVP.

## Circuit: User Interface

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
    fdi: u64,                        // Fixed denomination index (fully padded)
    merkle_path: [pallas::Base; 32], // Path to genesis root ? 

    // Note commitment components
    rho: pallas::Base,               // Unique note identifier
    psi: pallas::Base,               // PRF output
    rcm: pallas::Scalar,             // Commitment randomness
}
// Total: 7 private witnesses
```

**Derived Values (computed in-circuit):**

```rust
// Message binding note to recipient
let m = poseidon_hash([recp, v, nd, fdi]);

// HKDF-derived Pallas keypair
let pallas_sk = poseidon_hash([DST, elig_sk_native, m]);
let pallas_pk = pallas_sk * G_pallas;

// ? (any more)
```

### In-Circuit Constraint Flow

**Step 1: Secp256k1 Key Pairing (Foreign Field)**
**Step 2: HKDF Derivation (Native - In-Circuit!)**
**Step 3: Genesis Distribution Inclusion(Sinsemilla HashDomain)**

## Circuit: Chip Specs

### PallasLookupRangeCheck

There are 3 chips that use the lookup range check:

| Chip| Use| limb-bits|
|-------------------------------|--|-|
| **ecc chip**| | |
| **foreign field chip**|||
| **sinsemilla chip**|    Sinsemilla operations require range checks on bit decompositions and intermediate values |

**Key Configuration Constants:foreign field chip**

```rust
// From halo2-ecc/configs/secp256k1/ecdsa_circuit.config
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const LOOKUP_BITS: usize = 17;
const DEGREE: u32 = 18; // Circuit size: 2^18 rows
```

> q: what are the rows and parameters for each chips that makes use of the lookup range check?
> a: ecc & sinsemilla uses 10 bit limbs, should we also require the foriegn field arithmetic ? right now its parameter is 88 bits

The `RangeChip` is the foundation for foreign field arithmetic in our Pallas-based circuit. It provides lookup tables for efficient range checking of limb values, ensuring that our BigInt representations don't overflow when emulating non-native field arithmetic.

**Limb Parameters (Secp256k1 → Pallas)**  

| Parameter                     | Value / Details                                                                            |
|-------------------------------|-------------------------------------------------------------------------------------------|
| **limb_bits**                 | 88                                                                                        |
| **num_limbs**                 | 3                                                                                         |
| **Total bits**                | 264 (covers 256‑bit secp256k1 fields with an 8‑bit overflow buffer)                     |
| **Lookup bits**               | 17 → lookup table size = 2⁷¹⁷ = 131,072 entries                                         |
| **Rationale**                 | 88‑bit limbs fit comfortably within the Pallas field capacity while minimizing limbs   |
| **RangeChip enforcement**    | `0 ≤ limb_i < 2^88` via lookup tables                                                    |

### Ecc (Secp256k1 chip)

The `EccChip` performs elliptic curve operations over `secp256k1` using foreign field arithmetic. It's essential for both key pairing verification (`pk = sk·G`) and HKDF constraints.

#### Key Operations

**1. Fixed-Base Scalar Multiplication** (for `pk = sk·G`)
**Optimization:** Fixed-base multiplication uses precomputed multiples of G (windowed method) to reduce constraints compared to variable-base.

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

### FqChip (Secp256k1::Fq)

**Purpose:** Represents and operates on secp256k1 scalar field elements (the curve order).

**Type Signature:**

```rust
pub type FqChip<'range, F> = fp::FpChip<'range, F, Secp256k1::Fq>;
```

**Construction:** Same as FpChip but parameterized with `Secp256k1::Fq`

**Used For:**

- Secret key `sk`

**Critical Difference from FpChip:**

- Modulus is `Secp256k1::Fq` (curve order) not `Secp256k1::Fp` (base field)
- Used for scalars, not point coordinates
- Operations are mod `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`

## Circuit: Fixed Points

Fixed points are precomputed generators used in Sinsemilla hashing and commitment schemes. They're defined in `src/constants/fixed_bases.rs`.

- **MerkleHashCrh:** Generator for Sinsemilla hash function in merkle trees
- **NoteCommitR:** Generator for blinding factor in pedersen commitments
- Window tables enable efficient fixed-base scalar multiplication

## Non-Circuit Tooling

## Metamask Snap: Headstash

"A good UX does not require the user to learn anything they do not already know." Powered by this principle, we can make use of a metamask snap plugin to power the hkdf & note management steps:

### Snap Requirements

- download/import/store pubkeys eligilbe notes from headstash registry
- free will derived entropy generation
- perform hkdf + nullifier generation
- broadcast to sc/verifiable service mesh

## Smart Contract Design

This contracts will keep hold the static verification key, record of the spent nullifiers, maintain control of funds to distribute, and power the proof verification.

## Verifiable Service Mesh

A Verifiable Service mesh of nodes acting an a proxy for broadcasting proofs on chain unlocks a number of UX benefits:

- dedicated API for broadcasting claims
- minimizing fee-grants
- delayed claiming support

### Smart-Account Use

### Key Aggregation & Rotation

### Additional Features

## Genesis Bootstrapping

### 1. Genesis Distribution Tree Construction

First, the tree is constructed by separating separating all distributions into the smallest amount of fixed denomination notes, for each token allocated (The Headstash Airdrop distributes TERP & THIOL, so there is a set of leaves for each address due to their allocation including 2 tokens.). We generate leaves in an non-interactive manner using the pre-known public information available:

### Step 2: Deploy Verifiable Proxy Service

This steps involves deploying the verifiable service used to route claiming actions on-chain for proof validation,nullifier & note commitment storage, and also token distributions.

#### Upload/Instantiate Zk-Headstash Contract

- tokenfactory or existing token
- randomness multiplier

#### Create/Seed Tokens To Distribute

#### Register Service Owned Address w/ Smart-Account

The proxy service must control an on-chain account, in order to register the zk-headstash contract as its on-chain authenticator.

- **single feegrant/payment address**: Instead of allocating feegrants to each public address claiming headstashes, we can allocate a single feegrant to the services owned account.

- **granularizes sequence of operations**: authenticators require specific steps of a tx broadcasted to be performed within the scope defined by the x/smart-account authentication module. This allows us to separate the signature verification coming from the off-chain service from the users proof verification sequence.

### Step 3: Eligible Addresses Generate Proofs for claiming

In the proof circuit, the user proves:

- They own `addr_eligible` via `elig_pk` `elig_sk` pairing.
- The genesis note corresponds to an unclaimed entry in the genesis Merkle tree.
- The nullifier `nf` for the genesis note has not been published.

### Step 4: Claim Spent Note By Contract Call

A user will broadcast their proof generated to the verifiable service, which has feegrants registered under an account it controls to cover gas cost to broadcast to a chain state.

## Implementation Checklist

- [x] Define Sinsemilla hashing parameters for Merkle trees and commitments.
- [ ] Implement Halo2 circuits for:
  - [ ] Merkle inclusion proofs
  - [ ] Proof Of Ownership (key-pairing)
  - [ ] Proof Of Destination (erc-7524)
  - [ ] Nullifier derivation
  - [ ] Note commitment derivation
- [ ] Design smart contract to manage:
  - Nullifier set
  - Note commitment tree
  - Token transfers
  - Wavs service authentication
- [ ] Develop off-line tools for key generation and proof construction.
  - [x] secure random number generator
  - [x] genesis proof generator
  - [x] genesis fixed amount note generator

### Claiming API

- exposes API used for users to broadcast & claim allocations.

### Fee Grants

- provides single time feegrants to diversifier keys of claiming addresses

## Research

- <https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/>
- <https://0xparc.org/blog/zk-ecdsa-1>
- <https://github.com/stealthdrop/stealthdrop>
- <https://eips.ethereum.org/EIPS/eip-7524>
- <https://www.rfc-editor.org/rfc/rfc9380.html>
= <https://eprint.iacr.org/2017/1108.pdf>
- <https://github.com/stealthdrop/stealthdrop>
- <https://zips.z.cash/zip-0216>
- <https://medium.com/zokrates/efficient-ecc-in-zksnarks-using-zokrates-bd9ae37b8186>
- <https://datatracker.ietf.org/doc/html/rfc5869>
- <https://github.com/dusk-network/jubjub-schnorr>
- <https://christophe.petit.web.ulb.be/files/16PKC_primeECDLP.pdf>
- <https://forum.zcashcommunity.com/t/status-update-rfc-zec-nam-shielded-airdrop-protocol/49144>
- <https://ebuchman.github.io/pdf/snarks.pdf>
- <https://github.com/DelphinusLab/halo2ecc-s>
- <https://github.com/tahowallet/extension/pull/3638>
- <https://halo2.zksecurity.xyz/intro/>
- <https://github.com/Lightprotocol/light-poseidon>
- <https://www.youtube.com/watch?v=r9hJiDrtukI>
- <https://snaps.metamask.io/snap/npm/chainsafe/webzjs-zcash-snap/>
