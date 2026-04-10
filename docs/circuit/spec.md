
# Spec: Zk-Airdrop Claiming
>
> **GOAL: Allow eligible headstash members to use zk-proofs to claim partial amounts of their rewards over time.**

## Context

The Headstash Contract is an existing smart contract designed for users to claim tokens by proving ownership of keys associated on-chain accounts of different blockchains.


These external addresses are pre-mapped as "eligible" for claiming specific token allocations, allowing users to claim tokens on new chains or existing chains but in a cross-chain airdrop method, sometimes without requireing any inital deposit for feetokens.

Naievely, claiming required users must prove they own the public/secret key pair `epk` & `esk`, via ECDSA signature of message `m`, that at minimum includes the recipient address  `recp`, which an new, different address on the native chain that is to recieve the eligible addresses allocations. 

```math
\sigma = \text{Sign}_{\text{elig}_{\text{sk}}}\big( H(m) \big), \quad \text{where } \text{recp} \in m
```

<center>

> **We can notice that this method requires a public, on-chain association between the eligible account `epk`, and the claiming address `recp`, as the signature being claimed is public and binds these two together.**

#### *Our goal is to dissolve this binding, while retaining the ability to proove ownership & eligibility*

___

</center>


### Privacy On Transparent Ledgers
*In order to prevent this association between verifying ownership & claiming tokens, there are 3 major obstacles:*

### Q: How Does Someone Prove They Own An Eligible Wallet Without Revealing The Actual Eligible Wallet?
**A: proof of ownership**: At first this may seem impossible, yet we can concretely do this by utilizing the keys in zk-circuit arithmetic that will provide certainty that an individual knows a private key paired with a public key of an eligible account with certainty, via deterministic properties of a hash-based key deriving function (hkdf).

### Q: How can someone prevent leaking where their claimed funds end up, if the total amount & distributions allocated are public?

Remembering that allocations are public, but claiming are private, if a user claims 100% of their funds to one destination at once defeats the whole purpose,  if there are unique distributions 

**A: Fixed Denomination Notes**: notes function as private UTXNs (Unspent Transaction Notes) that represent claims to portions of the airdropped tokens. Each note contains sensitive data that must remain private except for certain public components used for verification and transaction processing. Predetermined sets of notes are bootstrapped (generated) in a non-interative manner, allowing for partial claims of genesis allocations, where eligble claimers can distribute allocations over a span of time rather than immediately, to multiple different accounts as they choose.

### Q: How are users prevented from claiming more funds then they are allocated?

**A:nullifiers**: Deriving from private data within a note, collision-resistant nullifiers paired with note-commitments will prevent notes from being double-spent.note nullifiers derive from completely deterministic sources, such that it is impossible to alter one of the PRF inputs, that will result in the ability to reuse a note that has been spent.

> **Notes About Design**
> These obstacles are not unique to our requirements, and have been solved concretely by multiple teams, one for example is the zcash's sprout, sapling, and orchard protocols. We are designing our protocol for private airdrops so that we can leverage a large majority of the work done by the cypherpunk community, however there are some discrepancies we need to design around. Specifically:
>
> **1. Actions will be sending tokens to destination on a transparent ledger**
> When someone is claiming, they will be revealing how much and to whom the claimed tokens are going to *(along with the other crucial components like nullifiers & note commitments)*.
>
> **2. Viewing key magic is simplified for this iteration**
> We do not use diversifiers, viewing-keys & spending-keys as defined in multiple Zcash protocols, which is how note-commitments and nullifiers are
> derived. We instead implement a simplified version that satisfies our requirements, without sacraficing the core privacy
> guarantees that are available with use of halo2 circuits.
>
## Requirements

- **Proof Of Ownership: Hkdf + key pairing:**
we must constrain a reproducible hash-based key derivation was used to generate & derive keys unique to each notes from entropy & known inputs.
we must constrain a derived key is know from given inputs for proof of ownership, and also constrain a key pair (epk,esk) are paired together by divison of curves known G to expected constant.
- **Proof Of Inclusion: Sinsemilla Merkle Trees:**
we must constrain a note is included in a root path for a specific headstash distribution instance, and in future can implement respendable note-commitments + global nullifier store for multiple headstashes.
  <!-- - b. key rotation/authentication/backup-recovery system -->
- **Nullifier & Note Commitments: Private Double Spend Prevention**
- **On-Chain Verification: Zk-WasmVm:** Application layer state machine for spent-nullifiers list, token mint & distribution list, and verification key storage,access,and use by wasmvm.
- **Verifiable Service in TEE:** Certainty in transport & offchain runtime
- **Randomness Generators:** Middleware for generating or acessing randomness oracles during proof generation.
- **Metamask Snap Support:** Metamask plugin for deterministic proof-input preparation & generation wallet API.

___

## Hashes,Keys,Fields,Curves

### Keys

We have 3 main types of keys involved in this process.

1. **Eligible Keys:**  *the keys that has a public allocation set for them, and is what we must keep any signature or hash derived from private, in order to retain privacy.*
2. **Recipient Keys:** *the keys that will be recieving the public allocations claimed by the eligible keys*
3. **HKDF keys:** *the keys that are deterministically derived from private inputs of a circuit*

> HKDF keys are specifically used to make our proof of ownership step effecient & feasable in-circuit.

| # | Key type         | Curve used | Primary crate | Public / Private usage | Typical Rust type (example) | Key‑derivation notes |
|---|------------------|------------|--------------|------------------------|-----------------------------|----------------------|
| 1 | **Eligible Key** | `secp256k1`  | `k256` (or `secp256k1`) | Public key is **published** in the allocation; **private key + any signatures / hashes must stay secret** to preserve privacy. | `k256::ecdsa::SigningKey` / `k256::ecdsa::VerifyingKey` | - |
| 2 | **Recipient Key** | secp256k1 |  `cosmwasm_std` | Public key is **the recp** key the claimed allocation. This is the raw bech32 bytes of an account for the chain we are claiming a headstash on.| May be pre‑generated or created on‑the‑fly; no HKDF involved. | In-circuit we constrain a poseidon hash of a raw canonical bech32 addr represented in 2x16 byte limbs |
| 3 | **HKDF‑derived Key** |  `pallas` | `pasta-curves` | Keys derived from hashing input values. Used for encrypting data & *"pivoting"* from one cryptographic field to anothe.r |   | Deterministically derived via **poseidon-based** HKDF from circuit‑private inputs (e.g., a seed, a note commitment, a nullifier). The derived scalar is mapped to a pallas point using the crate’s `generator` |

> NOTE: zcash orchard protocol implements key derivation for viewing, authorization, and privacy retention purposes. Our initial scope removed the use of viewing or authorization keys,however upcoming interations will reimplement viewing keys for full disclosure selection to note data.

### Curves

  Our circuits primary curve is Pallas. We must mask forien curves field elements as expected field elements of our circuit native curve, and use Foreign Field Arithmetic aware logic.

| Chip     | Field       | Curve|   Value | |
|----------|-------------|--------------------------------------|--------------------------------------|------------|
| **Sinsemilla**| **Base(`Fp`)** | **Pallas**  | `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`|  |
| **Sinsemilla**| **Scalar(`Fq`)** | **Pallas**  | `q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`|  |
| **Sinsemilla**| **Point(`Ep`)** | **Pallas**  |  - |  |
| **Hkdf_Fp**   | **Base(`Fp`)** |**Secp256k1**  | `p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`|  |
| **Hkdf_Fq**| **Scalar(`Fq`)** | **Secp256k1**  |`q = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`|  |

## Hashes: Nullifier Key Generation Via HKDF

- *every note must have a way to derive a unique identifier that proves the note has been spent, without revealing which note it was or linking multiple spends together.*

Two core business logic requirement in the headstash circuit are to have a feasable way to verify that the owner of the `epk` is authorizing the spend of a specific note in a headstash instance, and prevent double-spending of headstash allocations. Normal ECDSA verification for field curves are computationally heavy in circuit, & generate extremely large proof sizes not compatible with on-chain gas limits & a nice UX.

> ### **To prevent double-spending of headstash allocations, a nullifier must be:**
>
> - **unique per note**
> - **unlinkable to the owner’s address**
> - **computable only by the note owner**
> - **resistant to tampering, especially against attacks where an adversary might attempt to redirect funds during transmission.**

When a note is is being spent, the owner generates a nullifier & note commitment, using carefully structured derivation process that results in two values `nc` & `null` that be shared publically without revealing any association about the sensitive data we are keeping private that note represents and was derived from.

Headstashes use a HKDF generated nullifier key `nk` seeded from private input, powering the key separation, verifiablility, & cryptographic binding of the nullifier and note commitment.
**Users end up proving they know the key pair `esk,epk` by providing the nullifier as a public input into the circuit when generating a proof.**

This lets the circuit use the known curve equation & generator points to constrain that the public and private key are either mathematically paired together or not.

### Derivation

> `TLDR:`
>
> 1. **select note**: this determines `v`,`nd`,`fdi`,`epk||esk`, `recp`, `rho` & `psi`
> 2. **prepare inputs**: values need some packaging into formats comaptible with our circuit. All clients generating proofs must prepare:
>     - `v`: fully padded `u64` value
>     - `fdi`: fully padded `u64` value
>     - `nd`: Blake3 Hash of token denomination, with top-most byte cleared to fit as Pallas field element.
>     - `recp`: Posiedon Hash of the recipients canonical bech32 addr in 2x16 byte chunks.
>     - `esk`: the Posiedon Hash of `esk`, where `esk` is a 3x88 bit pallas base field elemements representing the esk.
>
> 3. **derive note-commitment**: deriving `cm` requires `nd`, `v`, `fdi`,`recp`,`esk`, `rho`,`psi`,and blinded to r with`rcm`.\
> Specifically, we use the sinsemilla CommitDomain hashing function to commit these values for creating a note commitment in that specified order.
> 4. **derive nullifier**: deriving the nullifier requires `nk`, `rho`,`psi`, and `cm`. Specifically:
>
> - a. hash the `(nk,hkdf_sk)` with `rho` via Posiedon
> - b. add hash output to `psi`
> - c. multiply scalar by NullifierK
> - d. add product to note-commitment

**Headstashes derive from `esk`,*along with other private inputs a keypair `(nk)` that is on the pallas curve*.**

Specifically, we hash the 3 88-bit limbs of an esk using poseidon,and hash this value `esk_pallas` along with `rho` using a domain-separated posideon hasher, cryptographically bind the nullifier to a specific fund destination. *This defends against a subtle but serious class of attacks man-in-the-middle modifications where an adversary intercepts a transaction and attempts to redirect funds to a different address. Because the nullifier is determined by the exact allocation & destination, any such alteration would result in a different derived `nk`, causing the proof to fail verification.*

The following are inputs in the pseduo-random-function (prf) of deriving a nullifier key:

```math
\begin{array}{lcl}
\begin{array}{ }
\textbf{Nullifier Key `nk` Derivation} 
\end{array}
\\[10pt]
\textbf{Private Inputs} &
\begin{cases}
\mathsf{esk}\in \mathbb{F}_p      &\text{Posiedon hash of 3x88bit limb representation of `esk` }\text{}\\[2pt]
\mathsf{rho}\in \mathbb{F}_p      &\text{note randomness}\\[2pt]
% \mathsf{recp}^{\ast}\in \mathbb{F}_p      &\text{(Posiedon Hash of recipient of notes token }nd\text{)}\\[2pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\begin{array}{ }
\textbf{NoteCommitment Derivation} 
\end{array}
\\[10pt]
\textbf{Public (Instances)} &
\begin{cases}
\mathsf{nd}\in \mathbb{F}_p      &\text{Blake3 hash $nd$, top 3 bits to fit on pallas curve  }\text{}\\[2pt]
\mathsf{v}\in \mathbb{F}_p      &\text{(fully padded u64 of value being spent in note)}\\[2pt]
\mathsf{recp}\in \mathbb{F}_p      &\text{(recipient addr)}\\[2pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\textbf{Private (Witnesses)} &
\begin{cases}
\mathsf{fdi}\in \mathbb{F}_p &\text{fully padded u64 of fixed denomination index }fdi\text{}\\[2pt]
\mathsf{esk}\in\mathbb{F}_{\ell}&\text{( Posiedon hash of 3x88bit limb representation of `esk`)}\\[2pt]
\mathsf{{\psi }}\in \{0,1\}^{256}&:= \text{PRF}_{\text{PSI}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[4pt]
\mathsf{rho} & \text{note randomness} \\[6pt]
\mathsf{psi} & \text{private note randomness derived from rho} \\[6pt]
\mathsf{rcm} & \text{commitment trapdoor used for blinding} \\[6pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\begin{array}{ }
\textbf{Nullifier Derivation} 
\end{array}
\\[10pt]
\textbf{Private Inputs} &
\begin{cases}
\mathsf{nk}\in\mathbb{F}_{\ell}&\text{( key derived from $ek$ for generating nullifier)}\\[2pt]
\mathsf{{\psi }}\in \{0,1\}^{256}&:= \text{PRF}_{\text{PSI}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[4pt]
\mathsf{rho}\\[6pt]
\mathsf{rcm} &:= \text{PRF}_{\text{RCM}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[6pt]
\end{cases}
\end{array}
```

### Hashing Functions

#### Posiedon

For effecieny in-circuit hashing, we are using Posiedon as the hkdf hashing algorithm. Poseidon is a ZK-friendly hash function used for nullifier derivation, note commitments.

<!-- q: when exactly are we using the poseidon function -->

| use   |      context                     |                                   |    | ||
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|--|
| `prf_nf` |    ||||
| `esk_to_base` |    ||||
| `recp_to_fp` | Convert `RecpAddr` into field element by hashing 2 part pallas represenation  ||||
| `hdkf_pallas` |   ||||
<!-- | `prf_pallas_m` |   |||| -->

#### Blake3

For effecieny out of circuit, used as abci-like interface between token-denominations and inputs for `nd` into the circuit. Extremely , and we specifically drop 3 bits from the hash when describing an input, since the hashed values is a public known value we do not worry about the impact of collison resisance that occurs, and just specificy protocols to keep a map dedicated to the original values and their trimmed-hash representations.

<!-- q: when exactly are we using the blake3 function -->

| use   |      context                     |                                   |    | ||
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|--|
| `ultra_secure_random` |    ||||
| `rho_from_secure_random` |    ||||
| `NoteDenom::hash` |  padded value used in proof generation  ||||

### Derivation Inputs

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |Use |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|--|
| `DST_HEADSTASH`|  genesis tree dst hash  | | **Constant**                         | constant in library  | Genesis Trees |
| `DST_HKDF`|  nullififer input dst hash   | | **Constant**                         | constant in library  |  `hdkf_pallas` |
| `SECP256_GENERATOR` |  generator point for secp256k1 curve  |                     | **Constant** | constant in library  |  hkdf-Keypair |
| `PrfExpand::ORCHARD_ESK` |  used for deriving a note `rseed` |                    | **Constant** | constant in library  |  `RandomSeed::esk_inner()` |
| `PrfExpand::ORCHARD_RCM` | deriving a notes cm trapdoor (used for blinding) |.    | **Constant** | constant in library  |  `RandomSeed::rcm()` |
| `LEAF_PERSONALIZATION`|  leaf hasher dst for sinsemilla hashdomain    |           | **Constant**  | genesis merkle-tree  | `leaf_hash` |
| `MERKLE_CRH_PERSONALIZATION`|  hashing leaves   |                                 | **Constant** | constant in library  | `MerkleHashOrchard::combine()`\ `HeadstashSuite::merkle_crh()` |
| `root`   | Genesis Distribution Tree Root  | `u64`                                | **Constant** | *sinsemilla::HashDomain*  |
| `path`   | leaf path to root of note being spent   | [vestas::Affine;32]          | **Private**  | *sinsemilla::HashDomain*  |
| `rho`    |                                 |                                      | **Private**  |  generated by user |
| `rseed`  |                                 |                                      | **Private**  |   generated by user ||
| `psi`    | Note Randomness                 | ` `                                  | **Private**  |generated by user |Nullifier,hkdf-Keypair|
| `esk`| Eligible secret key             | `bytes[32]`                              | **Private**      | 3x 88bit limbs | Key-Pairing |
| `epk`| Eligible public key             | `bytes[32]`                              | **Private**      | 3x 88bit limbs | Key-Pairing |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**  | *fully padded u64* | Nullifier |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**   | *fully padded u64* | Nullifier |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**   | **blake3 Hash + top 3 bits** ||
| `leaf`   | Note Leaf                       | `bytes[32]`                          | **Private**  | *sinsemilla::HashDomain* |
| `recp`   | Recipient Address               | `bytes[32]`                          | **Public**   |  |

> in order to derive `psi` & `rcm`, we have a `rseed` that is a randomness source in a PRF, that expends into each.

## Sinsemilla Merkle Trees: Inclusion Constraints

Sinsemilla is a ZK-friendly hash function designed specifically for Pallas/Vesta curves. We use it for both genesis distribution tree (`HashDomain`) and note commitment tree (`CommitDomain`). `HashDomain` does not use a private value in the hashing function,unlike the `CommitDomain`, which involves a trap-door value in the hashing operation.

### 1. Genesis Sinsemilla Tree: `HashDomain`

**This is the starting configuration of a headstash that is created offchain.** Its purpose is to create the inital set of notes for a headstash instance,and will allow a user to prove a specific address `epk` have both key ownership constraints & headstash eligibility, without revealing which specific address or note being claimed exactly is.

Each leaf is a commitment to the `HashDomain`,that is public & binding (not blinding) an eligible recipients balance for a single token balance, so we can derive the expected hash result in circuit.

### Genesis Sinsemilla Tree: Leaf Input Preparation

A leaf is computed using the sinsemilla hashing function with the following input specification. Notice that we must perform some preparation before input into the hashing sequence expected, so that we can have optimized proofs:

<center>

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `DST_HKDF`   |                             |                                      | **Constant** |            |
| `epk`    | Eligible public key             | `bytes[32]`                          | **Public** |  *sum of 3x88 pallas field element representation* |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Public** | *fully padded u64* |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public** | *fully padded u64* |
| `nd`     | Note Denomination               | `NoteDenom([u8])`                    | **Public** | *blake3 Hash + top 3 bits |

</center>

> - **Denomination hashing** – Since the length of a denomination is unknown, we hash `nd` with **blake3** to obtain a 32‑byte digest. *Sinsemilla* expects a
> 253‑bit domain, so we simply clear the top three bits of the digest. The denomination is public, so smart contracts can map `nd` → `blake3(nd) &
> 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` in O(1) time.
>
> - **Padding for `v` and `fdi`** – Both values are `u64` (max 160 bits when concatenated). For table look‑ups we left‑pad each to the byte length required by the hashDomain of Sinsemilla (e.g., 32 bytes). This ensures the inputs line up with the fixed‑size field elements used inside the circuit.
>
> - **`epk` handling for Sinsemilla compatibility** – `epk` is a 32‑byte public‑key representation. The value is interpreted as a set of foriegn field element limbs; since we are focused on secp256k1 curve, we can expect the sum of 3 limbs of 88 bits to always fit within the pallas curve, to then allow reduction for each  88bit string for linear operations within the curve structure.
> - **The Full key is required in‑circuit:** Even though `epk` is private for the prover, the circuit must receive the entire key as we need to enforce the relationship of the
> `hkd_sk` being derived from a `esk` thyat is paired with an `epk`. This guarantees that the HKDF‑derived key used in the protocol is indeed tied to
> the secret key `esk`.
<!-- >q: can we use a point definition for the x & y of the keypair for a single input into the circuit and more clean decomposition? -->

> *This is how we enable non-interactive instances of headstash deployments, and can be optimized to bring more composability to these genesis distributions.*

```math
\begin{array}{lcl}
 \mathsf{m}=\text{Leaf}_{i,j}&= H_{\text{DST\_HKDF}}{\text{leaf}}\!\Bigl(
        \underbrace{\text{epk}_{i}}_{\text{public address (sum of 3x88 Fp)}}\;\parallel\;
        \underbrace{\text{nd}_{j}}_{\text{token identifier}}\;\parallel\;
        \underbrace{\text{v}_{i,j}}_{\text{amount for addr}_{i}}\;\parallel\;
        \underbrace{\text{fdi}_{j}}_{\text{fixed\_denom\_index}}\Bigr)  
\end{array}
```

```math
\begin{aligned}

\text{Root}
   &= H_{\text{root}}\!\Bigl(
        \{\,\text{Leaf}_{i,j}\mid
          \text{addr}_{i}\in\text{Elig},
          \text{nd}_{j}\in\mathcal{T}\,\}
      \Bigr)
\end{aligned}
```

<center>

| Symbol | Meaning |
|--------|---------|
| $$\text{Elig}$$ | Set of all public addresses receiving tokens |
| $$\mathcal{T}$$ | Set of token names being distributed |
| $$\text{epk}_{i}$$ | The *i*‑th address in `Elig`, expected as the sum of the 3x88 bit limb representation of itself |
| $$\text{nd}_{j}$$ | The *j*‑th token $\mathcal{T}$ hashed using a note denomination separation tag curve |
| $$\text{v}_{i,j}$$ | Amount of token *j* sent to address *i* |
| $$\text{fdi}_{j}$$ | Fixed denomination index for token *j*, always kept private and never revealed |
| $$H_{\text{DST\_HKDF}}{\text{leaf}}$$ | Hash function that creates a leaf from the concatenated fields |
| $$H_{\text{root}}$$ | (Merkle‑tree) hash that aggregates all leaves into the root |

</center>

### Account Headstash Instance Yaml

each accounts progress for claiming a headstash instance can be summed up into a single yaml definition:

```yaml
id: "0"
balance:
  - nd: "value1"
    v: "value2"
  - nd: "value3"
    v: "value4"
spent:
  - nd: "value5"
    v: "value6"
```

This can be viewed as a "private key", as it contains sensitive information related to your headstash transactions that can break the privacy properties of your headstash claims. Its purpose is to keep accounts in sync across user devices, encrypting and transporting this file across devices.

### note-commitments: futureproof system

Note Commitments `cm` are also is disclosed publicly during claiming. They are derived from the private and public inputs of a note, allowing the origin of the claiming address to be private. note commitments are derived from both deterministic and non-deterministic inputs of a note, as we do not use `cm` for preventing double spends (this is what nullifiers are for). For our use, this note commitment tree can be expand on to rely on more, as for things such as true utxo function of headstash notes and other future iterations.
>
> q: how can we actually implement a note-commitment tree given our specification, and taking into account possible discrepencies with
> note-commitment generation timing between multiple parties?\
> a: nullifiers are provided with note-commitments, and are batched process via vote-extensions, allow us to update the merkle root each block.

> **q: do we damage the blinding of the rest of the inputs to the hashing function due to some being public and some being private?**
>
> a: no! thanks to the hardness of hashing functions, its unfeasable to retroactively derive the private inputs given all of the public inputs and the output hash.

## Circuit: Chip Specs

Our circuit uses specialized "chips" to handle complex operations efficiently. Each chip manages a specific type of math or constraint, like working with different curves or hashing. Think of chips as reusable tools that keep our proofs small and fast. Our circuit is set to `K=17` (2^17 rows), with expected proof sizes around 5KB for a single proof.

### Foreign Field Arithmetic (FFA): Handling Big Numbers from Other Curves

Our circuit runs on the Pallas curve (fields up to ~255 bits), but headstash needs to work with secp256k1 keys (up to 256 bits). Since these don't fit directly, we break them into smaller "limbs" using the Chinese Remainder Theorem (CRT). This is like splitting a long number into parts for easier math.

Each secp256k1 value uses a **dual representation** for efficiency:

#### 1. Arithmetic Representation (88-Bit Limbs)

For math operations (add, multiply, etc.), we split 256-bit values into **3 limbs of 88 bits each**. For example: `value = limb[0] + limb[1] * 2^88 + limb[2] * 2^176`. This fits Pallas and handles carries well.

#### 2. Range Check Representation (10-Bit Chunks)

To ensure limbs stay valid (< 2^88), we break each 88-bit limb into **9 chunks of 10 bits** and check them against our lookup table. For example: `limb = chunk[0] + chunk[1] * 2^10 + ... + chunk[8] * 2^80`. This reuses our existing Sinsemilla table (K=10) to avoid overhead.

**Why 10-bit chunks?** They fit our table, cover 90 bits (>88), and keep proofs efficient.

In code, this looks like:

```rust
pub struct ProperCrtUint<F> {
    pub truncation: OverflowInteger<F>,  // Limbs for math
    pub native: AssignedValue<F>,        // Native Pallas value
    pub max_limb_bits: usize,
}
```

**How it works in practice:**

1. Load a secp256k1 value: `FpChip::load_private(secp_value)`.
2. Do math on limbs (e.g., add with carries).
3. Check ranges via table lookups.
4. Ensure consistency: `native ≡ limb[0] + limb[1] * 2^88 + limb[2] * 2^176 (mod Pallas)`.

### PallasLookupRangeCheck: Reusable Table for Bounds

This chip provides lookup tables to check that values stay within bounds. It's used by three chips:

- **Ecc chip**: Ensures curve points are valid.
- **Foreign field chip**: Checks limb sizes.
- **Sinsemilla chip**: Validates bit decompositions.

Key setup (from our code):

```rust
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const LOOKUP_BITS: usize = 17;  // Table size: 2^17 entries
```

Rationale: 88-bit limbs fit Pallas (254 bits), minimizing parts while handling secp256k1 (256 bits + buffer).

### Ecc (Secp256k1 Chip): Elliptic Curve Math for Keys

This chip handles secp256k1 curve operations using FFA. It's key for verifying that a public key matches a secret key (`pk = sk * G`).

**Main Operation:** Fixed-base multiplication (e.g., for `pk = sk * G`). It uses precomputed tables for speed, reducing constraints compared to variable-base math.

Example: Load and check a key pair in code:

```rust
let sk = fq_chip.load_private(sk_value);
let pk = ecc_chip.mul_fixed(sk, generator);
ecc_chip.assert_equal(pk, expected_pk);
```

### FpChip (Secp256k1 Base Field): Handling Public Key Parts

Represents secp256k1 base field elements (e.g., x/y coordinates of public keys) in our Pallas circuit.

**Type and Setup:**

```rust
pub type FpChip<'range, F> = fp::FpChip<'range, F, Secp256k1::Fp>;
let fp_chip = FpChip::<Pallas::Base, Secp256k1::Fp>::new(range, 88, 3);
```

**Key Operations:**

- `load_private(value)`: Load a witness.
- `add(a, b)`, `mul(a, b)`: Math on limbs.
- `assert_equal(a, b)`: Constrain equality.

Used for: Public key coordinates, point arithmetic.

### FqChip (Secp256k1 Scalar Field): Handling Secret Keys

Similar to FpChip but for scalars (secret keys, curve order). Modulus: `0xfff... (secp256k1 order)`.

**Difference:** Scalars are for multiplication, not coordinates. Same setup as FpChip but with `Secp256k1::Fq`.

Used for: Secret key `sk` in pairings.

### Ecc (Pallas Curve Chip): Native Curve Operations

Handles elliptic curve math on our native Pallas curve. Used for Pallas points in hashing or derivations.

Example: Multiply a scalar by the generator: `pallas_pk = pallas_sk * G_pallas`.

### Sinsemilla Chip: ZK-Friendly Hashing

This chip implements Sinsemilla, our hashing function for merkle trees and commitments. It breaks inputs into bit pieces and constrains them.

For genesis leaves (HashDomain), we build messages from decomposed inputs like `epk`, `nd`, `v`, `fdi`. Example from our code:

```rust
let a = MessagePiece::from_subpieces(sc, lo, [RangeConstrained::bitrange_of(epk.0.native.value(), 0..250)]);
let domain = HashDomain::new(sc, ecc_chip, &OrchardHashDomains::Leaf);
let hash = domain.hash_to_point(lo, message)?;
```

Inputs are bit-ranged: e.g., `nd` to 4-254 bits, `v` padded to 64 bits.

### Merkle Chip: Manual Inclusion Verification

We manually verify merkle inclusion by hashing the leaf with provided path siblings using Sinsemilla. No dedicated chip; we iterate hashes to compute the root and constrain it.

Example flow (simplified from our `constrain_genesis_inclusion`):

```rust
let mut current = leaf;
for sibling in path {
    // Hash current + sibling
    let hash = sinsemilla_hash(current.x, current.y, sibling.x, sibling.y);
    current = hash;
}
// Constrain current.x == root
```

This ensures the leaf is in the tree without revealing the path.

### LeafHashChip: Leaf Hashing with Canonicity

Our custom chip for genesis leaf hashing, including decomposition and canonicity constraints. It enforces bit breakdowns (e.g., `epk_x = a + b0 * 2^250`) and value bounds (e.g., `a < modulus` via prime checks).

From our code:

```rust
meta.create_gate("LeafHash canonicity check", |meta| {
    // Constraints like epk_x_decomposition, a_prime_check, etc.
});
```

Ensures all inputs (`epk`, `nd`, etc.) are valid and canonical for safe hashing.

## Metamask Snap: Headstash

Metamask snap plugin powering interface for importing/managin circuit proving keys, generating proofs, and for syncing with network for accounts current state across multiple devices. For documentation, [check here.](./metamask-snap.md)

## Headstash Suite: Orchestration Library

For documentation on our standard suite for interacting and managing headstashes, [check here](./suite.md)


```mermaid
flowchart LR
    A[Start: Input BigUint value, num_limbs, limb_bits] --> B[Initialize mask ]
    B --> C[Initialize empty limbs vector]
    C --> D[Initialize remaining = value ]
    D --> E{For i in 0..num_limbs}
    E -- Yes --> F[limb_big = remaining & mask]
    F --> G[Convert limb_big to little-endian bytes]
    G --> H[Pad bytes to 32-byte array]
    H --> I[Convert to pallas::Base using from_repr]
    I --> J[Push limb_fe to limbs]
    J --> K[remaining >>= limb_bits]
    K --> E
    E -- No --> L[Return limbs vector]
```


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
- <https://eprint.iacr.org/2025/2031.pdf>
- <https://github.com/axiom-crypto/halo2-lib/blob/community-edition/halo2-ecc/src/secp256k1/tests/ecdsa.rs>
- <https://zcash.github.io/halo2/user/wasm-port.html>
- <https://github.com/zcash/halo2/issues/443>
- <https://www.youtube.com/watch?v=pdHYe4GUT_o>
- <https://eprint.iacr.org/2017/1050.pdf>
- <https://github.com/zcash/zcash/issues/2465>
- <https://eprint.iacr.org/2008/096.pdf>
- <https://eprint.iacr.org/2025/695.pdf>