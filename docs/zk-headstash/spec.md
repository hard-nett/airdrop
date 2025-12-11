
# Spec: Zk-Airdrop Claiming
>
> **GOAL: Allow eligible headstash members to use zk-proofs to claim partial amounts of their rewards over time.**

## Context

Our current airdrop framework, `The Headstash Contract` powers distribution by mapping ECDSA addresses not native to the chain (ETH,SOL,etc) as eligible to claim a specific list of tokens. In order to claim, users need to verify they are owners of any eligible addresses secret key `esk`. This is done by generating a signature with `esk`, from a message that includes the address native to the chain that the user will use to broadcast the message to claim their allocations `recp`.

```math
\sigma = \text{Sign}_{\text{elig}_{\text{sk}}}\big( H(m) \big), \quad \text{where } \text{recp} \in m
```

**This creates an on-chain association between the eligible account `epk`, and the claiming address `recp`, which we want to prevent.**

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
> **2. Viewing key magic is simplified for this iteration**
> We do not use diversifiers, viewing-keys & spending-keys as defined in multiple Zcash protocols, which is how note-commitments and nullifiers are
> derived. We instead implement a simplified version that satisfies our requirements, without sacraficing the core privacy
> guarantees that are available with use of halo2 circuits.
>
## Requirements

- **Keys: Self-Custody Key Management Systems**:
  - a. Reproducible hash-based key derivation: generate & derive a key from use of an eligible key pair with entropy, both in circuit and out of circuit tooling.
  - b. key rotation/authentication/backup-recovery system
- **Private Proof Of Ownership: Hkdf + key pairing**
  - a. constrain a derived key is know from given inputs for proof of ownership
  - b. constrain a key pair (epk,esk)  are paired by divison with G to be an expected constant in the circuit used as element throughout.

- **Sinsemilla Merkle Trees - hash & commit domains:** ensures inclusion ins specific headstash distribution instance, and in future can implement respendable note-commitments
- **Nullifier & Note Commitments: Effecient & Private Double Spend Prevention**
- **On-Chain Smart Contract:** Application layer state machine for spent-nullifiers list, token mint & distribution list
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
| 2 | **Recipient Key** | secp256k1 |  `cosmwasm_std` | Public key is **the recp** key the claimed allocation. This is the raw bech32 bytes of an account for the chain we are claiming a headstash on.| May be pre‑generated or created on‑the‑fly; no HKDF involved. | In-circuit we constrain a posiedon hash of a raw canonical bech32 addr represented in 2x16 byte limbs |
| 3 | **HKDF‑derived Key** |  `pallas` | `pasta-curves` | Keys derived from hashing input values. Used for encrypting data & *"pivoting"* from one cryptographic field to anothe.r |   | Deterministically derived via **posiedon-based** HKDF from circuit‑private inputs (e.g., a seed, a note commitment, a nullifier). The derived scalar is mapped to a pallas point using the crate’s `generator` |

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

When a note is is being spent, the owner generates a nullifier & note commitment, using carefully structured derivation process that results in values that be shared publically and revela no association about the actions the note represents.

Headstashes use a HKDF generated nullifier key `nk` seeded from private input, powering the key separation, verifiablility, & cryptographic binding of the nullifier and note commitment.
**Users end up proving they know the key pair `esk,epk` by providing the nullifier as a public input into the circuit when generating a proof.**

This lets the circuit use the known curve equation & generator points to constrain that the public and private key are either mathematically paired together or not.

> ### **To prevent double-spending of headstash allocations, a nullifier must be:**
>
> - **unique per note**
> - **unlinkable to the owner’s address**
> - **computable only by the note owner**
> - **resistant to tampering, especially against attacks where an adversary might attempt to redirect funds during transmission.**

### Derivation

> `TLDR:`
>
> 1. **select note**: this determines `v`,`nd`,`fdi`,`epk`, `recp`, `rho` (and inherrently `esk` & `psi`)
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

Specifically, we hash the 3 88-bit limbs of an esk using posiedon,and hash this value `esk_pallas` along with `rho` using a domain-separated posideon hasher, cryptographically bind the nullifier to a specific fund destination, where only the owner has discrection in deciding who can derive the note from it since it depends on their private `note_secret` and the associated key of the `epk`.

*This defends against a subtle but serious class of attacks man-in-the-middle modifications where an adversary intercepts a transaction and attempts to redirect funds to a different address, while reusing the same proof structure. Because the nullifier depends on the exact allocation being spent, any such alteration would result in a different derived `nk`, causing the proof to fail verification.*

#### NoteCommitment Derivation
<!-- TODO: hash each limb of esk and sum limbs to get esk_pallas -->
```math
\begin{array}{lcl}

\textbf{Private witnesses} &
\begin{cases}
\mathsf{esk}\in\mathbb{F}_{\ell}&\text{( Posiedon hash of 3x88bit limb representation of `esk`)}\\[2pt]
\mathsf{fdi}\in \mathbb{F}_p &\text{fully padded u64 of fixed denomination index }fdi\text{}\\[2pt]
\mathsf{{\psi }}\in \{0,1\}^{256}&:= \text{PRF}_{\text{PSI}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[4pt]
\mathsf{rho}\\[6pt]
\mathsf{rcm} &:= \text{PRF}_{\text{RCM}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[6pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\\[10pt]
\textbf{Public inputs} &
\begin{cases}
\mathsf{recp}\in \mathbb{F}_p      &\text{(recipient adddr)}\\[2pt]
\mathsf{v}\in \mathbb{F}_p      &\text{(fully padded u64 of value being spent in note)}\\[2pt]
\mathsf{H(nd)}\in \mathbb{F}_p      &\text{Blake3 hash $nd$, top 3 bits to fit on pallas curve  }\text{}\\[2pt]
% \mathsf{recp}^{\ast}\in \mathbb{F}_p      &\text{(Posiedon Hash of recipient of notes token }nd\text{)}\\[2pt]
\end{cases}
\end{array}
```

#### Nullifier Derivation

```math
\begin{array}{lcl}

\textbf{Private witnesses} &
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

<!-- q: when exactly are we using the posiedon function -->

| use   |      context                     |                                   |    | ||
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|--|
| `recp_to_fp` | Convert `RecpAddr` into field element by hashing 2 part pallas represenation  ||||
| `hdkf_pallas` | Derive `nk` by hashing `esk_pallas` with `rho`  ||||

#### Blake3

For effecieny out of circuit, used as abci-like interface between token-denominations and inputs for `nd` into the circuit. Extremely , and we specifically drop 3 bits from the hash when describing an input, since the hashed values is a public known value we do not worry about the impact of collison resisance that occurs, and just specificy protocols to keep a map dedicated to the original values and their trimmed-hash representations.

q: when exactly are we using the blake3 function

### Derivation Inputs

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |Use |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|--|
| `DST_HEADSTASH`|  genesis tree dst hash  | | **Constant**                         | constant in library  | Genesis Trees |
| `DST_HKDF`|  nullififer input dst hash   | | **Constant**                         | constant in library  |  hkdf-Keypair |
| `SECP256_GENERATOR` |  generator point for secp256k1 curve  | | **Constant** | constant in library  |  hkdf-Keypair |
| `root`   | Genesis Distribution Tree Root  | `u64`                                | **Constant**                          | *sinsemilla::HashDomain*  |
| `rho`    |                                 |                                      | **Private**                          |  generated by user |
| `rseed`  |                                 |                                      | **Private**                           |   generated by user ||
| `psi`    | Note Randomness                 | ` `                                  | **Private**                          |generated by user |Nullifier,hkdf-Keypair|
| `esk`| Eligible secret key             | `bytes[32]`                          | **Private**                          | 3x 88bit limbs | Key-Pairing |
| `epk`| Eligible public key             | `bytes[32]`                          | **Private**                          | 3x 88bit limbs | Key-Pairing |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**                          | *fully padded u64* | Nullifier |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* | Nullifier |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**                           | **blake3 Hash + top 3 bits** ||
| `leaf`   | Note Leaf                       | `bytes[32]`                          | **Private**                          | *sinsemilla::HashDomain* |
| `recp`   | Recipient Address               | `bytes[32]`                          | **Public**                           |  |

> in order to derive `psi` & `rcm`, we have a `rseed` that is a randomness source in a PRF, that expends into each.

## Sinsemilla Merkle Trees: Inclusion Constraints

Sinsemilla is a ZK-friendly hash function designed specifically for Pallas/Vesta curves. We use it for both genesis distribution tree (HashDomain) and note commitment tree (CommitDomain).

### 1. Genesis Distribution Tree: `HashDomain`

**This is the static, starting state of the headstash before any claims happen.** Its purpose is to allow a user to prove a specific address `epk` is how we mesh key ownership constraints with airdrop instance eligibility, without revealing which specific address or note being claimed exactly is. Each leaf is a commitment to the `HashDomain`,that is public & binding an eligible recipients balance for a single token balance, so we can derive the expected hash result in circuit.

```math
\begin{array}{lcl}
 \mathsf{m}=\text{Leaf}_{i,j}&= H_{\text{DST\_HKDF}}{\text{leaf}}\!\Bigl(
        \underbrace{\text{epk}_{i}}_{\text{public address}}\;\parallel\;
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
| $$\text{epk}_{i}$$ | The *i*‑th address in `Elig`, expected as an array of 3 88 bit limbs |
| $$\text{nd}_{j}$$ | The *j*‑th token $\mathcal{T}$ hashed using a note denomination separation tag curve |
| $$\text{v}_{i,j}$$ | Amount of token *j* sent to address *i* |
| $$\text{fdi}_{j}$$ | Fixed denomination index for token *j*, always kept private and never revealed |
| $$H_{\text{DST\_HKDF}}{\text{leaf}}$$ | Hash function that creates a leaf from the concatenated fields |
| $$H_{\text{root}}$$ | (Merkle‑tree) hash that aggregates all leaves into the root |

</center>

### Tree Genesis: Leaf Input Preparation

A leaf is computed using the sinsemilla hashing function with the following input specification. Notice that we must perform some preparation before input into the hashing sequence expected, so that we can have optimized proofs:

<center>

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `DST_HKDF`      |    |                                      | **Constant**                         |   |
| `esk`| Eligible secret key             | `bytes[32]`                          | **Private**                          |  |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**                          | *fully padded u64* |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**                           | *blake3 Hash + top 3 bits |
| `psi`    | Note Randomness                 | ` `                                  | **Private**                          ||

</center>

> - **Denomination hashing** – Since the length of a denomination is unknown, we hash `nd` with **blake3** to obtain a 32‑byte digest. *Sinsemilla* expects a
> 253‑bit domain, so we simply clear the top three bits of the digest. The denomination is public, so smart contracts can map `nd` → `blake3(nd) &
> 0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF` in O(1) time.
>
> - **Padding for `v` and `fdi`** – Both values are `u64` (max 160 bits when concatenated). For table look‑ups we left‑pad each to the byte length required by the hashDomain of Sinsemilla (e.g., 32 bytes). This ensures the inputs line up with the fixed‑size field elements used inside the circuit.
>
> - **`epk` handling for Sinsemilla compatibility** – `epk` is a 32‑byte public‑key representation. The value is interpreted as a set of foriegn field element limbs; since we are focused on secp256k1 curve, we can expect 3 limbs of 88 bits to always fit within the pallas curve, to then allow reduction for each  88bit string for linear operations within the curve structure.
> - **The Full key is required in‑circuit:** Even though `epk` is private for the prover, the circuit must receive the entire key as we need to enforce the relationship of the
> `hkd_sk` being derived from a `esk` thyat is paired with an `epk`. This guarantees that the HKDF‑derived key used in the protocol is indeed tied to
> the secret key `esk`.
<!-- >q: can we use a point definition for the x & y of the keypair for a single input into the circuit and more clean decomposition? -->

*This is how we enable non-interactive instances of headstash deployments, and can be optimized to bring more composability to these genesis distributions*

#### Circuit Inputs

```math
\begin{array}{lcl}

\textbf{Private witnesses} &
\begin{cases}
 \text{no private inputs in sinsemilla hash (non-internative)}
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\\[10pt]
\textbf{Public inputs} &
\begin{cases}
\mathsf{v}\in \mathbb{F}_p      &\text{(fully padded u64 of value being spent in note)}\\[2pt]
\mathsf{H(nd\_{raw})}\in \mathbb{F}_p      &\text{(Posiedon Hash of notes token denomination }nd\text{)}\\[2pt]
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\\[10pt]
\textbf{Constants} &
\begin{cases}
\mathtt{DST}_{\!{Nullifier}}= \texttt{DST\_NULL}&\text{(domain‑separation tag)}\\[2pt]
\mathtt{DST}_{\!{Hkdf}}= \texttt{DST\_HKDF}&\text{(domain‑separation tag)}\\[2pt]
\mathtt{DST}_{\!{Sinsemilla}}= \texttt{DST\_SIN}&\text{(domain‑separation tag)}\\[2pt]
\mathbb{F}_p &\text{base field of the Pallas curve}\\[2pt]
G_{secp256k1}   = (G_{x},G_{y})                     &\text{(generator point secp256k1)}\\
\ell = \texttt{CURVE\_ORDER}            &\text{(sub‑group order)}
\end{cases}
\end{array}
```

```math
\begin{array}{lcl}
\textbf{Derived} &
\begin{cases}
 \mathsf{leaves}\;:=\;\\[2pt]
 \mathsf{root}\;:=\; \\[2pt]
\end{cases}
\end{array}
```

___

> <center>  DEMO: our script used to generate this is invokable via the command:
>
> `cargo run --bin create_merkle -- data/sinsemilla_json.json`</center>
>
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

## Foreign Field Arithmetic (FFA)

  Our circuit operates natively over the **Pallas base field** (`~255 bits`), but for the headstash contracts we need to verify operations on **secp256k1** keys, which use fields of size `~256 bits`. Since secp256k1 field elements **do not fit** natively in the Pallas field, we use **Chinese Remainder Theorem (CRT) representation** with limb decomposition.

### Two-Level Representation

Each secp256k1 field element is represented using a **dual representation**:

#### 1. **Arithmetic Representation (88-bit limbs, each making use of 9x 10-bit decomposition for foreign field arithmetic )**

  For field arithmetic (addition, multiplication, etc.), we decompose 256-bit values into **3 limbs of 88 bits each**:

  ```value = limb[0] + limb[1] *2^88 + limb[2]* 2^176```

  **Why 88 bits?**

- `3 × 88 = 264 bits > 256 bits` (sufficient to represent secp256k1 field elements)
- 88 bits fits comfortably in Pallas field capacity (254 bits)
- Allows efficient carry handling during multi-precision arithmetic

  **Arithmetic operations** (add, sub, mul, div) are performed on these 88-bit limbs using standard multi-precision algorithms with carry propagation.

#### 2. **Range Check Representation (10-bit chunks)**

  To **constrain** that each limb is actually < 2^88, we use **lookup range checks**. Since our circuit has an existing **10-bit lookup table** (from Sinsemilla, with K=10), each 88-bit limb is **decomposed
  into 9 × 10-bit chunks** for range checking:

  limb = chunk[0] + chunk[1] *2^10 + chunk[2]* 2^20 + ... + chunk[8] * 2^80

  **Why 10-bit chunks?**

- Reuses the existing Sinsemilla lookup table (`table_idx` column with 2^10 entries)
- Avoids adding a new lookup argument (minimal proof overhead)
- 9 chunks × 10 bits = 90 bits > 88 bits (sufficient coverage)

  **Important:** The 10-bit decomposition is **only used for range checks**, not for arithmetic operations.

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

1. Limb decomposition (for arithmetic):
   - A 256-bit secp256k1 field element is split into 3 limbs of 88 bits
   - Arithmetic operations (add, mul, etc.) work on these 88-bit limbs in 9x 10x bits
2. Chunk decomposition (for range checks):
   - Each 88-bit limb is further decomposed into 9 chunks of 10 bits
   - Each 10-bit chunk is looked up in the existing Sinsemilla table
   - This constrains each limb to be < 2^90 (which implies < 2^88)
3. Native reduction:
   - The value is also stored as value mod Pallas::Fq in native representation
   - This enables efficient equality checks without limb-by-limb comparison
4. Dual representation consistency:
   - Both representations are constrained to be equivalent via:
   `native ≡ limb[0] + limb[1] *2^88 + limb[2]* 2^176 (mod Pallas::Fq)`

#### Constraining Foreign Fields in Circuit

**Operation Flow:**

1. Load foreign field element as witness:\
   `FpChip::load_private( secp_value) → ProperCrtUint<Pallas::Base>`

2. **Perform operations in CRT representation:**
   - Addition: Add limbs element-wise, handle overflow via carry propagation
   - Multiplication: Multiply limbs using multi-precision algorithm, reduce modulo secp256k1 prime
   - Division: Compute modular inverse, multiply
   - All operations maintain the 88-bit limb structure
3. **Range check all limbs:**
   - Decomposes each 88-bit limb into 9 × 10-bit chunks
   - Looks up each chunk in the Sinsemilla table (K=10)
   - Constrains: limb = chunk[0] + chunk[1]*2^10 + ... + chunk[8]*2^80
   - This ensures limb < 2^90 (sufficient since 2^90 > 2^88)
4. **Verify CRT consistency**:
   - Constrain native value matches limb decomposition:
   `native ≡ Σ(limb[i] *2^(88*i)) (mod Pallas::Fq)`

**Critical Constraints:**

1. **Limb Bounds:** Each limb must be < 2^88 (enforced by RangeChip lookups)
2. **Modular Reduction:** After operations, values must be reduced mod foreign_prime
3. **Native Consistency:** `native ≡ Σ limbs (mod Pallas::Fq)`
4. **Carry Propagation:** Multi-limb arithmetic must handle carries correctly

```rust
let m = poseidon_hash(dst_hkdf,[recp, v, nd, fdi,psi]); 
let pallas_sk = poseidon_hash([DST_HKDF, esk_native, m]);
let pallas_pk = pallas_sk * G_pallas;
```

### In-Circuit Constraint Flow

**1. Secp256k1 Key Pairing (Foreign Field)**
**2. HKDF Derivation (Native - In-Circuit!)**
**3. Genesis Distribution Inclusion(Sinsemilla HashDomain)**
**4. Note Commitment Integrity (Sinsemilla CommitDomain)**

## Circuit: Chip Specs

### PallasLookupRangeCheck

There are 3 chips that use the lookup range check:

| Chip| Use| limb-bits|
|-------------------------------|--|-|
| **ecc chip**| constraining object is within field bounds| |
| **foreign field chip**| constraining objects (limbs) are within field bounds ||
| **sinsemilla chip**|    Sinsemilla operations require range checks on bit decompositions and intermediate values |

**Key Configuration Constants:foreign field chip**

```rust
// From halo2-ecc/configs/secp256k1/ecdsa_circuit.config
const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;
const LOOKUP_BITS: usize = 17;
const DEGREE: u32 = 18; // Circuit size: 2^18 rows
```

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
let fp = FpChip::<Pallas::Base, Secp256k1::Fp>::new(
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

### Ecc (Pallas curve chip)

### Sinsemilla Chip

### Merkle Chip

### NoteCommitChip Chip

Note commit chip constrains the derivation of the `cm` value, via decomposition & canonicity bounds. This chip uses sinsemilla CommitDomain, and expects the following structure:

- each MessagePiece for a Message to be composed must be:
  - < 64 bytes
- simming MessagePiece bytes ubti a Message requires:
  - < 260 total bytes
  - total bytes multiple of 10

#### Headstash Sinsemilla Running Sum Bitrange

| object  | variables | len |
|-|-|-|
|`nd`|`a:0..250`,`b0:250..255`| 255|
|`v`|`b1:0..55`,`c0:55..64`| 64|
|`fdi`|`c1:0..51`,`d0:51..64`| 64|
|`recp`|`d1:0..7`,`ea:7..67,eb:67..127,ec:127..187,ed:187..247, ee:247..255`| 255|
|`esk`|`ee:0..2`,`f:2..252`, `g0:252..255`| 255|
|`rho`|`g1:0..57`,`h0:57..117`,`h1:117..177`,`h2:177..237`,`h3:237..247`,`i0:247..255`| 255|
|`psi`|`i1:0..2`,`i1:2..252`,`i1:252..255`| 255|
|`padding`|`i4:0..7` | 7 |
|| **`1403`** |

## HeadstashAPI: Verifiable Service Mesh

full docs: [Documentation](./mesh-api)

## Metamask Snap: Headstash

Metamask snap plugin powering interface for importing/managin circuit proving keys, generating proofs, and for syncing with network for accounts current state across multiple devices

|   |   |   |
|-|-|-|
|[Snap-N-Pull](../../zk-crates/snap-n-pull/README) |[Documentation](./metamask-snap) |

actions: `claim-note-nullifier`, `manage-headstash-instance-yaml`, `gen-offline-nullifier`

## WasmBindgen

| actions  | descr | used-by  |
|-|-|-|
| web3-connect  |   |   |
| generating proofs  |   |   |
| verifying proofs  |   |   |
| syncing headstash-yamls  |   |   |

## Genesis Bootstrapping

## Randomness Generation

In order to make it impossible to retroatively derive randomness used during the note-commitment generation (which in theory would be possible if an adversary had access to a device, the timestamp of when randomness was generated), we want to enable user-derived input as an additional seed to the PRNG process, such as drawing on the screen or allowing modular inputs

> <center> DEMO: our script used to generate randomness can be invoked via :
>
> `cargo run --package zk-crates --bin generate_randomness`</center>

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
