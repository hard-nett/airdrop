
# Spec: Zk-Airdrop Claiming
>
> **GOAL: Allow eligible headstash members to use zk-proofs to claim partial amounts of their rewards over time.**

## Context

Our current airdrop framework, `The Headstash Contract` powers distribution by mapping ECDSA addresses not native to the chain (ETH,SOL,etc) as eligible to claim a specific list of tokens. In order to claim, users need to verify they are owners of any eligible addresses. This is done by generating a signature with the eligible address keys, from a message that includes the address native to the chain that the user will use to broadcast the message to claim their allocations.

```math
\sigma = \text{Sign}_{\text{sk}_{\text{eligible}}}\big( H(m) \big), \quad \text{where } \text{addr}_{\text{native}} \in m
```

**This creates an on-chain association between the eligible address, and the claiming address, which we want to prevent.**

In order to prevent this association between verifying ownership & claiming tokens, there are 3 major obstacles:

### Q: How Does Someone Prove They Own An Eligible Wallet Without Revealing Their Signature?

**A: proof of ownership + PLUME**: A circuit can provide certainty that an individual knows the private key paired with their public key of an eligible account. This circuit also can be able to constrain a destination wallet for the funds being claimed is the one that the private key owner desires, via use of the PLUME implementation we describe below.

### Q: How can someone prevent leaking where their claimed funds end up, if the total amount & distributions allocated are public?

- **note commitments.** Partial claims of genesis allocations via fixed denomination notes. This allows eligble claimers to designate unique addresses for receiving allocations over a span of time rather than immediately.

### Q: How are users prevented from claiming more funds then they are allocated?

- **nullifiers.** deriving from private data within a note, collision-resistant nullifiers paired with note-commitments will prevent notes from being double-spent.

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

___

## Keys

We have 2 main types of keys involved in this process.

1. **Eligible Keys:**  *the keys that has a public allocation set for them, and is what we must keep any signature or hash derived from private, in order to retain privacy.*
2. **Redemption Keys:** *the keys that will be recieving the public allocations claimed by the eligible keys*

<!-- 3. **HKDF keys:** *the keys that are deterministically derived from private inputs of a circuit* -->
<!-- > HKDF keys are specifically used to make our proof of ownership step effecient & feasable in-circuit. -->

| # | Key type         | Curve used | Primary crate | Public / Private usage | Typical Rust type (example) | Key‑derivation notes |
|---|------------------|------------|--------------|------------------------|-----------------------------|----------------------|
| 1 | **Eligible Key** | secp256k1  | `k256` (or `secp256k1`) | Public key is **published** in the allocation; **private key + any signatures / hashes must stay secret** to preserve privacy. | `k256::ecdsa::SigningKey` / `k256::ecdsa::VerifyingKey` | Directly generated or imported; never derived from other keys. |
| 2 | **Redemption Key** | secp256k1 | `k256` (or `secp256k1`) | Public key is **the recipient** of the claimed allocation; private key is used only to sign the redemption proof. | Same as Eligible (`SigningKey`/`VerifyingKey`) | May be pre‑generated or created on‑the‑fly; no HKDF involved. |
<!-- | 3 | **HKDF‑derived Key** | - | - | Private key **only**; the corresponding public key is *not* exposed – it is used inside the circuit for proof‑of‑ownership. |   | Deterministically derived via HKDF from circuit‑private inputs (e.g., a seed, a note commitment, a nullifier). The derived scalar is mapped to a JubJub point using the crate’s `generator`. | -->

> NOTE: zcash orchard protocol implements very complex (but useful) key derivation for viewing, authorization, and privacy retention purposes. Our scope does not require the use of viewing or authorization keys, as the end results of tokens claimed will be public. A large portion of the modifications from the orchard protocol altering how note-commitments & nullifiers are derived, as they rely heavily on the use of the key structure used by zcash orchard protocol.

## Randomness Generation

In order to make it impossible to retroatively derive randomness used during the note-commitment generation (which in theory would be possible if an adversary had access to a device, the timestamp of when randomness was generated, its theoretically possible to recreate the randomness source), we want to enable user-derived input as an additional seed to the PRNG process.

> <center> DEMO: our script used to generate randomness can be invoked via :
>
> `cargo run --package zk-crates --bin generate_randomness`</center>

## Ownership Verification: Pairing

Its crucial that our circuit has an feasable way to verify that the owner of the `elig_pk` is authorizing the spend of a specific note. Normal signature verification for secp256k1 curves are computationally heavy, & generate extremely large proof sizes not compatible with on-chain gas limits & a nice UX.

| **Aspect** | **Explanation** |
|------------|-----------------|
| **Private inputs** | `elig_pk` (public key) and `elig_sk` (secret key) must both be provided as **private** witnesses to the circuit. |
| **Arithmetic required** | The circuit needs **foreign‑field arithmetic** to operate over the secp256k1 scalar field (different from the base field of the halo2 proof system). |
| **Core constraint** |  $pk \;=\; sk \;\cdot\; G$, where `G` is the generator point of the secp256k1 curve. |

> **Reference implementation:**  <https://github.com/axiom-crypto/halo2-lib/blob/community-edition/halo2-ecc/src/secp256k1/tests/ecdsa.rs>

- **GENERATOR_X & GENERATOR_Y**
- **CURVE_ORDER**
- **elig_pk**
- **elig_sk**

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

## Ownership Verification: PLUME

PLUME is defined in  [ERC-7524](https://eips.ethereum.org/EIPS/eip-7524) as a way to effeciently verify a message was signed in circuit be a secp256k1 key. This will make it possible for our circuit to constrain that a key owner has authorized a specific address to receive the funds being claimed. This is an extremely important step in binding a proof with the destination of funds being claimed.

### Minimal Requirements

- `g` - generator (aka the base point) of the curve
- `m` - 32-byte message (will be defined as `m == H(amount||denom||fixed_denom_index)` )
- `(sk,pk)` - keypair
- `sec1(pk)` - SEC1 defined compressed public key (33 bytes)

### Signature Generation

1. `r` is a random point
2. `h` - a hash-to-curve of `htc([m,sec1(pk)])`\
*NOTE: the length of intput to htc is always 65 bytes, so `m` is required to be a hash of the raw message*
3. `z` - computed via `h^r`
4. `nul` - computed `h^sk`
5. `c` - computed dependent on the version of PLUME used:\
   V1 - `H([g,pk,h,nul,g^r,z])`\
   V2 - `H([nul,g^r,z])`
6. `s` - compute via `r + sk * c`

The signature is then defined as `(z,s,g^r,c,nul)`

## Notes

notes function as private UTXOs (Unspent Transaction Outputs) that represent claims to portions of the airdropped tokens. Each note contains sensitive data that must remain private, except for certain public components used for verification and transaction processing. We have generated a predetermined set of notes for users, classified by fixed-denomination amounts. we must note nullifiers from completely deterministic sources, such that it is impossible to alter one of the PRF inputs, that will result in the ability to reuse a note that has been spent.

### Nullifiers

To prevent double-spends, each note must have a unique, deterministic nullifier derivable only by the owner. This ensures the nullifier is:

- Unique per note.
- Unlinkable to the eligible address.
- Only computable by the note owner.

| Components   | Meaning                         | Type                                 | Public / Private / Constant / Output | Derivation |
|----------|---------------------------------|--------------------------------------|--------------------------------------|------------|
| `elig_sk`| Eligible secret key             | `bytes[32]`                          | **Private**                          | — |
| `fdi`    | Fixed Denomination Index        | `u64`                                | **Private**                          | *fully padded u64* |
| `NOTE_NULLIFIER_PERSONALIZATION`      |    |                             | **Constant**                          |   |
| `v`      | Note Value                      | `NoteValue(u64)`                     | **Public**                           | *fully padded u64* |
| `nd`     | Note Denomination               | `NoteDenom([u8; <128])`              | **Public**                           | *blake3 Hash + top 3 bits |

```math
\begin{array}{lcl}
\textbf{Private witnesses} &
\begin{cases}
\mathsf{fdi}      \in \mathbb{F}_p      &\text{(field element from private input }fdi\text{)}\\[2pt]
\mathsf{elig\_sk}  \in \{0,1\}^{256}   &\text{(32‑byte eligibility secret)}\\[2pt]
\mathsf{nd}        \in \{0,1\}^{256}   &\text{(32‑byte auxiliary data)}\\
\end{cases}
\\[10pt]
\textbf{Public inputs} &
\begin{cases}
\mathsf{v}        \in \mathbb{F}_p      &\text{(public value)}\\[2pt]
\mathsf{nd}^{\ast}\in \mathbb{F}_p      &\text{(public‑derived field element for }nd\text{)}\\[2pt]
\mathsf{elig\_sk}^{\ast}\in \mathbb{F}_p &\text{(public‑derived field element for }elig\_sk\text{)}\\
\end{cases}
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
    <!-- pub fn psi(&self, rho: &Rho) -> pallas::Base {
        to_base(PrfExpand::PSI.with(&self.0, &rho.to_bytes()))
    } -->
    <!-- pub fn rcm(&self, rho: &Rho) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(to_scalar(
            PrfExpand::ORCHARD_RCM.with(&self.0, &rho.to_bytes()),
        ))
    } -->

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

<!-- 
### Note Structure: HKDF + BabyJubJub verification

> NOTE: for `m`, we may need to implement a deterministic pedersen commitment to `elig_sk`, ensuring all inputs to the hash function are on the curve for posiedon hashing
> NOTE: we must explore how `denom_to_base` & `sec_sk_to_base` being hashed with posiedon will impact our circuit definition.

| Symbol         | Meaning.                                 | Type                   | Public / Private / Constant / Output| Derivation |
|----------------|------------------------------------------|------------------------|----------------------------------|------------|
| `dst_jub_hkdf` | Domain-separation string                 | `bytes[]`              | **Constant**                     | Hard-coded  |
| `G_jub`        | JubJub Curve Generator.                  |                        | **Constant**                     | Hard-coded  |
| `m`            | `H(amount‖denom‖fdi‖elig_sk)`            | `bytes[32]`            | **Private**                      | Needs to be private to prevent derivation, leaking privacy |
| `elig_sk`      | `elig_addr` secret key                   | `Fr`                   | **Private**                      | Supplied by prover|
| `jub_sk`       | `HKDF(elig_sk, dst_jub_hkdf) mod ℓ_jub`  | `Fr`                   | **Private (derived)**            | Deterministic HKDF |
| `sig_jub`      | Full signature `(R,S)`                   | `struct`               | **Public** (`R`) + **Private** (`S`) | `R` is public, `S` stays private (the circuit verifies it) |
| `fdi`          | fixed_denomination_idex                  | `u16`                  | **Private**                      | Used internally, not revealed |
| `amount`       | Amount being transferred                 | `u128`                 | **Public**                       | Input to hash `m`|
| `denom`        | Denomination of the asset                | `string`               | **Public**                       | Input to hash `m`|
| `recp`    | Recipient address of funds                    | `stripped bech32 addr` | **Public**                       | Public as funds are going to this destination |
| `jub_null`     | `jub_null = k·G_jub` (where `k = H(m, jub_sk)`) | `G1`            | **Public**                       | Deterministic because `k` is derived from `m` & `jub_sk`|
| `jub_pk`       | `jub_sk·G_jub` (public key)              | `G1`                   | **Public**                       | Computed from derived `jub_sk`         |
| `ψ` (Psi) | Randomness added to the note commitment to ensure it is hiding. |   | — |
| `note_cm`      | note commitment    `H(jub_null‖recp)`    |                   | **Output**                      |   |

> q: are we deriving nullifiers and note commitments so that we prevent any possibility of doublespend?
> a: we attempt to with use of the `jub_null`. The jubjub keypair is deterministic based on `elig_sk`, `m` is deterministic based on uniqueness powered by fixed_denom_index + the elig_sk, resulting in `jub_null` being deterministic & unique per note do to `k` hashing `m` & `jub_sk`.

**Public outputs during a claim:**

- `note_cm`
- `jub_null`
- `amount`
- `denom`
- `recp` -->

___

## Sinsemilla Merkle Trees

We make use of the sinsemilla merkle tree implementation for powering effecient note commitment and distirbution inclusion. We will utilize both the `HashDomain` and the `CommitDomain` for two distinct purposes:

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

### 1. Constrain `cm` is derived from public + private inputs

<!-- This tree is dynamic and is the core state of the private ledger. It is constantly updated with every claim transaction. Each claim by a user will generate a note-commitment. Each time a user is spending a note generated in the genesis distribution tree, the note-commitment will be appended to a top-level layer in the merkle tree, preventing any association between the geneiss leaf of the note being spent. A commitment is computed from all the fields of a note using a binding and hiding commitment scheme (Sinsemilla `CommitDomain` in our example): -->

```math
% old, need to update
% \mathrm{cm} = \mathrm{Commit}(d, \mathrm{pk}_d, v, \rho, \psi, \mathrm{rcm})
```
<!-- 
> Our genesis tree is non-interactive, derived from the sinsemilla `HashDomain`, but we want to have our note commitments retain same functionality as zcash orchard protocol, which uses the `CommitDomain` for the note-commitments. -->

<!-- > q: **do we need the merkle tree for note-commitments?** yes. our merkle tree will require spends of allocations always being one layer deep, and splitting of notes into sub-notes, as there are always a predetermined number of notes (due to using fixed denominations). -->
<!-- >
> q: **how can we implement a system that allows note-splitting from the original genesis distribution leaves?** If a user decides that they want to split a fixed-denomination note into additional, fixed-denomination sub-notes, we must be able to:
>
> - a. ensure the original notes will be percieved as consumed
> - b.ensure the sum total of the sub-notes are never more than what the parent note value was
> - c.allow for infinite recursiveness of subnotes up until the smallest fixed denomination possible
>
> -->
<!-- 
### Splitting Notes

A user may want to split a note such that:

- a parent note nullifier is created,marking the note as 'spent'
- a new child note(s) whose values sum to the parent value are created

```txt
Note Commitment Tree (CommitDomain)
├─ Position 0: First claimed genesis note
├─ Position 1: Second claimed genesis note  
├─ Position 2: Split from position 0 (child note 1)
├─ Position 3: Split from position 0 (child note 2)
├─ Position 4: Third claimed genesis note
├─ Position 5: Split from position 2 (grandchild note)
└─ ... continues growing
```

 The only time we allow appending to existing index in the tree is if the user decides to split a note into further sub-notes, using fixed-denominations that sub up to the parent notes value. whenever a sub-note is spent, it would be treated as if it was one of the top-level genesis notes, and the note-commitment would be appended to the top layer of the merkle tree, extending the total anonymity set of the note-commitments. We want to ensure that the path is kept private between all of the sub-notes and parent notest to prevent association -->
<!-- 
### How its Built

0. The tree starts empty, with the root being the root also being the genesis distribution tree root.
1. When a user makes a claim (either genesis or spending an existing note), their transaction output includes a new note commitment `cm_new`
2. The smart contract verifies the zk-proof and, if valid, inserts `cm_new` into the next available leaf position in this tree.
3. The contract then computes and stores the new root of this tree (root_notes_current). -->

## Smart Contract Design

This contracts will keep record of the spent nullifiers, maintain control of funds to distribute, and power the proof verification.

- static verification key (VK) - "compiled down" representation of the circuit
- public inputs
- halo2 proof

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
<!-- zcash primitives -->
- <https://seanbowe.com/blog/tachyon-scaling-zcash-oblivious-synchronization/>
<!-- helped figure out how to verify secp256k1 signatures -->
- <https://0xparc.org/blog/zk-ecdsa-1>
- <https://github.com/stealthdrop/stealthdrop>
- <https://eips.ethereum.org/EIPS/eip-7524>
- <https://www.rfc-editor.org/rfc/rfc9380.html>
= <https://eprint.iacr.org/2017/1108.pdf>
- <https://github.com/stealthdrop/stealthdrop>
<!-- used for (baby)jubjub understanding -->
- <https://zips.z.cash/zip-0216>
- <https://medium.com/zokrates/efficient-ecc-in-zksnarks-using-zokrates-bd9ae37b8186>
- <https://datatracker.ietf.org/doc/html/rfc5869>
- <https://github.com/dusk-network/jubjub-schnorr>
- <https://christophe.petit.web.ulb.be/files/16PKC_primeECDLP.pdf>
- <https://forum.zcashcommunity.com/t/status-update-rfc-zec-nam-shielded-airdrop-protocol/49144>
- <https://ebuchman.github.io/pdf/snarks.pdf>
- <https://github.com/DelphinusLab/halo2ecc-s>

### Alt Spec: 👻
<!-- 
### Option 1: PLUME signature proofs

### Zk-Prooving

We will use version two defined of the PLUME implementation, but modified to retain privcacy of the nullifer. specifically, since preventing doublespends of PLUME nullifiers is not required, as we are using it for proof of ownership constraints. Since the PLUME nullifier is a private input, we need to ensure `c` is accurately constructed,requireing us to define the public and private inputs as:

#### Public Inputs

| # | Input | Category | Type / Format | Description | Remarks |
|---|-------|----------|---------------|-------------|--------|
| **1** | `c` | Public | **FP** (field element) |   | **Generated with Posiedon Hashing** |
| **2** | `g^r` | Public | **G1** (group element on the curve) |   |   |
| **3** | `z` | Public | **G1** (group element) |   |   |
| **4** | `m` | Public | **32‑byte array** (`[u8;32]`) |  |   |

#### Private Inputs

| # | Input | Category | Type / Format | Description | Remarks |
|---|-------|----------|---------------|-------------|--------|
| **5** | `nul` | Private | **FP** (field element) |   |   |
| **6** | `pk` | Private | **G1** (group element) | Owner’s public key (kept private inside the circuit to hide the actual key). | Allows the circuit to prove possession of the corresponding secret key `sk`. |
| **7** | `sk` | Private | **Scalar** (`Fr`) | Secret key of the owner. | Never leaves the prover; only used to compute `pk` and the nullifier internally. |
| **8** | `r` | Private | **Scalar** (`Fr`) | Randomness used for blinding (`g^r`). | Must be freshly sampled for each proof. |
| **9** | `s` | Private | **Scalar** (`Fr`) |   |   |

#### PLUME constraint notes

- **Public inputs** are the values that appear in the proof’s public‑input vector and must be supplied to the verifier.  
- **Private inputs** are witness data supplied only to the prover; the circuit checks that they correctly relate to the public inputs without revealing them.  

#### Circuit Arithmetic

1. Compute $h = HTC([m,sec1(pk)])$
2. Compute $pk = g^{sk}$
3. Compute $left = g^s * pk^{-c}$
4. Compute $ right = g^r$
5. Compute $h^s * nul^{-c}$

#### Circuit Constraints

- $g^{s} * pk^{-c} = g^{r}$
- $h^{s} * nul^{-c} = z$

> what value should be used as the PRF input from the plume components so that we can assert that note-commitment and nullifiers concretely prevent double-spending of notes? They should not include and randomness source as this will lead to non-deterministic results of the nullifier & note-commitment.

> <center>
> DEMO: to demonstrate the lifecycle of generating & verifying a plume signature:
>
> `cargo test --package zk-crates --bin plume_demo --  --show-output`</center> -->

<!-- 
### Note Structure: PLUME authorization

| Symbol   | Meaning                                      | Type            | Public / Private / Constant / Output | Derivation (deterministic)                                            |
|----------|----------------------------------------------|-----------------|--------------------------------------|------------------------------------------------------------------------|
| `g`      | Curve generator                              | `G1`            | **Constant** | Hard‑coded in the circuit                                              |
| `elig_pk`| eligible public key                          |                 | **Private**  |                                                                        |
| `elig_sk`| eligible secret key                          |                 | **Private**  |                                                                        |
| `fdi`    | fixed‑denom‑index.                           | `u16`           | **Private**  | needs to be private as it will leak privacy, reducing anonimity set |
| `m`      | `H(amount‖denom‖fdi‖elig_sk)`                 | `bytes[32]`     | **Private**  | needs to be private to prevent derivation, leaking privacy          |
| `r`      | rho                                          |                 | **Private**  | randomness used to derive challenge                                   |
| `h`      | `HTC([m, sec1(elig_pk)])`                    | `G1`            | **Private**  | Deterministic because `m` and `pk` are inputs                         |
| `plume_nul`| `h^elig_sk` – “PLUME nullifier”            | `FP`            | **Private**  | `sk` (private) × `h` (deterministic)                                   |
| `s`      | `r + sk·c` (private scalar)                  | `Fr`            | **Private**  | Computed from `r`, `sk`, `c` – never leaves the prover                |
| `c`      | Challenge `H([plume_nul, g^r, z])` (PLUME V2)| `FP`            | **Public**   | All three arguments are deterministic                                 |
| `g^r`    | `g` raised to the prover’s random scalar `r` | `G1`            | **Public**   | `r` is a private scalar but `g^r` is published                        |
| `z`      | `h^r`                                        | `G1`            | **Public**   |                                                                        |
| `recp`   | reciepient address of funds                  | `CanonicalAddr` | **Public**   | public as funds are going to this destination                         |
| `amount` | token amount                                 |                 | **Public**   |                                                                        |
| `denom`  | token denomination                           |                 | **Public**   |                                                                        |
| `note_nul`| nullifier                                   |                 | **Output**   |                                                                        |
| `note_cm`| note-commitment                              |                 | **Output**   |                                                                        |

#### JSON Format

```json
{
  // ----- Private (witness) -----
  "elig_pk":  "G1",                 // g^sk (kept private inside circuit)
  "elig_sk":  "Fr",                 // eligible secret key (never leaves prover)
  "fdi":      "u16",        // which fixed‑denom leaf is spent (private)
  "m":        "bytes[32]",          // H(amount‖denom‖index)
  "r":        "Fr",                 // prover‑chosen randomness
  "h":        "G1",                 // HTC([m, sec1(pk)])
  "plume_nul":"FP",                 // h^sk
  "s":        "Fr",                 // r + sk·c

  // ----- Public (exposed to verifier) -----
  "c":        "FP",                 // PLUME challenge (Poseidon hash)
  "g_r":      "G1",                 // g^r
  "z":        "G1",                 // h^r
  "recp":     "CanonicalAddr",      // recipient
  "amount":   "u64",                // token amount (public, but part of m)
  "denom":    "u32",                // token denom (public, but part of m)
  "note_nul": "FP",                 // nullifier (public output)
  "note_cm":  "G1",                 // note commitment (public output)
}
``` -->

<!-- 
## HKDF STEPS

Specifically, we aim derive a keypair on the `TBD` curve from the `elig_sk`.  This keypair can then be used to sign `m`, being a hash of relevant components within a note being spent, which in turn will allow us to implement constraints within the circuit that will power both proof of ownership & nullifier derivation.

### Step 0: Prepare Inputs

We need a specific structure for the data used to derive the keys

### Step 1: Derive Keys

- derives `jub_sk` from the HKDF `HKDF(elig_sk, dst_jub_hkdf) mod ℓ_jub`
- computes the baby-jubjub public key `jub_pk = jub_sk * G_jub`

### Step 2: Hash & Sign Msg

- generates challenge being signed `m`, where `m == H(amount||denom||fdi||elig_sk)`
- signs `m` with the `jub_sk`, generating `sig_jub`

### Step 3: Verification

#### Out Of Circuit
>
> NOTE: This step is a simple signature verification, out of circuit. This can be implemented either within the smart contract state, or within a verifiable service logic.

- verifies `m` is accurately reconstructed from the given inputs
- verifies `sig_jub` against `m` and the supplied `jub_pk`.

#### In Circuit

- **Eligible Public‑key/Secret-Key Consistency**: constrains `elig_sk` is the counterpart to `elig_pk`
- **HKDF Derivation**: constrains the HKDF used `elig_sk` as an input to derive `jub_sk`
- **Derived Public‑key/Secret-Key Consistency:** Computes `jub_pk_calc = jub_sk·G_jub` and enforce `jub_pk_calc == jub_pk`.
- **Message Hash**: constrains `m` is accurately derived from the known values -->