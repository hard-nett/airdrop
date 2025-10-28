
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

- **proof of ownership within the note.** This is similar to the existing proof of ownership described above, however we must use zk-proof optimize implementation as constraining a ecdsa signature within a circuit is computationally expensive.

### Q: How can someone prevent leaking where their claimed funds end up, if the total amount & distributions allocated are public?

- **note commitments.** Partial claims of genesis allocations via fixed denomination notes. This allows eligble claimers to designate unique addresses for receiving allocations over a span of time rather than immediately.

### Q: How are users prevented from claiming more funds then they are allocated?

- **nullifiers.** deriving from data within a note, collision-resistant nullifiers paired with note-commitments will prevent notes from being double-spent.

> **Notes About Design**
> These obstacles are not unique to our requirements, and have been solved concretely by multiple teams, one for example is the zcash's sprout, sapling, and orchard protocols. We are designing our protocol for private airdrops so that we can leverage a large majority of the work done by the cypherpunk community, however there are some discrepancies we need to design around. Specifically:
>
> **1. Actions will be sending tokens to destination on a transparent ledger**
> When someone is claiming, they will be revealing how much and to whom the claimed tokens are going to *(along with the other crucial components like nullifiers & note commitments)*.
>
> **2. Viewing key magic is very limited**
> We do not use diversifiers, viewing-keys & spending-keys as defined in zcashs protocols, which is how note-commitments and nullifiers are
> derived. We instead implement a simplified implementation of this that satisfies our requirements, without sacraficing any of the privacy
> guarantees that are available with use of halo2 circuits.
>
## Requirements

- **Keys: Self-Custody Key Management Systems**
- **Randomness Generators**
- **Private Proof Of Ownership - PLUME or Baby-JubJub**
- **Sinsemilla Merkle Trees**
- **Notes & Note Commitments (UTXO)**
- **Nullifier Use**
- **Verifiable Service in TEE**

## Keys

We have 3 main types of keys involved in this process.

1. Eligible Keys
2. Redemption Keys
3. HKDF keys

Eligible keys are the keypair that has a public allocation set for them, and is they key that we must keep any signature or hash derived from it private, in order to retain privacy. Redemption keys are the keys that will be recieving the public allocations claimed by the eligible keys. HKDF keys are keys that are deterministically derived from private inputs of a circuit. HKDF keys are specifically used to make our proof of ownership step effecient & feasable in-circuit.

> NOTE: zcash orchard protocol implements very complex (but useful) key derivation for viewing, authorization, and privacy retention purposes. Our scope does not require the use of viewing or authorization keys, as the end results of tokens claimed will be public. A large portion of the modifications from the orchard protocol altering how note-commitments & nullifiers are derived, as they rely heavily on the use of the key structure used by zcash orchard protocol.

## Randomness Generation

In order to make it impossible to retroatively derive randomness used during the note-commitment generation (which in theory would be possible if an adversary had access to a device, the timestamp of when randomness was generated, its theoretically possible to recreate the randomness source), we want to enable user-derived input as an additional seed to the PRNG process.

> <center>
>
> DEMO: our script used to generate randomness can be invoked via :
>
> `cargo run --package zk-crates --bin generate_randomness`</center>
>

## Ownership Verification

Its crucial that our circuit has an feasable way to verify that the `eligible_addr` is authorizing the spend of a specific note. normal signature verification for secp256k1 curves are computationally heavy, & generate extremely large proof sizes not compatible with on-chain gas limits & a nice UX. We provide two alternatives for implementing this, both optimized for in-circuit verification so that we maintain the privacy integrity expected.

> NOTE: for either implementation,  we must make use of a deterministic value derived from this step, to make use of as an input in the PRF for a notes nullifier and note commitment. This ensures that notes are

### Option 1: PLUME signature proofs

The first option is to implement the [ERC-7524](https://eips.ethereum.org/EIPS/eip-7524) spec in circuit. This will allow users to produce two components, one deterministic & one non-deterministic, allowing us to use the determinstic on as an input in the PRF for note-commitments and nullifiers.

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
> `cargo test --package zk-crates --bin plume_demo --  --show-output`</center>

### Option 2: HKDF + BabyJubJub

Our second option is to make use of deterministic HMAC- Key Deriving Function, to derive a keypair on the Baby-Jubjub curve from the sk of an eligible_addr. This keypair can then be used to sign a hash of relevant components within a note being spent, which in turn will allow us to implement constraints within the circuit that will

1. Prover (AKA owner of an `eligible_addr`):

- generates challenge being signed `m`, where `m == H(amount||denom||fixed_denom_index)`
-
- computes the baby-jubjub public key `jub_pk = jub_sk * G_jub`
- signs `m` with the baby-jubjub key, generating `sig_jub`

2. Prover Generates Proof:

- reconstructs `m` from the given inputs
- verifies `sig_jub` against `m` and the supplied `jub_pk`.
- verifies the HKDF used `elig_sk` as an input to derive `jub_sk`

#### 1. Public Inputs (exposed to the verifier)

| Symbol | Description | Remarks |
|--------|-------------|---------|
| `jub_pk` | Baby‑JubJub public key (`jub_sk·G_jub`). | Two field elements `x` & `y` (each 256 bits). |
| `dst_jub_hkdf` | Domain‑separation string for the HKDF (e.g. `"Headstash-HKDF-BabyJubJub-v1"`). | Hard‑coded constant; the circuit treats it as a public byte array so the same value must be used off‑chain. |
| `amount` | Token amount being claimed. |   |
| `denom` | Denomination / token identifier. |   |

#### 2. Private Witnesses (never leave the prover)

| Symbol | Description | Used inside the circuit for … |
|--------|-------------|--------------------------------|
| `elig_sk` | Secret key of the *eligible* address (the original ECDSA/secp256k1 or other native key). | Input to HKDF to derive `jub_sk`. |
| `sig_jub` | Baby‑JubJub EdDSA signature on the message `m`. Represented as `(R, S)` where `R` is a point (x, y) and `S` a scalar. | Verified against `jub_pk` and `m`. |
| `m` | Message hash `H(amount‖denom‖fixed_denom_index)`. | Re‑computed inside the circuit to bind the signature to the public monetary fields. |
| `fixed_denom_index` | Index of the fixed‑denom note that is being spent. | **Private** because it leaks information about the note spender in the message hash `m`. |
| `jub_sk` *(derived, not supplied)* | Baby‑JubJub secret key = `HKDF(elig_sk, dst_jub_hkdf) mod ℓ_jub`. | Internally derived; the circuit asserts the derivation is correct. |

#### 3. Verification Flow (circuit constraints)

- **a. HKDF Derivation:** derives the baby-jubjub secret `jub_sk` using the known `dst_jub_hkdf` from the `elig_sk`.
- **b. Public‑key Consistency:** Computes `jub_pk_calc = jub_sk·G_jub` and enforce `jub_pk_calc == jub_pk`.
- **c. Message Hash:** Re‑compute the messages `calculated_m = H( amount || denom || fixed_denom_index )`, and enforce `calculated_m == m`.
- **c. Signature Verification (EdDSA on BabyJubJub):**`sig_jub` on `m` using `jub_pk`

## Notes

notes function as private UTXOs (Unspent Transaction Outputs) that represent claims to portions of the airdropped tokens. Each note contains sensitive data that must remain private, except for certain public components used for verification and transaction processing. We have generated a predetermined set of notes for users, classified by fixed-denomination amounts. we must derive our note-commitments & nullifiers from completely deterministic sources, such that it is impossible to alter one of the PRF inputs, that will result in the ability to reuse a note that has been spent. We can do this by expecting the resulting signature/nullifier from the owernship verification step as an input source in a PRF. This way, the circuit can constrain the nullifer & note-commitment with certainty.

- **note-commitment and nullifier derivation**: we need to ensure that note-commitments and nullifiers are impossible to be doublespent, given that we are not using nullifier-keys. specifically, our genesis merkle tree is created by generating leaves for each eligible address total possible fixed denominations. We included an index for all duplicate fixed denomination amounts (ie; if there was 4 1000 TERP fixed denomnination, each leaf without an index would have an identical hash). This allows us to then make use of the signature we are generating from the eligible address as the source of randomness that will derive nullifiers and note-commitment values, so that we can zk-verify that:
  - a. our signature is generated from `m == H(amount||denom||index)` by the `sk` of the `eligible_addr`
  - b. the note commitment `nc` (and in result the nullifier) is derived using this signature as the randomness input

These two constraints will ensure with certainty that nullifiers and note-commitments cannot be forged for doublespends.

### Note Structure: PLUME authorization

| Symbol | Meaning | Type | Public / Private | Derivation (deterministic) |
|--------|---------|------|------------------|----------------------------|
| `g` | Curve generator (constant) | `G1` | **Public** | Hard‑coded in the circuit |
| `recipient` | reciepient address of funds | `stripped bech32 addr` | **Public** | public as funds are going to this destination |
| `amount` | | | **Public** | |
| `denom` | | | **Public** | |
| `fixed_denom_index` | | | **Private** | needs to be private as it will leak privacy, reducing anonimity set |
| `m` | Message hash `H(amount‖denom‖fixed_denom_index)` | `bytes[32]` | **Private** | needs to be private to prevent derivation, leaking privacy |
| `elig_pk` | eligible public key |  | **Private** | |
| `r` | rho |  | **Private** | randomness used to derive challenge |
| `h` | `HTC([m, sec1(elig_pk)])` (hash‑to‑curve) | `G1` | **Private** (computed in‑circuit) | Deterministic because `m` and `pk` are inputs |
| `z` | `h^r` | `G1` | **Public** |   |
| `g^r` | `g` raised to the prover’s random scalar `r` | `G1` | **Public** | `r` is a private scalar but `g^r` is published |
| `plume_nul` | `h^elig_sk` – “PLUME nullifier” | `FP` | **Private** | `sk` (private) × `h` (deterministic) |
| `c` | Challenge `H([nul, g^r, z])` (PLUME V2) | `FP` | **Public** | All three arguments are deterministic |
| `s` | `r + sk·c` (private scalar) | `Fr` | **Private** | Computed from `r`, `sk`, `c` – never leaves the prover |

### Note Structure: HKDF + BabyJubJub verification

 | Symbol | Meaning | Type | Public / Private | Derivation |
|--------|---------|------|------------------|------------|
| `amount` | | | **Public** | |
| `denom` | | | **Public** | |
| `recipient` | reciepient address of funds | `stripped bech32 addr` | **Public** | public as funds are going to this destination |
| `fixed_denom_index` | | | **Private** | |
| `m` | Message hash `H(amount‖denom‖fixed_denom_index)` | `bytes[32]` | **Private** | needs to be private to prevent derivation, leaking privacy |
| `dst_jub_hkdf` | Domain‑separation string (e.g. `"Headstash-HKDF-BabyJubJub-v1"`) | `bytes[]` | **Public** | Hard‑coded |
| `elig_sk` | Secret key of the *eligible* address (ECDSA/secp256k1) | `Fr` | **Private** | Supplied by prover |
| `jub_sk` | Baby‑JubJub secret = `HKDF(elig_sk, dst_jub_hkdf) mod ℓ_jub` | `Fr` | **Private (derived)** | Deterministic HKDF |
| `jub_pk` | `jub_sk·G_jub` (public key) | `G1` | **Public** | Computed from derived `jub_sk` |
| `sig_jub` | Full signature `(R,S)` | `struct` | **Public** (`R`) + **Private** (`S`) | `R` is public, `S` stays private (the circuit verifies it) |

**Public outputs during a claim:**

- `cm` (note commitment, added to the Merkle tree)
- `nf` (nullifier, added to the nullifier set to prevent double-spending)
- `amount` (amount)
- `denom` (denom of token)
- `pk_d` and `d` (diversified address components)

### Note Commitments

Note Commitments `cm` are what is disclosed publicly during claiming, by appending to the Note Commitment Tree. They are derived from the private and public inputs of a note, allowing the origin of the claiming address to be private.

### Nullifiers (Anti Double Spend)

To prevent double-spends, each note must have a unique, deterministic nullifier derivable only by the owner. For the genesis claim (first redemption), derive `nf_secret` from the eligible address and a secret known only to the user:

```math
% old. need to update to satisfy new requirements
% \text{nf} = \text{PRF}_{\text{nk}}(\rho) \quad \text{where } \rho = H(\text{addr\_eligible} \parallel \text{nonce})
```

- `nk` is the nullifier-deriving key (part of the user’s private keys)
- `nonce` is a user-generated secret. This ensures the nullifier is:

This ensures the nullifier is:

- Unique per note.
- Unlinkable to the eligible address or note commitment.
- Only computable by the note owner.

For subsequent claims (spending output notes), use:

```math
 \text{nf} = \text{PRF}_{\text{nk}}(\rho)
```

where `ρ` is taken directly from the input note.

### Note Notation Details

| Notation | Purpose | Derivation | Usage |
|---|---|---|---|
| `pk_d` (Diversified Transmission Key) | The public key that serves as the recipient address for the claimed tokens. **This is the key that will receive the public tokens from a note instance.** | **`pk_d = ivk * G + d`**, where:<br>‑ `ivk` = incoming viewing key (a private key derived from the user's spending key)<br>‑ `G` = generator point of the elliptic curve (e.g., Pallas or Vesta in Halo2)<br>‑ `d` = the diversifier, often represented as a point on the curve via a hash‑to‑curve function (e.g., `DiversifyHash(d)`). | `pk_d` provides a canonical way for users to claim partial amounts of their balance to multiple addresses under their control, improving privacy post‑claim. |
| `v` *(Amount)* | The value of tokens being claimed in a note. Always a portion of the total allocation from `addr_eligible`. | Fixed‑denomination values to improve privacy across the set:<br>‑ `1_000_000_000` = 1 000<br>‑ `100_000_000` = 100<br>‑ `10_000_000` = 10<br>‑ `1_000_000` = 1 | Publicly exposed so the contract verifying the proof can transfer `v` to address `pk_d`. |
| `ρ` (Rho) | Private value used as input to the pseudo‑random function `PRF` for nullifier derivation. Ensures each nullifier is unique and unlinkable to the note. | For the genesis note (first claim), `ρ` is derived from `addr_eligible` and a user‑generated nonce. For subsequent notes, `ρ` is generated randomly. | Used as an input to the derivation of `ψ` and `rcm`. |
| `ψ` (Psi) | Randomness added to the note commitment to ensure it is hiding. | Generated randomly by the user using a secure random number generator when creating the note; must be unique per note. | — |
| `rcm` (Commitment Randomness) | Guarantees the note commitment `cm` is computationally binding & hiding from guessing the note contents from `cm`. | Generated randomly by the user, similarly to `ψ`. | — |
| `nf_rand` | Additional randomness used in nullifier derivation to increase security and prevent collisions. | Generated randomly by the user for each note. | — |

___

## Sinsemilla Merkle Trees

We make use of the sinsemilla merkle tree implementation for powering effecient note commitment and distirbution inclusion. We will utilize both the `HashDomain` and the `CommitDomain` for two distinct purposes:

### 1. Genesis Distribution Tree: `HashDomain`

**This is the static, starting state of the headstash before any claims happen.**
Its purpose is to allow a user to prove a specific address `addr_eligible` is eligible to claim a certain allocation `v` without revealing which specific address it is. Each leaf is a commitment to the `HashDomain`,that is public & binding an eligible recipients balance for a single token balance. A leaf is computed using the sinsemilla hashing function as:

```math
\begin{aligned}
\text{Leaf}_{i,j}
   &= H_{\text{leaf}}\!\Bigl(
        \underbrace{\text{addr}_{i}}_{\text{public address}}
        \;\parallel\;
        \underbrace{\text{token\_name}_{j}}_{\text{token identifier}}
        \;\parallel\;
        \underbrace{\text{token\_amount}_{i,j}}_{\text{amount for addr}_{i}}
        \;\parallel\;
        \underbrace{\text{fixed\_denomination\_index}_{j}}_{\text{index}}
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
| $$\text{token\_name}_{j}$$ | The *j*‑th token name in $\mathcal{T}$ |
| $$\text{token\_amount}_{i,j}$$ | Amount of token *j* sent to address *i* |
| $$\text{fixed\_denomination\_index}_{j}$$ | Fixed denomination index for token *j* |
| $$H_{\text{leaf}}$$ | Hash function that creates a leaf from the concatenated fields |
| $$H_{\text{root}}$$ | (Merkle‑tree) hash that aggregates all leaves into the root |

</center>

> <center>  DEMO: our script used to generate this is invokable via the command:
>
> `cargo run --bin create_merkle -- data/sinsemilla_json.json`</center>

### 2. Note Commitment Tree: `CommitDomain`

This tree is dynamic and is the core state of the private ledger. It is constantly updated with every claim transaction. Each claim by a user will generate a note-commitment. Each time a user is spending a note generated in the genesis distribution tree, the note-commitment will be appended to a top-level layer in the merkle tree, preventing any association between the geneiss leaf of the note being spent. A commitment is computed from all the fields of a note using a binding and hiding commitment scheme (Sinsemilla `CommitDomain` in our example):

```math
% old, need to update
% \mathrm{cm} = \mathrm{Commit}(d, \mathrm{pk}_d, v, \rho, \psi, \mathrm{rcm})
```

> Our genesis tree is non-interactive, derived from the sinsemilla `HashDomain`, but we want to have our note commitments retain same functionality as zcash orchard protocol, which uses the `CommitDomain` for the note-commitments.

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

### How its Built

0. The tree starts empty, with the root being the root also being the genesis distribution tree root.
1. When a user makes a claim (either genesis or spending an existing note), their transaction output includes a new note commitment `cm_new`
2. The smart contract verifies the zk-proof and, if valid, inserts `cm_new` into the next available leaf position in this tree.
3. The contract then computes and stores the new root of this tree (root_notes_current).

## Genesis Bootstrapping

### 1. Genesis Distribution Tree Construction

First, the tree is constructed by separating separating all distributions into the smallest amount of fixed denomination notes, for each token allocated (The Headstash Airdrop distributes TERP & THIOL, so there is a set of leaves for each address due to their allocation including 2 tokens.). We generate leaves in an non-interactive manner using the pre-known public information available:

### Step 2: Deploy Verifiable Proxy Service

This steps involves deploying the verifiable service used to route claiming actions on-chain for proof validation,nullifier & note commitment storage, and also token distributions.

#### Register Service Owned Address w/ Smart-Account

#### Upload/Instantiate Zk-Headstash Contract

#### Create/Seed Tokens To Distribute

### Step 3: Eligible Addresses Generate & Broadcast Proofs for claiming

In the proof circuit, the user proves:

- They own `addr_eligible` (via signature verification).
- The genesis note corresponds to an unclaimed entry in the genesis Merkle tree.
- The nullifier `nf` for the genesis note has not been published.

### Step 4: Output New Note

for the claimed amount (or the full amount if claiming entirely), with its own `cm` and `nf`.

### Zk Circuit Design

The circuit should verify:

1. **Merkle inclusion**: Prove that addr_eligible is in the genesis tree with root root_genesis.
2. **Signature verification**: Prove knowledge of sig valid for addr_eligible signing H(m), where m includes the diversified address pk_d.
3. **Nullifier checks**\
  a. Prove correct derivation of `nf` from private inputs.
  b. Check that `nf` is not in the nullifier set.
4. **Value balancing**: For partial claims, ensure input value ≥ output value.
5. **Note commitment integrity**: Verify correct computation of cm for output notes.

Public inputs to the circuit:

- `root_genesis`
- `nf` (nullifier of the input note, or for genesis, a commitment to it)
- `cm_out` (commitment of the output note)
- `cv` (value commitment)
- `pk_d`, `d` (diversified address)

Private inputs to the circuit:

- `addr_eligible`
- Signature components
- Merkle path for `addr_eligible`
- `v`, `ρ`, `ψ`, `rcm`, `nf_rand`

___

## Claim Process

### Step 1: User generates keys

- `sk` (spending key), `ak` (proving key), `nk` (nullifier key), `ivk` (incoming viewing key).
- Diversifier `d` and `pk_d` = `ivk` * `G` + `d`.

### Step 2: User constructs proof

- For genesis claim, use `addr_eligible` and `signature` to derive `ρ` and `nf`.
- For subsequent claims, use an existing note as input.

### Step 3: Submit transaction

- Public: `nf`, `cm_out`, `cv`, `pk_d`, `d`, `root_genesis`.
- Proof verifying all constraints

### Step 4: Contract updates state

- Add `nf` to nullifier set.
- Add `cm_out` to note commitment tree.
- Transfer tokens to `pk_d`.
  
## Implementation Checklist

- [ ] Define Sinsemilla hashing parameters for Merkle trees and commitments.
- [ ] Implement Halo2 circuits for:
  - Merkle inclusion proofs
  - Signature verification (erc-7524)
  - Nullifier derivation
  - Note commitment computation
- [ ] Design smart contract to manage:
  - Nullifier set
  - Note commitment tree
  - Token transfers
  - Wavs service authentication
- [ ] Develop off-line tools for key generation and proof construction.
  - [x] secure random number generator
  - [x] genesis proof generator
  - [x] genesis fixed amount note generator

## Smart Contract Design

- static verification key (VK) - "compiled down" representation of the circuit
- public inputs
- halo2 proof

A cosmwasm smart contract will be paired with a wavs instance, which we expect to have a set of bls12-381 keys as identity and authentication. This contracts must accept and process a proof of ownership of function for the bls12-381 keys, as we will implement support for key aggregation and rotation. This smart contract will manage the nullifier set as well, in an append-only accepted only from the account managed by the set of wavs operators. It will make use of the sudo entrypoint interface required by the x/smart-account module, allowing for a granular approach to implementing this.

## Verifiable Service Mesh

### Note Commitment Tree

- use TEE for securing note tree

### Claiming API

- exposes API used for users to broadcast & claim allocations.

### Fee Grants

- provides single time feegrants to diversifier keys of claiming addresses

### Delayed Claiming Support

- poweres delayed claims + masking tx for obfuscation
- schedule/incentivize claim delay for maximum entropic contribution

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
