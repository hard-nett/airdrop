
# Spec: Zk-Airdrop Claiming
>
> **GOAL: Allow eligible headstash members to use zk-proofs to claim partial amounts of their rewards over time.**

#### Context

Our current airdrop framework, `The Headstash Contract` powers distribution by mapping ECDSA addresses not native to the chain (ETH,SOL,etc) as eligible to claim a specific list of tokens. In order to claim, users need to verify they are owners of any eligible addresses. This is done by generating a signature with the eligible address keys, from a message that includes the address native to the chain that the user will use to broadcast the message to claim their allocations.
$$
\sigma = \text{Sign}_{\text{sk}_{\text{eligible}}}\big( H(m) \big), \quad \text{where } \text{addr}_{\text{native}} \in m

$$
**This creates an on-chain association between the eligible address, and the claiming address, which we want to prevent.**

In order to prevent this association between verifying ownership & claiming tokens, there are 3 major obstacles:

### Q: How Does Someone Prove They Own An Eligible Wallet Without Revealing Their Signature?

- **proof of ownership within the note.** Signature made by eligible wallet of the hash of the destination wallet.

### Q: How can someone prevent leaking where their claimed funds end up, if the total amount & distributions allocated are public?

- **note commitments.** Partial claims of genesis allocations, by revealing note commitments derived from input notes, which create fresh output notes.

### Q: How are users prevented from claiming more funds then they are allocated?

- **nullifiers.** deriving from data within a note, collision-resistant nullifiers paired with note-commitments will prevent notes from being double-spent.

> **Notes About Design**
> These obstacles are not unique to our requirements, and have been solved concretely by multiple teams, one for example is the zcash's sprout, sapling, and orchard protocols. We are designing our protocol for private airdrops so that we can leverage a large majority of the work done by the cypherpunk community, however there are some discrepancies we need to design around. Specifically:
>
> **1. Actions will be sending tokens to destination on a transparent ledger**
> When someone is claiming, they will be revealing how much and to whom the claimed tokens are going to *(along with the other crucial components like nullifiers & note commitments)*.
>
> **2. Viewing key magic is very limited**
> We still need a design around how a user who may have spent some, but not all of their allocation can view their remaining balance, without ever revealing it publicly. We must do this in a trustless way, without introducing actions that may leak information, such as storage-access-patterns or others.
>
## Requirements

- **Keys: Self-Custody Key Management Systems**
- **Randomness Generators**
- **Private Proof Of Ownership - PLUME**
- **Sinsemilla Merkle Tree**
- **Notes & Note Commitments (UTXO)**
- **Nullifier Use**
- **Verifiable Service in TEE**

## Keys

We have two main types of keys involved in this process.

1. Eligible Keys
2. Redemption Keys

Eligible keys are the keypair that has a public allocation set for them, and is they key that we must keep any signature or hash derived from it private, in order to retain privacy. Redemption keys are the keys that will be recieving the public allocations claimed by the eligilbe keys.

> NOTE: zcash orchard protocol implements very complex (but useful) key derivation for viewing, authorization, and privacy retention purposes. Our scope does not require the use of viewing or authorization keys, as the end results of tokens claimed will be public. A large portion of the modifications from the orchard protocol altering how note-commitments & nullifiers are derived, as they rely heavily on the use of the key structure used by zcash orchard protocol.

## Randomness Generation

In order to make it impossible to retroatively derive randomness used during the note-commitment generation (which in theory would be possible if an adversary had access to a device, the timestamp of when randomness was generated, its theoretically possible to recreate the randomness source), we want to enable user-derived input as an additional seed to the PRNG process.

> <center> DEMO: our script used to generate randomness can be invoked via :
>
> `cargo run --package zk-crates --bin generate_randomness`</center>

## Ownership Verification - PLUME signature proofs

Our circuit needs to effecietly verify a note being claimed has been authorized to do so by the eligilbe address, without revealing this address itself. In order to do this, we will leverage the design specification of [ERC-7524](https://eips.ethereum.org/EIPS/eip-7524). This will allow users to produce two components, one deterministic & one non-deterministic, allowing us to use the determinstic on as a nullifier.

### Minimal Requirements

- `g` - generator (aka the base point) of the curve
- `m` - 32-byte message
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

We will use version two defined of the PLUME implementation, but modified to retain privcacy of the nullifer

- **Public Inputs:** `nul`,`c`,`g^r`,`z`
- **Private Inputs:** `pk`,`r`,`s`,`H(m,g^sk)`

> NOTE: since we justy seed ownership proof, rather than uniqueness (i.e prevent doublespend), we can modify this implementation to require the nullifier `nul` to be a private input to the circuit. We want to ensure c is accurately constructed, meaning we will have to include a posiedon hash constraint in the circuit.

> TODO: generate table higlighting when /where each component is generated/constructed
>
#### Circuit Arithmetic

1. Compute `h = htc([m,sec1(pk)])`
2. Compute `pk = g^sk`
3. Compute `g^s * pk^-c`
4. Compute `g^r`
5. Compute `h^s * nul^-c`

#### Circuit Constraints

- `g^s * pk^-c = g^r`
- `h^s * nul^-c = z`

#### Additional Verification

In addition to verifying the zk-SNARK, the PLUME verifier performs the following check.

`c == H(nul,g^r,h^r)`

> <center> DEMO: to demonstrate the lifecycle of generating & verifying a plume signature:
>
> `cargo test --package zk-crates --bin plume_demo --  --show-output`</center>

## Sinsemilla Merkle Trees

We make use of the sinsemilla merkle tree implementation for powering effecient note commitment and distirbution inclusion. We will utilize both the `HashDomain` and the `CommitDomain` for two distinct purposes:

| Component | Current description | **What to add / rename** |
|-----------|--------------------|--------------------------|
| **Public eligibility/inclusion leaf** | `leaf = H_leaf(addr,token_name, token_amount)` | Explicitly state that this leaf is a **HashDomain** commitment *only* (binding, no hiding). |
| **Private note commitment** | `cm = Commit(d, pk_d, v, ρ, ψ, rcm)` | Rename to `cm = CommitDomain.Commit(d, pk_d, v, ρ, ψ, rcm)`.  Mention that `CommitDomain` provides *binding + hiding* (Sinsemilla‑based Pedersen‑style commitment). |

### 1. Genesis Distribution Tree: `HashDomain`

**This is the static, starting state of the headstash before any claims happen.**
Its purpose is to allow a user to prove a specific address `addr_eligible` is eligible to claim a certain allocation `v` without revealing which specific address it is. Each leaf is a commitment to the `HashDomain`, as an eligible recipients balance for a single token balance. A leaf is computed using the sinsemilla hashing function as:

$$\mathrm{leaf} = H_{\mathrm{leaf}}(\mathrm{addr} \parallel \mathrm{token\_name} \parallel \mathrm{token\_amount})$$

> <center>  DEMO: our script used to generate this is invokable via the command:
>
> `cargo run --bin create_merkle -- data/sinsemilla_json.json`</center>

### 2. Note Commitment Tree: `CommitDomain`

This tree is dynamic and is the core state of the private ledger. It is constantly updated with every claim transaction. It serves to record the existance of all unspent notes (UTXOs) in a way that allows users to prove a note exists without revealing its contents. Each leaf is a **note commitment `cm`.** A commitment is computed from all the fields of a note (`d`,`pk_d`,`v`,`p`,`ψ`,`rcm`) using a binding and hiding commitment scheme (Sinsemilla in our example)
$$\mathrm{cm} = \mathrm{Commit}(d, \mathrm{pk}_d, v, \rho, \psi, \mathrm{rcm})$$

> Our genesis tree is non-interactive, derived from the sinsemilla `HashDomain`, but we want to have our note commitments retain same functionality as zcash orchard protocol, which uses the `CommitDomain` for the note-commitments.

#### How its Built

0. The tree starts empty, with the root being the root also being the genesis distribution tree root.
1. When a user makes a claim (either genesis or spending an existing note), their transaction output includes a new note commitment `cm_new`
2. The smart contract verifies the zk-proof and, if valid, inserts `cm_new` into the next available leaf position in this tree.
3. The contract then computes and stores the new root of this tree (root_notes_current).

## Notes

notes function as private UTXOs (Unspent Transaction Outputs) that represent claims to portions of the airdropped tokens. Each note contains sensitive data that must remain private, except for certain public components used for verification and transaction processing.

```json
{
  "d": "diversifier",         // public; used to derive diversified address
  "pk_d": "diversified transmission key", // public; derived as ivk * G + d
  "v": "amount",              // private; value being claimed (e.g., 100 uterp)
  "ρ": "rho",                 // private; used in nullifier derivation (input to PRF)
  "ψ": "psi",                 // private; randomness for note commitment
  "rcm": "commitment randomness", // private; blinds the note commitment
  "addr_eligible": "A",       // private; original eligible address
  "nf_rand": "p"              // private; randomness for nullifier derivation
}
```

> NOTE: we must update the definition of a note to include the inputs needed for PLUME signature verification, and also simply the use of diverisfier and transmission keys
> specifically:
>
> - `d` & `pk_d` can be replaced to be the public key that will recieve the claimed assets. This pubkey hash is also `m` for PLUME, and is a public input.
> - we need to integrate PLUME inputs for notes, specifically:
>   - `nul` - as a private input to mimize post-quantum breaking
>   - `r` should be devised from same randomness as note commitments
>   - `c` needs to be inlcuded in note
>   - `g` should be a known constant in circuit (not needed to include in note)
>   - `z` can be computed as circuit knows `g` and `r` is already public input
>   - `s` added as private input to note as derived from `sk` which is never provided as input to circuit

**Public outputs during a claim:**

- `cm` (note commitment, added to the Merkle tree)
- `nf` (nullifier, added to the nullifier set to prevent double-spending)
- `cv` (value commitment, for amount balancing)
- `pk_d` and `d` (diversified address components)

### Note Notation Details

| Notation                              | Purpose                                                                                                                                                                                                                                             | Derivation                                                                                                                                                                                                                                                                                                                                        | Usage                                                                                                                                                           |     |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `d` (Diversifier)                     | public value that allows a user to generate multiple unique addresses from a single key set.                                                                                                                                                        | Generated randomly by the user when creating a new note. 11-byte value (as in Zcash)                                                                                                                                                                                                                                                              | Combined with the incoming viewing key `ivk` to derive `pk_d`. It is included in the note commitment to bind it to the note.                                    |     |
| `pk_d` (Diversified Transmission Key) | This is the public key that serves as the recipient address for the claimed tokens.  It is derived from the user's incoming viewing key `ivk` and the diversifier (d). **This is the key that will receive the public tokens from a note instance** | **`pk_d = ivk * G + d`**, where:<br>- `ivk` is an incoming viewing key (a private key derived from the user's spending key)<br>- `G` is the generator point of the elliptic curve (e.g., Pallas or Vesta in Halo2).<br>-`d` is the diversifier, often represented as a point on the curve via a hash-to-curve function (e.g., `DiversifyHash(d)`) | `pk_d` provides a canonical way for users claim partial amounts of their balance to multiple address under their control, improving the privacy set post claim. |     |
| `v` *(Amount)*                        | The value of tokens being claimed in a note. Always a portion of the total allocation from `addr_eligible`                                                                                                                                          | Always will be a Fixed-Denomination, to improve privacy throughout the set.<br><br>1_000_000_000 == 1,000<br>100_000_000 == 100<br>10_000_000 == 10<br>1_000_000 == 1                                                                                                                                                                             | Publicly exposed so contract verifying proof can transfer `v` to address `pk_d`                                                                                 |     |
| `ρ` (Rho)                             | A private value used as input to the pseudo-random function `PRF` for nullifier derivation. It ensures that each nullifier is unique and unlinkable to the note.                                                                                    |  For the genesis note (first claim), `p` is derived from `addr_eligible` and a user generated nonce. For subsequent notes, `p` is generated randomly                                                                                                                                                                                              | `ρ` as an input to the derivation of `ψ` and `rcm`        |     |
| ψ (Psi)                               | Randomness to add to the note commitment to ensure it is hiding                                                                                                                                                                                     | Generated randomly by the user using a secure random number generator when creating the note. Should be unique per note                                                                                                                                                                                                                           |                                                                                                                                                                 |     |
| `rcm` (Commitment Randomness)         | Ensure note commitment `cm` is computationally binding & hiding. It prevents anyone from guessing the note contents from `cm`                                                                                                                       | Generated randomly by user, similarly to ψ.                                                                                                                                                                                                                                                                                                       |                                                                                                                                                                 |     |
| `nf_rand`                             | Additional randomness used in nullifier derivation to increase security and prevent collisions                                                                                                                                                      | Generated randomly by the user for each note.                                                                                                                                                                                                                                                                                                     |                                                                                                                                                                 |     |

___

### Note Commitments

- is what is disclosed publicly during claiming, by appending to the Note Commitment Tree
- allows the origin of the claiming address to be private

### Nullifiers (Anti Double Spend)

To prevent double-spends, each note must have a unique, deterministic nullifier derivable only by the owner. For the genesis claim (first redemption), derive `nf_secret` from the eligible address and a secret known only to the user:

$$

\text{nf} = \text{PRF}_{\text{nk}}(\rho) \quad \text{where } \rho = H(\text{addr\_eligible} \parallel \text{nonce})

$$

- `nk` is the nullifier-deriving key (part of the user’s private keys)
- `nonce` is a user-generated secret. This ensures the nullifier is:

This ensures the nullifier is:

- Unique per note.
- Unlinkable to the eligible address or note commitment.
- Only computable by the note owner.

For subsequent claims (spending output notes), use:

$$

 \text{nf} = \text{PRF}_{\text{nk}}(\rho)
$$
where `ρ` is taken directly from the input note.

___

## Genesis Bootstrapping

To bootstrap the first claim without a prior input note:

### 1. Genesis Note Construction

Construct a genesis note for the full allocation, with:

- `v` = total_allocation
- `ρ` = `H(addr_eligilbe || nonce)`
- `rcm`, `ψ`, `nf_rand` generated randomly.

### Step 2: Genesis Commitment

Compute a commitment `cm_genesis` for this note, but do not insert it into the Merkle tree yet.

### Step 3: User Generates Proof

In the proof circuit, the user proves:

- They own `addr_eligible` (via signature verification).
- The genesis note corresponds to an unclaimed entry in the genesis Merkle tree.
- The nullifier `nf` for the genesis note has not been published.

### Step 4: Output New Note

for the claimed amount (or the full amount if claiming entirely), with its own `cm` and `nf`.

___

### Note Commitment Computation

Use a Sinsemilla-based commitment for efficiency in Halo2:

$$
  \text{cm} = \text{SinsemillaCommit}(\text{repr}(d), \text{repr}(pk_d), v, ρ, ψ, rcm)
$$

The commitment must bind all critical note components to ensure integrity and privacy.

___

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

- [ ]   Define   Sinsemilla hashing parameters for Merkle trees and commitments.
- [ ] Implement Halo2 circuits for:
  - Merkle inclusion proofs
  - Signature verification (erc-7524)
  - Nullifier derivation
  - Note commitment computation
- [ ] Design smart contract to manage:
  - Nullifier set
  - Note commitment tree
  - Token transfers
- [ ] Develop off-line tools for key generation and proof construction.
  - [ ] secure random number generator
  - [x] genesis proof generator
  - [x] genesis fixed amount note generator

## Smart Contract Design

- static verification key (VK) - "compiled down" representation of the circuit
- public inputs
- halo2 proof

A  cosmwasm smart contract will be paired with a wavs instance, which we expect to have a set of bls12-381 keys as identity and authentication. This contracts must accept and process a proof of ownership of function for the bls12-381 keys, as we will implement support for key aggregation and rotation. This smartt contract will manage the nullifier set as well, in an append-only accepted only from the account managed by the set of wavs operators.

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
