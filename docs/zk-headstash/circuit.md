# Circuit Specs

## TLDFR

- each action requires us to constrain the "internal action steps" as math (easy cuz all data in computers are just 1 & 0, and if you split them up (and remember the order) very precisely, letting us form numbers in binary representation, ). **headstash has 3 main internal actions, 1.key-pairing,2.note-merkle-tree-inclusion,3.nullifier/note-commitment integrity**
-

## Canonicity Gates

The note-commit circuit uses the Sinsemilla hash function to commit to a note's constituent data (recp, fdi, nd, v, rho, esk, psi). Sinsemilla processes data in 10-bit chunks.

Canonicity in this context has two primary goals:

Unique Representation: Ensure that every unique set of input values produces a unique sequence of bits to be hashed. There should be no two different sets of inputs that could be decomposed into the same bit string for the commitment. This is fundamental to the security of the commitment scheme.
Range Constraints: Prove that the values are within their expected bit lengths (e.g., v is 64 bits, rho is 254 bits) without having to perform an expensive full-range check. This is done by proving the values can be correctly decomposed into their constituent bits.
The "10-bit gate canonicity" refers to the custom gates that enforce the correct decomposition of values at the boundaries between these 10-bit Sinsemilla message pieces. Since a single field value (like the 254-bit rho) is split across multiple message pieces, the circuit must ensure the pieces fit together perfectly to reconstruct the original value.

The gates achieve this by:

Decomposing a value into smaller, constrained sub-pieces (e.g., b_0, b_1, b_2, b_3 for message piece b).
Constraining the sub-pieces to their correct bit lengths (using lookup tables and boolean checks).
Reconstructing the original value from the sub-pieces with a constraint like b = b_0 + (2^4) *b_1 + (2^5)* b_2 + (2^6) * b_3.
Linking across gates to ensure the value in one piece correctly connects to the next piece, forming a continuous bit string.

### Design

### Verifying Key
<!-- q: what is minimum required data needed to verify a proof? -->
<!-- q: how do we store/retrieve these keys in a cosmwasm contract for use to prooveF -->

Verifying Key (VK)

Size: Typically 10-50 KB (depends on circuit complexity)
Contents:

Fixed commitments: Commitments to fixed columns in your circuit
Permutation commitments: For the copy constraint system
Circuit structure metadata: Number of columns, gates, etc.
Domain information: FFT domain size

### Proving Key

### Serializing And Deserializing Keys

We specifically define how do serialize and deserialize circuit proving & verification keys. WE implement this via the logic defined in this pr: <https://github.com/zcash/halo2/pull/661/>

#### Writing

| bytes | value | description | |
|--------|-----------|--------|--------------|
|  0..1 | `0x01` | version byte checked on read |||
|  1..`fixed_commitments.len()` | `vk.fixed_commitments` ||||
|  `fixed_commitments.len()`..`permutation.len()` | `vk.permutation` ||||
|  `permutation.len()`..`selectors.len()` | `vk.selectors` ||||

#### Reading

Reading requires the vk deserialized params, or manually deserializing each value composing the key via knowledge of the byte positions set upon serialization. Below are the values needed to reconstruct and what knowledge we need to do so:

| Offset | Size | Value | Description | Label |
|--------|------|-------|-------------|-------|
| 0 | 1 byte | `0x01` | Version byte | |
| 1 | 4 bytes | `u32` (little-endian) | Number of fixed columns | `num_fixed_columns` |
| 5 | `num_fixed_columns * commitment_size` | `Vec<C>` | Fixed commitments (each commitment is typically 64 bytes) | `fixed_commitments` |
| ... | 4 bytes | `u32` (little-endian) | Number of permutation commitments | `permutation.num_commitments` |
| ... | `num_commitments * commitment_size` | `Vec<C>` | Permutation commitments (each typically 64 bytes) | `permutation.commitments` |
| ... | 4 bytes | `u32` (little-endian) | Number of selectors | `num_selectors` |
| ... | `sum((selector.len() + 7) / 8)` | `Vec<Vec<bool>>` | Selectors (packed as bits, 8 bools per byte) | `selectors` |

**Key Points:**

- `from_bytes()` is a convenience wrapper around `read()` that works with byte slices
- Requires `params` and `ConcreteCircuit` type to reconstruct the domain and constraint system
- Selectors are bit-packed for efficiency (8 boolean values per byte)
- The permutation section contains its own count followed by its commitments
- The total size can be calculated with `bytes_length()` which accounts for all components

### Generating Proof

**What you need to provide:**

1. **Params**: The universal setup parameters
2. **Proving Key**: Generated earlier
3. **Circuit instance**: Your actual circuit with witness data filled in
4. **Public inputs**: The instance values (public inputs to your circuit)
5. **RNG**: For generating random challenges

#### **Proof Size**

- **Typical size**: 1-5 KB for most circuits
- **Fixed components** (don't scale much with circuit size):
  - Advice commitments: 32 bytes each
  - Lookup commitments: 32 bytes each
  - Opening proofs: ~64 bytes each
  - Evaluations: 32 bytes each (field elements)

  ```

Proof Components (approximate):
├─ Advice commitments: 32 bytes × (number of advice columns) × (number of phases)
├─ Lookup commitments: 32 bytes × (number of lookup arguments)
├─ Permutation product commitments: 32 bytes × (number of permutation products)
├─ Vanishing argument commitment: 32 bytes
├─ Random commitment: 32 bytes
├─ Opening evaluations: 32 bytes × (number of opened points)
└─ Multi-open proof: ~128 bytes
