
## Sinsemilla Commitdomain

- messge limb rules: 1 single 250 bit limb (or limbs that are factors of 10 and less than 64, totaling less than 250)

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

```
// Optimized decomposition for Sinsemilla (250 bit pieces, 10-bit limb alignment):
//   Piece a: bits 0-249 of nd (250 bits)
//   Piece b: bits 250-253 of nd || bits 0-56 of v  (4 + 56 = 60 bits)
//   Piece c: bits 57-64 of v || 0-53 of fdi  (7 + 53 = 60 bits)
//   Piece d: bits 54-64 of fdi || 0-49 of recp (11 + 49 = 60 bits)
//   Piece e: bits 50..109 of recp || 111..171 of recp  || 172..232 of recp  || 233..254 of recp || 0..9 bits of esk ||  10..40 bits of esk  (60+60+60 +21 +9+30 = 240 bits)
//   Piece f: bits 41..101 of esk  || 102..=162 of esk  || 163..=223 of esk  || 224..=254 of esk || 0..9 bits of rho ||  10..40 bits of rho  (60+60+60 +24 +8+28 = 240 bits)
//   Piece g: bits 41..101 of rho  || 102..=162 of rho  || 163..=223 of rho  || 224..=254 of rho || 0..9 bits of psi ||  10..40 bits of psi  (60+60+60 +24 +8+28 = 240 bits)
//   Piece h: bits 41-253 of psi || 7 bits blank (213 + 7 = 220 bits)
```
