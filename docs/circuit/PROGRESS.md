# Headstash circuit progress

Product A is a clearnet claim. The proof must show ownership of an eligible secp256k1 key and a single nullifier for that note. The distribution root, denomination, value, recipient, nullifier, and note digest are public.

## Done

- [x] Poseidon-v1 distribution tree, depth 32. Leaf is `(epk_x, epk_y, nd, v, fdi)`. Domain `poseidon-v1`.
- [x] Poseidon-v1 note commitment. Public `cmx` is the digest. The Pallas point is only there so the nullifier equation has a point to add.
- [x] Instance columns bound in the circuit: `anchor`, `nd`, `v`, `recp`, `nf`, `cmx`.
- [x] Ownership is in-circuit GLV: `epk = k1·G + k2·ψ(G)` with `k1 + k2·λ ≡ esk (mod n)`. `ψ(x, y) = (βx, y)`.
- [x] Soundness tests for the split (bounds, `k·G` via libsecp) and for the chip (MockProver accepts a real key, rejects a mismatched key).
- [x] Native release bench, 10 threads, K=18: keygen 19.0s, prove 6.7s, verify 0.20s, proof 4704 bytes. `artifacts/snap-proof-bench.json`.
- [x] Spec rewritten to this circuit (`spec.md`).
- [x] Contract denom mask is byte 31. Claim recipient is the raw 32 bytes.

This ownership proof needs `esk` in the prover. That is fine for a host prover. It is the wrong shape for a wallet that only signs.

## Not this circuit

- [ ] MetaMask snap proving. The snap can hold the key. It cannot thread the prove, and it must not hand the key to the page.
- [ ] The fixed-base and variable-base scalar-mul challenge interfaces. Fixed-base is `[k]G` with the scalar as input (the pairing above). Variable-base is `[k]P`, which is one multiplication inside a signature check. Neither hashes a wallet message or derives a nullifier.

## Next

- [ ] Ownership without `esk` in the prover: the wallet signs the claim offline, the circuit verifies that signature under the leaf's `epk`.
- [ ] Nullifier derived from note values the circuit has, not from `esk`, so one note still has one nullifier.
