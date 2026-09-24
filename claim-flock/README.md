# Headstash claim on Flock

`headstash-claim` is the claim statement that can be proved without putting
`esk` or a Poseidon tree in the circuit. Flock is a library (`flock-core`,
`flock-hash`, `flock-prover`). This crate does not live inside the prover.

The chain does not verify these proofs yet. One Halo2 verify was already
about half a block. A Ligerito verify of this statement is milliseconds, and
the proof is about 100 KB, so the proofs stay off the consensus record.
What the chain should store is a batch root. That sidecar is specified in
`docs/circuit/PROOF-SIDECAR.md`.

## What a claim proves

Five Blake3 compressions, wired together. Depth is `DEPTH` (2). Each extra
level is one more node compression.

| Row | Input | Output |
|---|---|---|
| Commitment | private `rseed` | `rseed_com` |
| Nullifier | the same `rseed`, different flag | public nullifier |
| Leaf | `rseed_com` plus the public allocation (`epk_x`, denomination, amount, piece index) | leaf digest |
| Node | `left ‖ right`, side chosen by the public index bit | next digest |
| Root | last node | public root |

`rseed` and the siblings are private wires. The allocation, the nullifier,
and the root are public. The index is public, so the circuit shape fixes
which side the running digest is on. There is no mux.

A second `rseed` is a different nullifier and a different leaf, so it does
not open the same root. The same `rseed` always compresses to the same
nullifier, which is the double-spend key. The nullifier is the compression
output, not a free witness.

Key ownership is not this circuit. It is the personal-sign statement in
`circuit/`: the wallet signs the claim prefix, the circuit checks the
signature under the leaf key, and `esk` is not a witness.

## Flags

Each compression is domain-separated by the Blake3 flags word, not by a
second hash function.

| Flag | Value | Row |
|---|---:|---|
| `FLAG_RSEED` | 1 | commitment |
| `FLAG_NULLIFIER` | 2 | nullifier |
| `FLAG_LEAF` | 3 | leaf |
| `FLAG_NODE` | 4 | Merkle node |

The chaining value is the Blake3 IV. The message is one 64-byte block
(`block_len = 64`, counter 0).

## Proof system

`prove_and_verify` builds the circuit, proves it with
`prove_fast_ligerito_union_circuit`, and verifies it with
`verify_ligerito_union_circuit`. The Fiat–Shamir domain is
`terp-headstash-flock-v1`. A public root with the last word flipped is
rejected.

The Blake3 table is the one already in `flock-prover`. This crate only
supplies the wires. Capacity is `nu = 8` (256 rows). A claim uses
`3 + DEPTH` rows.

## Bench

One release sample, depth 2, five gates:

| | |
|---|---:|
| Circuit build | 1.63 s |
| Prove | 17.2 ms |
| Verify | 5.8 ms |
| Proof | 103,194 bytes |

The build time is the Blake3 table, paid once if the shape is reused.
Prove is the 17 ms. Halo2 personal-sign on the same machine was 17.6 s
prove, 1.27 s verify, 4,800 bytes, K=19.

```bash
cd crates/headstash
cargo bench -p headstash-claim --bench headstash_claim
```

The bench writes `artifacts/flock-claim-bench.json`.

## What this is not

- Not a depth-32 community tree. The published Poseidon root in
  `artifacts/community-notes/` is a different statement.
- Not on-chain `proof_instance_verify`.
- Not a Wasmer guest. The verifier is native Flock.
- The note file `artifacts/community-notes/notes.json` holds every `rseed`.
  It is not part of the public tree and must not be committed.
