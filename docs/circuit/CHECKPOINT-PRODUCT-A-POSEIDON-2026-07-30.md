# Checkpoint: Product A Poseidon note + suite + keys path

**Date:** 2026-07-30  
**Branch:** `zk-mvp` (local checkpoint — not published)  
**Scope:** private distro + claim (Product A); SEAM shield remains Product B

## Landed

| Area | Status |
|------|--------|
| Poseidon private note `cmx` + lift nullifier | pure + gadget + synthesize |
| Poseidon-v1 distro leaf/path | suite + circuit |
| Suite tooling depth-32 `circuit_anchor` | sound vs shallow root |
| `suite_backed_claim_pair` MockProver | green |
| Offline keygen for zkvm upload | `build_headstash_keys_to` / `just demo-keys` |

## Commands

```bash
cd crates/headstash

# Fast Product A regression (no K=18 full prove)
just demo-product-a

# Suite unit tests
cargo test -p zk-headstash --lib suite::

# Offline store-circuit blob (long keygen; no network)
just demo-keys
# → artifacts/headstash_vk.bin (or HEADSTASH_VK_PATH)

# Optional upload (requires MNEMONIC; not for this checkpoint)
# MNEMONIC='…' cargo run -p zk-test-press --bin cc_headstash --features interface -- --upload
```

## Do not

- Publish / push without review  
- Commit mnemonics or key material  
- Mix shallow suite roots into on-chain genesis_root  
- Claim mainnet production  

## Next

1. Run `just demo-keys` once and verify footer / store-circuit on lab chain.  
2. Contract multi-test claim with mock ZK then real prove.  
3. FE: public mint → shield SEAM (Product B).
