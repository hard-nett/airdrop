# Product A — CW Orchestrator + ICTRS expected usage

**Status:** lab workflow (2026-07-30)  
**Product:** private distro + claim → public mint; SEAM shield is Product B.

## Workflow spine

```text
1. suite_backed_claim_pair / build_suite_backed_claim_fixture
   → depth-32 Poseidon root + Instance (168 B) + partial note
2. just demo-keys  (offline)
   → artifacts/headstash_vk.bin  [params‖cs‖vk‖footer] K=18 i=6
3. cw-orch / ICTRS
   → upload wasm (cw-headstash) [no zk-api feature on stock wasmd]
   → instantiate { genesis_root, distro_hash_domain: poseidon_v1, claim_mock_verify? }
   → [optional] upload_circuit / store-circuit → SetCircuitId
4. ProcessHeadstash
   → lab: claim_mock_verify + non-empty proof
   → prod: zk-api + proof_instance_verify(cid, proof, instance_bytes)
5. Public recipient funds → FE shield SEAM (Product B)
```

## Contract instance fields (Product A)

| Field | Expected |
|-------|----------|
| `genesis_root` | 32-byte **depth-32** Poseidon path root |
| `distro_hash_domain` | `poseidon_v1` (default) |
| `circuit_id` | store-circuit id after VK upload (0 until set) |
| `claim_mock_verify` | **lab only** true for multi-test without zk wasmvm |

Owner later: `SetCircuitId`, `SetClaimMockVerify`.

## Local commands (headstash crate)

```bash
cd crates/headstash

# Fast soundness (no full prove)
just demo-product-a
cargo test -p cw-headstash --lib
cargo test -p zk-test-press --lib harness::claim_fixture --features interface

# Offline store-circuit blob (long keygen)
just demo-keys

# CW-orch Mock L1 bridge mint (no claim circuit)
just demo-e2e-l1   # if defined / demo-corridor-lab

# ICTRS Docker (zk image + wasm) — see crates/ict-rs/examples/headstash.rs
# cargo run -p ict-rs --example headstash --features docker
```

## ICTRS integration map

| Workflow family | Entry | Notes |
|-----------------|-------|--------|
| Headstash Product A claim | `examples/headstash.rs` | Wire VK from `HEADSTASH_VK_PATH` / `artifacts/headstash_vk.bin` |
| Corridor mint (bridge) | `corridor_ict_funded` / `just demo-corridor-ict` | No claim keygen; BridgeMintNote |
| Hashmerchant | `ict-rs` examples `hashmerchant*` | Orthogonal module; same Terp Docker image family |
| Private DEX settle | `deploy_private_dex_testnet` | After public mint / SEAM |

Shared **lab honesty**: mock verify ≠ production `proof_instance_verify`.

## Fixture export

```rust
// zk-test-press (interface)
use zk_test_press::harness::claim_fixture::build_suite_backed_claim_fixture;
let fix = build_suite_backed_claim_fixture(8, 3)?;
fix.validate_policy()?;
// fix.root → InstantiateMsg.genesis_root
// fix.instance_* → HeadstashInstances for ProcessHeadstash
```

## Do not

- Publish shallow suite roots as genesis_root  
- Enable `claim_mock_verify` on mainnet  
- Commit mnemonics or VK secrets  
- Mix Sinsemilla roots with `poseidon_v1` domain  
