#!/bin/bash

# Terp custom optimizer (terp-optimize.sh): mount monorepo crates/ at /workspace
# so path deps (cosmwasm, zcash/halo2, cw-orch, …) resolve as sibling libraries.
# Default image: terpnetwork/workspace-optimizer-arm64:0.17.0 (override DOCKER_IMAGE).
docker_image := env_var_or_default('DOCKER_IMAGE', 'terpnetwork/workspace-optimizer-arm64:0.17.0')
arch := `if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then echo "linux/arm64"; else echo "linux/amd64"; fi`
crates_root := justfile_directory() / ".."
# monorepo root (terp-core) so docs/fixtures + crates/* path deps resolve together
repo_root := justfile_directory() / "../.."

schema-codegen:
        @sh scripts/sh/schema-codegen.sh

# Full workspace optimize via terp image:
#   monorepo → /workspace, PROJECT_DIR=/workspace/crates/headstash
#   path libs under /workspace/crates/{cosmwasm,zcash,...}
workspace-optimize:
        docker run --rm \
                --platform {{arch}} \
                -v "{{repo_root}}":/workspace \
                -e PROJECT_DIR=/workspace/crates/headstash \
                --mount type=volume,source=headstash_corridor_opt_cache,target=/target \
                --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
                {{docker_image}}

# Alias used by corridor prepare script path docs
workspace-optimize-quick: workspace-optimize

# Clear optimizer caches (after toolchain / path-dep changes)
optimizer-clean:
        docker volume rm headstash_corridor_opt_cache headstash_cache registry_cache 2>/dev/null || true

# Force rebuild corridor Daemon wasm via e2e prepare (optimizer + install both artifacts/)
prepare-corridor-wasm-force:
        #!/usr/bin/env bash
        set -euo pipefail
        FORCE_WASM_REBUILD=1 bash "{{justfile_directory()}}/../../crates/terp-rs/docs/private-bridge/e2e/prepare-corridor-ict-wasm.sh"

# ── Demo path (see docs/circuit/DEMO-PATH.md) ─────────────────────────────

# Fast: Poseidon distro pure + suite + contract policy (no K=18 MockProver).
demo-policy:
        cargo test -p zk-headstash --lib --features "circuit,std,interface" -- distro_poseidon poseidon_v1 partial_claim suite_backed zkvm_circuit
        cargo test -p cw-headstash --lib distro::

# Medium: Part T structural + suite claim construct (still no full prove).
demo-circuit-smoke:
        cargo test -p zk-headstash --lib --features "circuit,std,interface" -- \
                orchard_delta_part_t::h2_ orchard_delta_part_t::h6_ \
                orchard_delta_part_t::claim_surface

# Slow: full H1 MockProver (K=18, ~8–10 min). Run when greening claim circuit.
# Separate track from L1 mock ZK / demo-e2e-l0 — never a PR CI gate while red.
demo-h1:
        cargo test -p zk-headstash --lib --features "circuit,std,interface" orchard_delta_part_t::h1_valid_claim -- --nocapture

# Keys for zkvm (writes artifacts; long keygen).
demo-keys:
        cargo run -p zk-test-press --bin cc_headstash --features interface

# ── E2E harness L0 (pure seams + suite re-exports; no Docker / no H1 prove) ──
# Inventory + E2E-id map: crates/terp-rs/docs/private-bridge/E2E-HARNESS-PLAN.md
# L1 mock ZK: policy + mock proof bytes only; real prove = demo-h1 / nightly.

spectrum_fixtures := justfile_directory() / "../../terp-rs/crates"

# Round-3: emit/validate Domain B BridgeMintClaimPublic golden fixture (mock LC).
# Documents Tacit anvil roundtrip; optional --try-anvil if forge/anvil present.
demo-bridge-fixture:
        #!/usr/bin/env bash
        set -euo pipefail
        FIX="{{spectrum_fixtures}}"
        bash "$FIX/emit_bridge_mint_fixture.sh" --regenerate
        echo "== harness load + authorize golden =="
        cargo test -p zk-test-press --lib harness::bridge_mint_fixture:: -- --nocapture
        echo "golden: $FIX/bridge_mint_claim_happy.v1.json"
        echo "anvil (optional): just demo-bridge-fixture-anvil"

# Optional live anvil annotation on the fixture meta (degrades if tools missing).
demo-bridge-fixture-anvil:
        #!/usr/bin/env bash
        set -euo pipefail
        FIX="{{spectrum_fixtures}}"
        bash "$FIX/emit_bridge_mint_fixture.sh" --regenerate --try-anvil
        cargo test -p zk-test-press --lib harness::bridge_mint_fixture::

# Alias used in ROUND2-HARNESS / E2E plan.
demo-e2e-l0: e2e-l0

e2e-l0:
        #!/usr/bin/env bash
        set -euo pipefail
        FIX="{{spectrum_fixtures}}"
        echo "== L0 bridge_auth_seams (E2E-01..07 seeds) =="
        (cd "$FIX/bridge_auth_seams" && cargo test)
        echo "== L0 private_dex_seams (E2E-10..13 seeds) =="
        (cd "$FIX/private_dex_seams" && cargo test)
        echo "== L0 seam_note_out (E2E-09 / SEAM-N1..N6) =="
        (cd "$FIX/seam_note_out" && cargo test)
        echo "== L0 compose_seams (C1–C4 + product_path_burn_to_swap_sketch) =="
        (cd "$FIX/compose_seams" && cargo test)
        echo "== L0 zk-test-press harness re-exports + claim / bridge mint fixtures + compose =="
        cargo test -p zk-test-press --lib harness::
        echo "== L0 PrivateBridgeSuite method wrappers (interface) =="
        cargo test -p zk-test-press --lib suites::private_bridge:: --features interface
        echo ""
        echo "E2E-id min-layer map (L0 pure):"
        echo "  E2E-01 burn→mint happy     → bridge_auth_seams / assert_policy_bridge_mint_happy"
        echo "  E2E-01 fixture packet      → harness::bridge_mint_fixture (Domain B §9 JSON)"
        echo "  E2E-02 double mint         → assert_double_mint_reject"
        echo "  E2E-03 H-1 spent≠burn      → assert_h1_spent_only_reject"
        echo "  E2E-04..07 tip/value/asset → bridge_auth_seams unit tests"
        echo "  E2E-08 claim policy        → harness::claim_fixture (mock ZK; no prove)"
        echo "  E2E-09 note schema         → seam_note_out + compose_bridge_mint_to_seam"
        echo "  E2E-10..13 swap/oracle     → private_dex_seams"
        echo "  compose C1–C4             → compose_seams (mint→SEAM→swap pure)"
        echo "  product pure e2e          → compose_seams::product_path_burn_to_swap_sketch"
        echo "                              (or cargo test -p zk-test-press --lib harness::compose_l0)"
        echo "  E2E-18..19 L2/L3           → NOT in this recipe (anvil / ict-rs)"
        echo "  demo-bridge-fixture       → golden BridgeMintClaimPublic emit + load"

# ── E2E harness L1 (cw-orch Mock: deploy cw-headstash + BridgeMintNote) ────
# Mock ZK verify only (BridgeCfg.mock_verify). No Docker / no H1 prove / no anvil.
# See agents/ROUND3-HARNESS-E2E.md

demo-e2e-l1: e2e-l1

e2e-l1:
        #!/usr/bin/env bash
        set -euo pipefail
        echo "== L1 cw-headstash bridge unit (contract crate) =="
        cargo test -p cw-headstash --lib bridge::
        echo "== L1 cw-headstash multi-test BridgeMintNote e2e =="
        cargo test -p cw-headstash --test test_bridge_e2e -- --nocapture
        echo "== L1 fixture world builders =="
        cargo test -p zk-test-press --lib harness::bridge_l1:: --features interface
        echo "== L1 PrivateBridgeSuite cw-orch Mock execute (BridgeMintNote) =="
        # Filter l1_* Mock execute tests; full private_bridge module also runs under demo-e2e-l0.
        cargo test -p zk-test-press --lib suites::private_bridge:: --features interface -- l1_ --nocapture
        echo ""
        echo "L1 E2E methods (Mock only):"
        echo "  e2e_bridge_mint_happy          → E2E-01 CW"
        echo "  e2e_bridge_double_mint_reject  → E2E-02 CW"
        echo "  e2e_h1_spent_only_reject       → E2E-03 CW"
        echo "  e2e_unregistered_asset_reject  → E2E-06 CW"
        echo "  (upload_and_instantiate_mint: cw-headstash only; no manifold/circuit)"

# ── Private Bridge corridor lab film (Layer A host; D1–D7 freezes) ───────────
# Honest: lab_simulated notify + pure/Mock suites — NOT mainnet Cash App / BTC / ZEC.
# SSOT: crates/terp-rs/docs/private-bridge/e2e/CORRIDOR-LAB-STATUS.md
# Design freezes: crates/terp-rs/docs/private-bridge/DESIGN-DECISIONS-CORRIDOR-2026-07-20.md

spectrum_e2e := justfile_directory() / "../../terp-rs/docs/private-bridge/e2e"

# One-command host film: cashapp pure + harness + hash-market notify smoke.
demo-corridor-lab:
        #!/usr/bin/env bash
        set -euo pipefail
        FIX="{{spectrum_fixtures}}"
        E2E="{{spectrum_e2e}}"
        echo "== corridor pure (cashapp_zec_corridor fixtures I1–I6) =="
        (cd "$FIX/cashapp_zec_corridor" && cargo test)
        echo "== corridor harness (zk-test-press cashapp_zec; Simulated backend) =="
        cargo test -p zk-test-press --lib cashapp_zec --features 'interface,l0-seams'
        echo "== hash-market notify plane smoke (Layer A host) =="
        chmod +x "$E2E/corridor-lab-host.sh" "$E2E/corridor-lab-smoke.sh"
        bash "$E2E/corridor-lab-host.sh"
        echo ""
        echo "OK demo-corridor-lab (lab only)"
        echo "  companion pure L0 spine: just demo-e2e-l0"
        echo "  companion L1 Mock mint:  just demo-e2e-l1"
        echo "  status: crates/terp-rs/docs/private-bridge/e2e/CORRIDOR-LAB-STATUS.md"

# Notify plane only (build/start hash-market lab + smoke).
demo-corridor-lab-smoke:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-lab-host.sh" "$E2E/corridor-lab-smoke.sh"
        bash "$E2E/corridor-lab-host.sh"

# Full pure L0 + corridor lab (longer; PR-ish).
demo-corridor-lab-full: demo-e2e-l0 demo-corridor-lab

# Post-deposit host film: W0–W7 pure + automation PUT for UI poll (D3+D7).
demo-corridor-mint-after-observe:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-lab-mint-after-observe.sh"
        bash "$E2E/corridor-lab-mint-after-observe.sh"

# ── ict_local_funded (S1/S2/S6) — fresh Terp + regtest observe + chain mint ─
# Honest: local multi-net fidelity, NOT mainnet money. mock_verify labeled.
# Requires: Docker, dockerd, terpnetwork/terp-core:local-zk (or CORRIDOR_ICT_IMAGE_TAG).
# SSOT: crates/terp-rs/docs/private-bridge/e2e/CORRIDOR-LAB-STATUS.md + agents/.../STATUS-HARNESS-OBSERVE.md

prepare-corridor-ict-wasm:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/prepare-corridor-ict-wasm.sh"
        bash "$E2E/prepare-corridor-ict-wasm.sh"

# Headstash + private-dex wasm for G3 settle profile.
prepare-corridor-ict-wasm-settle:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/prepare-corridor-ict-wasm.sh"
        CORRIDOR_PREPARE_PRIVATE_DEX=1 bash "$E2E/prepare-corridor-ict-wasm.sh"

# Full funded path: regtest observe + reporter + ict-rs Daemon BridgeMintNote + swap film.
demo-corridor-ict:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        bash "$E2E/corridor-ict-funded.sh"

# Chain mint only (still real Daemon path). Dev residual if observe not required.
demo-corridor-ict-mint-only:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        SKIP_REGTEST=1 CORRIDOR_ALLOW_MINT_ONLY=1 CORRIDOR_ALLOW_HAPPY_FIXTURE=1 \
          bash "$E2E/corridor-ict-funded.sh"

# Funded observe + mint + on-chain SettleSwap (mock_verify lab). Pure film residual.
demo-corridor-ict-settle:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        CORRIDOR_CHAIN_SETTLE=1 bash "$E2E/corridor-ict-funded.sh"

# Dev residual: mint + settle without regtest (still chain mint+settle required).
demo-corridor-ict-settle-mint-only:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        SKIP_REGTEST=1 CORRIDOR_ALLOW_MINT_ONLY=1 CORRIDOR_ALLOW_HAPPY_FIXTURE=1 \
          CORRIDOR_CHAIN_SETTLE=1 bash "$E2E/corridor-ict-funded.sh"

# P2 machine preflight (ports, docker, wasm surfaces, optional Zakura).
preflight-corridor-local:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/preflight-corridor-local.sh"
        CORRIDOR_CHAIN_SETTLE=1 CORRIDOR_ZEC_EGRESS_D=1 bash "$E2E/preflight-corridor-local.sh"

# Option D continuous: mint + settle + pure burn record + lab ZEC pay (mock_verify lab).
# Requires CORRIDOR_CHAIN_SETTLE + CORRIDOR_ZEC_EGRESS_D. CW BridgeEgressBurn residual → pure_record_lab.
demo-corridor-ict-egress-d:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        CORRIDOR_CHAIN_SETTLE=1 CORRIDOR_ZEC_EGRESS_D=1 bash "$E2E/corridor-ict-funded.sh"

# Dev residual: mint + settle + Option D without regtest observe.
demo-corridor-ict-egress-d-mint-only:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/corridor-ict-funded.sh" "$E2E/prepare-corridor-ict-wasm.sh"
        SKIP_REGTEST=1 CORRIDOR_ALLOW_MINT_ONLY=1 CORRIDOR_ALLOW_HAPPY_FIXTURE=1 \
          CORRIDOR_CHAIN_SETTLE=1 CORRIDOR_ZEC_EGRESS_D=1 \
          bash "$E2E/corridor-ict-funded.sh"

# One-button stable local multi-net (P1): prepare wasm → Zakura up (best effort)
# → full Option D egress-d → print receipts; fail-closed on dest mismatch / missing burn.
# Soft-skip only Zakura *start*; burn + dual receipts still mandatory.
demo-corridor-full-local:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/demo-corridor-full-local.sh" \
          "$E2E/corridor-ict-funded.sh" \
          "$E2E/prepare-corridor-ict-wasm.sh" \
          "$E2E/zakura/zakura-local.sh" 2>/dev/null || true
        bash "$E2E/demo-corridor-full-local.sh"

# ── Zakura local (D6) — ZEC dest / RPC; does not break demo-corridor-lab ─────
# SSOT: crates/terp-rs/docs/private-bridge/e2e/ZAKURA-LOCAL.md

demo-zakura-local-dest:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/zakura/zakura-local.sh"
        echo "== golden terp-dest-binding-v0 =="
        bash "$E2E/zakura/zakura-local.sh" golden
        echo "== dest + owner_binding (offline OK) =="
        bash "$E2E/zakura/zakura-local.sh" dest
        echo "== harness offline binding + golden tests =="
        cargo test -p zk-test-press --lib zakura_local::tests --features 'interface,l0-seams' -- --nocapture owner_binding golden_vector cashapp_w0_w7_with_golden

demo-zakura-local:
        #!/usr/bin/env bash
        set -euo pipefail
        E2E="{{spectrum_e2e}}"
        chmod +x "$E2E/zakura/zakura-local.sh"
        bash "$E2E/zakura/zakura-local.sh" golden
        bash "$E2E/zakura/zakura-local.sh" dest
        if bash "$E2E/zakura/zakura-local.sh" status 2>/dev/null; then
          bash "$E2E/zakura/zakura-local.sh" rpc-smoke
        else
          echo "Zakura RPC down — attempting up (needs ZAKURAD_BIN + docker)…"
          if bash "$E2E/zakura/zakura-local.sh" up; then
            bash "$E2E/zakura/zakura-local.sh" rpc-smoke
          else
            echo "SKIP live Zakura (bin/docker residual) — offline dest still printed above"
          fi
        fi
        echo "== harness zakura_local tests (live skips if RPC down) =="
        cargo test -p zk-test-press --lib zakura_local --features 'interface,l0-seams' -- --nocapture
