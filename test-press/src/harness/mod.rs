//! L0 harness helpers for private-bridge / Headstash compose.
//!
//! Always available (no `interface` feature). Pure seams + DEMO-PATH claim
//! fixture schema + Domain B bridge mint packet fixture. Suite methods under
//! `suites::private_bridge` re-export these.
//!
//! L1 Binary world builders (`bridge_l1`) require the `interface` feature.
//!
//! Product pure E2E (burn→SEAM→swap apply): [`compose_l0`] → `compose_seams`.
//!
//! SSOT: `docs/plans/spectrum/E2E-HARNESS-PLAN.md`

pub mod bridge_l0;
#[cfg(feature = "interface")]
pub mod bridge_l1;
pub mod bridge_mint_fixture;
/// Cash App → ZEC corridor workflow W0–W7 (Simulated backend default).
pub mod cashapp_zec_corridor;
/// G1 continuous deposit → BridgeMintClaim builder (provisional ν).
pub mod claim_from_deposit;
pub mod claim_fixture;
pub mod compose_l0;
/// Mint evidence + settle receipt artifacts (G3).
pub mod mint_evidence;
/// Option D continuous corridor: settle → egress burn → lab ZEC pay (HARNESS-D).
pub mod egress_d;
/// Headstash note envelope persist L0 (opaque ciphertext; hash-market path SSOT).
pub mod note_persist_l0;
/// Product call site: encrypt SEAM → PUT / local HeadstashStore-shaped store.
pub mod note_persist_client;
/// Pure → CW swap statement map + lab settle handoff (G3).
pub mod swap_statement_cw;
/// Local Zakura RPC + dest_owner_binding helper (D6).
pub mod zakura_local;
/// Option D lab Zcash inventory pay gated on Terp burn evidence.
pub mod lab_pay_zec;

pub use bridge_l0::{
    assert_double_mint_reject, assert_h1_spent_only_reject, assert_policy_bridge_mint_happy,
    compose_bridge_mint_to_seam_bytes, L0Error,
};
#[cfg(feature = "interface")]
pub use bridge_l1::BridgeL1World;
pub use bridge_mint_fixture::{
    assert_fixture_matches_hinge_happy, authorize_from_bridge_mint_fixture,
    build_happy_bridge_mint_fixture, default_golden_bridge_mint_path, load_bridge_mint_fixture,
    load_or_build_happy_bridge_mint_fixture, BridgeMintFixtureClaim, BridgeMintFixtureDoc,
    BridgeMintFixtureError,
};
pub use claim_from_deposit::{
    claim_from_deposit_watch, corridor_allow_happy_fixture, deposit_nullifier_v0,
    lab_snapshot_for_policy, lab_terp_asset_for_policy, parse_txid32, try_claim_from_env,
    BridgeMintClaimPure, ClaimFromDepositError, CorridorLabMintPolicy, DepositObservationView,
    DepositWatchView, TERP_BTC_DEPOSIT_NU_V0,
};
pub use claim_fixture::{
    build_policy_claim_fixture, load_claim_fixture, ClaimFixture, ClaimFixtureInstance,
    ClaimFixturePartialNote, CLAIM_INSTANCE_BYTES_LEN,
};
pub use compose_l0::{
    assert_product_path_burn_to_swap_oracle_zec, assert_product_path_burn_to_swap_sketch,
    mint_evidence_to_swap_action, seam_note_out_to_swap_action, seam_note_out_to_swap_openings,
    swap_action_public_to_statement, CorridorSwapSpendParams, MintSpendEvidence,
    SwapStatementPublicView,
};
pub use cashapp_zec_corridor::{
    run_cashapp_zec_corridor_w0_w7, CorridorAssetBackend, CorridorReceiptV0, CorridorScenario,
    CorridorWorkflowOutcome, DepositIntentV0, LcMode,
};
pub use mint_evidence::{
    mint_evidence_from_claim_fields, mint_evidence_path, settle_receipt_path, MintEvidenceError,
    MintEvidenceV0, SettleReceiptV0, PROOF_MODE_MOCK_VERIFY_LAB, PROOF_MODE_ZK_API,
};
pub use egress_d::{
    apply_pure_egress_burn_labeled, refuse_pay_without_evidence, run_option_d_after_settle,
    sealed_dest_for_option_d, settle_opening_from_handoff, zec_egress_d_enabled,
    BURN_SURFACE_CW_BRIDGE_EGRESS, BURN_SURFACE_PURE_RECORD_LAB, ENV_CORRIDOR_ZEC_EGRESS_D,
    EgressBurnEvidenceJson, EgressBurnPublicJson, EgressDError, EgressDStageInputs,
    EgressDStageOutcome, ZecEgressReceiptJson,
};
#[cfg(feature = "interface")]
pub use egress_d::{cw_egress_statement_from_opening, lab_mock_egress_proof};
pub use swap_statement_cw::{
    assert_mint_handoff_continuous, build_swap_spend_handoff_from_mint, lab_mock_swap_proof,
    seam_sketch_from_mint_evidence, swap_action_public_to_cw, ProofModeLabel, SwapHandoffError,
    SwapSpendHandoffV0, LAB_MOCK_SWAP_PROOF,
};
pub use note_persist_l0::{
    assert_bridge_note_persist_l0, assert_compose_seam_envelope_meta, bridge_note_addr_from_cm_public,
    NoteEnvelope, MiniNoteStore, SEAM_NOTE_OUT_LEN,
};
pub use note_persist_client::{NotePersistReceipt, NotesPersistConfig};
#[cfg(feature = "l0-seams")]
pub use note_persist_client::{
    get_and_decrypt_note, l2_smoke_put_get_decrypt, put_note_after_mint, recover_note,
};
#[cfg(all(feature = "l0-seams", feature = "note-http"))]
pub use note_persist_client::{list_note_addrs, recover_note_via_pir};
pub use zakura_local::{
    assert_dest_binding_equal, assert_golden_dest_binding, default_dest_display,
    default_golden_dest_binding_path, fetch_corridor_dest, is_placeholder_owner_binding_hex,
    load_golden_dest_binding, owner_binding_from_dest_display, owner_binding_hex,
    primary_golden_dest, reject_empty_dest, reject_empty_dest_seal, reject_placeholder_binding_hex,
    require_binding_hex_width, rpc_ready, seal_funded_dest, soft_validate_dest_prefix,
    DestSealError, GoldenDestBindingDoc, GoldenDestError, GoldenDestSample, SealedDestSource,
    SealedDestV0, ZakuraDest, ZakuraLocalConfig, DEFAULT_ZAKURA_RPC, DEST_BINDING_DOMAIN_PREFIX,
    REGTEST_MINER_DEST, REGTEST_MINER_OWNER_BINDING_HEX, ZAKURA_METRICS_PORT, ZAKURA_P2P_PORT,
    ZAKURA_RPC_PORT,
};
pub use lab_pay_zec::{
    confirm_open_at_sealed_dest, confirm_open_at_sealed_dest_with_cfg, dest_kind_from_display,
    egress_burn_evidence_path, is_real_zec_txid, lab_evidence_for_sealed, lab_pay_zec_after_burn,
    lab_pay_zec_after_burn_with_cfg, synthetic_lab_txid, try_getbalance_zat,
    try_getreceivedbyaddress_zat, validate_lab_pay_gates, wallet_rpc_available,
    write_zec_egress_receipt_json, zec_egress_receipt_path, LabPayError, OpenConfirmResult,
    LAB_SIMULATED_TXID_PREFIX, MODE_LAB_INVENTORY_PAY, MODE_LAB_INVENTORY_PAY_SIMULATED,
    MODE_LC_MINT, OPEN_CONFIRM_RPC_OK, OPEN_CONFIRM_SKIP_NO_RPC, OPEN_CONFIRM_SKIP_NO_WALLET,
    OPEN_CONFIRM_SKIP_VALIDATE_ONLY,
};
// Pure Option D types (SSOT private_dex_seams) used by lab pay surface.
pub use private_dex_seams::{
    DestKind, EgressBurnEvidenceV0, EgressBurnPublic, ZecEgressReceiptV0,
};
