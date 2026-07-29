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
/// OmniBridge-shaped LP bootstrap (GUIDE Phases 1–3): dual-home → mint LP → seed pool.
pub mod omni_lp_seed;
/// Multi-net dual-home prep (WAVE-2 MN-DUAL-HOME): bitcoind LP+user + Zakura escrow.
pub mod omni_dual_home;
/// Local Zakura RPC + dest_owner_binding helper (D6).
pub mod zakura_local;
/// Option D lab Zcash inventory pay gated on Terp burn evidence.
pub mod lab_pay_zec;
/// Multi-chain account curation + tokenfactory plans (BTC/ZEC/Terp).
pub mod account_curation;
/// Multi-cycle private-DEX + bridge seam routes under curated accounts.
pub mod seam_multi_cycle;
/// Negative-contrast (adversarial / fail-closed) catalog + tests.
pub mod seam_negative_contrast;

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
    intent_allows_mint, intent_allows_timeout_recovery, run_cashapp_zec_corridor_w0_w7,
    CorridorAssetBackend, CorridorReceiptV0, CorridorScenario, CorridorWorkflowOutcome,
    DepositIntentV0, LcMode,
};
#[cfg(feature = "l0-seams")]
pub use cashapp_zec_corridor::{
    put_and_recover_after_mint, seam_note_from_mint_openings, try_persist_mint_note,
};
pub use mint_evidence::{
    mint_evidence_from_claim_fields, mint_evidence_path, settle_receipt_path, MintEvidenceError,
    MintEvidenceV0, SettleReceiptV0, PROOF_MODE_MOCK_VERIFY_LAB, PROOF_MODE_ZK_API,
};
pub use egress_d::{
    apply_pure_egress_burn_labeled, assert_lab_degrade_labels, product_celebrate_forbidden,
    refuse_pay_without_evidence, run_option_d_after_settle, sealed_dest_for_option_d,
    settle_opening_from_handoff, zec_egress_d_enabled, BURN_SURFACE_CW_BRIDGE_EGRESS,
    BURN_SURFACE_PURE_RECORD_LAB, ENV_CORRIDOR_ZEC_EGRESS_D, EgressBurnEvidenceJson,
    EgressBurnPublicJson, EgressDError, EgressDStageInputs, EgressDStageOutcome,
    ZecEgressReceiptJson,
};
#[cfg(feature = "interface")]
pub use egress_d::{cw_egress_statement_from_opening, lab_mock_egress_proof};
pub use swap_statement_cw::{
    assert_mint_handoff_continuous, build_swap_spend_handoff_from_mint,
    build_swap_spend_handoff_from_mint_with_reserves, lab_mock_swap_proof,
    quote_delta_out_with_reserves, seam_sketch_from_mint_evidence, swap_action_public_to_cw,
    ProofModeLabel, SwapHandoffError, SwapSpendHandoffV0, LAB_MOCK_SWAP_PROOF,
};
pub use omni_lp_seed::{
    bootstrap_omni_liquidity, bootstrap_omni_liquidity_from_multinet, bootstrap_omni_liquidity_with,
    bridged_notes_source_label, corridor_pool_seed_policy, corridor_profile_is_omni,
    lp_mint_log_line, lp_seed_receipt_path, magic_lab_source_label,
    refuse_magic_pool_if_bridged_policy, require_bridged_lp_seed, resolve_pool_reserves,
    DualHomePrepJson, LpSeedInnerJson, LpSeedReceiptJson, OmniLiquidityBootstrap, OmniLpError,
    ENV_CORRIDOR_POOL_SEED, POOL_SEED_BRIDGED_LP, POOL_SEED_MAGIC_LAB,
};
pub use omni_dual_home::{
    dual_home_prep_path, dual_home_supports_multinet_lp, fixture_amounts, load_dual_home_prep,
    load_dual_home_prep_or_fixture, observe_escrow_balance, require_omni_product_green,
    resolve_dual_home_for_bootstrap, try_prefund_escrow_wallet, write_dual_home_run_pack,
    DualHomeMultiNetPrepV0, EscrowObserveV0, OmniDualHomeError, PrefundEscrowResult,
    ENV_CORRIDOR_DUAL_HOME_PREP_PATH, ENV_CORRIDOR_ESCROW_ADDR,
    ENV_CORRIDOR_OMNI_REQUIRE_PRODUCT_GREEN,
};
pub use note_persist_l0::{
    assert_bridge_note_persist_l0, assert_compose_seam_envelope_meta, bridge_note_addr_from_cm_public,
    NoteEnvelope, MiniNoteStore, SEAM_NOTE_OUT_LEN,
};
pub use note_persist_client::{NotePersistReceipt, NotesPersistConfig};
#[cfg(feature = "l0-seams")]
pub use note_persist_client::{
    get_and_decrypt_note, l2_smoke_put_get_decrypt, put_and_film_recover_after_mint,
    put_note_after_mint, recover_note, recover_note_film,
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
    allow_lab_inventory_residual, assert_product_release_mode,
    authorize_threshold_escrow_for_evidence, confirm_open_at_sealed_dest,
    confirm_open_at_sealed_dest_with_cfg, corridor_profile, dest_kind_from_display,
    egress_burn_evidence_path, hash_market_base_url, in_process_threshold_escrow_auth,
    is_product_profile, is_real_zec_txid, lab_committee_params, lab_evidence_for_sealed,
    lab_pay_zec_after_burn, lab_pay_zec_after_burn_with_cfg, lab_threshold_escrow_auth,
    live_hashmerchant_custody_ready, live_threshold_escrow_auth, peek_last_threshold_auth_meta,
    require_live_threshold, synthetic_lab_txid, take_last_threshold_auth_meta, try_getbalance_zat,
    try_getreceivedbyaddress_zat, validate_lab_pay_gates, wallet_rpc_available,
    write_zec_egress_receipt_json, zec_egress_receipt_path, zec_release_policy, LabPayError,
    OpenConfirmResult, ThresholdAuthMeta, ZecReleasePolicy, AUTH_SOURCE_HASHMERCHANT_LIVE,
    AUTH_SOURCE_IN_PROCESS_LAB, COMMITTEE_CRYPTO_LAB_T_OF_N, ENV_CORRIDOR_HASH_MARKET_URL,
    ENV_CORRIDOR_PROFILE, ENV_CORRIDOR_ALLOW_LAB_INVENTORY_RESIDUAL,
    ENV_CORRIDOR_REQUIRE_LIVE_THRESHOLD, ENV_CORRIDOR_ZEC_RELEASE, ENV_HASH_MARKET_URL,
    ESCROW_SIGN_PATH_P_LAB, LAB_SIMULATED_TXID_PREFIX, MODE_LAB_INVENTORY_PAY,
    MODE_LAB_INVENTORY_PAY_SIMULATED, MODE_LC_MINT, OPEN_CONFIRM_RPC_OK,
    OPEN_CONFIRM_SKIP_NO_RPC, OPEN_CONFIRM_SKIP_NO_WALLET, OPEN_CONFIRM_SKIP_VALIDATE_ONLY,
    THRESHOLD_SIMULATED_TXID_PREFIX,
};
pub use account_curation::{
    asset_id_from_denom, credit_tokenfactory_holding, curate_lab_accounts, lab_owner_binding,
    AccountRegistry, AccountRole, ChainKind, SeededAccount, TokenFactoryDenomPlan,
    LAB_BTC_LP_SATS, LAB_BTC_USER_SATS, LAB_TF_MINT, LAB_ZEC_ESCROW_ZATS,
};
pub use seam_multi_cycle::{
    assert_oracle_cannot_mint, route_corridor_btc_to_zec, route_multi_cycle_rebalance,
    route_tokenfactory_into_corridor, MultiCycleWorld, SeamAsset, CYCLE_GAMMA, CYCLE_GAMMA_DEN,
};
pub use seam_negative_contrast::{catalog_ids, ContrastCase, CONTRAST_CATALOG};

// Pure Option D types (SSOT private_dex_seams) used by lab pay surface.
pub use private_dex_seams::{
    reject_funder_only_as_product, DestKind, EgressBurnEvidenceV0, EgressBurnPublic,
    ThresholdEscrowAuth, ZecEgressReceiptV0, MODE_THRESHOLD_ESCROW_RELEASE,
    MODE_THRESHOLD_ESCROW_RELEASE_SIMULATED,
};
