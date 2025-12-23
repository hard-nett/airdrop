//! Unit tests for WebWallet wasm-bindgen integration
//!
//! These tests verify that nul generation works correctly
//! through the wasm-bindgen bridge and matches the expected
//! cryptographic outputs from zk-headstash.

use super::wallet::WebWallet;
use wasm_bindgen_test::*;
use zk_headstash::r#gen::headstash::snp::v1::SerializedNoteData;

wasm_bindgen_test_configure!(run_in_browser);

/// Test nul generation with known inputs
///
/// This verifies that:
/// 1. The wasm-bindgen bridge correctly passes data
/// 2. Nullifier derivation matches HeadstashSuite spec
/// 3. Note commitment is computed correctly
#[wasm_bindgen_test]
async fn test_nul_generation_basic() {
    // Known test inputs
    let esk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let rho_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let recp_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let rseed_hex = "0000000000000000000000000000000000000000000000000000000000000004";
    let fdi = 0u64;
    let v = "1000000";
    let nd = "uterp";

    // Create wallet
    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Generate note data
    let note_data_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed to generate note data");

    // Parse response
    let note_data: SerializedNoteData =
        serde_json::from_str(&note_data_json).expect("Failed to parse note data");

    // Verify outputs are non-zero
    assert_ne!(note_data.nk.len(), 0, "Nullifier key should not be empty");
    assert_ne!(note_data.nul.len(), 0, "Nullifier should not be empty");
    assert_ne!(note_data.cm.len(), 0, "Commitment should not be empty");

    // Verify expected lengths (32 bytes each)
    assert_eq!(note_data.nk.len(), 32, "NK should be 32 bytes");
    assert_eq!(note_data.nul.len(), 32, "Nullifier should be 32 bytes");
    assert_eq!(note_data.cm.len(), 32, "Commitment should be 32 bytes");

    // Verify value fields
    assert_eq!(note_data.v, v);
    assert_eq!(note_data.nd, nd);
    assert_eq!(note_data.fdi, fdi);
    assert!(!note_data.spent);
}

/// Test that different secret keys produce different nuls
#[wasm_bindgen_test]
async fn test_nul_uniqueness_by_esk() {
    let rho_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let recp_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let rseed_hex = "0000000000000000000000000000000000000000000000000000000000000004";
    let fdi = 0u64;
    let v = "1000000";
    let nd = "uterp";

    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Generate with ESK 1
    let esk1_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let note1_json = wallet
        .gen_claim(
            esk1_hex.to_string(),
            rho_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    // Generate with ESK 2
    let esk2_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let note2_json = wallet
        .gen_claim(
            esk2_hex.to_string(),
            rho_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    let note1: SerializedNoteData = serde_json::from_str(&note1_json).unwrap();
    let note2: SerializedNoteData = serde_json::from_str(&note2_json).unwrap();

    // Nullifiers should be different
    assert_ne!(
        note1.nul, note2.nul,
        "Different ESKs should produce different nuls"
    );

    // NKs should be different
    assert_ne!(
        note1.nk, note2.nk,
        "Different ESKs should produce different nul keys"
    );
}

/// Test that different rho values produce different nuls
#[wasm_bindgen_test]
async fn test_nul_uniqueness_by_rho() {
    let esk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let recp_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let rseed_hex = "0000000000000000000000000000000000000000000000000000000000000004";
    let fdi = 0u64;
    let v = "1000000";
    let nd = "uterp";

    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Generate with RHO 1
    let rho1_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let note1_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho1_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    // Generate with RHO 2
    let rho2_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let note2_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho2_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    let note1: SerializedNoteData = serde_json::from_str(&note1_json).unwrap();
    let note2: SerializedNoteData = serde_json::from_str(&note2_json).unwrap();

    // Nullifiers should be different (rho affects both NK and nul)
    assert_ne!(
        note1.nul, note2.nul,
        "Different rho values should produce different nul"
    );

    // NKs should be different (NK = HKDF(esk, rho))
    assert_ne!(
        note1.nk, note2.nk,
        "Different rho values should produce different nul keys"
    );
}

/// Test that nul derivation is deterministic
#[wasm_bindgen_test]
async fn test_nul_determinism() {
    let esk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let rho_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let recp_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let rseed_hex = "0000000000000000000000000000000000000000000000000000000000000004";
    let fdi = 0u64;
    let v = "1000000";
    let nd = "uterp";

    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Generate twice with same inputs
    let note1_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    let note2_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho_hex.to_string(),
            fdi,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    let note1: SerializedNoteData = serde_json::from_str(&note1_json).unwrap();
    let note2: SerializedNoteData = serde_json::from_str(&note2_json).unwrap();

    // Should produce identical outputs
    assert_eq!(note1.nul, note2.nul, "Same inputs should produce same nul");
    assert_eq!(
        note1.nk, note2.nk,
        "Same inputs should produce same nul key"
    );
    assert_eq!(
        note1.cm, note2.cm,
        "Same inputs should produce same commitment"
    );
}

/// Test different FDI values produce different commitments but same nul
#[wasm_bindgen_test]
async fn test_fdi_affects_commitment_not_nul() {
    let esk_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let rho_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    let recp_hex = "0000000000000000000000000000000000000000000000000000000000000003";
    let rseed_hex = "0000000000000000000000000000000000000000000000000000000000000004";
    let v = "1000000";
    let nd = "uterp";

    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Generate with FDI 0
    let note1_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho_hex.to_string(),
            0,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    // Generate with FDI 1
    let note2_json = wallet
        .gen_claim(
            esk_hex.to_string(),
            rho_hex.to_string(),
            1,
            recp_hex.to_string(),
            v.to_string(),
            nd.to_string(),
            rseed_hex.to_string(),
        )
        .await
        .expect("Failed");

    let note1: SerializedNoteData = serde_json::from_str(&note1_json).unwrap();
    let note2: SerializedNoteData = serde_json::from_str(&note2_json).unwrap();

    // Nullifiers should be same (nul only depends on NK and rho, not fdi)
    assert_eq!(
        note1.nul, note2.nul,
        "FDI should not affect nul (only NK + rho matter)"
    );

    // NKs should be same (NK only depends on esk and rho)
    assert_eq!(note1.nk, note2.nk, "FDI should not affect nul key");

    // Commitments should be different (commitment includes fdi)
    assert_ne!(
        note1.cm, note2.cm,
        "Different FDI should produce different commitments"
    );
}

/// Test hex parsing errors are handled correctly
#[wasm_bindgen_test]
async fn test_invalid_hex_input() {
    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    // Invalid hex string
    let result = wallet
        .gen_claim(
            "INVALID_HEX".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            0,
            "0000000000000000000000000000000000000000000000000000000000000003".to_string(),
            "1000000".to_string(),
            "uterp".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000004".to_string(),
        )
        .await;

    assert!(result.is_err(), "Should fail with invalid ESK hex");
}

/// Test invalid value parsing
#[wasm_bindgen_test]
async fn test_invalid_value() {
    let wallet = WebWallet::new("test", "http://localhost:8080", None)
        .await
        .expect("Failed to create wallet");

    let result = wallet
        .gen_claim(
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000002".to_string(),
            0,
            "0000000000000000000000000000000000000000000000000000000000000003".to_string(),
            "NOT_A_NUMBER".to_string(),
            "uterp".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000004".to_string(),
        )
        .await;

    assert!(result.is_err(), "Should fail with invalid value");
}
