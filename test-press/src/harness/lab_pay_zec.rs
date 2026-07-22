//! Option D lab Zcash leg: inventory pay **only after** Terp burn evidence.
//!
//! **Not Option B:** `lab_pay_zec_after_burn` refuses missing evidence, dest seal
//! mismatch, or zero value. Offline mock records a synthetic txid labeled
//! `lab_inventory_pay_simulated`. Live RPC probes wallet methods (`getbalance`,
//! `sendtoaddress` / `z_sendmany`); real send → `mode=lab_inventory_pay` + real
//! `zec_txid`. When wallet RPCs are missing (Zakura core without zcashd-compat),
//! degrades labeled simulated — never product host-pay without burn.
//!
//! Open/confirm: [`confirm_open_at_sealed_dest`] runs `validateaddress` + optional
//! balance/received checks; skip-clean when RPC/wallet unavailable.
//!
//! Types SSOT: `private_dex_seams::egress` (PURE-EGRESS).
//! Host attach: Zakura RPC + G4 [`SealedDestV0`].
//!
//! Design: `docs/plans/spectrum/agents/zec-egress-option-d-2026-07-22/DESIGN-ZEC-EGRESS-D.md`
//! Env: `CORRIDOR_LAB_ZEC_FORCE_SIMULATED=1` forces simulated even when wallet RPC up.

use crate::harness::zakura_local::{
    assert_dest_binding_equal, is_placeholder_owner_binding_hex, json_rpc_call,
    reject_placeholder_binding_hex, rpc_ready, soft_validate_dest_prefix, validate_address,
    SealedDestV0, ZakuraLocalConfig, ZakuraLocalError,
};
use private_dex_seams::{
    hex32, lab_receipt_after_burn, DestKind, EgressBurnEvidenceV0, EgressBurnPublic,
    ZecEgressReceiptV0,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Lab mode when RPC down or send RPCs unavailable — synthetic inventory film.
pub const MODE_LAB_INVENTORY_PAY_SIMULATED: &str = "lab_inventory_pay_simulated";
/// Lab mode when a real Zcash send RPC returned a txid.
pub const MODE_LAB_INVENTORY_PAY: &str = "lab_inventory_pay";
/// Reserved prod residual (not implemented this wave).
pub const MODE_LC_MINT: &str = "lc_mint";

/// Synthetic txid prefix (must appear in mock receipt `zec_txid`).
pub const LAB_SIMULATED_TXID_PREFIX: &str = "lab_inventory_pay_simulated";

/// Open/confirm skip labels (honest residual — not "ZEC received" claims).
pub const OPEN_CONFIRM_RPC_OK: &str = "rpc_open_confirm";
pub const OPEN_CONFIRM_SKIP_NO_RPC: &str = "skip_clean_no_rpc";
pub const OPEN_CONFIRM_SKIP_NO_WALLET: &str = "skip_clean_no_wallet_balance";
pub const OPEN_CONFIRM_SKIP_VALIDATE_ONLY: &str = "rpc_validate_only";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabPayError {
    /// Product / lab fail-closed: no burn evidence payload.
    EvidenceMissing(String),
    DestMismatch {
        evidence: String,
        sealed: String,
    },
    ValueZero,
    SoftValidateFailed(String),
    PlaceholderDest(String),
    Pure(String),
    Rpc(String),
    Io(String),
    Json(String),
}

impl std::fmt::Display for LabPayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EvidenceMissing(s) => write!(f, "egress burn evidence missing: {s}"),
            Self::DestMismatch { evidence, sealed } => {
                write!(
                    f,
                    "egress dest mismatch: evidence={evidence} sealed={sealed}"
                )
            }
            Self::ValueZero => write!(f, "egress value is 0 — refuse Zcash pay"),
            Self::SoftValidateFailed(s) => write!(f, "dest soft validate failed: {s}"),
            Self::PlaceholderDest(s) => write!(f, "placeholder dest rejected: {s}"),
            Self::Pure(s) => write!(f, "pure egress: {s}"),
            Self::Rpc(s) => write!(f, "zakura rpc: {s}"),
            Self::Io(s) => write!(f, "io: {s}"),
            Self::Json(s) => write!(f, "json: {s}"),
        }
    }
}

impl std::error::Error for LabPayError {}

impl From<ZakuraLocalError> for LabPayError {
    fn from(e: ZakuraLocalError) -> Self {
        Self::Rpc(e.to_string())
    }
}

/// Infer dest kind from display prefix (UI soft-validate parity).
pub fn dest_kind_from_display(dest_display: &str) -> DestKind {
    let s = dest_display.trim();
    if s.starts_with("u1")
        || s.starts_with("utest1")
        || s.starts_with("uregtest1")
        || s.starts_with("zs1")
        || s.starts_with("ztestsapling1")
        || s.starts_with("u1sim_")
    {
        DestKind::Shielded
    } else {
        DestKind::Transparent
    }
}

/// Default path for ZEC egress receipt artifact.
pub fn zec_egress_receipt_path() -> PathBuf {
    std::env::var("CORRIDOR_ZEC_EGRESS_RECEIPT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/corridor-zec-egress-receipt.json"))
}

/// Default path for burn evidence artifact.
pub fn egress_burn_evidence_path() -> PathBuf {
    std::env::var("CORRIDOR_EGRESS_BURN_EVIDENCE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/corridor-egress-burn-evidence.json"))
}

/// Synthetic labeled txid for offline / send-unavailable lab path.
pub fn synthetic_lab_txid(nullifier: &[u8; 32], amount_zat: u64) -> String {
    let mut h = Sha256::new();
    h.update(LAB_SIMULATED_TXID_PREFIX.as_bytes());
    h.update(b"|");
    h.update(nullifier);
    h.update(amount_zat.to_le_bytes());
    let dig = h.finalize();
    format!("{LAB_SIMULATED_TXID_PREFIX}:{}", hex::encode(&dig[..16]))
}

/// Gate: evidence present + dest seal equality + value > 0.
pub fn validate_lab_pay_gates(
    evidence: &EgressBurnEvidenceV0,
    sealed: &SealedDestV0,
) -> Result<(), LabPayError> {
    if evidence.proof_mode.trim().is_empty() {
        return Err(LabPayError::EvidenceMissing("proof_mode empty".into()));
    }
    if evidence.burn.value == 0 {
        return Err(LabPayError::ValueZero);
    }
    if evidence.burn.nullifier == [0u8; 32] {
        return Err(LabPayError::EvidenceMissing(
            "nullifier all-zero (egress ν missing)".into(),
        ));
    }
    if evidence.burn.cm_spent == [0u8; 32] {
        return Err(LabPayError::EvidenceMissing("cm_spent all-zero".into()));
    }
    if evidence.burn.dest_commitment == [0u8; 32] {
        return Err(LabPayError::EvidenceMissing(
            "dest_commitment all-zero".into(),
        ));
    }

    let sealed_hex = sealed.owner_binding_hex.trim().to_lowercase();
    let evidence_hex = hex32(&evidence.burn.dest_commitment);
    if sealed_hex.is_empty() {
        return Err(LabPayError::EvidenceMissing(
            "sealed dest owner_binding empty".into(),
        ));
    }
    if evidence.burn.dest_commitment != sealed.owner_binding {
        return Err(LabPayError::DestMismatch {
            evidence: evidence_hex,
            sealed: sealed_hex,
        });
    }
    assert_dest_binding_equal(&evidence_hex, &sealed_hex, "lab_pay_dest").map_err(|e| {
        LabPayError::DestMismatch {
            evidence: evidence_hex.clone(),
            sealed: format!("{sealed_hex} ({e})"),
        }
    })?;
    if sealed.dest_display.trim().is_empty() {
        return Err(LabPayError::SoftValidateFailed("empty dest_display".into()));
    }
    if !soft_validate_dest_prefix(&sealed.dest_display) {
        return Err(LabPayError::SoftValidateFailed(sealed.dest_display.clone()));
    }
    if is_placeholder_owner_binding_hex(&sealed_hex) {
        return Err(LabPayError::PlaceholderDest(sealed_hex));
    }
    reject_placeholder_binding_hex(&sealed_hex)
        .map_err(|e| LabPayError::PlaceholderDest(e.to_string()))?;
    Ok(())
}

fn env_truthy_lab(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// True if RPC error text indicates method not implemented / not found.
pub fn rpc_err_method_missing(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("method not found")
        || e.contains("unknown method")
        || e.contains("method not available")
        || e.contains("not implemented")
        || e.contains("\"code\":-32601")
        || e.contains("code\": -32601")
        || e.contains("code\":-32601")
        || e.contains("-32601")
}

/// Probe zcashd-compat wallet surface: `getbalance` succeeds or fails for a
/// non-missing-method reason (auth, unlocked wallet, etc.).
///
/// Zakura core without wallet residual → false → lab pay stays simulated.
pub fn wallet_rpc_available(cfg: &ZakuraLocalConfig) -> bool {
    if !rpc_ready(cfg) {
        return false;
    }
    match json_rpc_call(cfg, "getbalance", json!([])) {
        Ok(_) => true,
        Err(e) => {
            let s = e.to_string();
            let low = s.to_lowercase();
            if low.contains("rpc down") || low.contains("io:") || low.contains("timed out") {
                return false;
            }
            // Method exists but e.g. wallet locked / empty — still "available".
            !rpc_err_method_missing(&s)
        }
    }
}

/// Optional inventory balance in zatoshis when `getbalance` works.
pub fn try_getbalance_zat(cfg: &ZakuraLocalConfig) -> Result<Option<u64>, ZakuraLocalError> {
    let r = json_rpc_call(cfg, "getbalance", json!([]))?;
    Ok(zec_amount_to_zat(&r))
}

/// Optional transparent received total via `getreceivedbyaddress` (zcashd-compat).
pub fn try_getreceivedbyaddress_zat(
    cfg: &ZakuraLocalConfig,
    addr: &str,
) -> Result<Option<u64>, ZakuraLocalError> {
    // minconf=0 so lab unconfirmed inventory still surfaces.
    let r = json_rpc_call(cfg, "getreceivedbyaddress", json!([addr, 0]))?;
    Ok(zec_amount_to_zat(&r))
}

fn zec_amount_to_zat(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if f < 0.0 {
                    return None;
                }
                Some((f * 100_000_000.0).round() as u64)
            } else if let Some(i) = n.as_u64() {
                // Some nodes return sat/zat integer — treat large ints as zat.
                Some(i)
            } else if let Some(i) = n.as_i64() {
                if i < 0 {
                    None
                } else {
                    Some(i as u64)
                }
            } else {
                None
            }
        }
        Value::String(s) => s.parse::<f64>().ok().map(|f| (f * 100_000_000.0).round() as u64),
        _ => None,
    }
}

/// Attempt transparent `sendtoaddress` (amount in ZEC from zatoshis).
fn try_sendtoaddress(
    cfg: &ZakuraLocalConfig,
    dest: &str,
    amount_zat: u64,
) -> Result<String, ZakuraLocalError> {
    let zec = amount_zat as f64 / 100_000_000.0;
    let r = json_rpc_call(cfg, "sendtoaddress", json!([dest, zec]))?;
    match r {
        Value::String(txid) if !txid.is_empty() => Ok(txid),
        other => Err(ZakuraLocalError::Rpc(format!(
            "sendtoaddress unexpected result: {other}"
        ))),
    }
}

/// Attempt shielded `z_sendmany` (zcashd-compat residual; may be unavailable).
fn try_z_sendmany(
    cfg: &ZakuraLocalConfig,
    dest: &str,
    amount_zat: u64,
) -> Result<String, ZakuraLocalError> {
    let zec = amount_zat as f64 / 100_000_000.0;
    let params = json!(["", [{ "address": dest, "amount": zec }]]);
    let r = json_rpc_call(cfg, "z_sendmany", params)?;
    match r {
        Value::String(opid_or_txid) if !opid_or_txid.is_empty() => Ok(opid_or_txid),
        other => Err(ZakuraLocalError::Rpc(format!(
            "z_sendmany unexpected result: {other}"
        ))),
    }
}

/// True if a string looks like a real chain txid (64 hex), not lab synthetic.
pub fn is_real_zec_txid(txid: &str) -> bool {
    let t = txid.trim();
    if t.is_empty() || t.starts_with(LAB_SIMULATED_TXID_PREFIX) {
        return false;
    }
    // zcashd/zebra style: 64 hex chars; opids from z_sendmany may be opid-…
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    t.starts_with("opid-") || t.starts_with("opid:")
}

fn build_receipt(
    evidence: &EgressBurnEvidenceV0,
    sealed: &SealedDestV0,
    zec_txid: Option<String>,
    mode: &str,
) -> Result<ZecEgressReceiptV0, LabPayError> {
    lab_receipt_after_burn(evidence, sealed.dest_display.clone(), zec_txid, mode).map_err(|e| {
        LabPayError::Pure(format!("{e:?}"))
    })
}

/// Lab Zcash pay gated on Terp burn evidence + G4 sealed dest.
///
/// - Refuses missing evidence / dest mismatch / value 0
/// - RPC down → synthetic txid `lab_inventory_pay_simulated:…`, mode same label
/// - RPC up + wallet methods → try t-addr `sendtoaddress`, else UA `z_sendmany`;
///   success → `mode=lab_inventory_pay` + real txid
/// - Wallet missing / send fail → labeled simulated (never silent product pay)
pub fn lab_pay_zec_after_burn(
    evidence: &EgressBurnEvidenceV0,
    sealed: &SealedDestV0,
) -> Result<ZecEgressReceiptV0, LabPayError> {
    lab_pay_zec_after_burn_with_cfg(evidence, sealed, &ZakuraLocalConfig::default())
}

/// Same as [`lab_pay_zec_after_burn`] with explicit RPC config (tests use closed port).
pub fn lab_pay_zec_after_burn_with_cfg(
    evidence: &EgressBurnEvidenceV0,
    sealed: &SealedDestV0,
    cfg: &ZakuraLocalConfig,
) -> Result<ZecEgressReceiptV0, LabPayError> {
    validate_lab_pay_gates(evidence, sealed)?;

    let amount_zat = evidence.burn.value;
    let force_sim = env_truthy_lab("CORRIDOR_LAB_ZEC_FORCE_SIMULATED");

    if force_sim || !rpc_ready(cfg) {
        let txid = synthetic_lab_txid(&evidence.burn.nullifier, amount_zat);
        return build_receipt(
            evidence,
            sealed,
            Some(txid),
            MODE_LAB_INVENTORY_PAY_SIMULATED,
        );
    }

    // Soft-validate dest on chain when possible (does not replace burn gate).
    let _ = validate_address(cfg, &sealed.dest_display);

    // Prefer probing wallet; if getbalance missing, still attempt send once
    // (some residual stacks expose send without getbalance).
    let wallet = wallet_rpc_available(cfg);
    if !wallet {
        // One-shot send attempt still allowed — success upgrades to live mode.
        let send_result = attempt_lab_send(cfg, evidence, sealed, amount_zat);
        return match send_result {
            Ok(txid) if is_real_zec_txid(&txid) || !txid.starts_with(LAB_SIMULATED_TXID_PREFIX) => {
                build_receipt(evidence, sealed, Some(txid), MODE_LAB_INVENTORY_PAY)
            }
            Ok(_) | Err(_) => {
                let txid = synthetic_lab_txid(&evidence.burn.nullifier, amount_zat);
                build_receipt(
                    evidence,
                    sealed,
                    Some(txid),
                    MODE_LAB_INVENTORY_PAY_SIMULATED,
                )
            }
        };
    }

    // Wallet present: optional fundedness soft-check (do not refuse — residual
    // may fund via miner; send failure still degrades simulated).
    let _ = try_getbalance_zat(cfg);

    let send_result = attempt_lab_send(cfg, evidence, sealed, amount_zat);
    match send_result {
        Ok(txid) => {
            // Refuse to label simulated-looking strings as live.
            if txid.starts_with(LAB_SIMULATED_TXID_PREFIX) {
                build_receipt(
                    evidence,
                    sealed,
                    Some(txid),
                    MODE_LAB_INVENTORY_PAY_SIMULATED,
                )
            } else {
                build_receipt(evidence, sealed, Some(txid), MODE_LAB_INVENTORY_PAY)
            }
        }
        Err(_e) => {
            let txid = synthetic_lab_txid(&evidence.burn.nullifier, amount_zat);
            build_receipt(
                evidence,
                sealed,
                Some(txid),
                MODE_LAB_INVENTORY_PAY_SIMULATED,
            )
        }
    }
}

fn attempt_lab_send(
    cfg: &ZakuraLocalConfig,
    evidence: &EgressBurnEvidenceV0,
    sealed: &SealedDestV0,
    amount_zat: u64,
) -> Result<String, ZakuraLocalError> {
    match evidence.burn.dest_kind {
        DestKind::Transparent => try_sendtoaddress(cfg, &sealed.dest_display, amount_zat),
        DestKind::Shielded => try_z_sendmany(cfg, &sealed.dest_display, amount_zat)
            .or_else(|_| try_sendtoaddress(cfg, &sealed.dest_display, amount_zat)),
    }
}

// ── Open / confirm at sealed dest (P1) ─────────────────────────────────────

/// Result of post-pay (or pre-pay) open/confirm checks against sealed dest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenConfirmResult {
    pub dest_display: String,
    pub dest_owner_binding_hex: String,
    pub rpc_ready: bool,
    /// `validateaddress` isvalid when RPC answered.
    pub address_valid: Option<bool>,
    /// Wallet total balance in zat when `getbalance` available.
    pub wallet_balance_zat: Option<u64>,
    /// `getreceivedbyaddress` for transparent dest when available.
    pub received_zat: Option<u64>,
    /// Honest label: rpc_open_confirm | skip_clean_* | rpc_validate_only
    pub mode: String,
    pub note: String,
}

impl OpenConfirmResult {
    /// True when we got at least address validation on live RPC.
    pub fn confirmed_address(&self) -> bool {
        self.address_valid == Some(true)
    }

    /// True only when balance/received RPCs returned (not a funds claim alone).
    pub fn has_balance_probe(&self) -> bool {
        self.wallet_balance_zat.is_some() || self.received_zat.is_some()
    }
}

/// Open/confirm helper at sealed dest: `validateaddress` + optional balance.
///
/// **Skip-clean** when RPC down or wallet balance RPCs missing — never fails
/// the corridor for residual Zakura core. Soft-fails only when
/// `CORRIDOR_REQUIRE_ZAKURA_RPC=1` and RPC down (caller may ignore `Result` Err).
pub fn confirm_open_at_sealed_dest(
    sealed: &SealedDestV0,
) -> Result<OpenConfirmResult, LabPayError> {
    confirm_open_at_sealed_dest_with_cfg(sealed, &ZakuraLocalConfig::default())
}

/// Same as [`confirm_open_at_sealed_dest`] with explicit config.
pub fn confirm_open_at_sealed_dest_with_cfg(
    sealed: &SealedDestV0,
    cfg: &ZakuraLocalConfig,
) -> Result<OpenConfirmResult, LabPayError> {
    if sealed.dest_display.trim().is_empty() {
        return Err(LabPayError::SoftValidateFailed("empty dest_display".into()));
    }
    if !soft_validate_dest_prefix(&sealed.dest_display) {
        return Err(LabPayError::SoftValidateFailed(sealed.dest_display.clone()));
    }
    let require_rpc = env_truthy_lab("CORRIDOR_REQUIRE_ZAKURA_RPC");
    let ready = rpc_ready(cfg);
    if !ready {
        if require_rpc {
            return Err(LabPayError::Rpc(format!(
                "rpc required but down at {}",
                cfg.rpc_url
            )));
        }
        return Ok(OpenConfirmResult {
            dest_display: sealed.dest_display.clone(),
            dest_owner_binding_hex: sealed.owner_binding_hex.clone(),
            rpc_ready: false,
            address_valid: None,
            wallet_balance_zat: None,
            received_zat: None,
            mode: OPEN_CONFIRM_SKIP_NO_RPC.into(),
            note: format!("Zakura RPC down at {} — open/confirm skip-clean", cfg.rpc_url),
        });
    }

    let address_valid = match validate_address(cfg, &sealed.dest_display) {
        Ok(v) => Some(v),
        Err(e) => {
            // validate may be absent on broken stacks — skip-clean
            if require_rpc {
                return Err(LabPayError::Rpc(e.to_string()));
            }
            None
        }
    };

    let wallet_balance_zat = try_getbalance_zat(cfg).ok().flatten();
    let received_zat = if matches!(
        dest_kind_from_display(&sealed.dest_display),
        DestKind::Transparent
    ) {
        try_getreceivedbyaddress_zat(cfg, &sealed.dest_display)
            .ok()
            .flatten()
    } else {
        None
    };

    let (mode, note) = if wallet_balance_zat.is_some() || received_zat.is_some() {
        (
            OPEN_CONFIRM_RPC_OK.to_string(),
            format!(
                "validateaddress={:?} balance_zat={:?} received_zat={:?}",
                address_valid, wallet_balance_zat, received_zat
            ),
        )
    } else if address_valid.is_some() {
        (
            OPEN_CONFIRM_SKIP_VALIDATE_ONLY.to_string(),
            format!(
                "validateaddress={:?}; no getbalance/getreceivedbyaddress (Zakura core residual)",
                address_valid
            ),
        )
    } else {
        (
            OPEN_CONFIRM_SKIP_NO_WALLET.to_string(),
            "RPC up but open/confirm probes unavailable — skip-clean".into(),
        )
    };

    Ok(OpenConfirmResult {
        dest_display: sealed.dest_display.clone(),
        dest_owner_binding_hex: sealed.owner_binding_hex.clone(),
        rpc_ready: true,
        address_valid,
        wallet_balance_zat,
        received_zat,
        mode,
        note,
    })
}

/// Build minimal lab evidence matching a sealed dest (harness / unit helper).
///
/// Uses pure `egress_nullifier` domain via `private_dex_seams::egress_nullifier`.
pub fn lab_evidence_for_sealed(
    sealed: &SealedDestV0,
    value: u64,
    proof_mode: impl Into<String>,
) -> EgressBurnEvidenceV0 {
    let mut cm = [0u8; 32];
    cm[0] = 0xce;
    cm[31] = 0x01;
    let mut rcm = [0u8; 32];
    rcm[0] = 0xac;
    rcm[1] = 0x01;
    let nf = private_dex_seams::egress_nullifier(&cm, &rcm);

    let mut asset = [0u8; 32];
    asset[0] = b'Z';
    asset[1] = b'E';
    asset[2] = b'C';

    EgressBurnEvidenceV0 {
        terp_tx_hash: Some("lab_terp_burn_tx".into()),
        burn: EgressBurnPublic {
            asset_id: asset,
            value,
            cm_spent: cm,
            nullifier: nf,
            dest_commitment: sealed.owner_binding,
            dest_kind: dest_kind_from_display(&sealed.dest_display),
            root: [0x11; 32],
            source_pool_id: Some(1),
        },
        proof_mode: proof_mode.into(),
        settle_receipt_ref: Some("lab_settle_ref".into()),
    }
}

/// Write receipt as JSON artifact (pure types lack serde — host mirror).
pub fn write_zec_egress_receipt_json(
    receipt: &ZecEgressReceiptV0,
    path: &Path,
) -> Result<(), LabPayError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| LabPayError::Io(e.to_string()))?;
    }
    let v = json!({
        "dest_display": receipt.dest_display,
        "dest_owner_binding_hex": receipt.dest_owner_binding_hex,
        "dest_kind": match receipt.dest_kind {
            DestKind::Transparent => "transparent",
            DestKind::Shielded => "shielded",
        },
        "zec_txid": receipt.zec_txid,
        "amount_zat": receipt.amount_zat,
        "mode": receipt.mode,
        "burn_nullifier_hex": receipt.burn_nullifier_hex,
    });
    let s = serde_json::to_string_pretty(&v).map_err(|e| LabPayError::Json(e.to_string()))?;
    fs::write(path, s).map_err(|e| LabPayError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::zakura_local::{
        seal_funded_dest, REGTEST_MINER_DEST, REGTEST_MINER_OWNER_BINDING_HEX, SealedDestSource,
    };
    use std::env;
    use std::time::Duration;

    fn offline_cfg() -> ZakuraLocalConfig {
        ZakuraLocalConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            timeout: Duration::from_millis(150),
        }
    }

    fn golden_sealed() -> SealedDestV0 {
        SealedDestV0 {
            dest_display: REGTEST_MINER_DEST.into(),
            owner_binding: {
                let mut b = [0u8; 32];
                let raw = hex::decode(REGTEST_MINER_OWNER_BINDING_HEX).unwrap();
                b.copy_from_slice(&raw);
                b
            },
            owner_binding_hex: REGTEST_MINER_OWNER_BINDING_HEX.into(),
            source: SealedDestSource::GoldenPrimary,
            rpc_ready: false,
            rpc_validated: false,
        }
    }

    #[test]
    fn refuse_value_zero() {
        let sealed = golden_sealed();
        let mut ev = lab_evidence_for_sealed(&sealed, 1, "mock_verify_lab");
        ev.burn.value = 0;
        let err = lab_pay_zec_after_burn_with_cfg(&ev, &sealed, &offline_cfg()).unwrap_err();
        assert!(matches!(err, LabPayError::ValueZero), "{err}");
    }

    #[test]
    fn refuse_dest_mismatch() {
        let sealed = golden_sealed();
        let mut ev = lab_evidence_for_sealed(&sealed, 50_000, "mock_verify_lab");
        ev.burn.dest_commitment = [0x42; 32];
        let err = lab_pay_zec_after_burn_with_cfg(&ev, &sealed, &offline_cfg()).unwrap_err();
        assert!(matches!(err, LabPayError::DestMismatch { .. }), "{err}");
    }

    #[test]
    fn refuse_missing_proof_mode_and_zero_nullifier() {
        let sealed = golden_sealed();
        let mut ev = lab_evidence_for_sealed(&sealed, 10, "mock_verify_lab");
        ev.proof_mode = String::new();
        let err = lab_pay_zec_after_burn_with_cfg(&ev, &sealed, &offline_cfg()).unwrap_err();
        assert!(matches!(err, LabPayError::EvidenceMissing(_)), "{err}");

        let mut ev2 = lab_evidence_for_sealed(&sealed, 10, "mock_verify_lab");
        ev2.burn.nullifier = [0u8; 32];
        let err2 = lab_pay_zec_after_burn_with_cfg(&ev2, &sealed, &offline_cfg()).unwrap_err();
        assert!(matches!(err2, LabPayError::EvidenceMissing(_)), "{err2}");
    }

    #[test]
    fn accept_mock_path_matching_seal() {
        if env::var("ZAKURA_DEST_ADDR").is_ok() || env::var("CORRIDOR_DEST_OWNER_BINDING").is_ok() {
            eprintln!("skip accept_mock: dest env override present");
            return;
        }
        let sealed = seal_funded_dest(&offline_cfg()).expect("golden seal");
        assert_eq!(sealed.owner_binding_hex, REGTEST_MINER_OWNER_BINDING_HEX);
        let ev = lab_evidence_for_sealed(&sealed, 100_000, "mock_verify_lab");
        assert_eq!(ev.burn.dest_commitment, sealed.owner_binding);

        let receipt =
            lab_pay_zec_after_burn_with_cfg(&ev, &sealed, &offline_cfg()).expect("mock pay");
        assert_eq!(receipt.dest_display, REGTEST_MINER_DEST);
        assert_eq!(receipt.dest_owner_binding_hex, REGTEST_MINER_OWNER_BINDING_HEX);
        assert_eq!(receipt.amount_zat, 100_000);
        assert_eq!(receipt.mode, MODE_LAB_INVENTORY_PAY_SIMULATED);
        let txid = receipt.zec_txid.expect("synthetic txid");
        assert!(
            txid.starts_with(LAB_SIMULATED_TXID_PREFIX),
            "txid must be labeled simulated: {txid}"
        );
        assert_eq!(receipt.burn_nullifier_hex, hex32(&ev.burn.nullifier));
        assert_eq!(receipt.dest_kind, DestKind::Transparent);
        eprintln!(
            "lab_pay mock OK mode={} txid={} amount_zat={}",
            receipt.mode, txid, receipt.amount_zat
        );
    }

    #[test]
    fn refuse_without_evidence_helper_gates() {
        let sealed = golden_sealed();
        assert!(validate_lab_pay_gates(
            &EgressBurnEvidenceV0 {
                terp_tx_hash: None,
                burn: EgressBurnPublic {
                    asset_id: [0u8; 32],
                    value: 0,
                    cm_spent: [0u8; 32],
                    nullifier: [0u8; 32],
                    dest_commitment: sealed.owner_binding,
                    dest_kind: DestKind::Transparent,
                    root: [0u8; 32],
                    source_pool_id: None,
                },
                proof_mode: String::new(),
                settle_receipt_ref: None,
            },
            &sealed
        )
        .is_err());
    }

    /// Live: when RPC up, attempt send; degrade to simulated if wallet RPC missing.
    #[test]
    fn lab_pay_live_rpc_skip_clean_when_available() {
        let cfg = ZakuraLocalConfig::default();
        if !rpc_ready(&cfg) {
            eprintln!(
                "skip live lab_pay: RPC not at {} (run zakura-local.sh up)",
                cfg.rpc_url
            );
            return;
        }
        let sealed = golden_sealed();
        let ev = lab_evidence_for_sealed(&sealed, 1, "mock_verify_lab");
        let receipt = lab_pay_zec_after_burn_with_cfg(&ev, &sealed, &cfg).expect("live or degrade");
        assert_eq!(receipt.dest_owner_binding_hex, REGTEST_MINER_OWNER_BINDING_HEX);
        assert!(receipt.zec_txid.is_some());
        assert!(
            receipt.mode == MODE_LAB_INVENTORY_PAY
                || receipt.mode == MODE_LAB_INVENTORY_PAY_SIMULATED
        );
        if receipt.mode == MODE_LAB_INVENTORY_PAY {
            let txid = receipt.zec_txid.as_deref().unwrap_or("");
            assert!(
                is_real_zec_txid(txid),
                "live mode must not use simulated prefix: {txid}"
            );
            assert!(!txid.starts_with(LAB_SIMULATED_TXID_PREFIX));
        } else {
            let txid = receipt.zec_txid.as_deref().unwrap_or("");
            assert!(
                txid.starts_with(LAB_SIMULATED_TXID_PREFIX),
                "simulated mode must label txid: {txid}"
            );
        }
        eprintln!(
            "lab_pay live path mode={} wallet_rpc={} txid={:?}",
            receipt.mode,
            wallet_rpc_available(&cfg),
            receipt.zec_txid
        );
    }

    #[test]
    fn open_confirm_skip_clean_when_rpc_down() {
        let sealed = golden_sealed();
        let r = confirm_open_at_sealed_dest_with_cfg(&sealed, &offline_cfg()).expect("skip-clean");
        assert!(!r.rpc_ready);
        assert_eq!(r.mode, OPEN_CONFIRM_SKIP_NO_RPC);
        assert!(r.address_valid.is_none());
        assert_eq!(r.dest_owner_binding_hex, REGTEST_MINER_OWNER_BINDING_HEX);
        eprintln!("open_confirm offline OK mode={} note={}", r.mode, r.note);
    }

    #[test]
    fn open_confirm_live_skip_clean_when_available() {
        let cfg = ZakuraLocalConfig::default();
        if !rpc_ready(&cfg) {
            eprintln!("skip live open_confirm: RPC not at {}", cfg.rpc_url);
            return;
        }
        let sealed = golden_sealed();
        let r = confirm_open_at_sealed_dest_with_cfg(&sealed, &cfg).expect("confirm");
        assert!(r.rpc_ready);
        assert!(
            r.mode == OPEN_CONFIRM_RPC_OK
                || r.mode == OPEN_CONFIRM_SKIP_VALIDATE_ONLY
                || r.mode == OPEN_CONFIRM_SKIP_NO_WALLET,
            "unexpected mode {}",
            r.mode
        );
        // Regtest miner dest should usually validate on Zakura regtest.
        if r.address_valid == Some(false) {
            eprintln!(
                "warn: validateaddress false for {} (network residual)",
                sealed.dest_display
            );
        }
        eprintln!(
            "open_confirm live mode={} valid={:?} bal={:?} recv={:?} note={}",
            r.mode, r.address_valid, r.wallet_balance_zat, r.received_zat, r.note
        );
    }

    #[test]
    fn real_txid_classifier() {
        assert!(!is_real_zec_txid(&synthetic_lab_txid(&[1u8; 32], 1)));
        assert!(!is_real_zec_txid(""));
        assert!(is_real_zec_txid(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(is_real_zec_txid("opid-deadbeef"));
        assert!(!rpc_err_method_missing("insufficient funds"));
        assert!(rpc_err_method_missing(r#"{"code":-32601,"message":"Method not found"}"#));
    }

    #[test]
    fn wallet_probe_offline_false() {
        assert!(!wallet_rpc_available(&offline_cfg()));
    }
}
