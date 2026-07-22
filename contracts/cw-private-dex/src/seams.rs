//! Pure host recompute math — mirrors
//! `docs/plans/spectrum/fixtures/private_dex_seams` and the XYK spirit of
//! `crates/dex/contracts/pair` (`compute_swap`), without pulling the full
//! astroport package graph into this guest.

use crate::error::ContractError;

/// Price fixed-point scale (1e18), same as pure seams fixture.
pub const PRICE_SCALE: u128 = 1_000_000_000_000_000_000;

/// Constant-product fee-aware exact-in quote (SPEC-private-dex-seams §2.2):
///
/// ```text
/// Δ_out = floor(R_out * γ * Δ_in / (R_in * γ_den + γ * Δ_in))
/// ```
///
/// Astroport XYK (`crates/dex` pair `compute_swap`) applies commission as a
/// post-curve take; our private-seam form folds fee into γ/γ_den so host
/// recompute stays integer-only and matches the pure fixture SSOT.
pub fn quote_exact_in(
    r_in: u128,
    r_out: u128,
    delta_in: u128,
    gamma: u64,
    gamma_den: u64,
) -> Result<u128, ContractError> {
    if delta_in == 0 || r_in == 0 || r_out == 0 || gamma_den == 0 {
        return Err(ContractError::BadAmount {});
    }
    let g = gamma as u128;
    let gd = gamma_den as u128;

    let num = r_out
        .checked_mul(g)
        .and_then(|x| x.checked_mul(delta_in))
        .ok_or(ContractError::BadAmount {})?;
    let fee_in = g.checked_mul(delta_in).ok_or(ContractError::BadAmount {})?;
    let den = r_in
        .checked_mul(gd)
        .and_then(|x| x.checked_add(fee_in))
        .ok_or(ContractError::BadAmount {})?;
    if den == 0 {
        return Err(ContractError::BadAmount {});
    }
    let delta_out = num / den;
    if delta_out == 0 {
        return Err(ContractError::BadAmount {});
    }
    if delta_out >= r_out {
        return Err(ContractError::InsufficientReserve {});
    }
    Ok(delta_out)
}

/// `R_in += Δ_in`, `R_out -= Δ_out`; require `R_out' > 0`.
pub fn apply_reserves(
    r_in: u128,
    r_out: u128,
    delta_in: u128,
    delta_out: u128,
) -> Result<(u128, u128), ContractError> {
    let r_in2 = r_in
        .checked_add(delta_in)
        .ok_or(ContractError::BadAmount {})?;
    if delta_out >= r_out {
        return Err(ContractError::InsufficientReserve {});
    }
    let r_out2 = r_out - delta_out;
    if r_out2 == 0 {
        return Err(ContractError::InsufficientReserve {});
    }
    Ok((r_in2, r_out2))
}

pub fn is_fresh(observed_height: u64, now_height: u64, max_age_blocks: u64) -> bool {
    now_height
        .checked_sub(observed_height)
        .map(|age| age <= max_age_blocks)
        .unwrap_or(false)
}

pub fn implied_price(delta_in: u128, delta_out: u128) -> Result<u128, ContractError> {
    if delta_out == 0 {
        return Err(ContractError::BadAmount {});
    }
    delta_in
        .checked_mul(PRICE_SCALE)
        .map(|n| n / delta_out)
        .ok_or(ContractError::BadAmount {})
}

pub fn within_slippage(implied: u128, mid: u128, max_slippage_bps: u32) -> bool {
    if mid == 0 {
        return false;
    }
    let bps = max_slippage_bps as u128;
    let low = mid.saturating_mul(10_000u128.saturating_sub(bps)) / 10_000;
    let high = mid
        .checked_mul(10_000u128.saturating_add(bps))
        .map(|x| x / 10_000)
        .unwrap_or(u128::MAX);
    implied >= low && implied <= high
}

/// Oracle mids are **bounds only** (SPEC §3) — never mint / never bump reserves alone.
pub fn check_oracle_bound(
    mid: Option<&OracleMidView>,
    params: &OracleBoundParamsView,
    now_height: u64,
    delta_in: u128,
    delta_out: u128,
) -> Result<(), ContractError> {
    match mid {
        None => {
            if params.require_oracle {
                Err(ContractError::OracleMissing {})
            } else {
                Ok(())
            }
        }
        Some(m) => {
            if !is_fresh(m.observed_height, now_height, params.max_age_blocks) {
                if params.require_oracle {
                    return Err(ContractError::OracleStale {});
                }
                // require_oracle=false + stale → MAY allow pure AMM
                return Ok(());
            }
            let implied = implied_price(delta_in, delta_out)?;
            if !within_slippage(implied, m.mid, params.max_slippage_bps) {
                return Err(ContractError::OracleSlippage {});
            }
            Ok(())
        }
    }
}

/// View types used by oracle check (owned by msg layer; seams stays free of cw_serde).
#[derive(Clone, Debug)]
pub struct OracleMidView {
    pub mid: u128,
    pub observed_height: u64,
}

#[derive(Clone, Debug)]
pub struct OracleBoundParamsView {
    pub max_age_blocks: u64,
    pub max_slippage_bps: u32,
    pub require_oracle: bool,
}

/// Domain tag for synthetic pool-spend nullifiers (pure fixture `POOL_NF_LABEL`).
pub const POOL_NF_LABEL: &[u8] = b"pool-nf-v0";

/// Domain tag for abstract harness leaves (`ABSTRACT_LEAF_LABEL`).
pub const ABSTRACT_LEAF_LABEL: &[u8] = b"terp-seam-leaf-v0";

/// Domain-separated instance encoding label for swap public statement.
pub const SWAP_INSTANCE_LABEL: &[u8] = b"cw-private-dex-swap-v0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_matches_demo_pool() {
        // γ/γ_den = 997/1000, R_in=1e6, R_out=2e6, Δ_in=1000
        let out = quote_exact_in(1_000_000, 2_000_000, 1000, 997, 1000).unwrap();
        assert!(out > 0 && out < 2000);
    }

    #[test]
    fn empty_reserve_rejected() {
        assert!(matches!(
            quote_exact_in(0, 1_000_000, 100, 997, 1000),
            Err(ContractError::BadAmount {})
        ));
        // BadAmount is a unit variant — structural match is enough.
    }
}
