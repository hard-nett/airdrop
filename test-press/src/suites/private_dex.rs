//! cw-orch suite helpers for `cw-private-dex` (CreatePool / SettleSwap / queries).
//!
//! G3 harness settle. SSOT: `DESIGN-HARNESS-SETTLE.md`.

use cosmwasm_std::{Binary, Uint128};
use cw_orch::prelude::*;
use cw_private_dex::interface::CwPrivateDexContract;
use cw_private_dex::msg::{
    ConfigResponse, ExecuteMsg, InstantiateMsg, Pool, QueryMsg, QuoteResponse, SwapStatementPublic,
};

use crate::harness::swap_statement_cw::{
    lab_allowed_root, LAB_GAMMA, LAB_GAMMA_DEN, LAB_R_IN, LAB_R_OUT, SwapSpendHandoffV0,
};

/// Thin suite around one `cw-private-dex` instance.
pub struct PrivateDexSuite<Chain: CwEnv> {
    pub dex: CwPrivateDexContract<Chain>,
}

impl<Chain: CwEnv> PrivateDexSuite<Chain> {
    pub fn new(chain: Chain) -> Self
    where
        Chain: Clone,
    {
        Self {
            dex: CwPrivateDexContract::new(chain),
        }
    }

    /// Upload + instantiate with lab mock_verify and allowed root window.
    pub fn upload_and_instantiate(
        &mut self,
        mock_verify: bool,
        allowed_root: Option<Binary>,
    ) -> Result<(), CwOrchError> {
        self.dex.upload()?;
        self.dex.instantiate(
            &InstantiateMsg {
                mock_verify,
                zkid: None,
                allowed_root,
            },
            None,
            &[],
        )?;
        Ok(())
    }

    /// Lab defaults: mock_verify + fixed root `[7;32]`.
    pub fn upload_and_instantiate_lab(&mut self, mock_verify: bool) -> Result<(), CwOrchError> {
        self.upload_and_instantiate(
            mock_verify,
            Some(Binary::from(lab_allowed_root().to_vec())),
        )
    }

    pub fn create_pool(
        &self,
        asset_a: Binary,
        asset_b: Binary,
        r_a: u128,
        r_b: u128,
        gamma: u64,
        gamma_den: u64,
    ) -> Result<<Chain as TxHandler>::Response, CwOrchError> {
        self.dex.execute(
            &ExecuteMsg::CreatePool {
                asset_a,
                asset_b,
                r_a: Uint128::new(r_a),
                r_b: Uint128::new(r_b),
                gamma,
                gamma_den,
            },
            &[],
        )
    }

    /// Create lab pool for handoff asset orientation (asset_a = in, asset_b = out).
    pub fn create_lab_pool_for_handoff(
        &self,
        handoff: &SwapSpendHandoffV0,
    ) -> Result<<Chain as TxHandler>::Response, CwOrchError> {
        self.create_pool(
            handoff.statement.asset_in.clone(),
            handoff.statement.asset_out.clone(),
            LAB_R_IN,
            LAB_R_OUT,
            LAB_GAMMA,
            LAB_GAMMA_DEN,
        )
    }

    pub fn settle_swap(
        &self,
        statement: SwapStatementPublic,
        proof: Binary,
    ) -> Result<<Chain as TxHandler>::Response, CwOrchError> {
        self.dex.execute(
            &ExecuteMsg::SettleSwap { statement, proof },
            &[],
        )
    }

    pub fn settle_handoff(
        &self,
        handoff: &SwapSpendHandoffV0,
    ) -> Result<<Chain as TxHandler>::Response, CwOrchError> {
        self.settle_swap(handoff.statement.clone(), handoff.proof.clone())
    }

    pub fn query_config(&self) -> Result<ConfigResponse, CwOrchError> {
        self.dex.query(&QueryMsg::Config {})
    }

    pub fn query_pool(&self, pool_id: u64) -> Result<Pool, CwOrchError> {
        self.dex.query(&QueryMsg::Pool { pool_id })
    }

    pub fn query_nullifier_spent(&self, nullifier: Binary) -> Result<bool, CwOrchError> {
        self.dex.query(&QueryMsg::IsNullifierSpent { nullifier })
    }

    pub fn query_quote(
        &self,
        pool_id: u64,
        asset_in: Binary,
        delta_in: u128,
    ) -> Result<QuoteResponse, CwOrchError> {
        self.dex.query(&QueryMsg::QuoteExactIn {
            pool_id,
            asset_in,
            delta_in: Uint128::new(delta_in),
        })
    }

    /// Post-settle asserts: reserves + nullifiers (fail-closed).
    pub fn assert_settle_ok(&self, handoff: &SwapSpendHandoffV0) -> Result<(u128, u128), CwOrchError> {
        let st = &handoff.statement;
        let pool = self.query_pool(st.pool_id)?;
        let r_in_after = st.r_in_before.u128() + st.delta_r_in.u128();
        let r_out_after = st.r_out_before.u128() - st.delta_r_out.u128();
        // Orient: asset_in is a (lab create puts in as a)
        if pool.r_a.u128() != r_in_after || pool.r_b.u128() != r_out_after {
            return Err(CwOrchError::StdErr(format!(
                "reserve mismatch: pool r_a={} r_b={} expected r_in_after={} r_out_after={}",
                pool.r_a, pool.r_b, r_in_after, r_out_after
            )));
        }
        for nf in &st.nullifiers {
            let spent = self.query_nullifier_spent(nf.clone())?;
            if !spent {
                return Err(CwOrchError::StdErr(format!(
                    "nullifier not spent: {}",
                    hex::encode(nf.as_slice())
                )));
            }
        }
        Ok((r_in_after, r_out_after))
    }

    pub fn address_string(&self) -> Result<String, CwOrchError> {
        Ok(self.dex.address()?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::mint_evidence::mint_evidence_from_claim_fields;
    use crate::harness::swap_statement_cw::{
        build_swap_spend_handoff_from_mint, ProofModeLabel,
    };

    fn fixture_mint() -> crate::harness::MintEvidenceV0 {
        let mut asset_in = [0u8; 32];
        asset_in[0] = b'H';
        asset_in[1] = b'U';
        asset_in[2] = b'B';
        mint_evidence_from_claim_fields(
            "ict_local_funded",
            "mock",
            "terp1hs",
            &[0x11; 32],
            &[0x22; 32],
            5_000,
            &asset_in,
            Some(&[0x33; 32]),
            Some(&[0x44; 32]),
            true,
            None,
            None,
        )
    }

    #[test]
    fn settle_after_mint_mock() {
        let app = Mock::new("owner");
        let mut suite = PrivateDexSuite::new(app.clone());
        suite
            .upload_and_instantiate_lab(true)
            .expect("upload/instantiate");

        let mint = fixture_mint();
        let handoff =
            build_swap_spend_handoff_from_mint(&mint, ProofModeLabel::MockVerifyLab).unwrap();

        suite
            .create_lab_pool_for_handoff(&handoff)
            .expect("create pool");

        // Optional preflight quote
        let q = suite
            .query_quote(
                handoff.statement.pool_id,
                handoff.statement.asset_in.clone(),
                handoff.statement.delta_r_in.u128(),
            )
            .expect("quote");
        assert_eq!(q.delta_out, handoff.statement.delta_r_out);

        suite.settle_handoff(&handoff).expect("settle");
        let (r_in, r_out) = suite.assert_settle_ok(&handoff).expect("assert");
        assert_eq!(r_in, LAB_R_IN + handoff.statement.delta_r_in.u128());
        assert_eq!(r_out, LAB_R_OUT - handoff.statement.delta_r_out.u128());

        // Double settle same ν → reject
        let err = suite.settle_handoff(&handoff).unwrap_err();
        let es = err.to_string().to_lowercase();
        assert!(
            es.contains("nullifier"),
            "expected nullifier reject, got {err}"
        );

        let cfg = suite.query_config().unwrap();
        assert!(cfg.mock_verify);
    }

    #[test]
    fn empty_proof_rejected() {
        let app = Mock::new("owner");
        let mut suite = PrivateDexSuite::new(app);
        suite.upload_and_instantiate_lab(true).unwrap();
        let mint = fixture_mint();
        let mut handoff =
            build_swap_spend_handoff_from_mint(&mint, ProofModeLabel::MockVerifyLab).unwrap();
        suite.create_lab_pool_for_handoff(&handoff).unwrap();
        handoff.proof = Binary::from(Vec::<u8>::new());
        let err = suite.settle_handoff(&handoff).unwrap_err();
        let es = err.to_string().to_lowercase();
        assert!(
            es.contains("proof") || es.contains("reject"),
            "expected proof reject, got {err}"
        );
    }
}
