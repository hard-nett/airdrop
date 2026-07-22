//! Dual-path proof acceptance for private swap settle.
//!
//! | Path | Gate | Behavior |
//! |------|------|----------|
//! | mock | `cfg.mock_verify \|\| cfg!(test)` | non-empty proof after seam host checks |
//! | host | feature `zk-api` + `!mock_verify` | `api.proof_instance_verify(zkid, proof, instances)` |
//! | fail-closed | otherwise | reject |

use cosmwasm_std::{Api, Binary};

use crate::error::ContractError;
use crate::instances::encode_swap_instances;
use crate::msg::SwapStatementPublic;
use crate::state::Config;

/// Verify proof for a swap statement under current config.
pub fn verify_swap_proof(
    api: &dyn Api,
    cfg: &Config,
    statement: &SwapStatementPublic,
    proof: &Binary,
) -> Result<(), ContractError> {
    let allow_mock = cfg.mock_verify || cfg!(test);

    if allow_mock {
        if proof.is_empty() {
            return Err(ContractError::ProofRejected(
                "empty proof under mock_verify".into(),
            ));
        }
        // Lab path: structural host checks in settle_swap still run.
        return Ok(());
    }

    // Production path: require zkid + host import.
    let zkid = cfg.zkid.ok_or(ContractError::ZkidMissing {})?;
    let instances = encode_swap_instances(statement);

    #[cfg(feature = "zk-api")]
    {
        let ok = api
            .proof_instance_verify(zkid, proof.as_slice(), &instances)
            .map_err(|e| ContractError::ProofRejected(e.to_string()))?;
        if !ok {
            return Err(ContractError::ProofRejected("invalid proof".into()));
        }
        let _ = api; // silence if unused in other cfgs — actually used above
        Ok(())
    }

    #[cfg(not(feature = "zk-api"))]
    {
        let _ = (api, zkid, instances);
        Err(ContractError::ZkApiUnavailable {})
    }
}
