//! `TerpVmSuite` implementation for the **No-Rick** test circuit.
//!
//! Each circuit has one `NoRickCircuit` (implements the `Circuit` trait),
//! one `NoRickContract` (implements the `Contract` trait), and one
//! `NoRickSuite` (implements the `TerpVmSuite` orchestration trait).
//!
//! # Usage
//! ```rust,ignore
//! use zk_test_press::NoRickSuite;
//! use ict_rs::chain::terp::TerpVmSuite;
//!
//! let suite = NoRickSuite::new("./data/keys/no_rick");
//! // Generate and persist circuit keys + zk-wasmvm combined binary
//! suite.build_and_save_keys(10)?;
//! // Prove a word doesn't contain "rick"
//! let proof = suite.prove(&NoRickInputs::new("sandy", "rick"))?;
//! // Deploy to a running ict-rs Terp chain
//! let result = suite.deploy(&chain, "validator").await?;
//! ```
//!
//! # Keys directory layout
//! ```text
//! <keys_dir>/
//!   params.bin          — SRS / commitment parameters
//!   verifying_key.bin   — standalone halo2 VK
//!   proving_key.bin     — VK written for reference (pk rebuilt on load)
//!   vk_combined.bin     — params || vk || cs || 32-byte footer (zk-wasmvm format)
//! ```

use cw_no_rick::NoRickContractSuite;
use cw_no_rick::interface::NoRickDeployData;
use cw_orch::prelude::*;
use halo2_proofs::{COSMWASM_METADATA_LENGTH, plonk};
use std::io::Cursor;

use ict_rs::chain::terp::{Circuit, ZkSuiteError};
use pasta_curves::{Fp, vesta};
use rand_core::OsRng;

use crate::circuits::no_rick::{NoRickCircuit, NoRickInputs, NoRickInstance};
pub use interface::NoRickCircuitSuite;

pub mod interface {
    use super::*;

    // ── NoRickSuite ───────────────────────────────────────────────────────────────

    /// Full development suite for the No-Rick ZK circuit + CosmWasm verifier pair.
    ///
    /// Holds typed references to the circuit and contract components so callers
    /// can reach them directly (`self.circuit`, `self.contract`) instead of
    /// going through static method dispatch.
    ///
    /// # Layout
    /// ```text
    /// NoRickSuite
    ///   ├── circuit  : NoRickCircuit      — halo2 keygen / prove / verify
    ///   ├── contract : NoRickContract — CosmWasm wasm bytes + VK validation
    ///   └── keys_dir : PathBuf            — on-disk key storage root
    /// ```
    pub struct NoRickSuite<Chain: ZkCwEnv> {
        /// The zero-sized circuit type; provides keygen / prove / verify.
        pub circuit: NoRickCircuitSuite<Chain>,
        /// The zero-sized contract type; provides wasm bytes + VK validation.
        pub contract: NoRickContractSuite<Chain>,
    }

    impl<Chain: ZkCwEnv> NoRickSuite<Chain> {
        pub fn new(chain: Chain) -> Self {
            Self {
                circuit: NoRickCircuitSuite::new(chain.clone()),
                contract: NoRickContractSuite::new(chain.clone()),
            }
        }
        pub fn deploy_on(chain: Chain, data: NoRickDeployData) -> Result<Self, CwOrchError> {
            Ok(Self {
                circuit: NoRickCircuitSuite::deploy_on(chain.clone(), data.clone())?,
                contract: NoRickContractSuite::deploy_on(chain.clone(), data)?,
            })
        }
    }

    // #[circuit_interface(
    // id = "no_rick",
    // artifacts_dir = "artifacts",
    // summary_json = "artifacts/headstash_circuit_summary.json",
    // has_lookups = true
    // )]
    #[cw_orch::circuit_interface(id = "no_rick")]
    pub struct NoRickCircuitSuite;

    impl<Chain: ZkCwEnv> Deploy<Chain> for NoRickCircuitSuite<Chain> {
        type Error = CwOrchError;
        type DeployData = NoRickDeployData;
        fn deploy_on(chain: Chain, data: Self::DeployData) -> Result<Self, Self::Error> {
            // Your deployment logic here
            let suite = Self::store_on(chain.clone())?;
            Ok(suite)
        }

        fn store_on(chain: Chain) -> Result<Self, Self::Error> {
            // Your deployment logic here
            let suite = Self::new(chain);
            suite.upload_circuit()?;
            Ok(suite)
        }

        fn get_contracts_mut(&mut self) -> Vec<Box<&mut dyn ContractInstance<Chain>>> {
            todo!()
        }

        fn load_from(chain: Chain) -> Result<Self, Self::Error> {
            todo!()
        }
    }
}

// ── Circuit trait impl ────────────────────────────────────────────────────────

impl Circuit for NoRickCircuit<Fp> {
    /// Serialised SRS / commitment params (raw bytes).
    type Params = Vec<u8>;
    type ProvingKey = crate::circuits::no_rick::ProvingKey;
    type VerifyingKey = crate::circuits::no_rick::VerifyingKey;
    type Proof = crate::circuits::no_rick::Proof;
    type PublicInputs = NoRickInputs;

    fn circuit_name() -> &'static str {
        "no-rick"
    }

    fn keygen(
        params_bytes: &Self::Params,
    ) -> std::result::Result<(Self::ProvingKey, Self::VerifyingKey), ZkSuiteError> {
        let p = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut Cursor::new(
            params_bytes,
        ))
        .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;

        let circuit: NoRickCircuit<Fp> = Default::default();
        let vk = plonk::keygen_vk(&p, &circuit)
            .map_err(|e| ZkSuiteError::Circuit(format!("keygen_vk: {:?}", e)))?;
        let pk = plonk::keygen_pk(&p, vk.clone(), &circuit)
            .map_err(|e| ZkSuiteError::Circuit(format!("keygen_pk: {:?}", e)))?;

        Ok((
            Self::ProvingKey::new(pk, p.clone()),
            Self::VerifyingKey { params: p, vk },
        ))
    }

    fn prove(
        _params_bytes: &Self::Params,
        pk: &Self::ProvingKey,
        inputs: &Self::PublicInputs,
    ) -> std::result::Result<Self::Proof, ZkSuiteError> {
        use halo2_proofs::circuit::Value;

        // Pad private word to the fixed 20-byte circuit width.
        let mut bytes = inputs.private_word.as_bytes().to_vec();
        bytes.resize(20, 0);
        let priv_input: Vec<Value<Fp>> = bytes
            .iter()
            .map(|&b| Value::known(Fp::from(b as u64)))
            .collect();

        let circuit = NoRickCircuit { priv_input };
        let instance = NoRickInstance {
            word: inputs.forbidden_word.clone(),
        };

        Self::Proof::create(pk, &[circuit], &[instance], &mut OsRng)
            .map_err(|e| ZkSuiteError::Circuit(format!("prove: {:?}", e)))
    }

    fn verify(
        _params_bytes: &Self::Params,
        vk: &Self::VerifyingKey,
        proof: &Self::Proof,
        inputs: &Self::PublicInputs,
    ) -> std::result::Result<(), ZkSuiteError> {
        let instance = NoRickInstance {
            word: inputs.forbidden_word.clone(),
        };
        proof
            .verify(vk, &[instance])
            .map_err(|e| ZkSuiteError::Verification(format!("{:?}", e)))
    }

    fn proof_to_bytes(proof: &Self::Proof) -> Vec<u8> {
        proof.bytes()
    }

    /// Serialise the VK as `params || vk` bytes.
    ///
    /// For the full zk-wasmvm format (with `cs` and footer) use
    /// [`NoRickSuite::build_and_save_keys`] which writes `vk_combined.bin`.
    fn vk_to_bytes(vk: &Self::VerifyingKey) -> Vec<u8> {
        let mut out = Vec::new();
        vk.params.write(&mut out).expect("params write");
        vk.vk.write(&mut out).expect("vk write");
        out
    }

    fn vk_from_bytes(bytes: &[u8]) -> std::result::Result<Self::VerifyingKey, ZkSuiteError> {
        let mut cursor = Cursor::new(bytes);
        let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut cursor)
            .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
        let vk = plonk::VerifyingKey::<vesta::Affine>::read::<_, NoRickCircuit<Fp>>(
            &mut cursor,
            &params,
        )
        .map_err(|e| ZkSuiteError::Circuit(format!("read vk: {:?}", e)))?;
        Ok(Self::VerifyingKey { params, vk })
    }

    fn validate_vk_header(vk_bytes: &[u8]) -> std::result::Result<(), ZkSuiteError> {
        if vk_bytes.len() < 32 {
            return Err(ZkSuiteError::VkValidation(
                "vk too short (< 32 bytes)".into(),
            ));
        }
        Ok(())
    }

    fn validate_vk_footer(vk_bytes: &[u8]) -> std::result::Result<(), ZkSuiteError> {
        if vk_bytes.len() < COSMWASM_METADATA_LENGTH {
            return Err(ZkSuiteError::VkValidation(format!(
                "vk missing footer: need {} bytes, got {}",
                COSMWASM_METADATA_LENGTH,
                vk_bytes.len()
            )));
        }
        Ok(())
    }
}
