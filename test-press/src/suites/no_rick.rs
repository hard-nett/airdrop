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

use std::io::{BufWriter, Cursor, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use cw_no_rick::NoRickContractSuite;
use cw_no_rick::interface::NoRickDeployData;
use cw_orch::prelude::*;
use halo2_proofs::{COSMWASM_METADATA_LENGTH, plonk};

use ict_rs::chain::terp::{Circuit, ZkSuiteError};
use pasta_curves::{Fp, vesta};
use rand_core::OsRng;

use crate::circuits::no_rick::{NoRickCircuit, NoRickInputs, NoRickInstance};
use crate::suites::interface::NoRickCircuitSuite;

// ── Circuit trait impl ────────────────────────────────────────────────────────

impl Circuit for NoRickCircuit<Fp> {
    /// Serialised SRS / commitment params (raw bytes).
    type Params = Vec<u8>;
    type ProvingKey = crate::circuits::no_rick::ProvingKey;
    type VerifyingKey = crate::circuits::no_rick::VerifyingKey;
    type Proof = crate::circuits::no_rick::Proof;
    /// Bundles private witness + public instance.
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
            circuit: NoRickCircuitSuite::deploy_on(chain.clone()),
            contract: NoRickContractSuite::deploy_on(chain.clone()),
        })
    }
}
// #[async_trait]
// impl TerpVmSuite for NoRickSuite {
//     type Circuit = NoRickCircuit;
//     type Contract = NoRickContract;
//     type Chain = CosmosChain;

//     fn keys_dir(&self) -> &Path {
//         &self.keys_dir
//     }

//     fn load_circuit_keys(&self) -> std::result::Result<(ProvingKey, VerifyingKey), ZkSuiteError> {
//         let params_path = self.keys_dir.join("params.bin");
//         let vk_path = self.keys_dir.join("verifying_key.bin");

//         let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(
//             &mut std::fs::File::open(&params_path)?,
//         )
//         .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;

//         let vk = plonk::VerifyingKey::<vesta::Affine>::read::<_, NoRickCircuit<Fp>>(
//             &mut std::fs::File::open(&vk_path)?,
//             &params,
//         )
//         .map_err(|e| ZkSuiteError::Circuit(format!("read vk: {:?}", e)))?;

//         // Rebuild pk from params + vk — never persisted directly.
//         let circuit: NoRickCircuit<Fp> = Default::default();
//         let pk = plonk::keygen_pk(&params, vk.clone(), &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("rebuild pk: {:?}", e)))?;

//         Ok((
//             ProvingKey::new(pk, params.clone()),
//             VerifyingKey { params, vk },
//         ))
//     }

//     fn save_circuit_keys(
//         &self,
//         _pk: &ProvingKey,
//         vk: &VerifyingKey,
//     ) -> std::result::Result<(), ZkSuiteError> {
//         std::fs::create_dir_all(&self.keys_dir)?;

//         let mut pf = BufWriter::new(std::fs::File::create(self.keys_dir.join("params.bin"))?);
//         vk.params
//             .write(&mut pf)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         pf.flush()?;

//         let mut vf = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("verifying_key.bin"),
//         )?);
//         vk.vk
//             .write(&mut vf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         vf.flush()?;
//         Ok(())
//     }

//     /// Generate fresh circuit keys for depth `k`, write all key files, and
//     /// produce `vk_combined.bin` with the zk-wasmvm [`CircuitFooter`] appended.
//     ///
//     /// `vk_combined.bin` is the binary submitted via
//     /// `terpd tx wasm store-circuit`.  Format:
//     /// ```text
//     /// [params bytes][vk bytes][cs bytes][32-byte CircuitFooter]
//     /// ```
//     fn build_and_save_keys(&self, k: u32) -> std::result::Result<(), ZkSuiteError> {
//         std::fs::create_dir_all(&self.keys_dir)?;

//         const INSTANCE_COLS: u8 = 1;

//         // ── Build constraint system metadata (separate pass for footer). ────────
//         let mut cs = plonk::ConstraintSystem::<Fp>::default();
//         {
//             use halo2_proofs::plonk::Circuit as HCircuit;
//             let _ = <NoRickCircuit<Fp> as HCircuit<Fp>>::configure(&mut cs);
//         }

//         // ── Keygen ────────────────────────────────────────────────────────────────
//         let p = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(k);
//         let circuit: NoRickCircuit<Fp> = Default::default();
//         let vk = plonk::keygen_vk(&p, &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_vk: {:?}", e)))?;
//         let pk = plonk::keygen_pk(&p, vk.clone(), &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_pk: {:?}", e)))?;

//         // ── params.bin ────────────────────────────────────────────────────────────
//         let mut pf = BufWriter::new(std::fs::File::create(self.keys_dir.join("params.bin"))?);
//         p.write(&mut pf)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         pf.flush()?;

//         // ── verifying_key.bin ─────────────────────────────────────────────────────
//         let mut vf = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("verifying_key.bin"),
//         )?);
//         vk.write(&mut vf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         vf.flush()?;

//         // ── proving_key.bin  (vk written for reference; pk rebuilt on load) ──────
//         let mut pkf = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("proving_key.bin"),
//         )?);
//         pk.get_vk()
//             .write(&mut pkf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         pkf.flush()?;

//         // ── vk_combined.bin  (zk-wasmvm on-chain format) ─────────────────────────
//         let mut combined = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("vk_combined.bin"),
//         )?);

//         let mut params_bytes = Vec::new();
//         p.write(&mut params_bytes)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         let params_len = params_bytes.len() as u32;
//         combined.write_all(&params_bytes)?;

//         let mut vk_bytes = Vec::new();
//         vk.write(&mut vk_bytes)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         let vk_len = vk_bytes.len() as u32;
//         combined.write_all(&vk_bytes)?;

//         let mut cs_bytes = Vec::new();
//         cs.write(&mut cs_bytes)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         let cs_len = cs_bytes.len() as u32;
//         combined.write_all(&cs_bytes)?;

//         // Build and append the 32-byte CircuitFooter.
//         let footer = CircuitFooter::new(
//             CircuitType::Plonkish,
//             INSTANCE_COLS,
//             cs.get_num_fixed_columns(),
//             cs.get_num_advice(),
//             cs.get_num_instance_columns(),
//             cs.degree() as u8,
//             params_len,
//             vk_len,
//             cs_len,
//             cs.get_num_selectors(),
//             cs.get_gate_count() as u32,
//             false, // NoRickCircuit has no lookups
//             0,     // crc32 placeholder
//         );

//         let footer_bytes = footer.to_bytes();
//         assert_eq!(
//             footer_bytes.len(),
//             COSMWASM_METADATA_LENGTH,
//             "CircuitFooter size mismatch"
//         );
//         combined.write_all(&footer_bytes)?;
//         combined.flush()?;

//         Ok(())
//     }

//     fn prove(&self, inputs: &NoRickInputs) -> std::result::Result<Proof, ZkSuiteError> {
//         let params_bytes = std::fs::read(self.keys_dir.join("params.bin"))?;
//         let (pk, _) = self.load_circuit_keys()?;
//         <NoRickCircuit as Circuit>::prove(&params_bytes, &pk, inputs)
//     }

//     fn verify(
//         &self,
//         proof: &Proof,
//         inputs: &NoRickInputs,
//     ) -> std::result::Result<(), ZkSuiteError> {
//         let params_bytes = std::fs::read(self.keys_dir.join("params.bin"))?;
//         let (_, vk) = self.load_circuit_keys()?;
//         <NoRickCircuit as Circuit>::verify(&params_bytes, &vk, proof, inputs)
//     }

//     async fn deploy(
//         &self,
//         chain: &CosmosChain,
//         deployer_key: &str,
//     ) -> std::result::Result<DeployedContract, ZkSuiteError> {
//         use base64::Engine as _;

//         // 1. Copy wasm into the container.
//         let wasm = NoRickContract::wasm_byte_code();
//         let wasm_b64 = base64::engine::general_purpose::STANDARD.encode(wasm);
//         let remote_wasm = "/tmp/no_rick.wasm";
//         chain
//             .chain_exec(&[
//                 "sh",
//                 "-c",
//                 &format!("echo '{}' | base64 -d > {}", wasm_b64, remote_wasm),
//             ])
//             .await
//             .map_err(|e| ZkSuiteError::Deploy(format!("copy wasm: {e}")))?;

//         // 2. Store code.
//         let store_out = chain
//             .chain_exec(&[
//                 "terpd",
//                 "tx",
//                 "wasm",
//                 "store",
//                 remote_wasm,
//                 "--from",
//                 deployer_key,
//                 "--gas",
//                 "auto",
//                 "--gas-adjustment",
//                 "1.5",
//                 "--output",
//                 "json",
//                 "-y",
//             ])
//             .await
//             .map_err(|e| ZkSuiteError::Deploy(format!("store code: {e}")))?;

//         let store_json: serde_json::Value = serde_json::from_slice(&store_out.stdout)
//             .map_err(|e| ZkSuiteError::Deploy(format!("parse store output: {e}")))?;
//         let code_id: u64 = store_json
//             .pointer("/logs/0/events/0/attributes/0/value")
//             .or_else(|| store_json.get("code_id"))
//             .and_then(|v| v.as_str())
//             .and_then(|s| s.parse().ok())
//             .ok_or_else(|| ZkSuiteError::Deploy("could not parse code_id".into()))?;

//         // 3. Instantiate.
//         let inst_out = chain
//             .chain_exec(&[
//                 "terpd",
//                 "tx",
//                 "wasm",
//                 "instantiate",
//                 &code_id.to_string(),
//                 "{}",
//                 "--label",
//                 NoRickContract::contract_name(),
//                 "--no-admin",
//                 "--from",
//                 deployer_key,
//                 "--gas",
//                 "auto",
//                 "--gas-adjustment",
//                 "1.5",
//                 "--output",
//                 "json",
//                 "-y",
//             ])
//             .await
//             .map_err(|e| ZkSuiteError::Deploy(format!("instantiate: {e}")))?;

//         let inst_json: serde_json::Value = serde_json::from_slice(&inst_out.stdout)
//             .map_err(|e| ZkSuiteError::Deploy(format!("parse instantiate output: {e}")))?;
//         let contract_addr = inst_json
//             .pointer("/logs/0/events/1/attributes/0/value")
//             .or_else(|| inst_json.get("contract_address"))
//             .and_then(|v| v.as_str())
//             .ok_or_else(|| ZkSuiteError::Deploy("could not parse contract_address".into()))?
//             .to_string();

//         // 4. Register verifying key (vk_combined.bin → LoadVk).
//         let vk_combined = std::fs::read(self.keys_dir.join("vk_combined.bin"))
//             .map_err(|e| ZkSuiteError::KeyIo(e))?;
//         NoRickContract::validate_vk_header(&vk_combined)?;
//         NoRickContract::validate_vk_footer(&vk_combined)?;
//         let vk_b64 = base64::engine::general_purpose::STANDARD.encode(&vk_combined);

//         let vk_registered = chain
//             .chain_exec(&[
//                 "terpd",
//                 "tx",
//                 "wasm",
//                 "headstash",
//                 &contract_addr,
//                 "--vk",
//                 &vk_b64,
//                 "--from",
//                 deployer_key,
//                 "--gas",
//                 "auto",
//                 "--gas-adjustment",
//                 "1.5",
//                 "-y",
//             ])
//             .await
//             .is_ok();

//         Ok(DeployedContract {
//             code_id,
//             contract_addr,
//             vk_registered,
//         })
//     }
// }
