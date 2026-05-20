//! `TerpVmSuite` implementation for the **ZK Headstash Orchard circuit**.
//!
//! This is the production ZK circuit powering `cw-headstash` shielded-pool
//! operations: spend proofs over Merkle paths with Poseidon commitments.
//!
//! # Keys directory layout
//! ```text
//! <keys_dir>/
//!   params.bin          — SRS / commitment parameters (vesta::Affine)
//!   verifying_key.bin   — halo2 VK
//!   proving_key.bin     — VK written for reference (pk rebuilt on load)
//!   vk_combined.bin     — params || vk || cs || 32-byte footer (store-circuit)
//! ```

use std::io::{BufWriter, Cursor, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use cw_orch::{anyhow, contract::circuits::circuit_interface_traits::CircuitUploadable};
use halo2_proofs::{COSMWASM_METADATA_LENGTH, plonk};
use ict_rs::chain::Chain as _;
use ict_rs::chain::cosmos::CosmosChain;
use ict_rs::chain::terp::{Circuit, Contract, DeployedContract, TerpVmSuite, ZkSuiteError};
use pasta_curves::{Fp, pallas, vesta};
use rand_core::OsRng;
use zk_cosmwasm::{CircuitFooter, CircuitType, CosmwasmCircuit, Instance, Proof, ProvingKey};
use zk_headstash::{
    Anchor,
    address::RecpAddr,
    circuit::{Circuit as OrchardCircuit, Instance as OrchardInstance},
    keys::{EligibleSk, FullViewingKey, SpendingKey},
    note::Note,
    tree::MerklePath,
    value::HeadstashValue,
};

use base64::Engine as _;
use std::string::String;

use cw_headstash::interface::HeadstashContract;
use cw_headstash_manifold::interface::CwHeadstashManifold;
use cw_headstash_manifold::msg::{ExecuteMsgFns, InstantiateMsg as ManifoldInstantiateMsg};
use cw_orch::prelude::*;

use cosmwasm_std::{Addr, Binary};
use cw_headstash::tokenfactory::{HeadstashTokenObject, TokenStrategy};
use cw_headstash::wavs::{WavsAuthMetadata, WavsProofOfOwnership};

#[cw_orch::circuit_interface(id = "headstash")]
pub struct HeadstashCircuitSuite;

/// ZK headstash deployment suite: cw-headstash contract + manifold factory.
///
/// Wraps the cw-orch interfaces for both contracts and provides
/// a `deploy_on` constructor matching the pattern used by other suites.
pub struct HeadstashSuite<Chain: ZkCwEnv> {
    pub headstash: HeadstashContract<Chain>,
    pub manifold: CwHeadstashManifold<Chain>,
    pub circuit: HeadstashCircuitSuite<Chain>,
}

impl<Chain: ZkCwEnv> HeadstashSuite<Chain> {
    pub fn new(chain: Chain) -> Self {
        let circuit = HeadstashCircuitSuite::new(chain.clone());
        let manifold = CwHeadstashManifold::new(chain.clone());
        let headstash = HeadstashContract::new(chain.clone());
        Self {
            headstash,
            manifold,
            circuit,
        }
    }
}

impl<Chain: ZkCwEnv + cw_orch::prelude::CircuitUploadable> Deploy<Chain> for HeadstashSuite<Chain> {
    type Error = CwOrchError;
    type DeployData = HeadstashDeployData;

    fn store_on(chain: Chain) -> Result<Self, Self::Error> {
        let suite = HeadstashSuite::new(chain.clone());
        suite.circuit.upload_circuit()?;
        suite.manifold.upload()?;
        suite.headstash.upload()?;
        Ok(suite)
    }

    fn get_contracts_mut(&mut self) -> Vec<Box<&mut dyn ContractInstance<Chain>>> {
        todo!()
    }

    fn load_from(chain: Chain) -> Result<Self, Self::Error> {
        todo!()
    }

    fn deploy_on(chain: Chain, data: Self::DeployData) -> Result<Self, Self::Error> {
        let circuit = HeadstashCircuitSuite::new(chain.clone());
        let manifold = CwHeadstashManifold::new(chain.clone());
        let headstash = HeadstashContract::new(chain.clone());

        circuit.upload_circuit()?;
        manifold.upload()?;
        headstash.upload()?;

        let headstash_code_id = headstash.code_id()?;
        manifold.instantiate(
            &ManifoldInstantiateMsg {
                owner: data.owner,
                headstash_code_id,
            },
            None,
            &[],
        )?;
        headstash.instantiate(&data.headstash_init, None, &[])?;

        Ok(Self {
            headstash,
            manifold,
            circuit,
        })
    }
}

/// Deploy configuration for the ZK headstash system.
#[derive(Clone, Debug)]
pub struct HeadstashDeployData {
    /// Owner address for the manifold factory.
    pub owner: Option<String>,
    /// Instantiate message for the cw-headstash contract.
    pub headstash_init: cw_headstash::msg::InstantiateMsg,
}

impl HeadstashDeployData {
    /// Create deploy data for a local test deployment.
    ///
    /// `genesis_root` is the hex-encoded merkle root of the headstash tree.
    /// `vk_combined_path` is the path to `vk_combined.bin` (optional).
    /// Create deploy data for a local test deployment.
    ///
    /// Uses `ExistingFungible` token strategy with `uterp` for simplicity.
    /// `genesis_root` is the raw merkle root bytes.
    /// `vk_combined_path` points to `vk_combined.bin` (optional).
    pub fn local_default(admin: Addr, genesis_root: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            owner: Some(admin.to_string()),
            headstash_init: cw_headstash::msg::InstantiateMsg {
                genesis_root: Binary::from(genesis_root.to_vec()),
                token_strategy: TokenStrategy::ExistingFungible(HeadstashTokenObject {
                    proof: Binary::default(),
                    raw: "uterp".into(),
                }),
                wavs: WavsProofOfOwnership {
                    poos: vec![],
                    msg: WavsAuthMetadata {
                        aggregate_key: String::new(),
                        threshold: 0,
                        total_operators: 0,
                        nonce: 0,
                    },
                },
            },
        })
    }
}

// // ─── Error ───────────────────────────────────────────────────────────────────

// #[derive(Debug, thiserror::Error)]
// pub enum ZkDeployError {
//     #[error("cw-orch error: {0}")]
//     CwEnv(#[from] IctError),
//     #[error("io error: {0}")]
//     Io(#[from] std::io::Error),
//     #[error("json error: {0}")]
//     Json(#[from] serde_json::Error),
//     #[error("deploy error: {0}")]
//     Other(String),
// }

// // ─── Zero-sized circuit bridge ───────────────────────────────────────────────

// /// Zero-sized bridge struct — implements the ict-rs `Circuit` trait for
// /// the Headstash Orchard circuit.
// pub struct HeadstashZkCircuit;

// /// Verifying key for the headstash Orchard circuit.
// pub struct HeadstashVerifyingKey {
//     pub params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
//     pub vk: plonk::VerifyingKey<vesta::Affine>,
// }

// /// Zero-sized bridge binding cw-headstash to the ict-rs `Contract` trait.
// ///
// /// The actual WASM is deployed via cw-orch; this only provides
// /// VK validation helpers used during `store-circuit`.
// pub struct HeadstashContractBridge;

// impl Contract for HeadstashContractBridge {
//     type Circuit = HeadstashZkCircuit;

//     fn contract_name() -> &'static str {
//         "cw-headstash"
//     }

//     fn wasm_byte_code() -> &'static [u8] {
//         &[]
//     }

//     fn validate_vk_header(vk_bytes: &[u8]) -> std::result::Result<(), ZkSuiteError> {
//         if vk_bytes.len() < 32 {
//             return Err(ZkSuiteError::VkValidation(
//                 "vk too short (< 32 bytes)".into(),
//             ));
//         }
//         Ok(())
//     }

//     fn validate_vk_footer(vk_bytes: &[u8]) -> std::result::Result<(), ZkSuiteError> {
//         if vk_bytes.len() < COSMWASM_METADATA_LENGTH {
//             return Err(ZkSuiteError::VkValidation(format!(
//                 "vk missing footer: need {}, got {}",
//                 COSMWASM_METADATA_LENGTH,
//                 vk_bytes.len()
//             )));
//         }
//         Ok(())
//     }
// }

// // // ─── HeadstashSuite ──────────────────────────────────────────────────────────

// // /// Development suite for the ZK Headstash Orchard circuit.
// // ///
// // /// Manages key generation, proof creation, and circuit binary upload.
// // /// Contract deployment is handled separately via cw-orch.
// // pub struct HeadstashSuite {
// //     pub circuit: HeadstashZkCircuit,
// //     pub deploy_data: Option<HeadstashDeployData>,
// //     keys_dir: PathBuf,
// // }

// // impl HeadstashSuite {
// //     pub fn new() -> Self {
// //         Self {
// //             circuit: HeadstashZkCircuit,
// //             deploy_data: None,
// //             keys_dir: PathBuf::from("/tmp/headstash-keys"),
// //         }
// //     }

// //     pub fn with_keys_dir<P: Into<PathBuf>>(keys_dir: P) -> Self {
// //         Self {
// //             circuit: HeadstashZkCircuit,
// //             deploy_data: None,
// //             keys_dir: keys_dir.into(),
// //         }
// //     }
// // }

// // ─── Circuit upload helper ───────────────────────────────────────────────────

// // ─── Circuit trait impl ──────────────────────────────────────────────────────

// impl Circuit for HeadstashZkCircuit {
//     type Params = Vec<u8>;
//     type ProvingKey = ProvingKey;
//     type VerifyingKey = HeadstashVerifyingKey;
//     type Proof = Proof;
//     type PublicInputs = HeadstashCircuitInputs;

//     fn circuit_name() -> &'static str {
//         "headstash"
//     }

//     fn keygen(
//         params_bytes: &Self::Params,
//     ) -> std::result::Result<(Self::ProvingKey, Self::VerifyingKey), ZkSuiteError> {
//         let p = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut Cursor::new(
//             params_bytes,
//         ))
//         .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;

//         let circuit = OrchardCircuit::default();
//         let vk = plonk::keygen_vk(&p, &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_vk: {:?}", e)))?;
//         let pk = plonk::keygen_pk(&p, vk.clone(), &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_pk: {:?}", e)))?;

//         Ok((
//             ProvingKey::build(11, CosmwasmCircuit::from(OrchardCircuit::default())),
//             HeadstashVerifyingKey { params: p, vk },
//         ))
//     }

//     fn prove(
//         _params_bytes: &Self::Params,
//         pk: &Self::ProvingKey,
//         inputs: &Self::PublicInputs,
//     ) -> std::result::Result<Self::Proof, ZkSuiteError> {
//         use zk_headstash::builder::SpendInfo;

//         let r = inputs.note.rseed().as_bytes();
//         let spk = SpendingKey::from_bytes(*r);
//         let fvk = if bool::from(spk.is_some()) {
//             FullViewingKey::from(&spk.unwrap())
//         } else {
//             return Err(ZkSuiteError::Circuit(
//                 "SpendingKey derivation failed".into(),
//             ));
//         };

//         let spend_info = SpendInfo::new(fvk, inputs.note.clone(), inputs.mp.clone())
//             .ok_or_else(|| ZkSuiteError::Circuit("SpendInfo creation failed".into()))?;
//         let circuit =
//             OrchardCircuit::from_action_context_unchecked(spend_info, inputs.note.clone());

//         let nf = inputs.note.nullifier();
//         let cmx = zk_headstash::note::ExtractedNoteCommitment::from(inputs.note.commitment());
//         let instance = OrchardInstance::from_parts(
//             inputs.anchor,
//             inputs.hv.denom(),
//             inputs.hv.amount(),
//             inputs.recp,
//             nf,
//             cmx,
//         );

//         Proof::create(
//             pk,
//             &[CosmwasmCircuit::from(circuit)],
//             &[Instance::new_from_vm(instance.to_bytes())
//                 .map_err(|e| ZkSuiteError::Circuit(format!("Instance::new_from_vm: {:?}", e)))?],
//             &mut OsRng,
//         )
//         .map_err(|e| ZkSuiteError::Circuit(format!("create_proof: {:?}", e)))
//     }

//     fn verify(
//         _params_bytes: &Self::Params,
//         vk: &Self::VerifyingKey,
//         proof: &Self::Proof,
//         inputs: &Self::PublicInputs,
//     ) -> std::result::Result<(), ZkSuiteError> {
//         let nf = inputs.note.nullifier();
//         let cmx = zk_headstash::note::ExtractedNoteCommitment::from(inputs.note.commitment());
//         let instance = OrchardInstance::from_parts(
//             inputs.anchor,
//             inputs.hv.denom(),
//             inputs.hv.amount(),
//             inputs.recp,
//             nf,
//             cmx,
//         );
//         let cosmwasm_vk =
//             zk_cosmwasm::VerifyingKey::new_with_params(vk.params.clone(), vk.vk.clone(), 1);
//         proof
//             .verify(
//                 &cosmwasm_vk,
//                 &[Instance::new_from_vm(instance.to_bytes()).map_err(|e| {
//                     ZkSuiteError::Circuit(format!("Instance::new_from_vm: {:?}", e))
//                 })?],
//             )
//             .map_err(|e| ZkSuiteError::Verification(format!("{:?}", e)))
//     }

//     fn proof_to_bytes(proof: &Self::Proof) -> Vec<u8> {
//         // zk_cosmwasm::Proof is a newtype Proof(Vec<u8>)
//         // SAFETY: Proof has identical layout to Vec<u8>
//         unsafe { &*(proof as *const Proof as *const Vec<u8>) }.clone()
//     }

//     fn vk_to_bytes(vk: &Self::VerifyingKey) -> Vec<u8> {
//         let mut out = Vec::new();
//         vk.params.write(&mut out).expect("params write");
//         vk.vk.write(&mut out).expect("vk write");
//         out
//     }

//     fn vk_from_bytes(bytes: &[u8]) -> std::result::Result<Self::VerifyingKey, ZkSuiteError> {
//         let mut cursor = Cursor::new(bytes);
//         let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(&mut cursor)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         let vk =
//             plonk::VerifyingKey::<vesta::Affine>::read::<_, OrchardCircuit>(&mut cursor, &params)
//                 .map_err(|e| ZkSuiteError::Circuit(format!("read vk: {:?}", e)))?;
//         Ok(HeadstashVerifyingKey { params, vk })
//     }
// }

// // ─── TerpVmSuite impl ───────────────────────────────────────────────────────

// #[async_trait]
// impl<Chain: CwEnv> TerpVmSuite for HeadstashSuite<Chain> {
//     type Circuit = HeadstashZkCircuit;
//     type Contract = HeadstashContractBridge;
//     type Chain = CosmosChain;

//     fn keys_dir(&self) -> &Path {
//         &self.headstash.
//     }

//     fn load_circuit_keys(
//         &self,
//     ) -> std::result::Result<(ProvingKey, HeadstashVerifyingKey), ZkSuiteError> {
//         let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::read(
//             &mut std::fs::File::open(self.keys_dir().join("params.bin"))?,
//         )
//         .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;

//         let vk = plonk::VerifyingKey::<vesta::Affine>::read::<_, OrchardCircuit>(
//             &mut std::fs::File::open(self.keys_dir.join("verifying_key.bin"))?,
//             &params,
//         )
//         .map_err(|e| ZkSuiteError::Circuit(format!("read vk: {:?}", e)))?;

//         Ok((
//             ProvingKey::build(11, CosmwasmCircuit::from(OrchardCircuit::default())),
//             HeadstashVerifyingKey { params, vk },
//         ))
//     }

//     fn save_circuit_keys(
//         &self,
//         _pk: &ProvingKey,
//         vk: &HeadstashVerifyingKey,
//     ) -> std::result::Result<(), ZkSuiteError> {
//         std::fs::create_dir_all(&self.keys_dir())?;

//         let mut pf = BufWriter::new(std::fs::File::create(self.keys_dir.join("params.bin"))?);
//         vk.params
//             .write(&mut pf)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         pf.flush()?;

//         let mut vf = BufWriter::new(std::fs::File::create(
//             self.keys_dir().join("verifying_key.bin"),
//         )?);
//         vk.vk
//             .write(&mut vf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         vf.flush()?;
//         Ok(())
//     }

//     fn build_and_save_keys(&self, k: u32) -> std::result::Result<(), ZkSuiteError> {
//         std::fs::create_dir_all(&self.keys_dir)?;

//         const INSTANCE_COLS: u8 = 1;

//         let mut cs = plonk::ConstraintSystem::<Fp>::default();
//         {
//             use halo2_proofs::plonk::Circuit as HCircuit;
//             let _ = <OrchardCircuit as HCircuit<Fp>>::configure(&mut cs);
//         }

//         let p = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(k);
//         let circuit = OrchardCircuit::default();
//         let vk = plonk::keygen_vk(&p, &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_vk: {:?}", e)))?;
//         let pk = plonk::keygen_pk(&p, vk.clone(), &circuit)
//             .map_err(|e| ZkSuiteError::Circuit(format!("keygen_pk: {:?}", e)))?;

//         // params.bin
//         let mut pf = BufWriter::new(std::fs::File::create(self.keys_dir.join("params.bin"))?);
//         p.write(&mut pf)
//             .map_err(|e| ZkSuiteError::Circuit(e.to_string()))?;
//         pf.flush()?;

//         // verifying_key.bin
//         let mut vf = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("verifying_key.bin"),
//         )?);
//         vk.write(&mut vf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         vf.flush()?;

//         // proving_key.bin (vk for reference)
//         let mut pkf = BufWriter::new(std::fs::File::create(
//             self.keys_dir.join("proving_key.bin"),
//         )?);
//         pk.get_vk()
//             .write(&mut pkf)
//             .map_err(|e| ZkSuiteError::Circuit(format!("{:?}", e)))?;
//         pkf.flush()?;

//         // vk_combined.bin
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
//             false,
//             0,
//         );
//         let footer_bytes = footer.to_bytes();
//         assert_eq!(
//             footer_bytes.len(),
//             COSMWASM_METADATA_LENGTH,
//             "footer size mismatch"
//         );
//         combined.write_all(&footer_bytes)?;
//         combined.flush()?;

//         Ok(())
//     }

//     fn prove(&self, inputs: &HeadstashCircuitInputs) -> std::result::Result<Proof, ZkSuiteError> {
//         let params_bytes = std::fs::read(self.keys_dir.join("params.bin"))?;
//         let (pk, _) = self.load_circuit_keys()?;
//         <HeadstashZkCircuit as Circuit>::prove(&params_bytes, &pk, inputs)
//     }

//     fn verify(
//         &self,
//         proof: &Proof,
//         inputs: &HeadstashCircuitInputs,
//     ) -> std::result::Result<(), ZkSuiteError> {
//         let params_bytes = std::fs::read(self.keys_dir.join("params.bin"))?;
//         let (_, vk) = self.load_circuit_keys()?;
//         <HeadstashZkCircuit as Circuit>::verify(&params_bytes, &vk, proof, inputs)
//     }

//     async fn deploy(
//         &self,
//         chain: &CosmosChain,
//         deployer_key: &str,
//     ) -> std::result::Result<DeployedContract, ZkSuiteError> {
//         let vk_combined = std::fs::read(self.keys_dir.join("vk_combined.bin"))
//             .map_err(|e| ZkSuiteError::KeyIo(e))?;
//         HeadstashContractBridge::validate_vk_header(&vk_combined)?;
//         HeadstashContractBridge::validate_vk_footer(&vk_combined)?;

//         let b64 = base64::engine::general_purpose::STANDARD.encode(&vk_combined);
//         let remote = "/tmp/headstash_circuit.bin";
//         chain
//             .chain_exec(&[
//                 "sh",
//                 "-c",
//                 &format!("echo '{}' | base64 -d > {}", b64, remote),
//             ])
//             .await
//             .map_err(|e| ZkSuiteError::Deploy(format!("copy circuit: {e}")))?;

//         let out = chain
//             .chain_exec(&[
//                 "terpd",
//                 "tx",
//                 "wasm",
//                 "store-circuit",
//                 remote,
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
//             .map_err(|e| ZkSuiteError::Deploy(format!("store-circuit: {e}")))?;

//         let json: serde_json::Value = serde_json::from_slice(&out.stdout)
//             .map_err(|e| ZkSuiteError::Deploy(format!("parse output: {e}")))?;
//         let code_id: u64 = json
//             .pointer("/logs/0/events/0/attributes/0/value")
//             .or_else(|| json.get("circuit_id"))
//             .and_then(|v| v.as_str())
//             .and_then(|s| s.parse().ok())
//             .ok_or_else(|| ZkSuiteError::Deploy("could not parse circuit_id".into()))?;

//         Ok(DeployedContract {
//             code_id,
//             contract_addr: String::new(),
//             vk_registered: false,
//         })
//     }
// }

// // ─── Input type ──────────────────────────────────────────────────────────────

// pub struct HeadstashCircuitInputs {
//     pub anchor: Anchor,
//     pub mp: MerklePath,
//     pub esk: EligibleSk,
//     pub recp: RecpAddr,
//     pub hv: HeadstashValue,
//     pub note: Note,
// }
