extern crate alloc;

#[cfg(feature = "interface")]
pub mod interface;
#[cfg(feature = "interface")]
pub use interface::NoRickContractSuite;

// ── Circuit bridge primitives ────────────────────────────────────────────────
// These types are the contract between zk-cosmwasm circuits and the CosmWasm
// host. They are always available (no feature gate) since they are pure
// Vec<u8> / generic wrappers with no heavy dependencies.

/// Wraps a concrete halo2 circuit so it can be named uniformly across the
/// headstash proving pipeline and the on-chain CosmWasm verifier.
pub struct CosmwasmCircuit<C> {
    inner: C,
}

impl<C> CosmwasmCircuit<C> {
    /// Wrap a circuit instance.
    pub fn new(inner: C) -> Self {
        Self { inner }
    }
    /// Borrow the wrapped circuit.
    pub fn inner(&self) -> &C {
        &self.inner
    }
    /// Consume and unwrap.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: Clone> Clone for CosmwasmCircuit<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Public instance values for a proof, stored as a flat byte vector.
///
/// On-chain the VM passes instances as raw bytes; use `new_from_vm` to decode.
#[derive(Clone, Debug, Default)]
pub struct Instance(pub Vec<u8>);

impl Instance {
    /// Construct from the byte representation produced by the on-chain VM.
    pub fn new_from_vm(bytes: Vec<u8>) -> Option<Self> {
        Some(Self(bytes))
    }
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A serialised halo2 proof blob.
///
/// `Proof::create` is a stub — fill in the halo2 `create_proof` call in the
/// circuit crate's concrete implementation once the proving key format is
/// settled.
#[derive(Clone, Debug)]
pub struct Proof(pub Vec<u8>);

impl Proof {
    /// Wrap existing proof bytes (e.g. read from disk).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Consume into owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Create a proof.
    ///
    /// **Stub** — replace with `halo2_proofs::plonk::create_proof` once the
    /// proving-key format and transcript strategy are finalised.
    #[allow(unused_variables)]
    pub fn create<C>(
        pk: &ProvingKey,
        circuits: &[CosmwasmCircuit<C>],
        instances: &[Instance],
        rng: &mut impl rand_core::RngCore,
    ) -> Result<Self, alloc::boxed::Box<dyn core::fmt::Debug>> {
        todo!("implement with halo2_proofs::plonk::create_proof")
    }
}

/// Opaque proving-key wrapper (bytes serialised by the circuit-specific
/// `ProvingKey::build_and_write` method).
#[derive(Clone)]
pub struct ProvingKey(pub Vec<u8>);

impl ProvingKey {
    /// Wrap already-serialised proving-key bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// Serialised bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Build a proving key and persist it to `path`.
    ///
    /// **Stub** — replace with `halo2_proofs::plonk::keygen_pk` call in the
    /// concrete circuit implementation.
    pub fn build_and_write(path: &str) -> Result<Self, alloc::string::String> {
        todo!("implement with halo2_proofs::plonk::keygen_pk")
    }
}

/// Circuit-specific proof and instance helpers, re-exported under the
/// `example_circuits` namespace so callers can do:
/// ```ignore
/// use zk_cosmwasm::example_circuits::NoRickProof;
/// ```
pub mod example_circuits {
    /// Proof type for the No-Rick circuit.
    pub type NoRickProof = super::Proof;
    /// Instance type for the No-Rick circuit.
    pub type NoRickInstance = super::Instance;
}

// ────────────────────────────────────────────────────────────────────────────

// #[cfg(target_arch = "wasm32")]
// use lol_alloc::{AssumeSingleThreaded, FreeListAllocator};
// // SAFETY: This application is single threaded, so using AssumeSingleThreaded is allowed.
// #[cfg(target_arch = "wasm32")]
// #[global_allocator]
// static ALLOCATOR: AssumeSingleThreaded<FreeListAllocator> =
//     unsafe { AssumeSingleThreaded::new(FreeListAllocator::new()) };

use cosmwasm_schema::{QueryResponses, cw_serde};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    AnyMsg, Binary, Checksum, CosmosMsg, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, VerificationError,
};
use ff::PrimeField;
use pasta_curves::{Fp, vesta};
use prost::Message as _;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Tokenfactory protobuf types (mirrors terp_rs::osmosis::tokenfactory::v1beta1)
// ---------------------------------------------------------------------------

/// cosmos.base.v1beta1.Coin
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtoCoin {
    #[prost(string, tag = "1")]
    pub denom: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub amount: ::prost::alloc::string::String,
}

/// osmosis.tokenfactory.v1beta1.MsgCreateDenom
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCreateDenom {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub subdenom: ::prost::alloc::string::String,
}

/// osmosis.tokenfactory.v1beta1.MsgMint
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgMint {
    #[prost(string, tag = "1")]
    pub sender: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub amount: ::core::option::Option<ProtoCoin>,
    #[prost(string, tag = "3")]
    pub mint_to_address: ::prost::alloc::string::String,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RICK_SUBDENOM: &str = "rick";
const RANDY_SUBDENOM: &str = "randy";
const CREATE_DENOM_TYPE_URL: &str = "/osmosis.tokenfactory.v1beta1.MsgCreateDenom";
const MINT_TYPE_URL: &str = "/osmosis.tokenfactory.v1beta1.MsgMint";

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

#[cw_serde]
pub struct Config {
    /// words we are prooving a privte instance does not contain
    pub words: Vec<String>,
}

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    /// Verify proof only — no side effects
    Proove {
        cid: u64,
        forbidden: String,
        proof: Binary,
    },
    /// Verify proof and mint rick/randy token via x/tokenfactory
    ProoveAndMint {
        cid: u64,
        forbidden: String,
        proof: Binary,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(Checksum)]
    VkChecksum {},
}

#[derive(Error, Debug)]
pub enum Never {}

#[cw_serde]
pub enum SudoMsg {}

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    VerificationError(#[from] VerificationError),
    #[error("invalid proof")]
    InalidProof {},
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let contract_addr = env.contract.address.to_string();

    // Create "rick" denom — minted when proof shows content contained rick
    let create_rick = CosmosMsg::Any(AnyMsg {
        type_url: CREATE_DENOM_TYPE_URL.to_string(),
        value: Binary::from(
            MsgCreateDenom {
                sender: contract_addr.clone(),
                subdenom: RICK_SUBDENOM.to_string(),
            }
            .encode_to_vec(),
        ),
    });

    // Create "randy" denom — minted when proof shows content did NOT contain rick
    let create_randy = CosmosMsg::Any(AnyMsg {
        type_url: CREATE_DENOM_TYPE_URL.to_string(),
        value: Binary::from(
            MsgCreateDenom {
                sender: contract_addr,
                subdenom: RANDY_SUBDENOM.to_string(),
            }
            .encode_to_vec(),
        ),
    });

    Ok(Response::new()
        .add_message(create_rick)
        .add_message(create_randy)
        .add_attribute("method", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Proove {
            cid,
            forbidden,
            proof,
        } => {
            if !deps.api.halo2_proof_instance_verify(
                cid.into(),
                &proof,
                &to_cosmwasm_instance(&forbidden),
            )? {
                return Err(ContractError::InalidProof {});
            }
            Ok(Response::new().add_attribute("action", "proove"))
        }
        ExecuteMsg::ProoveAndMint {
            cid,
            forbidden,
            proof,
        } => {
            let valid = deps.api.halo2_proof_instance_verify(
                cid.into(),
                &proof,
                &to_cosmwasm_instance(&forbidden),
            )?;

            let contract_addr = env.contract.address.to_string();
            let recipient = info.sender.to_string();

            // valid proof → content is rick-free → mint "randy"
            // invalid proof → content contained rick → mint "rick"
            let subdenom = if valid { RANDY_SUBDENOM } else { RICK_SUBDENOM };
            let denom = format!("factory/{}/{}", contract_addr, subdenom);

            let mint_msg = CosmosMsg::Any(AnyMsg {
                type_url: MINT_TYPE_URL.to_string(),
                value: Binary::from(
                    MsgMint {
                        sender: contract_addr,
                        amount: Some(ProtoCoin {
                            denom,
                            amount: "1".to_string(),
                        }),
                        mint_to_address: recipient,
                    }
                    .encode_to_vec(),
                ),
            });

            Ok(Response::new()
                .add_message(mint_msg)
                .add_attribute("action", "proove_and_mint")
                .add_attribute("result", subdenom))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VkChecksum {} => unimplemented!(),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(_deps: DepsMut, _env: Env, _msg: SudoMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

// ---------------------------------------------------------------------------
// Instance serialization helpers
// ---------------------------------------------------------------------------

/// serialize instances into set of circuit field bytes with lenth `I`,specifically for cosmwasm-std api
pub fn to_cosmwasm_instance(forbidden: &str) -> Vec<u8> {
    let instances = to_halo2_instance(forbidden);
    let mut bytes = Vec::with_capacity(1 * 32);
    for instance_row in instances.iter() {
        for scalar in instance_row.iter() {
            // to_repr() returns a 32-byte little-endian representation
            bytes.extend_from_slice(scalar.to_repr().as_ref());
        }
    }
    bytes
}

/// serialize instances into set of circuit field [vesta::Scalar] with lenth `I`
/// Must match NoRickInstance::to_halo2_instance() which uses 2 elements:
/// [0] = Fp::one() (constraint result)
/// [1] = str_to_field(forbidden) (the forbidden word)
pub fn to_halo2_instance(f: &str) -> [[vesta::Scalar; 1]; 1] {
    let mut instance = [vesta::Scalar::zero(); 1];
    instance[0] = str_to_field(&f);
    [instance]
}
/// string to field
pub fn str_to_field<F: PrimeField>(s: &str) -> F {
    let mut repr = F::default().to_repr();
    let src = s.as_bytes();
    let len = core::cmp::min(src.len(), repr.as_ref().len());
    repr.as_mut()[..len].copy_from_slice(&src[..len]);
    F::from_repr(repr).expect("str_to_field")
}
