use cosmwasm_schema::{QueryResponses, cw_serde};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    Binary, Checksum, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
    VerificationError,
};
use ff::PrimeField;
use pasta_curves::{Fp, vesta};
use thiserror::Error;

#[cw_serde]
pub struct Config {
    /// words we are prooving a privte instance does not contain
    pub words: Vec<String>,
}

// pub const CONFIG: Item<Config> = Item::new("config");
// pub const MOCK_DATA: Item<Vec<u8>> = Item::new("mock_data");

const CONTRACT_NAME: &str = "crates.io:cw-cadence";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    Proove {
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

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
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
            Ok(Response::default())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VkChecksum {} => unimplemented!(),
    }
}

// sudo msg
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, _env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    Ok(Response::default())
}

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

// #[test]
// fn test_gas_consumption() -> StdResult<()> {
//     #![cfg(not(target_arch = "wasm32"))]
//     let mut deps = cosmwasm_std::testing::mock_dependencies();
//     MOCK_DATA.save(&mut deps.storage, &vec![])?;
//     CONFIG.save(&mut deps.storage, &Config { val: 2 })?;

//     increment(deps.as_mut())?;

//     let data = MOCK_DATA.load(&deps.storage)?;
//     let byte_count = data.len();

//     println!("Byte count: {}", byte_count);

//     Ok(())
// }
