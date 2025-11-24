use cosmwasm_std::{
    Api, BLS12_381_G1_GENERATOR, BLS12_381_G2_GENERATOR, HashFunction, StdError, StdResult,
    to_json_binary,
};

use sha2::{Digest, Sha256};

#[cosmwasm_schema::cw_serde]
pub struct OperatorObject {
    // bls12_381 public key
    pub key: String,
    // proof of ownership signature of H(AuthorizationMessage) from the public key
    pub poo_signature: String,
}

// AuthorizationMessage is the object hashed and signed by all operator keys.
#[cosmwasm_schema::cw_serde]
struct AuthorizationMessage {
    aggregate_key: String,
    threshold: usize,
    total_operators: usize,
    nonce: u64,
}

#[cosmwasm_schema::cw_serde]
pub struct WavsObject {
    /// bech32 address wavs operator set controls
    pub address: String,
    /// list of aggregated keys (used for proof of ownership )
    pub keys: Vec<OperatorObject>,
    msg: AuthorizationMessage,
}

impl WavsObject {
    pub fn proof_of_possesion(&self, api: &dyn Api) -> StdResult<()> {
        for p in &self.keys {
            assert!(api.bls12_381_pairing_equality(
                &BLS12_381_G1_GENERATOR,
                p.key.as_bytes(),
                p.poo_signature.as_bytes(),
                &api.bls12_381_hash_to_g2(
                    HashFunction::Sha256,
                    &Sha256::digest(to_json_binary(&p.key.as_bytes())?.to_vec()),
                    &BLS12_381_G2_GENERATOR
                )?,
            )?);
        }
        Ok(())
    }

    pub fn verify(&self, api: &dyn Api, nonce: u64) -> StdResult<()> {
        if self.msg.nonce != nonce {
            return Err(StdError::generic_err("incorrect nonce"));
        }

        // aggregate all keys & signatures together
        let g: Vec<&[u8]> = self
            .keys
            .iter()
            .flat_map(|item| [item.key.as_bytes(), item.poo_signature.as_bytes()].into_iter())
            .collect();

        let aggregated_g1 = api.bls12_381_aggregate_g1(g[0])?;
        let aggregated_g2 = api.bls12_381_aggregate_g2(g[1])?;

        // ensure aggregate key matches self.msg.aggregate_key
        if self.msg.aggregate_key.as_bytes() != aggregated_g1 {
            return Err(StdError::generic_err("aggregate key does not match"));
        }

        // ensures all keys signed the hash of self.msg by verifying the aggregate pubkey & signature
        assert!(api.bls12_381_pairing_equality(
            &BLS12_381_G1_GENERATOR,
            &aggregated_g2,
            &aggregated_g1,
            &api.bls12_381_hash_to_g2(
                HashFunction::Sha256,
                &Sha256::digest(to_json_binary(&self.msg)?.to_vec()),
                &BLS12_381_G2_GENERATOR
            )?,
        )?);
        Ok(())
    }

    fn handle_key_rotation() -> StdResult<()> {
        Ok(())
    }
}
