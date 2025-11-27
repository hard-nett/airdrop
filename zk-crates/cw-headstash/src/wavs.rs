use cosmwasm_std::{
    Api, BLS12_381_G1_GENERATOR as G1, BLS12_381_G2_GENERATOR as G2, HashFunction, StdError,
    StdResult, to_json_binary,
};

use sha2::{Digest, Sha256};

#[cosmwasm_schema::cw_serde]
pub struct OperatorAuth {
    /// `bls12_381` public key
    pub key: String,
    /// proof of ownership signature of `H(WavsOpsAuthMsg)` from the public key
    pub poo: String,
}

// WavsOpsAuthMsg is the object hashed and signed by all operator keys.
#[cosmwasm_schema::cw_serde]
pub struct WavsOpsAuthMsg {
   pub aggregate_key: String,
   pub threshold: usize,
   pub total_operators: usize,
   pub nonce: u64,
}

#[cosmwasm_schema::cw_serde]
pub struct WavsOperatorSet {
    /// bech32 address wavs operator set controls (expected to be this smart contract)
    pub address: String,
    /// list of aggregated keys (used for proof of ownership )
    pub keys: Vec<OperatorAuth>,
    /// msg that is hashed and signed by wavs operators.
    pub msg: WavsOpsAuthMsg,
}

impl WavsOperatorSet {
    pub fn proof_of_possesion(&self, api: &dyn Api) -> StdResult<()> {
        for p in &self.keys {
            let kb = hex::decode(&p.key)?;
            let htg2 = api.bls12_381_hash_to_g2(HashFunction::Sha256, &kb, &G2)?;
            let s = hex::decode(&p.poo)?;
            if !api.bls12_381_pairing_equality(&kb, &htg2, &G1, &s)? {
                return Err(StdError::msg("proof of ownership failed"));
            }
        }
        Ok(())
    }

    pub fn verify(&self, api: &dyn Api) -> StdResult<()> {
        // if self.msg.nonce != nonce {
        //     return Err(StdError::msg("incorrect nonce"));
        // }
        let g: Vec<&[u8]> = self
            .keys
            .iter()
            .flat_map(|i| [i.key.as_bytes(), i.poo.as_bytes()].into_iter())
            .collect();
        let agg_g1 = api.bls12_381_aggregate_g1(g[0])?;
        let agg_g2 = api.bls12_381_aggregate_g2(g[1])?;
        if self.msg.aggregate_key.as_bytes() != agg_g1 {
            return Err(StdError::msg("aggregate key does not match"));
        }
        let g2 = &api.bls12_381_hash_to_g2(
            HashFunction::Sha256,
            &Sha256::digest(to_json_binary(&self.msg)?.to_vec()),
            &G2,
        )?;
        if !api.bls12_381_pairing_equality(&G1, &agg_g2, &agg_g1, g2)? {
            return Err(StdError::msg("incorrect signature verification"));
        }
        Ok(())
    }

    fn handle_key_rotation() -> StdResult<()> {
        // validate key rotating is in current set & has a valid signature for key rotation
        // update state to replace old pubkey with new pubkey
        // calculate new aggregated pk
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use cosmwasm_std::testing::MockApi;
    use rand_core::OsRng;

    // Helper to serialize G1 point
    fn serialize_g1(point: &G1Affine) -> Vec<u8> {
        let mut serialized = Vec::new();
        point.serialize_compressed(&mut serialized).unwrap();
        serialized
    }

    // Helper to serialize G2 point
    fn serialize_g2(point: &G2Affine) -> Vec<u8> {
        let mut serialized = Vec::new();
        point.serialize_compressed(&mut serialized).unwrap();
        serialized
    }

    // Helper to create a key pair and proof of possession
    fn create_operator(api: &dyn Api, secret_key: &Fr) -> (OperatorAuth, G2Affine) {
        // Generate public key in G1: pk = sk * G1_generator
        let public_key: G1Affine = (G1Affine::generator() * secret_key).into();
        let pk_bytes = serialize_g1(&public_key);

        // Hash the public key to G2 for PoP
        // IMPORTANT: Hash the raw key bytes, NOT Sha256::digest of them
        let pop_hash = api
            .bls12_381_hash_to_g2(HashFunction::Sha256, &pk_bytes, &G2)
            .unwrap();

        // Deserialize to compute signature
        let pop_hash_point = G2Affine::deserialize_compressed(&pop_hash[..]).unwrap();

        // Sign: pop_sig = sk * H(pk)
        let pop_signature: G2Affine = (pop_hash_point * secret_key).into();
        let pop_sig_bytes = serialize_g2(&pop_signature);

        (
            OperatorAuth {
                key: hex::encode(&pk_bytes),
                poo: hex::encode(&pop_sig_bytes),
            },
            pop_signature,
        )
    }

    #[test]
    fn test_bls12_381_pop() {
        let api = MockApi::default();
        let secret_key = Fr::rand(&mut OsRng);
        let (operator, _) = create_operator(&api, &secret_key);
        let kb = hex::decode(&operator.key).unwrap();
        let s = hex::decode(&operator.poo).unwrap();
        let hash_to_g2 = api
            .bls12_381_hash_to_g2(HashFunction::Sha256, &kb, &G2)
            .unwrap();

        // 4. Verify pairing equality: e(pk, H(pk)) == e(G1_gen, signature)
        let result = api.bls12_381_pairing_equality(&kb, &hash_to_g2, &G1, &s);

        assert!(result.unwrap(), "Pairing equality should hold");
    }

    #[test]
    fn test_proof_of_possession_valid_single_key() {
        let api = MockApi::default();

        let secret_key = Fr::rand(&mut OsRng);
        let (operator, _) = create_operator(&api, &secret_key);

        let public_key_bytes = hex::decode(&operator.key).unwrap();

        let wavs = WavsOperatorSet {
            address: "cosmos1test".to_string(),
            keys: vec![operator],
            msg: WavsOpsAuthMsg {
                aggregate_key: hex::encode(&public_key_bytes),
                threshold: 1,
                total_operators: 1,
                nonce: 42,
            },
        };

        // Should pass
        let result = wavs.proof_of_possesion(&api);
        assert!(
            result.is_ok(),
            "PoP verification should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_proof_of_possession_invalid_signature() {
        let api = MockApi::default();

        let secret_key = Fr::rand(&mut OsRng);
        let public_key: G1Affine = (G1Affine::generator() * secret_key).into();
        let pk_bytes = serialize_g1(&public_key);

        // Create invalid signature using wrong secret key
        let wrong_secret_key = Fr::rand(&mut OsRng);
        let pop_hash = api
            .bls12_381_hash_to_g2(HashFunction::Sha256, &pk_bytes, &G2)
            .unwrap();
        let pop_hash_point = G2Affine::deserialize_compressed(&pop_hash[..]).unwrap();
        let wrong_signature: G2Affine = (pop_hash_point * wrong_secret_key).into();

        let operator = OperatorAuth {
            key: hex::encode(&pk_bytes),
            poo: hex::encode(serialize_g2(&wrong_signature)),
        };

        let wavs = WavsOperatorSet {
            address: "cosmos1test".to_string(),
            keys: vec![operator],
            msg: WavsOpsAuthMsg {
                aggregate_key: hex::encode(&pk_bytes),
                threshold: 1,
                total_operators: 1,
                nonce: 42,
            },
        };

        // Should fail
        let result = wavs.proof_of_possesion(&api);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("proof of ownership failed")
        );
    }

    #[test]
    fn test_proof_of_possession_multiple_keys() {
        let api = MockApi::default();

        // Generate 3 operators
        let secret_keys: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut OsRng)).collect();
        let operators: Vec<OperatorAuth> = secret_keys
            .iter()
            .map(|sk| create_operator(&api, sk).0)
            .collect();

        // Aggregate public keys
        let public_keys: Vec<G1Affine> = secret_keys
            .iter()
            .map(|sk| (G1Affine::generator() * sk).into())
            .collect();

        let agg_pk: G1Affine = public_keys
            .iter()
            .fold(G1Projective::default(), |acc, pk| acc + pk)
            .into();

        let wavs = WavsOperatorSet {
            address: "cosmos1test".to_string(),
            keys: operators,
            msg: WavsOpsAuthMsg {
                aggregate_key: hex::encode(serialize_g1(&agg_pk)),
                threshold: 2,
                total_operators: 3,
                nonce: 100,
            },
        };

        // All PoPs should be valid
        let result = wavs.proof_of_possesion(&api);
        assert!(
            result.is_ok(),
            "All PoPs should be valid: {:?}",
            result.err()
        );
    }
}
