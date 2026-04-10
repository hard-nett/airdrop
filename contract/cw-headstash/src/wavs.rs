use cosmwasm_std::{
    Addr, Api, BLS12_381_G1_GENERATOR as G1, BLS12_381_G2_GENERATOR as G2, Binary, HashFunction,
    StdError, StdResult, to_json_binary,
};

use sha2::{Digest, Sha256};

#[cosmwasm_schema::cw_serde]
pub struct BlsThresholdAuthData {
    pub aggregated_signature: Binary, // G2
}

#[cosmwasm_schema::cw_serde]
pub struct WavsParams {
    pub keys: Vec<Binary>,
    pub msg: WavsAuthMetadata,
}

/// [WavsAuthMetadata] is the object hashed and signed by all operator keys during proof of ownership & key rotation requests.
#[cosmwasm_schema::cw_serde]
pub struct WavsAuthMetadata {
    pub aggregate_key: String,
    // if 0, disable threshold assertions & allow single aggregate signature to be provided for authetnication
    pub threshold: usize,
    pub total_operators: usize,
    pub nonce: u64,
}

#[cosmwasm_schema::cw_serde]

pub struct WavsProofOfOwnership {
    /// list of aggregated keys (used for proof of ownership)
    pub poos: Vec<WavsOpAuth>,
    /// msg that is used as dst for signing and hashing operators for offchain validation
    pub msg: WavsAuthMetadata,
}
impl WavsProofOfOwnership {
    pub fn verify(&self) -> StdResult<()> {
        if self.poos.len() != self.msg.total_operators || self.poos.is_empty() {
            return Err(StdError::msg(format!(
                "invalid amount of operators defined. got: {}. want: {}",
                self.msg.total_operators,
                self.poos.len()
            )));
        }

        if self.msg.threshold == 0 || self.msg.threshold > self.msg.total_operators {
            return Err(StdError::msg("invalid threshold"));
        }
        Ok(())
    }

    /// Proof of ownership verification where H(pk) is signed with sk. Required before instantiation for certainty in inital keyset.
    /// Message is <contract-addr>-<pubkey>> for doublespend-prevention.\
    /// ref: : https://eth2book.info/capella/part2/building_blocks/signatures/#proof-of-possession
    pub fn proof_of_ownership(&self, api: &dyn Api, c: &Addr) -> StdResult<WavsOperatorSet> {
        for poo in &self.poos {
            let ps = hex::decode(&poo.key)?;
            let qs = api.bls12_381_hash_to_g2(HashFunction::Sha256, &ps, &G2)?;
            let s = hex::decode(&poo.poo)?;
            if !api.bls12_381_pairing_equality(&ps, &qs, &G1, &s)? {
                return Err(StdError::msg("proof of ownership failed"));
            }
        }
        // bls12-381 proof of possession
        Ok(WavsOperatorSet {
            c: c.to_string(),
            keys: self.poos.iter().map(|e| e.key.clone()).collect(),
            msg: self.msg.clone(),
        })
    }
}

#[cosmwasm_schema::cw_serde]
pub struct WavsOperatorSet {
    /// bech32 address wavs operator set controls (expected to be this smart contract)
    pub c: String,
    /// list of aggregated keys (used for proof of ownership )
    pub keys: Vec<String>,
    /// msg that is hashed and signed by wavs operators.
    pub msg: WavsAuthMetadata,
}
#[cosmwasm_schema::cw_serde]
pub struct WavsOpAuth {
    /// `bls12_381` public key
    pub key: String,
    /// proof of ownership signature of `H(WavsAuthMetadata)` from the public key
    pub poo: String,
}

impl WavsOperatorSet {
    fn handle_key_rotation(&self) -> StdResult<()> {
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
    fn create_operator(c: &Addr, api: &dyn Api, secret_key: &Fr) -> (WavsOpAuth, G2Affine) {
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
            WavsOpAuth {
                key: hex::encode(&pk_bytes),
                poo: hex::encode(&pop_sig_bytes),
            },
            pop_signature,
        )
    }

    #[test]
    fn test_bls12_381_pop() {
        let api = MockApi::default();
        let c = api.addr_make("head");
        let r = G1;
        let (operator, _) = create_operator(&c, &api, &Fr::rand(&mut OsRng));
        let ps = hex::decode(&operator.key).unwrap();
        let s = hex::decode(&operator.poo).unwrap();
        let qs = api
            .bls12_381_hash_to_g2(HashFunction::Sha256, &ps, &G2)
            .unwrap();
        assert!(
            api.bls12_381_pairing_equality(&ps, &qs, &r, &s).unwrap(),
            "Pairing equality should hold"
        );
    }

    #[test]
    fn test_proof_of_possession_valid_single_key() {
        let api = MockApi::default();
        let c = api.addr_make("head");
        let secret_key = Fr::rand(&mut OsRng);
        let (wauth, _) = create_operator(&c, &api, &secret_key);

        let pk_bytes = hex::decode(&wauth.key).unwrap();
        let key = wauth.key.clone();

        let wavs = WavsOperatorSet {
            c: "cosmos1test".to_string(),
            keys: vec![key],
            msg: WavsAuthMetadata {
                aggregate_key: hex::encode(&pk_bytes),
                threshold: 1,
                total_operators: 1,
                nonce: 42,
            },
        };
        let poos = WavsProofOfOwnership {
            poos: vec![wauth],
            msg: WavsAuthMetadata {
                aggregate_key: hex::encode(&pk_bytes),
                threshold: 1,
                total_operators: 1,
                nonce: 42,
            },
        };

        // Should pass
        let result = poos.proof_of_ownership(&api, &c);
        assert!(
            result.is_ok(),
            "PoP verification should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_proof_of_possession_invalid_signature() {
        let api = MockApi::default();
        let c = api.addr_make("head");
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

        let operator = WavsOpAuth {
            key: hex::encode(&pk_bytes),
            poo: hex::encode(serialize_g2(&wrong_signature)),
        };

        let poos = WavsProofOfOwnership {
            poos: vec![operator],
            msg: WavsAuthMetadata {
                aggregate_key: hex::encode(&pk_bytes),
                threshold: 1,
                total_operators: 1,
                nonce: 42,
            },
        };

        // Should fail
        let result = poos.proof_of_ownership(&api, &c);
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
        let c = api.addr_make("head");
        // Generate 3 operators
        let secret_keys: Vec<Fr> = (0..3).map(|_| Fr::rand(&mut OsRng)).collect();
        let operators: Vec<WavsOpAuth> = secret_keys
            .iter()
            .map(|sk| create_operator(&c, &api, sk).0)
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
            c: "cosmos1test".to_string(),
            keys: operators.iter().map(|e| e.key.clone()).collect(),
            msg: WavsAuthMetadata {
                aggregate_key: hex::encode(serialize_g1(&agg_pk)),
                threshold: 2,
                total_operators: 3,
                nonce: 100,
            },
        };
        let poos = WavsProofOfOwnership {
            poos: operators,
            msg: WavsAuthMetadata {
                aggregate_key: hex::encode(serialize_g1(&agg_pk)),
                threshold: 2,
                total_operators: 3,
                nonce: 100,
            },
        };

        // All PoPs should be valid
        let result = poos.proof_of_ownership(&api, &c);
        assert!(
            result.is_ok(),
            "All PoPs should be valid: {:?}",
            result.err()
        );
    }
}
