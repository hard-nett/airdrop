//! main suite for headstash
use alloc::boxed::Box;
use cosmwasm_std::to_json_binary;
use rand_core::OsRng;

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use serde_json::{Value, json};
use zk_cosmwasm::{CosmwasmCircuit, Instance, Proof, ProvingKey, example_circuits::NoRickProof};
use zk_headstash::{
    Anchor, FIXED_AMOUNTS, LEAF_PERSONALIZATION, MERKLE_CRH_PERSONALIZATION,
    address::RecpAddr,
    builder::SpendInfo,
    circuit::Circuit,
    keys::{EligibleSk, FullViewingKey, NullifierDerivingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::MerklePath,
    value::{HeadstashValue, NoteDenom, NoteValue},
};
// use crate::tree::MerklePath;

// use crate::{Anchor, Proof, spec};
use base64::{Engine as _, engine::general_purpose};
use sinsemilla::HashDomain;
use ff::{Field, FromUniformBytes, PrimeField, PrimeFieldBits};
use hex::decode;
use pasta_curves::pallas::Base;
use pasta_curves::{Fp, arithmetic::CurveAffine, group::Curve, pallas};
use std::error::Error;

use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::sync::Mutex;
use std::vec::Vec;
use std::{env, eprintln, fs, println};

const KEYS_DIR: &str = "./circuit_keys";
const PARAMS_FILE: &str = "params.bin";
const VK_FILE: &str = "verifying_key.bin";
const PK_FILE: &str = "proving_key.bin";

/// BoxError
pub type BoxError = Box<dyn Error + Send + Sync>;
/// get_cli_args
pub fn get_cli_args() -> Result<(String, String), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("flag format: {} <input-file> <address>", args[0]);
        std::process::exit(1);
    }
    Ok((args[1].clone(), args[2].clone()))
}

/// TerpHeadstashConfig
#[derive(Debug)]
pub struct TerpHeadstashConfig {
    // smart contract params
    // file location params
    // storage params
    // deployment params
    // node params
}

/// HeadstashSuite
#[derive(Debug, Default)]
pub struct HeadstashSuite {}
impl HeadstashBitwiseInstance for HeadstashSuite {}
impl HeadstashLaunchpadInstance for HeadstashSuite {}
impl HeadstashSinsemillaTree for HeadstashSuite {}
impl HeadstashIpfsInstance for HeadstashSuite {}
impl HeadstashSuite {
    /// create new headsatsh suite
    pub fn new() -> Self {
        Self {}
    }
}

/// # Trait: `HeadstashInstance`
///
/// implement expected functions for client side interactions headstashes.
// pub trait HeadstashInstance {
//     type HsErr;

//     /// TODO: wire into network client for headstash market contract state queries
//     fn find_new_headstashes() -> Result<(), Self::HsErr> {
//         todo!()
//     }

//     /// TODO: query ipfs file to retrieve headstash config
//     fn list_headstash_info() -> Result<(), Self::HsErr> {
//         todo!()
//     }

//     /// TODO: read folder and display sum of notes and number of fdi counts
//     fn list_unspent_notes() -> Vec<Note> {
//         todo!()
//     }

//     /// TODO: read folder and display notes spent
//     fn list_spent_notes() -> Vec<Note> {
//         todo!()
//     }

//     /// TODO: select unspent notes used to claim and move note file over into spent,
//     /// specify method of preparing and harvesting (creating proof) for a given note (either wasm-bindgen invocation,locally via cargo script, or external method invoked with a bash script)
//     fn prepare_and_harvest_note() -> Result<(), Self::HsErr> {
//         todo!()
//     }

//     fn headstash_action() -> Result<(), Self::HsErr> {
//         todo!()
//     }
// }

/// HeadstashBitwiseInstance
pub trait HeadstashBitwiseInstance {
    /// `derive_esk`: derives the 3x88 libs of a raw esk.
    fn derive_esk(&self, sk: [u8; 32]) -> [Fp; 3] {
        use zk_headstash::decompose_biguint_simple as decompose;
        let skfq = halo2_base::halo2_proofs::halo2curves::secq256k1::Fp::from_repr(sk).expect("Fq");
        let sk_big = halo2_base::utils::fe_to_biguint(&skfq);
        decompose(&sk_big, 3, 88).try_into().unwrap()
    }

    /// derive_epk
    fn derive_epk(&self, pk: [u8; 32]) -> [Fp; 3] {
        use zk_headstash::decompose_biguint_simple as decompose;
        let pkfq = halo2_base::halo2_proofs::halo2curves::secq256k1::Fp::from_repr(pk).expect("Fq");
        let sk_big = halo2_base::utils::fe_to_biguint(&pkfq);
        decompose(&sk_big, 3, 88).try_into().unwrap()
    }

    /// derive_v
    fn derive_v(&self, v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    /// derive_fdi
    fn derive_fdi(&self, fdi: u64) -> [u8; 8] {
        fdi.to_le_bytes()
    }

    /// derive_nk
    fn derive_nk(&self, esk: &[u8; 32], rho: Rho) -> NullifierDerivingKey {
        NullifierDerivingKey::derive_from(
            EligibleSk::from(secp256k1::SecretKey::from_byte_array(*esk).unwrap()),
            rho,
        )
    }

    /// Convert a byte slice into an iterator of little‑endian bits (LSB first per byte).
    fn bytes_to_bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
    }

    /// Returns the sum of the 3 88-bit pallas curve point representation of a secp256k1 value
    fn derive_secp256k1_limbs_sum_const_time(&self, bytes: &[Fp; 3]) -> Fp {
        let limb3 = &bytes[0];
        let limb2 = &bytes[1];
        let limb1 = &bytes[2];
        limb1.add(&limb2.add(&limb3))
    }

    /// Note‑Denom (nd): blake3 hash of the token, 1 bit cleared.
    fn derive_nd(&self, raw_nd: &str) -> [u8; 32] {
        NoteDenom::new_for_proof(raw_nd)
            .as_bytes()
            .try_into()
            .expect("NoteDenom is always 32 bytes")
    }
    /// Recipient (recp): poseidon hash a 2x16byte limbs of `CanonicalAddr`
    fn derive_recp(&self, addr: [u8; 32]) -> pallas::Base {
        zk_headstash::recp_to_fp(&RecpAddr::new(addr))
    }

    /// extend_with_base_field_bits
    fn extend_with_base_field_bits(bits: &mut Vec<bool>, a: pallas::Base) {
        let bit_slice = a.to_le_bits();
        bits.extend(bit_slice.iter().take(250).map(|b| *b));
    }

    /// rho_from_secure_random
    fn rho_from_secure_random(&self) -> Rho {
        let mut randomness_64 = [0; 64];
        blake3::Hasher::new()
            .update(&headstash_randomness::ultra_secure_random())
            .finalize_xof()
            .fill(&mut randomness_64);

        Rho::from_bytes(&Base::from_uniform_bytes(&randomness_64).to_repr()).unwrap()
    }
}

/// `HeadstashSinsemillaTree`: all functions powering creating of headstash distribution merkle tree instances
pub trait HeadstashSinsemillaTree: HeadstashBitwiseInstance {
    /// `get_input_path`: cli helper to retrieve input path
    fn get_input_path(&self) -> Result<String, BoxError> {
        let args: Vec<String> = env::args().collect();
        if args.len() != 2 {
            eprintln!("Usage: {} <input-file>", args[0]);
            std::process::exit(1);
        }
        Ok(args[1].clone())
    }
    /// Find the first note matching token & amount, return its fdi
    fn print_tree(
        &self,
        input: &mut Value,
        output: Value,
        path: &std::path::Path,
    ) -> Result<(), BoxError> {
        fs::write(
            &self.get_input_path()?,
            serde_json::to_string_pretty(&input)?,
        )?;
        eprintln!("✅ Input with leaves written to {}", self.get_input_path()?);
        let merkle_path = path.join("merkle_output.json");
        fs::write(&merkle_path, serde_json::to_string_pretty(&output)?)?;
        eprintln!("✅ Merkle output written to {}", merkle_path.display());
        Ok(())
    }

    /// gen_headstash_tree
    fn gen_headstash_tree(&self, output_path: PathBuf) -> Result<String, BoxError>
    where
        Self: Sync,
    {
        let mut data: Value = serde_json::from_str(&fs::read_to_string(&self.get_input_path()?)?)?;
        let mut leaves = Vec::new();
        let balances = data.as_object_mut().ok_or("Input JSON must be an object")?;

        // Sort addresses lexicographically
        let mut addresses: Vec<_> = balances.keys().cloned().collect();
        addresses.sort();

        for addr in addresses {
            let alloc_array = match balances.get_mut(addr.as_str()) {
                Some(v) => v,
                None => continue,
            };

            let alloc_array = match alloc_array.as_array_mut() {
                Some(arr) => arr,
                None => continue,
            };

            // Sort token allocations by `name` field
            alloc_array.sort_by_key(|t| t["name"].to_string());

            for token in alloc_array.iter_mut() {
                let v: u64 = token["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap();

                // ---- parallel leaf generation ---------------------------------
                // Parallel leaf generation (now also gives us an index)
                let (lidxh, raw_leaves) =
                    self.derive_leaf(addr.as_str(), &token["name"].to_string(), v)?;
                // ---- attach leaves back to the JSON object (single‑thread) ----
                {
                    token
                        .as_object_mut()
                        .unwrap()
                        .entry("leaves")
                        .or_insert_with(|| json!([]));
                }

                // Push each leaf together with its index:
                for (fixed_amount, idx, leaf_hex) in lidxh {
                    token
                        .get_mut("leaves")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                        .push(json!({ "amnt":fixed_amount,"index": idx, "leaf": leaf_hex }));
                }

                // ---- push raw leaves into the global vector -------------------
                leaves.extend(raw_leaves);
            }
        }

        if leaves.is_empty() {
            println!("No leaves generated.");
            return Ok(String::default());
        }

        // Build Merkle root
        let merkle_root = self.tree_root_from_leaves(leaves.clone())[0];
        let root_hex = format!("0x{}", hex::encode(merkle_root.to_repr()));
        let leaves_hex: Vec<String> = leaves
            .into_iter()
            .map(|leaf| format!("0x{}", hex::encode(leaf.to_repr())))
            .collect();

        // Output Merkle result
        let merkle_output = json!({
            "root": root_hex,
            "leaves": leaves_hex,
            "count": leaves_hex.len()
        });

        self.print_tree(&mut data, merkle_output, &output_path)?;

        Ok(root_hex)
    }

    /// Helper that generates all leaves for a single token (parallelised)
    fn derive_leaf(
        &self,
        addr: &str,
        token_name: &str,
        v: u64,
    ) -> Result<(Vec<(u64, usize, String)>, Vec<Fp>), BoxError>
    where
        Self: Sync,
    {
        // ---------- build work list ------------------------------------------------
        let mut work_items: Vec<u64> = Vec::new();
        let mut remainder = v;
        for &fixed_amount in FIXED_AMOUNTS.iter() {
            let count = remainder / fixed_amount;
            if count == 0 {
                remainder %= fixed_amount;
                continue;
            }
            // push *count* copies of the denomination value
            work_items.extend(std::iter::repeat(fixed_amount).take(count as usize));
            remainder %= fixed_amount;
        }
        debug_assert_eq!(remainder, 0, "remainder not zero after denomination split");

        // ---------- parallel leaf generation ---------------------------------------
        let leaf_hexes = Mutex::new(Vec::<(u64, usize, String)>::new());
        let raw_leaves = Mutex::new(Vec::<Fp>::new());

        let addr_bytes: &[u8; 32] = match addr.starts_with("0x") {
            true => &decode(addr.trim_start_matches("0x"))?.try_into().unwrap(),
            false => &general_purpose::STANDARD
                .decode(addr)
                .unwrap()
                .try_into()
                .unwrap(),
        };

        // `enumerate` gives us the leaf‑index (0‑based) for this address/token
        #[cfg(feature = "multicore")]
        work_items.par_iter().enumerate().try_for_each(
            |(idx, &fixed_amount)| -> Result<(), BoxError> {
                let leaf = self.leaf_hash(
                    &self
                        .derive_secp256k1_limbs_sum_const_time(&self.derive_esk(*addr_bytes))
                        .to_repr(),
                    &self.derive_nd(token_name),
                    &self.derive_v(fixed_amount),
                    &self.derive_fdi(idx as u64),
                )?;
                let leaf_hex = format!("0x{}", hex::encode(leaf.to_repr()));
                leaf_hexes
                    .lock()
                    .unwrap()
                    .push((fixed_amount, idx, leaf_hex));
                raw_leaves.lock().unwrap().push(leaf);
                Ok(())
            },
        )?;

        Ok((
            leaf_hexes.into_inner().unwrap(),
            raw_leaves.into_inner().unwrap(),
        ))
    }

    /// Build Merkle tree from list of leaves
    fn tree_root_from_leaves(&self, leaves: Vec<pallas::Base>) -> Vec<pallas::Base> {
        let mut c = leaves;
        let mut n: Vec<Fp> = Vec::new();
        let mut l = 0;

        #[cfg(feature = "multicore")]
        while c.len() > 1 {
            if c.len() % 2 != 0 {
                c.push(pallas::Base::ZERO);
            }
            let lp = l;
            let p = c
                .par_chunks(2)
                .map(|c| Self::merkle_crh(lp, c[0], c[1]))
                .collect::<Vec<pallas::Base>>();
            n.extend(p);
            c = n;
            n = Vec::new();
            l += 1;
        }
        if c.is_empty() {
            vec![pallas::Base::ZERO]
        } else {
            c
        }
    }

    /// Calculate MerkleCRH: H(layer || left || right)
    fn merkle_crh(layer: u32, left: pallas::Base, right: pallas::Base) -> pallas::Base {
        let domain = HashDomain::new(MERKLE_CRH_PERSONALIZATION);
        // bit string: 10 + 250 + 250 = 510 bits
        let mut message = Vec::with_capacity(510);

        for i in 0..10 {
            message.push((layer >> i) & 1 == 1);
        }

        <HeadstashSuite as HeadstashBitwiseInstance>::extend_with_base_field_bits(
            &mut message,
            left,
        );
        <HeadstashSuite as HeadstashBitwiseInstance>::extend_with_base_field_bits(
            &mut message,
            right,
        );

        // Hash and return x-coordinate
        let point = domain.hash_to_point(message.into_iter()).unwrap();
        point.to_affine().coordinates().unwrap().x().clone()
    }

    /// Compute the leaf hash
    fn leaf_hash(
        &self,
        epk: &[u8],
        nd: &[u8],
        v: &[u8],
        fdi: &[u8],
    ) -> Result<pallas::Base, BoxError> {
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(epk);
        message_bytes.extend_from_slice(nd);
        message_bytes.extend_from_slice(v);
        message_bytes.extend_from_slice(fdi);
        Ok(HashDomain::new(LEAF_PERSONALIZATION)
            .hash_to_point(HeadstashSuite::bytes_to_bits_le(&message_bytes).into_iter())
            .expect("dang")
            .to_affine()
            .coordinates()
            .unwrap()
            .x()
            .clone())
    }

    /// create_headstash_notes
    fn create_headstash_notes(&self) -> Result<(), BoxError> {
        let (input_path, addr_target) = get_cli_args().unwrap();
        let input_data: Value = serde_json::from_str(&fs::read_to_string(&input_path)?)?;
        let mut address_notes = serde_json::Map::new();

        if let Value::Object(map) = &input_data {
            if let Some(holdings) = map.get(&addr_target) {
                if let Value::Array(holding_array) = holdings {
                    for holding in holding_array.iter() {
                        // token identifier: raw value ("uterp", "ibc/...", "tokenfactory/...")
                        let token_name = holding["name"].as_str().unwrap().to_string();
                        let _total_amount = holding["amount"].as_str().unwrap();

                        let leaves = match holding.get("leaves") {
                            Some(Value::Array(arr)) => arr,
                            _ => {
                                eprintln!("⚠️  No \"leaves\" array for token {}", token_name);
                                std::process::exit(1);
                            }
                        };

                        let mut generated_notes = Vec::new();

                        for leaf in leaves.iter() {
                            // concrete amount for this note
                            let amnt = leaf["amnt"].as_u64().unwrap_or_else(|| {
                                eprintln!("⚠️  Missing \"amnt\" in leaf for token {}", token_name);
                                std::process::exit(1);
                            });

                            // the fdi value (the leaf itself)
                            let fdi = leaf["index"].as_u64().unwrap_or_else(|| {
                                eprintln!("⚠️  Missing \"index\" in leaf for token {}", token_name);
                                std::process::exit(1);
                            });
                            generated_notes.push(json!({
                                "nd":      NoteDenom::new_for_proof(&token_name.clone()).to_string(),
                                "v":     NoteValue::from_bytes(amnt.to_le_bytes()).inner(),
                                "fdi":        fdi,
                            }));
                        }

                        // ------------------------------------------------------------------
                        // 3️⃣  Insert the array of notes for this token into the final map
                        // ------------------------------------------------------------------
                        address_notes.insert(token_name, Value::Array(generated_notes));
                    }
                } else {
                    eprintln!(
                        "Error: Address '{}' does not have holdings array.",
                        addr_target
                    );
                    std::process::exit(1);
                }
            } else {
                eprintln!("Error: Address '{}' not found in input data.", addr_target);
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: Input data is not a JSON object.");
            std::process::exit(1);
        }

        // Create output file: ./data/<address>_notes.json
        let output_dir = Path::new("./data/notes");
        fs::create_dir_all(output_dir)?;
        let safe_addr: String = addr_target
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let output_path = output_dir.join(format!("{}.json", safe_addr));

        fs::write(&output_path, serde_json::to_string_pretty(&address_notes)?)?;

        eprintln!("✅ Default Genesis Notes generated for {}", addr_target);
        eprintln!("📁 Written to: {}", output_path.display());

        Ok(())
    }

    /// TODO: create default notes of a specific public key allocation for a given headstash instance.
    /// retrieves the entire tree from the headstash-API client, and then generate our notes 100% client side
    fn gen_headstash_my_notes(&self, input: PathBuf, output: PathBuf) -> Result<(), BoxError> {
        todo!()
    }

    /// Find the first note matching token & amount, return its fdi
    fn find_fdi(input_path: &str, token: &str, amount: &str) -> Result<u64, BoxError> {
        let json: Value =
            serde_json::from_str(&fs::read_to_string(std::path::Path::new(input_path))?)?;

        let notes = json
            .get(token)
            .and_then(|v| v.as_array())
            .ok_or("Missing or invalid `uterp` array")?;

        for note in notes {
            let denom_match = note.get("denom").and_then(|v| v.as_str()) == Some(token);
            let amount_match = note.get("amount").and_then(|v| v.as_str()) == Some(amount);

            if denom_match && amount_match {
                // fdi is a number (u32); pull it out
                let fdi = note
                    .get("fdi")
                    .and_then(|v| v.as_u64())
                    .ok_or("Missing or invalid `fdi` field")?;
                return Ok(fdi);
            }
        }

        Err(format!(
            "No note found for token '{}' with amount '{}'",
            token, amount
        )
        .into())
    }

    /// # get_note_path
    fn get_note_path() -> Result<(String, String, String), BoxError> {
        let args: Vec<String> = env::args().collect();
        if args.len() != 4 {
            eprintln!(
                "Usage: {} ./data/notes/<elig_addr> <token-denom> <amount> ",
                args[0]
            );
            std::process::exit(1);
        }
        Ok((args[1].clone(), args[2].clone(), args[3].clone()))
    }
}

/// All actions any user would take for creating a new headstash 100% client side using this launchpad framework.
///  Requires struct implementing trait to also implement `HeadstashBitwiseInstance` default members.
/// TODO: feature flag parallelization in tree generation
/// TODO: add default documentation to each member
pub trait HeadstashIpfsInstance: HeadstashBitwiseInstance {
    /// `upload_circuit_keys`: upload keys to ipfs for public distribution
    fn upload_circuit_keys(&self) -> Result<(), BoxError> {
        // check for existing ipfs connection
        // options:
        // -  use node local ipfs gateway
        // -  use remote ipfs gateway
        // -  deploy new one if needed
        // load key files from default folder
        // upload and handle response gracefully
        Ok(())
    }
    /// `upload_headstash_params`: upload headstash params to ipfs for public distribution
    fn upload_headstash_yaml(&self) -> Result<(), BoxError> {
        Ok(())
    }
    /// `req_headstash_pk`: request headstash proof keys from storage method defined by params
    async fn req_headstash_pk(&self) -> Result<ProvingKey, BoxError> {
        todo!()
    }
}

/// launchpad
pub trait HeadstashLaunchpadInstance: HeadstashBitwiseInstance + HeadstashIpfsInstance {
    /// ## [create_headstash_proof]
    /// > #### Default method for creating a proof. Requires both the *public (instance)* & *private (witnesses)* values.
    async fn create_headstash_proof(
        &self,
        a: Anchor,
        mp: MerklePath,
        esk: EligibleSk,
        recp: RecpAddr,
        hv: HeadstashValue,
    ) -> Result<Proof, BoxError> {
        let mut rng = OsRng;
        let r = self.rho_from_secure_random().to_bytes();
        let rho = self.rho_from_secure_random();
        let rseed = RandomSeed::from_bytes(r, &rho).expect("random seed");

        let pk = self.req_headstash_pk().await?;
        let spk = SpendingKey::from_bytes(r).expect("spk");
        let fvk = FullViewingKey::from(&spk);

        let n = Note::from_parts(hv, recp, esk, rho, rseed).expect("note derivation");
        let nf = n.nullifier();
        let cmx = ExtractedNoteCommitment::from(n.commitment());

        let c = SpendInfo::new(fvk, n, mp).expect("headstash claim");

        // generate proof, unchecked as we rho is not deterministically derived
        let instances =
            zk_headstash::circuit::Instance::from_parts(a, hv.denom(), hv.amount(), recp, nf, cmx);
        let circuit = Circuit::from_action_context_unchecked(c, n);
        Ok(Proof::create(
            &pk,
            &[CosmwasmCircuit::from(circuit)],
            &[Instance::new_from_vm(instances.to_bytes()).unwrap()],
            &mut rng,
        )?)
    }
    /// create_new_headstash
    fn create_new_headstash(&self) -> Result<(), BoxError> {
        // generate template headstash yaml
        self.gen_new_headstash_params();
        // prompt to determine communities to include in headstash airdrop
        // deploy/retrieve holder distributions via full ephemeral full nodes api queries
        self.gen_community_snapshots();
        // prompt calculations on percentile distribution and suggested ranges for normalization of airdrop allocation between communities
        self.gen_calculate_distribution();
        // generate headstash circuit
        // self.gen_headstash_circuit()?;
        // upload circuit keys to ipfs
        self.upload_circuit_keys()?;
        // upload headstash yaml to ipfs
        self.upload_headstash_yaml()?;
        // call headstash launchpad
        // deploy new headstash aggregator
        unimplemented!()
    }

    /// `gen_headstgen_community_snapshotsash_keys`: retrive snapshot and pubkeys of list of community holders.
    fn gen_new_headstash_params(&self) {
        // load config file or create new one
        // a. determine what circuit keys used
        //  - default headstash, custom one we upload
        // b. smart contract params
        // c. deployment params
        // d. node params
    }

    /// `gen_headstgen_community_snapshotsash_keys`: retrive snapshot and pubkeys of list of community holders.
    fn gen_community_snapshots(&self) {
        // load config file
        // connect to eth node
        // retrieve latest holder distribution and pubkeys for each community
        // write csv into each community folder
    }
    /// `gen_calculate_distribution`:  .
    fn gen_calculate_distribution(&self) {}

    // /// `gen_headstash_circuit`: generate circuit [ProvingKey] & [VerifyingKey] with hex-encode, write to ./data/keys/.
    // fn gen_headstash_circuit(&self) -> Result<(), BoxError> {
    //     fs::create_dir_all("./data/keys")?;
    //     let pk_path = Path::new("./data/keys").join(PK_FILE);
    //     ProvingKey::build_and_write(pk_path)?;
    //     Ok(())
    // }
}

// TODO:
// - notecommitment derivation accuracy
// - nullifier derivation accuracy
// - document DST & hashing algo constant in spec

// TEST:
// nullifier should not be impacted by randomness inputs
// nullifier should change with different esk/epk
//

#[cfg(test)]
mod test {
    use super::*;
    use std::boxed::Box;
    use std::collections::HashMap;

    #[test]
    pub fn test_note_accuracy() -> Result<(), Box<dyn std::error::Error>> {
        // Load original allocations
        let input_data: Value =
            serde_json::from_str(&fs::read_to_string("./data/genesis_sinsemilla.json")?)?;

        // Load generated notes for the zero address
        let notes_path = "./data/notes/0x0000000000000000000000000000000000000000.json";
        let calculated_notes: Value = serde_json::from_str(&fs::read_to_string(notes_path)?)?;

        // Extract original holdings
        let mut original_balances: HashMap<String, u64> = HashMap::new();

        if let Value::Object(map) = &input_data {
            if let Some(holdings) = map.get("0x0000000000000000000000000000000000000000") {
                if let Value::Array(holding_array) = holdings {
                    for holding in holding_array {
                        if let Some(name) = holding["name"].as_str() {
                            let amount_str = holding["amount"].as_str().unwrap_or("0");
                            let amount: u64 = amount_str.parse().unwrap_or(0);
                            *original_balances.entry(name.to_string()).or_insert(0) += amount;
                        }
                    }
                }
            }
        }

        // Extract and sum note values from generated notes
        let mut notes_sum: HashMap<String, u64> = HashMap::new();

        if let Value::Object(note_map) = &calculated_notes {
            for (token_name, notes) in note_map {
                if let Value::Array(note_array) = notes {
                    for note in note_array {
                        if let Some(v_str) = note["v"].as_str() {
                            let v: u64 = v_str.parse().unwrap_or(0);
                            *notes_sum.entry(token_name.clone()).or_insert(0) += v;
                        }
                    }
                }
            }
        }

        // Compare: original vs summed note values
        for (token, original_amount) in &original_balances {
            let note_total = notes_sum.get(token).copied().unwrap_or(0);
            assert_eq!(
                original_amount, &note_total,
                "Token {}: allocation ({}) does not match total notes ({})",
                token, original_amount, note_total
            );
        }

        // Also check for extra tokens in notes not in original
        for (token, _) in &notes_sum {
            assert!(
                original_balances.contains_key(token),
                "Token {} appears in notes but not in original allocation",
                token
            );
        }

        Ok(())
    }

    fn load_data() -> Result<Value, BoxError> {
        let file = fs::File::open("./data/genesis_sinsemilla.json")?;
        let reader = std::io::BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    // Ensures input data is in compatible format
    #[test]
    pub fn test_input_data_accuracy() -> Result<(), BoxError> {
        let data = load_data()?;
        if !data.is_object() {
            panic!("Expected JSON object (map) at root");
        }

        for (addr, tokens) in data.as_object().unwrap().iter() {
            assert!(tokens.is_array(), "Value for {} must be an array", addr);
            for token in tokens.as_array().unwrap() {
                let obj = token.as_object().unwrap();
                assert!(obj.contains_key("amount"), "missing required key 'amount'");
                assert!(obj.contains_key("token"), " missing required key 'token'");
                assert!(obj["amount"].is_string(), "'amount' must be a string");
                assert!(obj["token"].is_string(), "'token' must be a string");
            }
        }

        Ok(())
    }

    // #[test]
    // pub fn test_leaves_accuracy() -> Result<(), BoxError> {
    //     let data = load_data()?;
    //     // Expect top-level object: { "addr": [ { token, amount, leaf }, ... ] }
    //     let balances = data.as_object().ok_or("JSON must be an object")?;
    //     for (address, allocs) in balances {
    //         let alloc_array = allocs.as_array().unwrap();

    //         for token_obj in alloc_array {
    //             let token_name = token_obj["token"].as_str().unwrap_or_default();
    //             let amount = token_obj["amount"].as_str().unwrap_or_default();
    //             let expected_leaf_hex = token_obj["leaf"].as_str().unwrap_or_default();

    //             // Remove 0x prefix if present
    //             let expected_bytes = if expected_leaf_hex.starts_with("0x") {
    //                 hex::decode(&expected_leaf_hex[2..])?
    //             } else {
    //                 hex::decode(expected_leaf_hex)?
    //             };

    //             // Re-compute expected scalar from address + token + amount
    //             let computed_leaf = leaf_hash(address, token_name, amount,)?;
    //             let computed_bytes = computed_leaf.to_repr();

    //             // Compare raw field element bytes
    //             assert_eq!(
    //                 computed_bytes.as_ref(),
    //                 expected_bytes.as_slice(),
    //                 "Leaf mismatch for address={}, token={}",
    //                 address,
    //                 token_name
    //             );
    //         }
    //     }

    //     Ok(())
    // }
}
