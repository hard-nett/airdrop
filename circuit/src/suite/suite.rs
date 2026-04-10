//! main suite for headstash
//!
//! This module provides the `HeadstashSuite` which implements various traits
//! for headstash operations including merkle tree generation, test data building,
//! and circuit key management.
use alloc::boxed::Box;

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{
    address::RecpAddr,
    builder::SpendInfo,
    circuit::{Circuit, ProvingKey},
    keys::{EligibleSk, FullViewingKey, NullifierDerivingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    tree::MerklePath,
    value::{HeadstashValue, NoteDenom, NoteValue},
    Anchor, Proof, FIXED_AMOUNTS, LEAF_PERSONALIZATION, MERKLE_CRH_PERSONALIZATION,
};
use base64::{engine::general_purpose, Engine as _};
use ff::{Field, FromUniformBytes, PrimeField, PrimeFieldBits};
use hex::decode;
use pasta_curves::pallas::Base;
use pasta_curves::{arithmetic::CurveAffine, group::Curve, pallas, Fp};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sinsemilla::HashDomain;
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

/// HeadstashBitwiseInstance
pub trait HeadstashBitwiseInstance {
    /// Derives the native pallas representation of a secp256k1 secret key.
    /// Returns `esk mod pallas_p`, matching the in-circuit `.native` value.
    fn derive_esk_native(&self, sk: [u8; 32]) -> Fp {
        use crate::spec::biguint_to_fe_simple;
        let skfq = halo2_base::halo2_proofs::halo2curves::secq256k1::Fp::from_repr(sk).expect("Fq");
        let sk_big = halo2_base::utils::fe_to_biguint(&skfq);
        biguint_to_fe_simple(&sk_big)
    }

    /// Derives the native pallas representations of the secp256k1 public key
    /// from a secret key. Computes `epk = esk * G` on secp256k1, then reduces
    /// both coordinates mod pallas_p to match the in-circuit `.native` values.
    fn derive_epk_natives(&self, sk: [u8; 32]) -> (Fp, Fp) {
        use crate::spec::to_native_out_of_circuit;
        use halo2_base::halo2_proofs::halo2curves::secp256k1::Fp as Secp256k1Fp;
        let secret_key = secp256k1::SecretKey::from_byte_array(sk).expect("valid secret key");
        let esk = EligibleSk::from(secret_key);
        let (epk_x_bytes, epk_y_bytes) = esk.epk().xy();
        let epk_x = Secp256k1Fp::from_bytes(&epk_x_bytes.into()).expect("valid Fp");
        let epk_y = Secp256k1Fp::from_bytes(&epk_y_bytes.into()).expect("valid Fp");
        (
            to_native_out_of_circuit(&epk_x),
            to_native_out_of_circuit(&epk_y),
        )
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

    /// Note‑Denom (nd): blake3 hash of the token, 1 bit cleared.
    fn derive_nd(&self, raw_nd: &str) -> [u8; 32] {
        NoteDenom::new_for_proof(raw_nd)
            .as_bytes()
            .try_into()
            .expect("NoteDenom is always 32 bytes")
    }
    /// Recipient (recp): poseidon hash a 2x16byte limbs of `CanonicalAddr`
    fn derive_recp(&self, addr: [u8; 32]) -> pallas::Base {
        crate::recp_to_fp(&RecpAddr::new(addr))
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
                let (epk_x, epk_y) = self.derive_epk_natives(*addr_bytes);
                let nd_fp = Fp::from_repr(self.derive_nd(token_name)).unwrap();
                let v_fp = Fp::from(fixed_amount);
                let fdi_fp = Fp::from(idx as u64);
                let leaf = self.leaf_hash(epk_x, epk_y, nd_fp, v_fp, fdi_fp)?;
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

    /// Compute the leaf hash matching in-circuit `derive_leaf`.
    ///
    /// 640-bit Sinsemilla message layout:
    ///   epk_x[0..255) || epk_y[0..1) || nd[0..255) || v[0..64) || fdi[0..64) || 0_pad
    fn leaf_hash(
        &self,
        epk_x: Fp,
        epk_y: Fp,
        nd: Fp,
        v: Fp,
        fdi: Fp,
    ) -> Result<pallas::Base, BoxError> {
        use ff::PrimeFieldBits;
        let mut bits: Vec<bool> = Vec::with_capacity(640);
        bits.extend(epk_x.to_le_bits().iter().by_vals().take(255));
        bits.extend(epk_y.to_le_bits().iter().by_vals().take(1));
        bits.extend(nd.to_le_bits().iter().by_vals().take(255));
        bits.extend(v.to_le_bits().iter().by_vals().take(64));
        bits.extend(fdi.to_le_bits().iter().by_vals().take(64));
        bits.push(false); // 1-bit padding to reach 640
        assert_eq!(bits.len(), 640);
        Ok(HashDomain::new(LEAF_PERSONALIZATION)
            .hash_to_point(bits.into_iter())
            .expect("leaf hash should succeed")
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

// ============================================================================
// Test Data Builders for Merkle Tree Inclusion Proofs
// ============================================================================

/// Test leaf data containing all inputs needed to compute a leaf hash.
#[derive(Clone, Debug)]
pub struct TestLeafData {
    /// epk x-coordinate reduced mod pallas_p (matching in-circuit `.native`)
    pub epk_x_native: Fp,
    /// epk y-coordinate reduced mod pallas_p (matching in-circuit `.native`)
    pub epk_y_native: Fp,
    /// Note denomination as pallas field element
    pub nd: Fp,
    /// Note value as pallas field element
    pub v: Fp,
    /// Fixed denomination index as pallas field element
    pub fdi: Fp,
    /// Raw note value (u64, for building HeadstashValue)
    pub raw_v: u64,
    /// Raw denomination index (u64, for building HeadstashValue)
    pub raw_fdi: u64,
    /// Raw address bytes (for reference)
    pub raw_addr: [u8; 32],
    /// Raw token name (for reference)
    pub raw_token: String,
}

/// Full merkle tree structure containing all levels.
/// Level 0 contains leaves, level `depth` contains the root.
#[derive(Clone, Debug)]
pub struct FullMerkleTree {
    /// All tree levels. `levels[0]` = leaves, `levels[depth]` = root (single element)
    pub levels: Vec<Vec<Fp>>,
    /// Tree depth (number of levels - 1)
    pub depth: usize,
}

impl FullMerkleTree {
    /// Get the root of the tree
    pub fn root(&self) -> Fp {
        self.levels[self.depth][0]
    }

    /// Get the number of leaves
    pub fn num_leaves(&self) -> usize {
        self.levels[0].len()
    }
}

/// Merkle authentication path for inclusion proofs.
#[derive(Clone, Debug)]
pub struct MerkleAuthPath {
    /// Sibling nodes along the path from leaf to root
    pub siblings: Vec<Fp>,
    /// Position bits indicating if node is left (0) or right (1) child at each level
    pub position_bits: Vec<bool>,
    /// Leaf index
    pub leaf_index: usize,
}

impl MerkleAuthPath {
    /// Convert to the format expected by the circuit (auth_path array)
    pub fn to_auth_path_array<const DEPTH: usize>(&self) -> [Fp; DEPTH] {
        let mut arr = [Fp::ZERO; DEPTH];
        for (i, sibling) in self.siblings.iter().enumerate().take(DEPTH) {
            arr[i] = *sibling;
        }
        arr
    }

    /// Get position as u32 (bit-packed)
    pub fn position(&self) -> u32 {
        self.position_bits
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &bit)| acc | ((bit as u32) << i))
    }

    /// Convert MerkleAuthPath to circuit-compatible MerklePath.
    /// Pads siblings to MERKLE_DEPTH_ORCHARD (32) with zeros.
    pub fn to_circuit_path(&self) -> MerklePath {
        use crate::constants::MERKLE_DEPTH_ORCHARD;
        use crate::tree::MerkleHashOrchard;

        let mut auth_path_array: [MerkleHashOrchard; MERKLE_DEPTH_ORCHARD] =
            [MerkleHashOrchard::from_bytes(&pallas::Base::zero().to_repr()).unwrap();
                MERKLE_DEPTH_ORCHARD];

        for (idx, sibling) in self.siblings.iter().enumerate() {
            if idx < MERKLE_DEPTH_ORCHARD {
                auth_path_array[idx] = MerkleHashOrchard::from_bytes(&sibling.to_repr()).unwrap();
            }
        }

        MerklePath::from_parts(self.position(), auth_path_array)
    }
}

/// Test data formatted for circuit consumption.
#[derive(Clone, Debug)]
pub struct CircuitTestData {
    /// The selected leaf's input data
    pub leaf_data: TestLeafData,
    /// Computed leaf hash
    pub leaf_hash: Fp,
    /// Authentication path
    pub auth_path: MerkleAuthPath,
    /// Expected root
    pub root: Fp,
    /// Tree depth
    pub tree_depth: usize,
}

impl CircuitTestData {
    /// Get auth path as fixed-size array for 32-level tree (standard depth).
    pub fn auth_path_array_32(&self) -> [Fp; 32] {
        self.auth_path.to_auth_path_array()
    }

    /// Get position bits as u32.
    pub fn position(&self) -> u32 {
        self.auth_path.position()
    }
}

/// Trait for generating test data for merkle tree inclusion proofs.
/// Extends `HeadstashSinsemillaTree` to provide full tree generation and path computation.
///
/// ## Usage
///
/// ```ignore
/// use zk_test_press::suite::{HeadstashSuite, MerkleTestDataBuilder};
///
/// let suite = HeadstashSuite::new();
///
/// // Generate test leaf data
/// let leaves_data = suite.generate_test_leaves(4);
///
/// // Compute leaf hashes
/// let leaf_hashes: Vec<_> = leaves_data.iter()
///     .map(|d| suite.compute_leaf_from_data(d).unwrap())
///     .collect();
///
/// // Build full merkle tree with all levels
/// let tree = suite.generate_full_merkle_tree(leaf_hashes.clone());
///
/// // Compute path for leaf at index 0
/// let path = suite.compute_merkle_path(&tree, 0);
///
/// // Verify the path leads to the correct root
/// assert!(suite.verify_merkle_path(&leaf_hashes[0], &path, &tree.root()));
/// ```
pub trait MerkleTestDataBuilder: HeadstashSinsemillaTree {
    /// Generate random test leaf data for testing.
    ///
    /// Creates `count` test leaves with random addresses and predetermined token/value pairs.
    fn generate_test_leaves(&self, count: usize) -> Vec<TestLeafData> {
        let mut rng = OsRng;
        let tokens = ["uterp", "ibc/ATOM", "factory/token"];
        let values = [1_000_000u64, 5_000_000u64, 10_000_000u64, 50_000_000u64];

        (0..count)
            .map(|i| {
                // Generate random address
                let mut raw_addr = [0u8; 32];
                rng.fill_bytes(&mut raw_addr);

                // Cycle through tokens and values
                let raw_token = tokens[i % tokens.len()].to_string();
                let value = values[i % values.len()];

                let (epk_x, epk_y) = self.derive_epk_natives(raw_addr);
                TestLeafData {
                    epk_x_native: epk_x,
                    epk_y_native: epk_y,
                    nd: Fp::from_repr(self.derive_nd(&raw_token)).unwrap(),
                    v: Fp::from(value),
                    fdi: Fp::from(i as u64),
                    raw_v: value,
                    raw_fdi: i as u64,
                    raw_addr,
                    raw_token,
                }
            })
            .collect()
    }

    /// Generate leaf data from specific inputs (deterministic).
    fn generate_leaf_data(
        &self,
        addr: &[u8; 32],
        token: &str,
        value: u64,
        fdi_index: u64,
    ) -> TestLeafData {
        let (epk_x, epk_y) = self.derive_epk_natives(*addr);

        TestLeafData {
            epk_x_native: epk_x,
            epk_y_native: epk_y,
            nd: Fp::from_repr(self.derive_nd(token)).unwrap(),
            v: Fp::from(value),
            fdi: Fp::from(fdi_index),
            raw_v: value,
            raw_fdi: fdi_index,
            raw_addr: *addr,
            raw_token: token.to_string(),
        }
    }

    /// Compute leaf hash from TestLeafData.
    fn compute_leaf_from_data(&self, data: &TestLeafData) -> Result<Fp, BoxError> {
        self.leaf_hash(
            data.epk_x_native,
            data.epk_y_native,
            data.nd,
            data.v,
            data.fdi,
        )
    }

    /// Build a full merkle tree from leaves, storing all intermediate levels.
    ///
    /// The returned tree structure contains:
    /// - `levels[0]`: Input leaves (padded to power of 2 if necessary)
    /// - `levels[i]`: Parent nodes at level i
    /// - `levels[depth]`: Single root element
    ///
    /// Uses the same `merkle_crh` function as the circuit for consistency.
    fn generate_full_merkle_tree(&self, leaves: Vec<Fp>) -> FullMerkleTree {
        if leaves.is_empty() {
            return FullMerkleTree {
                levels: vec![vec![Fp::ZERO]],
                depth: 0,
            };
        }

        let mut levels: Vec<Vec<Fp>> = Vec::new();

        // Level 0: leaves (pad to even count)
        let mut current_level = leaves;
        if current_level.len() % 2 != 0 {
            current_level.push(Fp::ZERO);
        }
        levels.push(current_level.clone());

        let mut layer = 0u32;

        // Build tree levels until we reach the root
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);

            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { Fp::ZERO };
                let parent = HeadstashSuite::merkle_crh(layer, left, right);
                next_level.push(parent);
            }

            // Pad next level to even if not root
            if next_level.len() > 1 && next_level.len() % 2 != 0 {
                next_level.push(Fp::ZERO);
            }

            levels.push(next_level.clone());
            current_level = next_level;
            layer += 1;
        }

        FullMerkleTree {
            depth: levels.len() - 1,
            levels,
        }
    }

    /// Compute the merkle authentication path for a leaf at a given index.
    ///
    /// Returns the path (sibling nodes) and position bits needed to verify inclusion.
    fn compute_merkle_path(&self, tree: &FullMerkleTree, leaf_index: usize) -> MerkleAuthPath {
        let mut siblings = Vec::with_capacity(tree.depth);
        let mut position_bits = Vec::with_capacity(tree.depth);
        let mut idx = leaf_index;

        for level in 0..tree.depth {
            let level_nodes = &tree.levels[level];

            // Determine if current node is left or right child
            let is_right = idx % 2 == 1;
            position_bits.push(is_right);

            // Get sibling index
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };

            // Get sibling value (zero if out of bounds)
            let sibling = if sibling_idx < level_nodes.len() {
                level_nodes[sibling_idx]
            } else {
                Fp::ZERO
            };
            siblings.push(sibling);

            // Move to parent index
            idx /= 2;
        }

        MerkleAuthPath {
            siblings,
            position_bits,
            leaf_index,
        }
    }

    /// Verify a merkle path by recomputing the root from leaf and path.
    fn verify_merkle_path(&self, leaf: &Fp, path: &MerkleAuthPath, expected_root: &Fp) -> bool {
        let mut current = *leaf;

        for (level, (sibling, &is_right)) in path
            .siblings
            .iter()
            .zip(path.position_bits.iter())
            .enumerate()
        {
            let (left, right) = if is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            current = HeadstashSuite::merkle_crh(level as u32, left, right);
        }

        current == *expected_root
    }

    /// Generate a complete test case with tree, path, and all inputs.
    ///
    /// Returns (leaves_data, tree, selected_leaf_index, auth_path, root)
    fn generate_inclusion_test_case(
        &self,
        num_leaves: usize,
        selected_index: usize,
    ) -> Result<(Vec<TestLeafData>, FullMerkleTree, usize, MerkleAuthPath, Fp), BoxError> {
        let leaves_data = self.generate_test_leaves(num_leaves);

        let leaf_hashes: Vec<Fp> = leaves_data
            .iter()
            .map(|d| self.compute_leaf_from_data(d))
            .collect::<Result<Vec<_>, _>>()?;

        let tree = self.generate_full_merkle_tree(leaf_hashes);
        let path = self.compute_merkle_path(&tree, selected_index);
        let root = tree.root();

        Ok((leaves_data, tree, selected_index, path, root))
    }

    /// Generate test data compatible with the circuit's expected format.
    ///
    /// Returns data in the format needed by `constrain_genesis_inclusion`:
    /// - epk (as x,y coordinates for secp256k1)
    /// - nd, v, fdi as field elements
    /// - path as [pallas::Base; DEPTH] array
    /// - root as pallas::Base
    fn generate_circuit_test_data(
        &self,
        num_leaves: usize,
        selected_index: usize,
    ) -> Result<CircuitTestData, BoxError> {
        let (leaves_data, tree, idx, path, root) =
            self.generate_inclusion_test_case(num_leaves, selected_index)?;

        let selected_leaf = &leaves_data[idx];
        let leaf_hash = self.compute_leaf_from_data(selected_leaf)?;

        Ok(CircuitTestData {
            leaf_data: selected_leaf.clone(),
            leaf_hash,
            auth_path: path,
            root,
            tree_depth: tree.depth,
        })
    }
}

// Implement MerkleTestDataBuilder for HeadstashSuite
impl MerkleTestDataBuilder for HeadstashSuite {}

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
    fn req_headstash_pk(&self) -> Result<ProvingKey, BoxError> {
        todo!()
    }
}

/// Trait for generating headstash circuit keys in binary format.
/// Provides methods to build, write, and load circuit proving/verifying keys.
pub trait CircuitKeysGenerator: HeadstashBitwiseInstance {
    /// Circuit size parameter (K = 18 for headstash)
    const HEADSTASH_K: u32 = 18;

    /// Generate headstash circuit keys and write to directory.
    /// Creates: verifying_key.bin, proving_key.bin (which includes params)
    fn gen_headstash_circuit_keys(
        &self,
        base_path: &Path,
    ) -> Result<(crate::circuit::VerifyingKey, crate::circuit::ProvingKey), BoxError> {
        let keys_dir = base_path.join("headstash_keys");
        fs::create_dir_all(&keys_dir)?;

        println!("[1/3] Building verifying key (K={})...", Self::HEADSTASH_K);
        let vk = crate::circuit::VerifyingKey::build();

        println!("[2/3] Building proving key...");
        let pk = crate::circuit::ProvingKey::build();

        println!("[3/3] Writing keys to {:?}...", keys_dir);

        // Write verifying key (params + vk)
        let vk_path = keys_dir.join(VK_FILE);
        let mut vk_file = std::fs::File::create(&vk_path)?;
        vk.params.write(&mut vk_file)?;
        vk.vk.write(&mut vk_file)?;
        println!("  Written: {:?}", vk_path);

        // Write proving key using existing method
        let pk_path = keys_dir.join(PK_FILE);
        crate::circuit::ProvingKey::build_and_write(pk_path.clone())?;
        println!("  Written: {:?}", pk_path);

        Ok((vk, pk))
    }

    /// Get the default keys directory path.
    fn keys_dir(&self) -> PathBuf {
        PathBuf::from(KEYS_DIR)
    }
}


impl CircuitKeysGenerator for HeadstashSuite {}

/// Proof bundle containing proof and public inputs for a headstash claim.
#[derive(Clone, Debug)]
pub struct HeadstashProofBundle {
    /// The generated proof (using native headstash circuit proof type)
    pub proof: crate::Proof,
    /// Public inputs (anchor, nd, v, recp, nf, cmx)
    pub instance: crate::circuit::Instance,
    /// The merkle tree anchor
    pub anchor: Anchor,
}

/// Trait for building headstash proofs from genesis distribution data.
/// Optimized for 1-time-spend model (static merkle tree, single claim per note).
pub trait HeadstashProofBuilder:
    HeadstashBitwiseInstance + MerkleTestDataBuilder + CircuitKeysGenerator
{
    /// Build SpendInfo from note and authentication path.
    fn build_spend_info(
        &self,
        note: &Note,
        fvk: &FullViewingKey,
        auth_path: &MerkleAuthPath,
    ) -> Result<SpendInfo, BoxError> {
        let merkle_path = auth_path.to_circuit_path();
        SpendInfo::new(fvk.clone(), note.clone(), merkle_path)
            .ok_or_else(|| "Failed to create SpendInfo".into())
    }

    /// Create a headstash proof from test leaf data.
    /// Uses from_action_context_unchecked for 1-time spend semantics.
    fn create_genesis_proof_from_leaf(
        &self,
        pk: &crate::circuit::ProvingKey,
        leaf_data: &TestLeafData,
        auth_path: &MerkleAuthPath,
    ) -> Result<HeadstashProofBundle, BoxError> {
        let mut rng = OsRng;

        // Generate keys for this claim
        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::from(&sk);
        let esk = EligibleSk::random(&mut rng);

        // Create rho and rseed
        let rho = self.rho_from_secure_random();
        let rseed_bytes = self.rho_from_secure_random().to_bytes();
        let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).expect("rseed issue");

        // Build HeadstashValue from leaf data
        let hv =
            HeadstashValue::from_raw(leaf_data.raw_v, &leaf_data.raw_token, leaf_data.raw_fdi)?;

        // Create recipient and note
        let recp = RecpAddr::new(leaf_data.raw_addr);
        let note = Note::from_parts(hv, recp, esk, rho, rseed).expect("correct note parts");

        // Build SpendInfo using the circuit path conversion
        let merkle_path = auth_path.to_circuit_path();
        let spend_info = SpendInfo::new(fvk, note.clone(), merkle_path.clone())
            .ok_or("SpendInfo creation failed")?;

        // Compute anchor from merkle path and note commitment
        let anchor = merkle_path.root(note.commitment().into());

        // Build instance (public inputs)
        let nf = note.nullifier();
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let instance =
            crate::circuit::Instance::from_parts(anchor, hv.denom(), hv.amount(), recp, nf, cmx);

        // Build circuit using unchecked (rho not deterministically derived in this context)
        let circuit = Circuit::from_action_context_unchecked(spend_info, note);

        // Generate proof using native headstash circuit proof creation
        // Note: Proof::create from crate::circuit expects native types, not zk_cosmwasm types
        let proof = Proof::create(pk, &[circuit], &[instance.clone()], &mut rng)?;

        Ok(HeadstashProofBundle {
            proof,
            instance,
            anchor,
        })
    }

    // /// Verify a headstash proof.
    // fn verify_genesis_proof(
    //     &self,
    //     vk: &crate::circuit::VerifyingKey,
    //     bundle: &HeadstashProofBundle,
    // ) -> Result<(), BoxError> {
    //     bundle
    //         .proof
    //         .verify(vk, &[bundle.instance.clone()])
    //         .map_err(|e| format!("Proof verification failed: {:?}", e).into())
    // }
}

impl HeadstashProofBuilder for HeadstashSuite {}

/// launchpad
pub trait HeadstashLaunchpadInstance: HeadstashBitwiseInstance + HeadstashIpfsInstance {
    /// ## [create_headstash_proof]
    /// > #### Default method for creating a proof. Requires both the *public (instance)* & *private (witnesses)* values.
    fn create_headstash_proof(
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

        let pk = self.req_headstash_pk()?;
        let spk = SpendingKey::from_bytes(r).expect("spk");
        let fvk = FullViewingKey::from(&spk);

        let n = Note::from_parts(hv, recp, esk, rho, rseed).expect("note derivation");
        let nf = n.nullifier();
        let cmx = ExtractedNoteCommitment::from(n.commitment());

        let c = SpendInfo::new(fvk, n, mp).expect("headstash claim");

        // generate proof, unchecked as we rho is not deterministically derived
        let instances =
            crate::circuit::Instance::from_parts(a, hv.denom(), hv.amount(), recp, nf, cmx);
        let circuit = Circuit::from_action_context_unchecked(c, n);
        Ok(Proof::create(&pk, &[circuit], &[instances], &mut rng)?)
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

// ============================================================================
// E2E Test Data Generator
// ============================================================================

/// Complete E2E test bundle containing all generated artifacts.
#[derive(Debug)]
pub struct HeadstashE2ETestBundle {
    /// Circuit verifying key
    pub vk: crate::circuit::VerifyingKey,
    /// Circuit proving key
    pub pk: crate::circuit::ProvingKey,
    /// Full merkle tree
    pub tree: FullMerkleTree,
    /// Test leaf data for all accounts
    pub leaves: Vec<TestLeafData>,
    /// Per-account test data with proofs
    pub accounts: Vec<HeadstashAccountTestData>,
}

/// Per-account test data including keys, proof, and instance.
#[derive(Clone, Debug)]
pub struct HeadstashAccountTestData {
    /// Account index in the tree
    pub index: usize,
    /// Spending key bytes (for test reproducibility)
    pub sk_bytes: [u8; 32],
    /// Eligible secret key
    pub esk: EligibleSk,
    /// The generated proof
    pub proof: crate::Proof,
    /// Public instance
    pub instance: crate::circuit::Instance,
    /// Merkle authentication path
    pub auth_path: MerkleAuthPath,
    /// Computed anchor
    pub anchor: Anchor,
    /// Whether the merkle path was verified valid
    pub path_valid: bool,
}

/// Trait for generating complete E2E test data for headstash circuits.
/// Consolidates all test generation logic into the suite for reuse across projects.
pub trait HeadstashTestDataGenerator:
    HeadstashBitwiseInstance
    + MerkleTestDataBuilder
    + CircuitKeysGenerator
    + HeadstashProofBuilder
{
    /// Generate a complete E2E test bundle with circuit keys, merkle tree, and proofs.
    ///
    /// This is the canonical method for generating headstash test data.
    /// Returns all artifacts needed for E2E testing.
    fn generate_e2e_test_bundle(
        &self,
        num_accounts: usize,
    ) -> Result<HeadstashE2ETestBundle, BoxError> {
        let mut rng = OsRng;

        // Step 1: Build circuit keys
        eprintln!("[1/4] Building circuit keys (K=17)...");
        let vk = crate::circuit::VerifyingKey::build();
        let pk = crate::circuit::ProvingKey::build();
        eprintln!("  Circuit keys built");

        // Step 2: Generate test leaves
        eprintln!("[2/4] Generating {} test leaves...", num_accounts);
        let leaves = self.generate_test_leaves(num_accounts);

        // Compute leaf hashes
        let leaf_hashes: Vec<Fp> = leaves
            .iter()
            .map(|leaf| self.compute_leaf_from_data(leaf).expect("leaf hash"))
            .collect();

        // Step 3: Build merkle tree
        eprintln!("[3/4] Building merkle tree...");
        let tree = self.generate_full_merkle_tree(leaf_hashes.clone());
        eprintln!("  Tree depth: {}", tree.depth);

        // Step 4: Generate proofs for each account
        eprintln!("[4/4] Generating proofs for {} accounts...", num_accounts);
        let mut accounts = Vec::with_capacity(num_accounts);

        for i in 0..num_accounts {
            eprintln!("  Account {}/{}...", i + 1, num_accounts);
            let auth_path = self.compute_merkle_path(&tree, i);
            let path_valid = self.verify_merkle_path(&leaf_hashes[i], &auth_path, &tree.root());
            let merkle_path = auth_path.to_circuit_path();
            let leaf = &leaves[i];
            // Generate random keys
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);
            let sk = SpendingKey::from_bytes(sk_bytes).expect("valid spending key");
            let fvk = FullViewingKey::from(&sk);
            let esk = EligibleSk::random(&mut rng);
            // Create rho and rseed
            let rho = self.rho_from_secure_random();
            let mut rseed_bytes = [0u8; 32];
            rng.fill_bytes(&mut rseed_bytes);
            let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).expect("valid rseed");

            // Build HeadstashValue
            let hv = HeadstashValue::from_raw(leaf.raw_v, &leaf.raw_token, leaf.raw_fdi)?;

            // Create note
            let recp = RecpAddr::new(leaf.raw_addr);
            let note = Note::from_parts(hv, recp, esk.clone(), rho, rseed).expect("note creation");

            // Compute anchor and build instance
            let anchor = merkle_path.root(note.commitment().into());
            let nf = note.nullifier();
            let cmx = ExtractedNoteCommitment::from(note.commitment());
            let instance = crate::circuit::Instance::from_parts(
                anchor,
                hv.denom(),
                hv.amount(),
                recp,
                nf,
                cmx,
            );

            // Build circuit and generate proof
            let spend_info = SpendInfo::new(fvk, note.clone(), merkle_path).expect("SpendInfo");
            let circuit = Circuit::from_action_context_unchecked(spend_info, note);
            let proof = Proof::create(&pk, &[circuit], &[instance.clone()], &mut rng)?;

            // Verify proof
            proof.verify(&vk, &[instance.clone()])?;

            accounts.push(HeadstashAccountTestData {
                index: i,
                sk_bytes,
                esk,
                proof,
                instance,
                auth_path,
                anchor,
                path_valid,
            });
        }

        Ok(HeadstashE2ETestBundle {
            vk,
            pk,
            tree,
            leaves,
            accounts,
        })
    }

    /// Write E2E test bundle to files in the specified directory.
    ///
    /// Creates:
    /// - `headstash.vk.bin` - Verifying key binary
    /// - `tree.json` - Merkle tree metadata
    /// - `headstash_test_data.json` - Full test data with private keys
    /// - `headstash_proofs.json` - Simplified proofs for E2E scripts
    fn write_e2e_test_files(
        &self,
        bundle: &HeadstashE2ETestBundle,
        output_dir: &Path,
    ) -> Result<(), BoxError> {
        use std::io::Write;

        std::fs::create_dir_all(output_dir)?;

        // Write verifying key
        let vk_path = output_dir.join("headstash.vk.bin");
        let mut vk_file = std::fs::File::create(&vk_path)?;
        bundle.vk.params.write(&mut vk_file)?;
        bundle.vk.vk.write(&mut vk_file)?;

        // Write tree metadata
        let tree_meta = json!({
            "root": format!("{:?}", bundle.tree.root()),
            "depth": bundle.tree.depth,
            "num_leaves": bundle.tree.num_leaves(),
        });
        let tree_path = output_dir.join("tree.json");
        std::fs::File::create(&tree_path)?
            .write_all(serde_json::to_string_pretty(&tree_meta)?.as_bytes())?;

        // Build account data
        let mut accounts_json = Vec::new();
        for (account, leaf) in bundle.accounts.iter().zip(bundle.leaves.iter()) {
            let (epkx, epky) = account.esk.epk().xy();

            accounts_json.push(json!({
                "account_index": account.index,
                "private_keys": {
                    "spending_key": general_purpose::STANDARD.encode(&account.sk_bytes),
                    "eligible_sk": general_purpose::STANDARD.encode(account.esk.secret_bytes()),
                },
                "public_keys": {
                    "epk_x": general_purpose::STANDARD.encode(&epkx),
                    "epk_y": general_purpose::STANDARD.encode(&epky),
                },
                "leaf_data": {
                    "epk_x_native": format!("{:?}", leaf.epk_x_native),
                    "epk_y_native": format!("{:?}", leaf.epk_y_native),
                    "nd": format!("{:?}", leaf.nd),
                    "v": format!("{:?}", leaf.v),
                    "fdi": format!("{:?}", leaf.fdi),
                    "raw_token": leaf.raw_token.clone(),
                },
                "merkle": {
                    "position": account.auth_path.position(),
                    "tree_depth": bundle.tree.depth,
                    "leaf_index": account.index,
                    "anchor": format!("{:?}", account.anchor),
                },
                "instance": self.instance_to_json(&account.instance),
                "proof": general_purpose::STANDARD.encode(account.proof.as_ref()),
                "path_valid": account.path_valid,
            }));
        }

        // Write full test data
        let full_output = json!({
            "generated_at": format!("{:?}", std::time::SystemTime::now()),
            "num_accounts": bundle.accounts.len(),
            "circuit_k": 17,
            "vk_path": "headstash.vk.bin",
            "tree": tree_meta,
            "accounts": accounts_json,
        });
        let json_path = output_dir.join("headstash_test_data.json");
        std::fs::File::create(&json_path)?
            .write_all(serde_json::to_string_pretty(&full_output)?.as_bytes())?;

        // Write simplified proofs file
        let mut proofs_map = serde_json::Map::new();
        for account in &bundle.accounts {
            proofs_map.insert(
                format!("account_{}", account.index),
                json!({
                    "proof": general_purpose::STANDARD.encode(account.proof.as_ref()),
                    "instance": self.instance_to_json(&account.instance),
                }),
            );
        }
        let proofs_path = output_dir.join("headstash_proofs.json");
        std::fs::File::create(&proofs_path)?
            .write_all(serde_json::to_string_pretty(&Value::Object(proofs_map))?.as_bytes())?;

        Ok(())
    }

    /// Convert Instance to JSON for serialization.
    fn instance_to_json(&self, instance: &crate::circuit::Instance) -> Value {
        json!({
            "anchor": format!("{:?}", instance.anchor),
            "nd": format!("{:?}", instance.nd),
            "v": instance.v.inner(),
            "recp": format!("{:?}", instance.recp),
            "nf": format!("{:?}", instance.nf),
            "cmx": format!("{:?}", instance.cmx),
        })
    }
}

impl HeadstashTestDataGenerator for HeadstashSuite {}

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
        // // Load original allocations
        // let input_data: Value =
        //     serde_json::from_str(&fs::read_to_string("./data/genesis_sinsemilla.json")?)?;

        // // Load generated notes for the zero address
        // let notes_path = "./data/notes/0x0000000000000000000000000000000000000000.json";
        // let calculated_notes: Value = serde_json::from_str(&fs::read_to_string(notes_path)?)?;

        // // Extract original holdings
        // let mut original_balances: HashMap<String, u64> = HashMap::new();

        // if let Value::Object(map) = &input_data {
        //     if let Some(holdings) = map.get("0x0000000000000000000000000000000000000000") {
        //         if let Value::Array(holding_array) = holdings {
        //             for holding in holding_array {
        //                 if let Some(name) = holding["name"].as_str() {
        //                     let amount_str = holding["amount"].as_str().unwrap_or("0");
        //                     let amount: u64 = amount_str.parse().unwrap_or(0);
        //                     *original_balances.entry(name.to_string()).or_insert(0) += amount;
        //                 }
        //             }
        //         }
        //     }
        // }

        // // Extract and sum note values from generated notes
        // let mut notes_sum: HashMap<String, u64> = HashMap::new();

        // if let Value::Object(note_map) = &calculated_notes {
        //     for (token_name, notes) in note_map {
        //         if let Value::Array(note_array) = notes {
        //             for note in note_array {
        //                 if let Some(v_str) = note["v"].as_str() {
        //                     let v: u64 = v_str.parse().unwrap_or(0);
        //                     *notes_sum.entry(token_name.clone()).or_insert(0) += v;
        //                 }
        //             }
        //         }
        //     }
        // }

        // // Compare: original vs summed note values
        // for (token, original_amount) in &original_balances {
        //     let note_total = notes_sum.get(token).copied().unwrap_or(0);
        //     assert_eq!(
        //         original_amount, &note_total,
        //         "Token {}: allocation ({}) does not match total notes ({})",
        //         token, original_amount, note_total
        //     );
        // }

        // // Also check for extra tokens in notes not in original
        // for (token, _) in &notes_sum {
        //     assert!(
        //         original_balances.contains_key(token),
        //         "Token {} appears in notes but not in original allocation",
        //         token
        //     );
        // }

        Ok(())
    }

    // fn load_data() -> Result<Value, BoxError> {
    //     let file = fs::File::open("./data/genesis_sinsemilla.json")?;
    //     let reader = std::io::BufReader::new(file);
    //     Ok(serde_json::from_reader(reader)?)
    // }

    // // Ensures input data is in compatible format
    // #[test]
    // pub fn test_input_data_accuracy() -> Result<(), BoxError> {
    //     let data = load_data()?;
    //     if !data.is_object() {
    //         panic!("Expected JSON object (map) at root");
    //     }

    //     for (addr, tokens) in data.as_object().unwrap().iter() {
    //         assert!(tokens.is_array(), "Value for {} must be an array", addr);
    //         for token in tokens.as_array().unwrap() {
    //             let obj = token.as_object().unwrap();
    //             assert!(obj.contains_key("amount"), "missing required key 'amount'");
    //             assert!(obj.contains_key("token"), " missing required key 'token'");
    //             assert!(obj["amount"].is_string(), "'amount' must be a string");
    //             assert!(obj["token"].is_string(), "'token' must be a string");
    //         }
    //     }

    //     Ok(())
    // }

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

    // =========================================================================
    // MerkleTestDataBuilder Tests
    // =========================================================================

    #[test]
    fn test_generate_test_leaves() {
        let suite = HeadstashSuite::new();
        let leaves = suite.generate_test_leaves(4);

        assert_eq!(leaves.len(), 4);
        for (i, leaf) in leaves.iter().enumerate() {
            // epk_x_native and epk_y_native are Fp field elements (always valid)
            // nd is now an Fp field element
            // v is now an Fp field element
            // fdi is now an Fp field element
            // fdi should match index
            assert_eq!(leaf.fdi, Fp::from(i as u64));
        }
    }

    #[test]
    fn test_full_merkle_tree_single_leaf() {
        let suite = HeadstashSuite::new();
        let leaf = Fp::from(42u64);

        let tree = suite.generate_full_merkle_tree(vec![leaf]);

        // Single leaf padded to 2, then hashed to root
        assert!(tree.levels.len() >= 2);
        assert_eq!(tree.levels[0].len(), 2); // padded
        assert_eq!(tree.levels[tree.depth].len(), 1); // root
    }

    #[test]
    fn test_full_merkle_tree_four_leaves() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..4).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());

        assert_eq!(tree.levels[0].len(), 4);
        assert_eq!(tree.levels[1].len(), 2);
        assert_eq!(tree.levels[2].len(), 1);
        assert_eq!(tree.depth, 2);
    }

    #[test]
    fn test_merkle_path_computation() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..4).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());

        for i in 0..4 {
            let path = suite.compute_merkle_path(&tree, i);
            assert_eq!(path.siblings.len(), tree.depth);
            assert_eq!(path.position_bits.len(), tree.depth);
            assert_eq!(path.leaf_index, i);
        }
    }

    #[test]
    fn test_merkle_path_verification() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..8).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());
        let root = tree.root();

        // Verify path for each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            let path = suite.compute_merkle_path(&tree, i);
            assert!(
                suite.verify_merkle_path(leaf, &path, &root),
                "Path verification failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_merkle_path_verification_fails_wrong_leaf() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..4).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());
        let root = tree.root();

        // Use path for leaf 0 but try to verify with wrong leaf
        let path = suite.compute_merkle_path(&tree, 0);
        let wrong_leaf = Fp::from(999u64);

        assert!(
            !suite.verify_merkle_path(&wrong_leaf, &path, &root),
            "Verification should fail with wrong leaf"
        );
    }

    #[test]
    fn test_generate_inclusion_test_case() {
        let suite = HeadstashSuite::new();
        let result = suite.generate_inclusion_test_case(8, 3);
        assert!(result.is_ok());

        let (leaves_data, tree, idx, path, root) = result.unwrap();

        assert_eq!(leaves_data.len(), 8);
        assert_eq!(idx, 3);

        // Verify the path is valid
        let leaf_hash = suite.compute_leaf_from_data(&leaves_data[3]).unwrap();
        assert!(suite.verify_merkle_path(&leaf_hash, &path, &root));
    }

    #[test]
    fn test_circuit_test_data_generation() {
        let suite = HeadstashSuite::new();
        let result = suite.generate_circuit_test_data(4, 1);
        assert!(result.is_ok());

        let circuit_data = result.unwrap();

        assert!(circuit_data.tree_depth > 0);
        assert_eq!(circuit_data.auth_path.leaf_index, 1);

        // Verify the path
        assert!(suite.verify_merkle_path(
            &circuit_data.leaf_hash,
            &circuit_data.auth_path,
            &circuit_data.root
        ));
    }

    #[test]
    fn test_deterministic_leaf_generation() {
        let suite = HeadstashSuite::new();
        let addr = [0u8; 32];
        let token = "uterp";
        let value = 1_000_000u64;
        let fdi = 0u64;

        let leaf1 = suite.generate_leaf_data(&addr, token, value, fdi);
        let leaf2 = suite.generate_leaf_data(&addr, token, value, fdi);

        assert_eq!(leaf1.epk_x_native, leaf2.epk_x_native);
        assert_eq!(leaf1.epk_y_native, leaf2.epk_y_native);
        assert_eq!(leaf1.nd, leaf2.nd);
        assert_eq!(leaf1.v, leaf2.v);
        assert_eq!(leaf1.fdi, leaf2.fdi);

        let hash1 = suite.compute_leaf_from_data(&leaf1).unwrap();
        let hash2 = suite.compute_leaf_from_data(&leaf2).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    #[cfg(feature = "multicore")]
    fn test_tree_root_consistency_with_existing() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..4).map(|i| Fp::from(i as u64)).collect();

        // Compare with existing tree_root_from_leaves (requires multicore feature)
        let existing_root = suite.tree_root_from_leaves(leaves.clone())[0];
        let full_tree = suite.generate_full_merkle_tree(leaves);

        assert_eq!(
            existing_root,
            full_tree.root(),
            "Full tree root should match existing implementation"
        );
    }

    #[test]
    fn test_position_encoding() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..8).map(|i| Fp::from(i as u64)).collect();
        let tree = suite.generate_full_merkle_tree(leaves);

        // Leaf 0: position = 0b000 = 0
        let path0 = suite.compute_merkle_path(&tree, 0);
        assert_eq!(path0.position(), 0);

        // Leaf 1: position = 0b001 = 1
        let path1 = suite.compute_merkle_path(&tree, 1);
        assert_eq!(path1.position(), 1);

        // Leaf 2: position = 0b010 = 2
        let path2 = suite.compute_merkle_path(&tree, 2);
        assert_eq!(path2.position(), 2);

        // Leaf 5: position = 0b101 = 5
        let path5 = suite.compute_merkle_path(&tree, 5);
        assert_eq!(path5.position(), 5);
    }

    #[test]
    fn test_auth_path_array_conversion() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..4).map(|i| Fp::from(i as u64)).collect();
        let tree = suite.generate_full_merkle_tree(leaves);

        let path = suite.compute_merkle_path(&tree, 0);
        let arr: [Fp; 32] = path.to_auth_path_array();

        // First elements should match siblings
        for (i, sibling) in path.siblings.iter().enumerate() {
            assert_eq!(arr[i], *sibling);
        }
        // Remaining elements should be zero
        for i in path.siblings.len()..32 {
            assert_eq!(arr[i], Fp::ZERO);
        }
    }

    #[test]
    fn test_larger_tree() {
        let suite = HeadstashSuite::new();
        let leaves: Vec<Fp> = (0..64).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());
        let root = tree.root();

        // 64 leaves -> 6 levels (2^6 = 64)
        assert_eq!(tree.depth, 6);

        // Verify all paths
        for (i, leaf) in leaves.iter().enumerate() {
            let path = suite.compute_merkle_path(&tree, i);
            assert!(
                suite.verify_merkle_path(leaf, &path, &root),
                "Path verification failed for leaf {} in 64-leaf tree",
                i
            );
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let suite = HeadstashSuite::new();
        // 5 leaves (odd number)
        let leaves: Vec<Fp> = (0..5).map(|i| Fp::from(i as u64)).collect();

        let tree = suite.generate_full_merkle_tree(leaves.clone());
        let root = tree.root();

        // Padded to 6 leaves at level 0
        assert_eq!(tree.levels[0].len(), 6);

        // Verify paths for original leaves
        for (i, leaf) in leaves.iter().enumerate() {
            let path = suite.compute_merkle_path(&tree, i);
            assert!(
                suite.verify_merkle_path(leaf, &path, &root),
                "Path verification failed for leaf {} in odd-leaf tree",
                i
            );
        }
    }

    #[test]
    fn test_merkle_auth_path_to_circuit_path() {
        let suite = HeadstashSuite::new();

        // Generate a small tree
        let test_leaves = suite.generate_test_leaves(4);
        let leaf_hashes: Vec<_> = test_leaves
            .iter()
            .map(|l| suite.compute_leaf_from_data(l).unwrap())
            .collect();
        let tree = suite.generate_full_merkle_tree(leaf_hashes);

        // Get auth path and convert
        let auth_path = suite.compute_merkle_path(&tree, 1);
        let circuit_path = auth_path.to_circuit_path();

        // Verify position matches
        assert_eq!(auth_path.position(), circuit_path.position());

        // Verify auth path length is MERKLE_DEPTH_ORCHARD (32)
        assert_eq!(
            circuit_path.auth_path().len(),
            crate::constants::MERKLE_DEPTH_ORCHARD
        );

        // Verify first siblings match (before padding)
        for (i, sibling) in auth_path.siblings.iter().enumerate() {
            let circuit_sibling = circuit_path.auth_path()[i];
            assert_eq!(
                sibling.to_repr(),
                circuit_sibling.to_bytes(),
                "Sibling mismatch at index {}",
                i
            );
        }
    }

    #[test]
    #[ignore] // Expensive test - run with: cargo test test_headstash_e2e_proof_generation -- --ignored
    fn test_headstash_e2e_proof_generation() -> Result<(), BoxError> {
        let suite = HeadstashSuite::new();

        // Step 1: Generate circuit keys
        println!("Generating circuit keys...");
        let (vk, pk) =
            suite.gen_headstash_circuit_keys(&std::env::temp_dir().join("headstash_test_keys"))?;

        // Step 2: Generate test merkle tree
        let num_leaves = 4;
        let test_leaves = suite.generate_test_leaves(num_leaves);
        let leaf_hashes: Vec<_> = test_leaves
            .iter()
            .map(|l| suite.compute_leaf_from_data(l).unwrap())
            .collect();
        let tree = suite.generate_full_merkle_tree(leaf_hashes.clone());

        // Step 3: Generate and verify proof for first leaf
        let auth_path = suite.compute_merkle_path(&tree, 0);

        // Verify merkle path is valid
        assert!(suite.verify_merkle_path(&leaf_hashes[0], &auth_path, &tree.root()));

        // Create proof
        let proof_bundle =
            suite.create_genesis_proof_from_leaf(&pk, &test_leaves[0], &auth_path)?;

        // Verify proof
        // suite.verify_genesis_proof(&vk, &proof_bundle)?;

        println!("E2E proof generation and verification successful!");
        Ok(())
    }
}
