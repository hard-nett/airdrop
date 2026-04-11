//! main suite for headstash
use alloc::boxed::Box;
use ict_rs::chain::terp::ZkSuiteError;
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
use ff::{Field, FromUniformBytes, PrimeField, PrimeFieldBits};
use hex::decode;
use pasta_curves::pallas::Base;
use pasta_curves::{Fp, arithmetic::CurveAffine, group::Curve, pallas};
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



// ── TestPressSuite ────────────────────────────────────────────────────────────

/// Composed suite of **all** test-press circuit suites.
///
/// Retains every method from the headstash helpers (via the same trait blanket
/// impls) and adds one `TerpVmSuite`-compatible field per test circuit.
///
/// # Feature gating
/// The circuit-suite fields (`no_rick`, …) are only present when the
/// `interface` feature is enabled (pulls in ict-rs).  The struct is still
/// usable without that feature — it is then just a zero-sized wrapper that
/// provides all the `HeadstashBitwiseInstance` / tree / IPFS / launchpad
/// helpers.
///
/// # Layout (keys dir)
/// ```text
/// <keys_base>/
///   no_rick/
///     params.bin
///     proving_key.bin
///     verifying_key.bin
/// ```
pub struct TestPressSuite {
    /// No-Rick circuit: key management, prove, verify, on-chain deploy.
    #[cfg(feature = "interface")]
    pub no_rick: crate::suites::no_rick::NoRickSuite,
    /// Headstash Orchard circuit: production spend-proof circuit.
    #[cfg(feature = "interface")]
    pub headstash_circuit: crate::suites::headstash::HeadstashSuite,
    // sinsemilla merkle tree
    // zk-hashmerchant (proove know mirrored tree root path )
    // plonky3
    // groth16
    // cario
    // zk-tls
}

/// TerpHeadstashConfig
#[derive(Debug)]
pub struct TerpHeadstashConfig {}

// All stateless circuit-utility traits are delegated with default impls.
impl HeadstashBitwiseInstance for TestPressSuite {}
impl HeadstashSinsemillaTree for TestPressSuite {}
impl HeadstashIpfsInstance for TestPressSuite {}
impl HeadstashLaunchpadInstance for TestPressSuite {}

impl TestPressSuite {
    /// Create with a default keys directory (`./circuit_keys`).
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "interface")]
            no_rick: crate::suites::no_rick::NoRickSuite::new(
                std::path::PathBuf::from(KEYS_DIR).join("no_rick"),
            ),
            #[cfg(feature = "interface")]
            headstash_circuit: crate::suites::headstash::HeadstashSuite::with_keys_dir(
                std::path::PathBuf::from(KEYS_DIR).join("headstash"),
            ),
        }
    }

    /// Create with an explicit base directory for all circuit key files.
    pub fn with_keys_dir<P: Into<std::path::PathBuf>>(base: P) -> Self {
        let base = base.into();
        Self {
            #[cfg(feature = "interface")]
            no_rick: crate::suites::no_rick::NoRickSuite::new(base.join("no_rick")),
            #[cfg(feature = "interface")]
            headstash_circuit: crate::suites::headstash::HeadstashSuite::with_keys_dir(
                base.join("headstash"),
            ),
        }
    }
}

#[cfg(feature = "interface")]
impl TestPressSuite {
    /// Generate or load No-Rick circuit keys, then create proofs for each
    /// `(private_word, forbidden_word)` pair.
    pub fn gen_test_circuit_keys(
        &self,
        path: &std::path::Path,
        key_path: Option<&std::path::Path>,
        proof_specs: Vec<(&str, &str)>,
    ) -> Result<Vec<crate::circuits::no_rick::Proof>, BoxError> {
        use crate::suites::no_rick::{NoRickInputs, NoRickSuite};
        use ict_rs::chain::terp::TerpVmSuite as _;

        let suite = NoRickSuite::new(key_path.unwrap_or(path));
        if key_path.is_none() {
            suite.build_and_save_keys(10)?;
        }

        proof_specs
            .into_iter()
            .map(|(private_word, forbidden_word)| {
                suite
                    .prove(&NoRickInputs::new(private_word, forbidden_word))
                    .map_err(|e| Box::new(e) as BoxError)
            })
            .collect()
    }
}

/// HeadstashBitwiseInstance
pub trait HeadstashBitwiseInstance {
    /// Derives the native pallas representation of a secp256k1 secret key.
    /// Returns `esk mod pallas_p`, matching the in-circuit `.native` value.
    fn derive_esk_native(&self, sk: [u8; 32]) -> Fp {
        use zk_headstash::biguint_to_fe_simple;
        let skfq = halo2_base::halo2_proofs::halo2curves::secq256k1::Fp::from_repr(sk).expect("Fq");
        let sk_big = halo2_base::utils::fe_to_biguint(&skfq);
        biguint_to_fe_simple(&sk_big)
    }

    /// Derives the native pallas representations of the secp256k1 public key
    /// from a secret key. Computes `epk = esk * G` on secp256k1, then reduces
    /// both coordinates mod pallas_p to match the in-circuit `.native` values.
    fn derive_epk_natives(&self, sk: [u8; 32]) -> (Fp, Fp) {
        use zk_headstash::to_native_out_of_circuit;
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

    /// Convert a byte slice into an iterator of little-endian bits (LSB first per byte).
    fn bytes_to_bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
    }



    /// Note-Denom (nd): blake3 hash of the token, 1 bit cleared.
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
        eprintln!("Input with leaves written to {}", self.get_input_path()?);
        let merkle_path = path.join("merkle_output.json");
        fs::write(&merkle_path, serde_json::to_string_pretty(&output)?)?;
        eprintln!("Merkle output written to {}", merkle_path.display());
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

                let (lidxh, raw_leaves) =
                    self.derive_leaf(addr.as_str(), &token["name"].to_string(), v)?;
                {
                    token
                        .as_object_mut()
                        .unwrap()
                        .entry("leaves")
                        .or_insert_with(|| json!([]));
                }

                for (fixed_amount, idx, leaf_hex) in lidxh {
                    token
                        .get_mut("leaves")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                        .push(json!({ "amnt":fixed_amount,"index": idx, "leaf": leaf_hex }));
                }

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
        let mut work_items: Vec<u64> = Vec::new();
        let mut remainder = v;
        for &fixed_amount in FIXED_AMOUNTS.iter() {
            let count = remainder / fixed_amount;
            if count == 0 {
                remainder %= fixed_amount;
                continue;
            }
            work_items.extend(std::iter::repeat(fixed_amount).take(count as usize));
            remainder %= fixed_amount;
        }
        debug_assert_eq!(remainder, 0, "remainder not zero after denomination split");

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
        let mut message = Vec::with_capacity(510);

        for i in 0..10 {
            message.push((layer >> i) & 1 == 1);
        }

        <TestPressSuite as HeadstashBitwiseInstance>::extend_with_base_field_bits(
            &mut message,
            left,
        );
        <TestPressSuite as HeadstashBitwiseInstance>::extend_with_base_field_bits(
            &mut message,
            right,
        );

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
                        let token_name = holding["name"].as_str().unwrap().to_string();
                        let _total_amount = holding["amount"].as_str().unwrap();

                        let leaves = match holding.get("leaves") {
                            Some(Value::Array(arr)) => arr,
                            _ => {
                                eprintln!("No \"leaves\" array for token {}", token_name);
                                std::process::exit(1);
                            }
                        };

                        let mut generated_notes = Vec::new();

                        for leaf in leaves.iter() {
                            let amnt = leaf["amnt"].as_u64().unwrap_or_else(|| {
                                eprintln!("Missing \"amnt\" in leaf for token {}", token_name);
                                std::process::exit(1);
                            });

                            let fdi = leaf["index"].as_u64().unwrap_or_else(|| {
                                eprintln!("Missing \"index\" in leaf for token {}", token_name);
                                std::process::exit(1);
                            });
                            generated_notes.push(json!({
                                "nd":      NoteDenom::new_for_proof(&token_name.clone()).to_string(),
                                "v":     NoteValue::from_bytes(amnt.to_le_bytes()).inner(),
                                "fdi":        fdi,
                            }));
                        }

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

        let output_dir = Path::new("./data/notes");
        fs::create_dir_all(output_dir)?;
        let safe_addr: String = addr_target
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        let output_path = output_dir.join(format!("{}.json", safe_addr));

        fs::write(&output_path, serde_json::to_string_pretty(&address_notes)?)?;

        eprintln!("Default Genesis Notes generated for {}", addr_target);
        eprintln!("Written to: {}", output_path.display());

        Ok(())
    }

    /// TODO: create default notes of a specific public key allocation for a given headstash instance.
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
pub trait HeadstashIpfsInstance: HeadstashBitwiseInstance {
    /// `upload_circuit_keys`: upload keys to ipfs for public distribution
    fn upload_circuit_keys(&self) -> Result<(), BoxError> {
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
    /// Default method for creating a proof.
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
        let spk = SpendingKey::from_bytes(r);
        let fvk = if bool::from(spk.is_some()) {
            FullViewingKey::from(&spk.unwrap())
        } else {
            return Err("SpendingKey derivation failed".into());
        };

        let n = Note::from_parts(hv, recp, esk, rho, rseed).expect("note derivation");
        let nf = n.nullifier();
        let cmx = ExtractedNoteCommitment::from(n.commitment());

        let c = SpendInfo::new(fvk, n, mp).expect("headstash claim");

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
        self.gen_new_headstash_params();
        self.gen_community_snapshots();
        self.gen_calculate_distribution();
        self.upload_circuit_keys()?;
        self.upload_headstash_yaml()?;
        unimplemented!()
    }

    fn gen_new_headstash_params(&self) {}
    fn gen_community_snapshots(&self) {}
    fn gen_calculate_distribution(&self) {}
}
