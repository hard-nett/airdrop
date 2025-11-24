use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;
use std::{env, fs};

// use group::GroupEncoding;
// use halo2_gadgets::poseidon::primitives as poseidon;
// use crate::constants::DST_HKDF;
// use crate::keys::EligibleSk;
// use secp256k1::SecretKey;
use rayon::prelude::*;

use crate::constants::fixed_bases::FIXED_AMOUNTS;
use crate::constants::sinsemilla::{DST_ND, LEAF_PERSONALIZATION, MERKLE_CRH_PERSONALIZATION};

use crate::note::Note;
use crate::value::NoteDenom;

use base64::{engine::general_purpose, Engine as _};
use hex::decode;
use serde_json::{json, Value};

use ff::{Field, PrimeField, PrimeFieldBits};
use pasta_curves::{arithmetic::CurveAffine, group::Curve, pallas, Fp};
use sinsemilla::HashDomain;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub struct TerpHeadstash {}

pub trait HeadstashInstance {
    type HeadstashError;
    type PreInputConfig;
    fn new() -> Self;
    fn find_new_headstashes() -> Result<(), Self::HeadstashError>;
    fn create_new_headstash() -> Result<(), Self::HeadstashError>;
    fn list_headstash_info() -> Result<(), Self::HeadstashError>;
    fn list_unspent_notes() -> Vec<Note>;
    fn list_spent_notes() -> Vec<Note>;
    fn prepare_and_harvest_note() -> Result<(), Self::HeadstashError>;
    fn headstash_action() -> Result<(), Self::HeadstashError>;
}

pub trait HeadstashBitwiseInstance {
    /// Convert a byte slice into an iterator of little‑endian bits (LSB first per byte).
    fn bytes_to_bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_;
    /// Returns the sum of the 3 88-bit pallas curve point representation of a secp256k1 value
    fn derive_secp256k1_limbs_sum_const_time(&self, limbs: &[Fp; 3]) -> Fp;
    /// Note‑Denom (nd): blake3 hash of the token denomination string, represented as the sum of the 3 88-bit pallas curve point representation of private key.
    fn derive_nd(&self, raw_nd: &str) -> [u8; 32];
    fn derive_prf_m(&self, i: &Vec<pallas::Base>) -> pallas::Base;
    fn derive_m(
        &self,
        e_sk: &[u8; 32],
        fdi: u64,
        v: u64,
        nd: &str,
    ) -> Result<pallas::Base, BoxError>;
    fn mbe_btfe(&self, e_sk: [u8; 32]) -> pallas::Base;
    /// Note‑Value (v): u64 encoded as little‑endian 8 bytes (fully padded).
    fn derive_v(&self, value: u64) -> [u8; 8];
    /// Fixed‑Denom‑Index (fdi): u64 encoded as little‑endian 8 bytes (fully padded).
    fn derive_fdi(&self, index: u64) -> [u8; 8];
    /// nullifier-key derived from private inputs
    fn derive_nk(&self, raw_pubkey: &[u8; 32], rho: pallas::Base) -> pallas::Base;
    /// Eligible Pubkey (e_pk): raw 32‑byte public key as 3x8 limbs.
    /// Get the bit representation (Lsb0 = little-endian bit order)
    // Take first 250 bits and convert each to `bool`
    fn extend_with_base_field_bits(&self, bits: &mut Vec<bool>, a: pallas::Base);
    /// generates a specific leaf for a given e_pk,nd,v
    fn derive_leaf(
        &self,
        e_pk: &str,
        nd: &str,
        v: u64,
    ) -> Result<(Vec<(u64, usize, String)>, Vec<Fp>), BoxError>;
    // fn derive_note(&self) -> Note;
}

pub struct HeadstashConfig {}

pub trait TerpHeadstashActions {
    fn leaf_hash(
        &self,
        e_pk: &[u8],
        nd: &[u8],
        v: &[u8],
        fdi: &[u8],
    ) -> Result<pallas::Base, BoxError>;
    // Calculate MerkleCRH: H(layer || left || right)
    fn merkle_crh(&self, layer: u32, left: pallas::Base, right: pallas::Base) -> pallas::Base;
    fn tree_root_from_leaves(&self, leaves: Vec<pallas::Base>) -> Vec<pallas::Base>;
    fn get_input_path(&self) -> Result<String, BoxError>;
    fn gen_headstash_tree(&self, input: PathBuf) -> Result<String, BoxError>;
    fn print_tree(
        &self,
        input: &mut Value,
        output: Value,
        path: &std::path::Path,
    ) -> Result<(), BoxError>;
}

impl HeadstashInstance for TerpHeadstash {
    type HeadstashError = BoxError;
    type PreInputConfig = HeadstashConfig;
    fn new() -> Self {
        Self {}
    }

    fn find_new_headstashes() -> Result<(), Self::HeadstashError> {
        todo!()
    }

    fn create_new_headstash() -> Result<(), Self::HeadstashError> {
        todo!()
    }

    fn list_headstash_info() -> Result<(), Self::HeadstashError> {
        todo!()
    }

    fn list_unspent_notes() -> Vec<Note> {
        todo!()
    }

    fn list_spent_notes() -> Vec<Note> {
        todo!()
    }

    fn prepare_and_harvest_note() -> Result<(), Self::HeadstashError> {
        todo!()
    }

    fn headstash_action() -> Result<(), Self::HeadstashError> {
        todo!()
    }
}


use num_bigint::BigUint;
impl HeadstashBitwiseInstance for TerpHeadstash {
    fn bytes_to_bits_le(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
        bytes
            .iter()
            .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
    }

    /// Derives `nd` by domain-separation blake3 hash with domain-separation `DST_ND` of a note denomination.
    ///  We drop 3 bits to allow hash to become point on pallas curve.
    fn derive_nd(&self, raw_nd: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(DST_ND);
        hasher.update(raw_nd.as_bytes());
        let mut digest = hasher.finalize().as_bytes().clone();
        digest.try_into().expect("digest is 32 bytes")
    }

    /// Derive fully padded `v`.
    fn derive_v(&self, v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    /// Derive fully padded `fdi`.
    fn derive_fdi(&self, fdi: u64) -> [u8; 8] {
        fdi.to_le_bytes()
    }

    /// Derive pallas foriegn field representation of e_pk `fdi`.This should also be constant-time. If hashing, use a constant-time hash-to-curve.
    /// Step 1: split bytes into 3x 88 b it limbs
    /// Step 2: define limbs as pallas curve points
    /// Step 3: Convert the reduced scalar to a Pallas point (e.g., by hashing or multiplication).
    /// modular big-endian byte-to-field-element conversion
    fn mbe_btfe(&self, e_sk: [u8; 32]) -> pallas::Base {
        crate::spec::mbe_btfe(e_sk)
    }

    fn extend_with_base_field_bits(&self, bits: &mut Vec<bool>, a: pallas::Base) {
        let bit_slice = a.to_le_bits();

        bits.extend(bit_slice.iter().take(250).map(|b| *b));
    }

    // -----------------------------------------------------------------------------
    // Helper that generates all leaves for a single token (parallelised)
    fn derive_leaf(
        &self,
        addr: &str,
        token_name: &str,
        total_amount: u64,
    ) -> Result<(Vec<(u64, usize, String)>, Vec<Fp>), BoxError> {
        // ---------- build work list ------------------------------------------------
        let mut work_items: Vec<u64> = Vec::new();
        let mut remainder = total_amount;
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
        // work_items.par_iter().enumerate().try_for_each(
        //     |(idx, &fixed_amount)| -> Result<(), BoxError> {
        //         let leaf = self.leaf_hash(
        //             &self
        //                 .derive_secp256k1_limbs_sum_const_time(
        //                     &self.derive_hkdf_pallas(&addr_bytes),
        //                 )
        //                 .to_repr(),
        //             &self.derive_nd(token_name),
        //             &self.derive_v(fixed_amount),
        //             &self.derive_fdi(idx as u64),
        //         )?;
        //         let leaf_hex = format!("0x{}", hex::encode(leaf.to_repr()));
        //         leaf_hexes
        //             .lock()
        //             .unwrap()
        //             .push((fixed_amount, idx, leaf_hex));
        //         raw_leaves.lock().unwrap().push(leaf);
        //         Ok(())
        //     },
        // )?;

        Ok((
            leaf_hexes.into_inner().unwrap(),
            raw_leaves.into_inner().unwrap(),
        ))
    }

    fn derive_secp256k1_limbs_sum_const_time(&self, bytes: &[Fp; 3]) -> Fp {
        let limb3 = &bytes[0];
        let limb2 = &bytes[1];
        let limb1 = &bytes[2];
        limb1.add(&limb2.add(&limb3))
    }

    fn derive_m(
        &self,
        e_sk: &[u8; 32],
        fdi: u64,
        v: u64,
        nd: &str,
    ) -> Result<pallas::Base, BoxError> {
        // generate the sum of 3x88bit limbs of e_sk
        // let sk = EligibleSk::from_sk(SecretKey::from_byte_array(*e_sk)?);
        // let secp256k1_ls = self.derive_secp256k1_limbs_sum_const_time(limbs)

        // ensure fdi & v are fully padded
        let fdi = self.derive_fdi(fdi);
        let v = self.derive_v(v);

        // posiedon hash nd
        let nd = crate::spec::denom_to_base(&NoteDenom::from_str(nd).unwrap());

        // derive m as hash of ()
        Ok(pallas::Base::one())
    }

    fn derive_prf_m(&self, i: &Vec<pallas::Base>) -> pallas::Base {
        let (fdi, v, nd, e_sk) = (i[0], i[1], i[2], i[3]);
        crate::spec::prf_pallas_m(fdi, v, nd, e_sk)
    }

    fn derive_nk(&self, raw_pubkey: &[u8; 32], rho: pallas::Base) -> pallas::Base {
        // TODO: convert raw_pubkey to pallas point used in hdkf specification of deriving the nullifier.
        crate::spec::hdkf_pallas(pallas::Base::one(), rho)
    }
}

impl TerpHeadstashActions for TerpHeadstash {
    /// Compute the leaf hash for an address-token-amount tuple
    /// Concatenate all bytes in canonical order: e_pk + nd + v + fdi
    fn leaf_hash(
        &self,
        e_pk: &[u8],
        nd: &[u8],
        v: &[u8],
        fdi: &[u8],
    ) -> Result<pallas::Base, BoxError> {
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(e_pk);
        message_bytes.extend_from_slice(nd);
        message_bytes.extend_from_slice(v);
        message_bytes.extend_from_slice(fdi);
        Ok(HashDomain::new(LEAF_PERSONALIZATION)
            .hash_to_point(TerpHeadstash::bytes_to_bits_le(&message_bytes).into_iter())
            .expect("dang")
            .to_affine()
            .coordinates()
            .unwrap()
            .x()
            .clone())
    }

    fn merkle_crh(&self, layer: u32, left: pallas::Base, right: pallas::Base) -> pallas::Base {
        let domain = HashDomain::new(MERKLE_CRH_PERSONALIZATION);
        // bit string: 10 + 250 + 250 = 510 bits
        let mut message = Vec::with_capacity(510);

        for i in 0..10 {
            message.push((layer >> i) & 1 == 1);
        }

        self.extend_with_base_field_bits(&mut message, left);
        self.extend_with_base_field_bits(&mut message, right);

        // Hash and return x-coordinate
        let point = domain.hash_to_point(message.into_iter()).unwrap();
        point.to_affine().coordinates().unwrap().x().clone()
    }

    fn gen_headstash_tree(&self, output_path: PathBuf) -> Result<String, BoxError> {
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
                let total_amount: u64 = token["amount"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap();

                // ---- parallel leaf generation ---------------------------------
                // Parallel leaf generation (now also gives us an index)
                let (lidxh, raw_leaves) =
                    self.derive_leaf(addr.as_str(), &token["name"].to_string(), total_amount)?;
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

        // If no leaves, exit early
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

    // Build Merkle tree from list of leaves
    fn tree_root_from_leaves(&self, leaves: Vec<pallas::Base>) -> Vec<pallas::Base> {
        let mut current = leaves;
        let mut next = Vec::new();
        let mut layer = 0;
        while current.len() > 1 {
            // Pad to even length with zero if needed
            if current.len() % 2 != 0 {
                current.push(pallas::Base::ZERO);
            }

            // Parallelize the pair‑wise hashing
            // ---------------------------------------------------------
            let layer_par = layer; // capture layer for closure
            let parents: Vec<pallas::Base> = current
                .par_chunks(2) // split into 2‑element chunks in parallel
                .map(|chunk| {
                    let left = chunk[0];
                    let right = chunk[1];
                    self.merkle_crh(layer_par, left, right)
                })
                .collect();

            next.extend(parents);
            // ---------------------------------------------------------

            current = next;
            next = Vec::new();
            layer += 1;
        }
        if current.is_empty() {
            vec![pallas::Base::ZERO]
        } else {
            current
        }
    }

    fn get_input_path(&self) -> Result<String, BoxError> {
        let args: Vec<String> = env::args().collect();
        if args.len() != 2 {
            eprintln!("Usage: {} <input-file>", args[0]);
            std::process::exit(1);
        }
        Ok(args[1].clone())
    }

    fn print_tree(
        &self,
        input: &mut Value,
        output: Value,
        path: &std::path::Path,
    ) -> Result<(), BoxError> {
        // Write augmented input (with embedded leaves)
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
}
