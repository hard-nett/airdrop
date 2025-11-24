// cargo run --bin create_merkle -- ./data/genesis_sinsemilla.json

use base64::{engine::general_purpose, Engine as _};

use hex::decode;
use pasta_curves::Fp;
use serde_json::{json, Value};

use ff::{Field, PrimeField, PrimeFieldBits};
use pasta_curves::{arithmetic::CurveAffine, group::Curve, pallas};
use sinsemilla::HashDomain;
use std::error::Error;
use std::{env, fs};
use zk_crates::constants::fixed_bases::FIXED_AMOUNTS;
use zk_crates::constants::sinsemilla::{LEAF_PERSONALIZATION, MERKLE_CRH_PERSONALIZATION};
use zk_crates::deploy::suite::{HeadstashInstance, TerpHeadstash, TerpHeadstashActions};

use rayon::prelude::*;
use std::sync::Mutex;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub fn get_input_path() -> Result<String, BoxError> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input-file>", args[0]);
        std::process::exit(1);
    }
    Ok(args[1].clone())
}

// Compute the leaf hash for an address-token-amount tuple
fn leaf_hash(
    address: &str,
    token: &str,
    amount: &str,
    idx: &str,
) -> Result<pallas::Base, BoxError> {
    // Concatenate all bytes in canonical order: address + token + amount + idx
    let mut message_bytes = Vec::new();
    message_bytes.extend_from_slice(&match address.starts_with("0x") {
        true => decode(address.trim_start_matches("0x"))?,
        false => general_purpose::STANDARD.decode(address).unwrap(),
    });
    message_bytes.extend_from_slice(token.as_bytes());
    message_bytes.extend_from_slice(amount.as_bytes());
    message_bytes.extend_from_slice(idx.as_bytes());

    // Convert the byte array to a vector of bits in little-endian order (LSB first per byte)
    let mut message_bits = Vec::new();
    for byte in message_bytes {
        for i in 0..8 {
            message_bits.push((byte >> i) & 1 == 1);
        }
    }

    // Hash the bits using Sinsemilla with leaf personalization
    let domain = HashDomain::new(LEAF_PERSONALIZATION);
    let point = domain
        .hash_to_point(message_bits.into_iter())
        .expect("dang");
    Ok(point.to_affine().coordinates().unwrap().x().clone())
}

// Calculate MerkleCRH: H(layer || left || right)
fn merkle_crh(layer: u32, left: pallas::Base, right: pallas::Base) -> pallas::Base {
    let domain = HashDomain::new(MERKLE_CRH_PERSONALIZATION);
    // bit string: 10 + 250 + 250 = 510 bits
    let mut message = Vec::with_capacity(510);

    for i in 0..10 {
        message.push((layer >> i) & 1 == 1);
    }

    extend_with_base_field_bits(&mut message, left);
    extend_with_base_field_bits(&mut message, right);

    // Hash and return x-coordinate
    let point = domain.hash_to_point(message.into_iter()).unwrap();
    point.to_affine().coordinates().unwrap().x().clone()
}

// Convert pallas::Base to 250-bit little-endian bool vector
fn extend_with_base_field_bits(bits: &mut Vec<bool>, a: pallas::Base) {
    // Get the bit representation (Lsb0 = little-endian bit order)
    let bit_slice = a.to_le_bits();
    // Take first 250 bits and convert each to `bool`
    bits.extend(bit_slice.iter().take(250).map(|b| *b));
}

// Build Merkle tree from list of leaves
fn build_merkle_tree(leaves: Vec<pallas::Base>) -> Vec<pallas::Base> {
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
                merkle_crh(layer_par, left, right)
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

// -----------------------------------------------------------------------------
// Helper that generates all leaves for a single token (parallelised)
fn gen_token_leaves(
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
    let leaf_hexes = Mutex::new(Vec::<(u64, usize, String)>::new()); // (index, hex)
    let raw_leaves = Mutex::new(Vec::<Fp>::new());

    // `enumerate` gives us the leaf‑index (0‑based) for this address/token
    work_items.par_iter().enumerate().try_for_each(
        |(idx, &fixed_amount)| -> Result<(), BoxError> {
            let leaf = leaf_hash(
                addr,
                token_name,
                &fixed_amount.to_string(),
                &idx.to_string(),
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

    let leaf_hexes = leaf_hexes.into_inner().unwrap();
    let raw_leaves = raw_leaves.into_inner().unwrap();
    Ok((leaf_hexes, raw_leaves))
}

fn main() -> Result<(), BoxError> {
    let output_path = std::path::Path::new("./data").join("merkle_output.json");
    let root_hex = TerpHeadstash::new().gen_headstash_tree(output_path)?;
    println!("🌳 Merkle Root: {}", root_hex);

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::Value;
    use std::fs;

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
