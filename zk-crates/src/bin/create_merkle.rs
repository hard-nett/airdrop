// cargo run --bin create_merkle -- ./data/genesis_sinsemilla.json

use base64::{Engine as _, engine::general_purpose};

use hex::decode;
use pasta_curves::Fp;
use serde_json::{Value, json};
use std::error::Error;
use std::{env, fs};
use zk_crates::constants::fixed_bases::FIXED_AMOUNTS;
use zk_crates::constants::sinsemilla::{LEAF_PERSONALIZATION, MERKLE_CRH_PERSONALIZATION};

use ff::{Field, PrimeField, PrimeFieldBits};
use pasta_curves::{arithmetic::CurveAffine, group::Curve, pallas};
use sinsemilla::HashDomain;

use rayon::prelude::*;
use std::sync::Mutex;

type BoxError = Box<dyn Error + Send + Sync>;

// Define the domain for MerkleCRH (from Orchard spec)
// Define a personalization for leaf hashing to ensure domain separation

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

        for chunks in current.chunks(2) {
            let left = chunks[0];
            let right = chunks[1];
            let parent = merkle_crh(layer, left, right);
            next.push(parent);
        }

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
) -> Result<(Vec<(usize, String)>, Vec<Fp>), BoxError> {
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
    let leaf_hexes = Mutex::new(Vec::<(usize, String)>::new()); // (index, hex)
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
            leaf_hexes.lock().unwrap().push((idx, leaf_hex));
            raw_leaves.lock().unwrap().push(leaf);
            Ok(())
        },
    )?;

    let leaf_hexes = leaf_hexes.into_inner().unwrap();
    let raw_leaves = raw_leaves.into_inner().unwrap();
    Ok((leaf_hexes, raw_leaves))
}

fn main() -> Result<(), BoxError> {
    let input_path = get_input_path()?;
    let output_dir = std::path::Path::new("./data");

    // Read and parse input JSON
    let mut input_data: Value = serde_json::from_str(&fs::read_to_string(&input_path)?)?;
    let mut leaves = Vec::new();
    let balances = input_data
        .as_object_mut()
        .ok_or("Input JSON must be an object")?;

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
            let (leaf_idx_hexes, raw_leaves) =
                gen_token_leaves(addr.as_str(), &token["name"].to_string(), total_amount)?;
            // ---- attach leaves back to the JSON object (single‑thread) ----
            {
                let obj = token
                    .as_object_mut()
                    .expect("token should be a JSON object");
                obj.entry("leaves").or_insert_with(|| json!([]));
            }
            let leaves_arr = token.get_mut("leaves").unwrap().as_array_mut().unwrap();

            // Push each leaf together with its index:
            //   { "index": <usize>, "leaf": "<hex>" }
            for (idx, leaf_hex) in leaf_idx_hexes {
                leaves_arr.push(json!({ "index": idx, "leaf": leaf_hex }));
            }

            // ---- push raw leaves into the global vector -------------------
            leaves.extend(raw_leaves);
        }
    }
    // Write augmented input (with embedded leaves)
    let augmented_path = input_path;
    fs::write(&augmented_path, serde_json::to_string_pretty(&input_data)?)?;
    eprintln!("✅ Input with leaves written to {}", augmented_path);

    // If no leaves, exit early
    if leaves.is_empty() {
        println!("No leaves generated.");
        return Ok(());
    }

    // Build Merkle root
    let merkle_root = build_merkle_tree(leaves.clone())[0];
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

    let merkle_path = output_dir.join("merkle_output.json");
    fs::write(&merkle_path, serde_json::to_string_pretty(&merkle_output)?)?;
    eprintln!("✅ Merkle output written to {}", merkle_path.display());
    println!("🌳 Merkle Root: {}", root_hex);

    Ok(())
}

fn get_input_path() -> Result<String, BoxError> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <input-file>", args[0]);
        std::process::exit(1);
    }
    Ok(args[1].clone())
}

#[cfg(test)]
mod test {
    use super::*;

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
            // // Validate address key format (simple check for "0x" prefix)
            // assert!(
            //     addr.starts_with("0x")
            //         || addr.len() == 40 && addr.chars().all(|c| c.is_ascii_hexdigit()),
            //     "Address key must be a valid hex string (with or without 0x): {}",
            //     addr
            // );
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
