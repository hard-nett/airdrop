use bip39::{Language, Mnemonic};
use cosmwasm_std::{Api, CanonicalAddr};
use ff::{Field, FromUniformBytes, PrimeField};
use hkdf::Hkdf;
use k256::sha2::Sha256;
use pasta_curves::pallas::{self, Base};
use rand_core::OsRng;
use secp256k1::SecretKey as SecpSecretKey;
use serde_json::Value;
use zk_crates::{
    address::HeadstashAddr,
    keys::{EligibleSk, FullViewingKey, JubJubKey},
    note::{Note, RandomSeed, Rho},
    value::{NoteDenom, NoteValue},
};

use std::fs;
use std::str::FromStr;
use std::{env, error::Error};

pub type BoxError = Box<dyn Error + Send + Sync>;

pub fn get_input_path() -> Result<(String, String, String), BoxError> {
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

const LABEL: &[u8] = b"SECP256K1_EDDSA";

/// Helper: HKDF‑SHA256 → 32‑byte output, domain‑separated.
fn hkdf_expand(label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm).expect("hkdf expand failed");
    okm
}

fn rho_from_secure_random() -> Rho {
    let mut randomness_64 = [0; 64];
    blake3::Hasher::new()
        .update(&zk_crates::randomness::ultra_secure_random())
        .finalize_xof()
        .fill(&mut randomness_64);

    Rho::from_bytes(&Base::from_uniform_bytes(&randomness_64).to_repr()).unwrap()
}

/// Derive a 32‑byte seed from a BIP‑39 mnemonic (no passphrase here for brevity).
fn derive_secp256k1_seed_from_mnemonic(mnemonic: &str) -> [u8; 64] {
    let mn = Mnemonic::parse_in_normalized(Language::English, mnemonic).unwrap();
    mn.to_seed_normalized("HEADSTASH")
}
/// Derive an Ethereum secp256k1 secret key.
fn eth_secret_from_seed(seed: &[u8]) -> SecpSecretKey {
    SecpSecretKey::from_byte_array(hkdf_expand(LABEL, seed)).expect("invalid eth secret")
}

// ------------------------------------------------
// Find the first note matching token & amount, return its fdi
fn find_fdi(input_path: &str, token: &str, amount: &str) -> Result<u64, BoxError> {
    let json: Value = serde_json::from_str(&fs::read_to_string(std::path::Path::new(input_path))?)?;

    let notes = json
        .get(token)
        .and_then(|v| v.as_array())
        .ok_or("Missing or invalid `uterp` array")?;

    // 4️⃣ iterate until we find a matching entry
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

// cargo run --bin create_nullifier -- ./data/notes/<elig_addr> <token-denom> <amount>
// ex:  cargo run --bin create_nullifiers -- ./data/notes/0x0000000000000000000000000000000000000000.json uterp 100
fn main() -> Result<(), BoxError> {
    let (input_path, token_str, amount_str) = get_input_path()?;
    let output_dir = std::path::Path::new("./data/spent-notes");
    let mut input_data: Value = serde_json::from_str(&std::fs::read_to_string(&input_path)?)?;
    let fdi = find_fdi(&input_path, &token_str, &amount_str)?;

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = derive_secp256k1_seed_from_mnemonic(mnemonic);
    let eth_sk = eth_secret_from_seed(&seed);
    let elig_sk = EligibleSk::from_sk(eth_sk);
    let jub_sk = JubJubKey::derive_from_elig_sk(elig_sk);

    let nd = NoteDenom::from_str(&token_str)?;
    let v = NoteValue::from_raw(
        amount_str
            .parse()
            .map_err(|e| format!("Invalid amount \"{}\": {}", amount_str, e))?,
    );

    let recipient = HeadstashAddr::try_from(
        CanonicalAddr::from(
            blake3::hash(
                "DE4BAA02C4855872BBA5464749157D06151ED215C6FD39A07454344DE8D9A2BF".as_bytes(),
            )
            .as_bytes(),
        )
        .as_ref(),
    )?;

    // determine what fixed-value-note available to spend
    //  - load available note templates from incoming addr
    let mut rng = OsRng;
    let randomness1 = zk_crates::randomness::ultra_secure_random();
    let randomness2 = zk_crates::randomness::ultra_secure_random();
    let rho = rho_from_secure_random();
    let rseed = RandomSeed::from_bytes(randomness2, &rho).unwrap();

    let note = Note::from_parts(recipient, v, nd, fdi, elig_sk, jub_sk, rho, rseed).unwrap();

    println!("note.commitment(): {:#?}", note.commitment());
    println!("note.rho(): {:#?}", note.rho());
    println!("note.rseed(): {:#?}", hex::encode(note.rseed().as_bytes()));
    println!("note.value(): {:#?}", note.value().inner());
    println!("note.nullifier(fvk);: {:#?}", note.nullifier());

    Ok(())
}
