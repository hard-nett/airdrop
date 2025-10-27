use babyjubjub_rs::{PrivateKey as BabySecretKey, Signature, verify, verify_schnorr};
use secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey as SecpSecretKey};
use std::str::FromStr;

use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use k256::sha2::Sha256;
use num_bigint::BigInt;

// GOAL: explore baby-jubjub curve, in order to understand more about how we can implement the proof of ownership step.
// specifically, we have the option to use Hashed Messaged Authentication Code Key Derivation Function (HKDF) 
// to derive a baby-jubjub key from an ethereum mnemonic/seed determinstically, and then sign/verify with the babyjubjub key. 
// 
// In order to have a circuit to proove ownerships, it would need to:
// - zk-proove correct derivation of jubjub key from the given ethereum secret key
// - validate the signature of the hashed key

// BabyJubJub field modulus (Fr)
const FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

const LABEL: &[u8] = b"BABYJUBJUB_EDDSA";

// constraint 256-byte hash into 254-bytes, compatible with BN254.
fn blake3_hash_to_field(data: &str) -> BigInt {
    let data_bytes = hex::decode(data).expect("invalid hex");
    BigInt::from_bytes_be(num_bigint::Sign::Plus, blake3::hash(&data_bytes).as_bytes())
        % &BigInt::from_str(FIELD_MODULUS).unwrap()
}
/// Helper: HKDF‑SHA256 → 32‑byte output, domain‑separated.
fn hkdf_expand(label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(label, &mut okm).expect("hkdf expand failed");
    okm
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

/// Derive a Baby‑JubJub secret key (scalar in Fr).
fn baby_secret_from_seed(seed: &[u8]) -> BabySecretKey {
    BabySecretKey::import(hkdf_expand(LABEL, seed).to_vec()).unwrap()
}

fn baby_secret_from_private_key(eth_key: &[u8; 32]) -> BabySecretKey {
    BabySecretKey::import(hkdf_expand(LABEL, eth_key).to_vec()).unwrap()
}

fn main() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let seed = derive_secp256k1_seed_from_mnemonic(mnemonic);
    let eth_sk = eth_secret_from_seed(&seed);
    let eth_pk = SecpPublicKey::from_secret_key(&Secp256k1::new(), &eth_sk);
    println!("Eth Addr: 0x{:x}", eth_pk);

    // -----------------------------------------------------------------
    let baby_sk_a = baby_secret_from_private_key(&eth_sk.secret_bytes());
    let baby_sk = baby_secret_from_seed(&seed);

    let baby_pk = baby_sk.public();
    println!(
        "Baby‑JubJub public (compressed hex): {}",
        hex::encode(baby_pk.compress())
    );
    println!("public key (x): {}", baby_pk.x);
    println!("public key (y): {}", baby_pk.y);

    // ------------------------------------------------------------
    // Sign: hash-to-field for a raw (stripped) bech32 address
    // ------------------------------------------------------------
    let not_hex_addr = "396f6189bd6c83728667e4d45d66a06a6aa8f9640373defaa89f821f8c78e52b";
    let hex_addr = "DE4BAA02C4855872BBA5464749157D06151ED215C6FD39A07454344DE8D9A2BF";
    let msg = blake3_hash_to_field(&hex_addr);
    println!("msg: {}", msg);

    let sig: Signature = baby_sk.sign(msg.clone()).expect("signing failed");
    println!("signature.r.x = {}", sig.r_b8.x);
    println!("signature.r.y = {}", sig.r_b8.y);
    println!("signature.s   = {}", sig.s);

    // ------------------------------------------------------------
    // 3️⃣  Verify the EdDSA‑style signature
    // ------------------------------------------------------------
    let ok = verify(baby_pk.clone(), sig.clone(), msg.clone());
    println!("EdDSA verification: {}", ok);
    // confirm msg is not verified on diffferent address
    assert!(!verify(
        baby_pk.clone(),
        sig.clone(),
        blake3_hash_to_field(&not_hex_addr)
    ));

    // ------------------------------------------------------------
    // 4️⃣  Schnorr‑style signature (r, s) – also fully verifiable
    // ------------------------------------------------------------
    let (r_point, s_scalar) = baby_sk.sign_schnorr(msg.clone()).expect("schnorr sign");
    let schnorr_ok = verify_schnorr(
        baby_pk.clone(),
        msg.clone(),
        r_point.clone(),
        s_scalar.clone(),
    )
    .expect("schnorr verify");
    println!(
        "Schnorr signature (r.x, r.y, s) = ({}, {}, {})",
        r_point.x, r_point.y, s_scalar
    );
    println!("Schnorr verification: {}", schnorr_ok);

    // ------------------------------------------------------------
    // 5️⃣  Show how to compress / decompress a point (optional)
    // ------------------------------------------------------------
    let compressed = baby_pk.compress();
    println!("compressed pub‑key: {}", hex::encode(compressed));
    let decompressed = babyjubjub_rs::decompress_point(compressed).expect("decompress");
    assert_eq!(baby_pk.x, decompressed.x);
    assert_eq!(baby_pk.y, decompressed.y);
    println!("decompression round‑trip successful");
}
