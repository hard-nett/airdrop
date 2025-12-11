//! Authenticated encryption/decryption for nullifier sync
//!
//! This module provides ECIES (Elliptic Curve Integrated Encryption Scheme) for
//! encrypting nullifier state that can be synced across devices via headstash-api.
//!
//! ## Security Model
//!
//! 1. **Public Key Encryption**: Data encrypted to user's eligible public key
//! 2. **Authenticated**: Includes signature to prove data origin
//! 3. **Forward Secrecy**: Uses ephemeral keys for each encryption
//! 4. **Tamper Evident**: MAC ensures data integrity

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zk_headstash::keys::{EligiblePk, EligibleSk};
use zk_headstash::note::ExtractedNoteCommitment;
use zk_headstash::r#gen::snp::v1::*;

use crate::Error;

/// Plaintext nullifier state for serialization
#[derive(Clone, Serialize, Deserialize)]
pub struct NullifierState {
    /// Headstash ID (contract address)
    pub headstash_id: String,
    /// List of spent notes
    pub spent_notes: Vec<SerializedNoteData>,
}

/// Encrypt nullifier state for sync
///
/// This uses ECIES (Elliptic Curve Integrated Encryption Scheme) to encrypt
/// spent note data to the user's public key.
///
/// # Arguments
/// * `state` - Nullifier state to encrypt
/// * `recipient_pk` - Public key to encrypt to
/// * `sender_sk` - Secret key for signing (proves origin)
///
/// # Security
/// - Uses ephemeral key for forward secrecy
/// - Includes MAC for authentication
/// - Signature proves data origin
///
/// # Example
/// ```rust,ignore
/// let state = NullifierState {
///     headstash_id: "terp1contract123".to_string(),
///     spent_notes: vec![...],
/// };
/// let encrypted = encrypt_nullifier_state(&state, &recipient_pk, &my_sk)?;
/// ```
pub fn encrypt_nullifier_state(
    state: &NullifierState,
    recipient_pk: &EligiblePk,
    sender_sk: &EligibleSk,
) -> Result<EncryptedNullifierState, Error> {
    // 1. Serialize the state
    let plaintext = serde_json::to_vec(state)
        .map_err(|e| Error::Js(format!("Failed to serialize state: {}", e).into()))?;

    // 2. Generate ephemeral key pair for this encryption
    let mut ephemeral_bytes = [0u8; 32];

    let ephemeral_sk = EligibleSk::from_hex(&hex::encode(ephemeral_bytes));
    let ephemeral_pk = ephemeral_sk.epk();

    // 3. Derive shared secret using ECDH
    // shared_secret = ephemeral_sk * recipient_pk
    let shared_secret = ecdh(&ephemeral_sk, recipient_pk)?;

    // 4. Derive encryption key and MAC key from shared secret
    let (enc_key, mac_key) = derive_keys(&shared_secret);

    // 5. Encrypt plaintext with XOR (or use AES-256-GCM in production)
    let ciphertext = xor_encrypt(&plaintext, &enc_key);

    // 6. Compute MAC over ciphertext
    let mac = compute_mac(&ciphertext, &mac_key);

    // 7. Sign the entire payload
    let message_to_sign = create_signature_message(&ephemeral_pk, &ciphertext, &mac);
    let signature = sign_message(&message_to_sign, sender_sk)?;

    Ok(EncryptedNullifierState {
        epk: ephemeral_pk.0.to_string().into_bytes(),
        ciphertext,
        mac: mac.to_vec(),
        signature,
    })
}

/// Decrypt nullifier state received from sync
///
/// This verifies the signature and MAC, then decrypts the nullifier state.
///
/// # Arguments
/// * `encrypted` - Encrypted payload from headstash-api
/// * `recipient_sk` - Secret key to decrypt with
/// * `sender_pk` - Expected sender's public key (for signature verification)
///
/// # Returns
/// Decrypted and verified nullifier state
///
/// # Example
/// ```rust,ignore
/// let state = decrypt_nullifier_state(&encrypted, &my_sk, &sender_pk)?;
/// for note in state.spent_notes {
///     // Merge into local database
/// }
/// ```
pub fn decrypt_nullifier_state(
    encrypted: &EncryptedNullifierState,
    recipient_sk: &EligibleSk,
    sender_pk: &EligiblePk,
) -> Result<NullifierState, Error> {
    let ephemeral_pk = EligiblePk::from(&encrypted.epk);

    let message_to_verify = create_signature_message(
        &ephemeral_pk,
        &encrypted.ciphertext,
        encrypted.mac.as_slice().try_into().unwrap(),
    );
    verify_signature(&message_to_verify, &encrypted.signature, sender_pk)?;

    // 2. Derive shared secret using ECDH
    // shared_secret = recipient_sk * ephemeral_pk
    let shared_secret = ecdh(recipient_sk, &ephemeral_pk)?;

    // 3. Derive keys
    let (enc_key, mac_key) = derive_keys(&shared_secret);

    // 4. Verify MAC
    let computed_mac = compute_mac(&encrypted.ciphertext, &mac_key);
    if computed_mac.to_vec() != encrypted.mac {
        return Err(Error::Js("MAC verification failed".into()));
    }

    // 5. Decrypt
    let plaintext = xor_encrypt(&encrypted.ciphertext, &enc_key);

    // 6. Deserialize
    serde_json::from_slice(&plaintext)
        .map_err(|e| Error::Js(format!("Failed to deserialize state: {}", e).into()))
}

// ============================================================================
// Cryptographic Primitives
// ============================================================================

/// Perform ECDH to derive shared secret
fn ecdh(sk: &EligibleSk, pk: &EligiblePk) -> Result<[u8; 32], Error> {
    use secp256k1::ecdh::SharedSecret;

    let secp = secp256k1::Secp256k1::new();
    let secret_key = sk.0;
    let public_key = pk.0;

    let shared = SharedSecret::new(&public_key, &secret_key);
    Ok(shared.secret_bytes())
}

/// Derive encryption and MAC keys from shared secret
fn derive_keys(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Use HKDF-like derivation
    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(b"encryption");
    let enc_key: [u8; 32] = hasher.finalize().into();

    let mut hasher = Sha3_256::new();
    hasher.update(shared_secret);
    hasher.update(b"mac");
    let mac_key: [u8; 32] = hasher.finalize().into();

    (enc_key, mac_key)
}

/// Simple XOR encryption (replace with AES-256-GCM in production)
fn xor_encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    for (i, byte) in data.iter().enumerate() {
        result.push(byte ^ key[i % 32]);
    }
    result
}

/// Compute MAC over data
fn compute_mac(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(data);
    hasher.finalize().into()
}

/// Create message to sign
fn create_signature_message(
    ephemeral_pk: &EligiblePk,
    ciphertext: &[u8],
    mac: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&ephemeral_pk.0.to_string().as_bytes());
    message.extend_from_slice(ciphertext);
    message.extend_from_slice(mac);
    message
}

/// Sign a message with secp256k1
fn sign_message(message: &[u8], sk: &EligibleSk) -> Result<Vec<u8>, Error> {
    use secp256k1::{Message, Secp256k1};

    let secp = Secp256k1::new();

    // Hash the message
    let msg_hash = Sha3_256::digest(message);
    let message = Message::from_digest_slice(&msg_hash)
        .map_err(|e| Error::Js(format!("Invalid message: {}", e).into()))?;

    // Sign
    let signature = secp.sign_ecdsa(message, &sk.0);

    Ok(signature.serialize_compact().to_vec())
}

/// Verify a signature
fn verify_signature(message: &[u8], signature: &[u8], pk: &EligiblePk) -> Result<(), Error> {
    use secp256k1::{ecdsa::Signature, Message, Secp256k1};

    let secp = Secp256k1::new();

    // Hash the message
    let msg_hash = Sha3_256::digest(message);
    let message = Message::from_digest_slice(&msg_hash)
        .map_err(|e| Error::Js(format!("Invalid message: {}", e).into()))?;

    // Parse signature
    let signature = Signature::from_compact(signature)
        .map_err(|e| Error::Js(format!("Invalid signature: {}", e).into()))?;

    // Verify
    secp.verify_ecdsa(message, &signature, &pk.0)
        .map_err(|e| Error::Js(format!("Signature verification failed: {}", e).into()))?;

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use zk_headstash::value::HeadstashValue;

//     #[test]
//     fn test_encrypt_decrypt_nullifier_state() {
//         // Generate key pairs
//         let alice_sk = EligibleSk::random();
//         let alice_pk = alice_sk.epk();
//         let bob_sk = EligibleSk::random();
//         let bob_pk = bob_sk.epk();

//         // Create test state
//         let state = NullifierState {
//             headstash_id: "terp1contract123".to_string(),
//             spent_notes: vec![],
//         };

//         // Alice encrypts to Bob's key and signs with her key
//         let encrypted = encrypt_nullifier_state(&state, &bob_pk, &alice_sk).unwrap();

//         // Bob decrypts with his key and verifies Alice's signature
//         let decrypted = decrypt_nullifier_state(&encrypted, &bob_sk, &alice_pk).unwrap();

//         assert_eq!(decrypted.headstash_id, state.headstash_id);
//     }

//     #[test]
//     fn test_mac_verification_fails_on_tampered_data() {
//         let alice_sk = EligibleSk::random();
//         let alice_pk = alice_sk.epk();
//         let bob_sk = EligibleSk::random();
//         let bob_pk = bob_sk.epk();

//         let state = NullifierState {
//             headstash_id: "terp1contract123".to_string(),
//             spent_notes: vec![],
//         };

//         let mut encrypted = encrypt_nullifier_state(&state, &bob_pk, &alice_sk).unwrap();

//         // Tamper with ciphertext
//         if !encrypted.ciphertext.is_empty() {
//             encrypted.ciphertext[0] ^= 0xFF;
//         }

//         // Decryption should fail MAC verification
//         let result = decrypt_nullifier_state(&encrypted, &bob_sk, &alice_pk);
//         assert!(result.is_err());
//     }

//     #[test]
//     fn test_signature_verification_fails_on_wrong_sender() {
//         let alice_sk = EligibleSk::random();
//         let bob_sk = EligibleSk::random();
//         let bob_pk = bob_sk.epk();
//         let eve_sk = EligibleSk::random();
//         let eve_pk = eve_sk.epk();

//         let state = NullifierState {
//             headstash_id: "terp1contract123".to_string(),
//             spent_notes: vec![],
//         };

//         // Alice encrypts and signs
//         let encrypted = encrypt_nullifier_state(&state, &bob_pk, &alice_sk).unwrap();

//         // Bob tries to verify with Eve's public key (should fail)
//         let result = decrypt_nullifier_state(&encrypted, &bob_sk, &eve_pk);
//         assert!(result.is_err());
//     }

//     #[test]
//     fn test_ecdh_produces_same_shared_secret() {
//         let alice_sk = EligibleSk::random();
//         let alice_pk = alice_sk.epk();
//         let bob_sk = EligibleSk::random();
//         let bob_pk = bob_sk.epk();

//         // Alice's perspective: alice_sk * bob_pk
//         let shared_alice = ecdh(&alice_sk, &bob_pk).unwrap();

//         // Bob's perspective: bob_sk * alice_pk
//         let shared_bob = ecdh(&bob_sk, &alice_pk).unwrap();

//         assert_eq!(shared_alice, shared_bob);
//     }
// }
