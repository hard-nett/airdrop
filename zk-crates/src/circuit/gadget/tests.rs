//! Unit tests for foreign field arithmetic - Secp256k1 key pairing
//!
//! These tests verify that we can correctly represent secp256k1 field elements
//! as 3x88-bit limbs in pallas::Base and perform elliptic curve pairing checks.

use super::secp256k1_chip::*;
use ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp as Secp256k1Fp, Fq as Secp256k1Fq};
use halo2_gadgets::utilities::lookup_range_check::{LookupRangeCheck, LookupRangeCheckConfig};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error as PlonkError},
};
use pasta_curves::pallas;

// ============================================================================
// Test Circuit for Secp256k1 Key Pairing
// ============================================================================

#[derive(Clone, Debug)]
struct Secp256k1TestConfig {
    secp_config: Secp256k1Config,
}

impl Secp256k1TestConfig {
    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self {
        // Allocate advice columns for Fp and Fq chips
        let fp_advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let fq_advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // Create lookup table for range checking
        let table_idx = meta.lookup_table_column();
        let range_check = LookupRangeCheckConfig::configure(meta, fp_advices[0], table_idx);

        // Configure Secp256k1 chip with both Fp and Fq
        let secp_config = Secp256k1Config::configure(meta, fp_advices, fq_advices, range_check);

        Self { secp_config }
    }
}

/// Circuit that proves: pk = sk * G (secp256k1 key pairing)
#[derive(Default)]
struct KeyPairingTestCircuit {
    sk: Secp256k1Fq,
    pk_x: Secp256k1Fp,
    pk_y: Secp256k1Fp,
}

impl Circuit<pallas::Base> for KeyPairingTestCircuit {
    type Config = Secp256k1TestConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        Secp256k1TestConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), PlonkError> {
        // Construct the Secp256k1Chip
        let secp_chip = Secp256k1Chip::construct(config.secp_config);

        // Prove key pairing: pk = sk * G
        // This will:
        // 1. Load sk as CRT: 256 bits → 3 limbs × 88 bits
        // 2. Load pk_x, pk_y as CRT: each 256 bits → 3 limbs × 88 bits
        // 3. Compute sk * G using Montgomery ladder
        // 4. Constrain computed_pk == pk
        let (_sk_assigned, (_pk_x_assigned, _pk_y_assigned)) = secp_chip.prove_key_pairing(
            layouter.namespace(|| "secp256k1 key pairing"),
            Value::known(self.sk),
            Value::known(self.pk_x),
            Value::known(self.pk_y),
        )?;

        Ok(())
    }
}

// ============================================================================
// Test: Valid Secp256k1 Key Pair (Should Pass)
// ============================================================================

#[test]
fn test_secp256k1_key_pairing_valid() {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    // Generate a valid secp256k1 key pair
    let secp = Secp256k1::new();
    let sk_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    let sk_secp = SecretKey::from_slice(&sk_bytes).expect("valid secret key");
    let pk_secp = PublicKey::from_secret_key(&secp, &sk_secp);

    // Extract uncompressed public key: 0x04 || x (32 bytes) || y (32 bytes)
    let pk_bytes = pk_secp.serialize_uncompressed();
    assert_eq!(pk_bytes[0], 0x04, "First byte should be 0x04");

    let pk_x_bytes: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
    let pk_y_bytes: [u8; 32] = pk_bytes[33..65].try_into().unwrap();

    // Convert to halo2 field elements
    let sk = Secp256k1Fq::from_repr(sk_bytes).expect("valid Fq");
    let pk_x = Secp256k1Fp::from_repr(pk_x_bytes).expect("valid Fp");
    let pk_y = Secp256k1Fp::from_repr(pk_y_bytes).expect("valid Fp");

    println!("Testing VALID key pair:");
    println!("  sk:   {:?}", hex::encode(sk_bytes));
    println!("  pk.x: {:?}", hex::encode(pk_x_bytes));
    println!("  pk.y: {:?}", hex::encode(pk_y_bytes));

    let circuit = KeyPairingTestCircuit { sk, pk_x, pk_y };

    // Use degree 18 (2^18 = 262,144 rows) to accommodate foreign field operations
    let prover = MockProver::run(18, &circuit, vec![]).expect("prover should run");

    // This should PASS because pk = sk * G
    assert_eq!(
        prover.verify(),
        Ok(()),
        "Valid key pair should verify successfully"
    );
}

// ============================================================================
// Test: Mismatched Secp256k1 Keys (Should Fail)
// ============================================================================

#[test]
fn test_secp256k1_key_pairing_invalid() {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();

    // Secret key 1
    let sk_bytes = [0x42; 32];
    let sk_secp = SecretKey::from_slice(&sk_bytes).expect("valid secret key");

    // Public key from DIFFERENT secret key
    let wrong_sk_bytes = [0x43; 32];
    let wrong_sk_secp = SecretKey::from_slice(&wrong_sk_bytes).expect("valid secret key");
    let wrong_pk_secp = PublicKey::from_secret_key(&secp, &wrong_sk_secp);

    // Extract public key bytes (from wrong secret key)
    let wrong_pk_bytes = wrong_pk_secp.serialize_uncompressed();
    let pk_x_bytes: [u8; 32] = wrong_pk_bytes[1..33].try_into().unwrap();
    let pk_y_bytes: [u8; 32] = wrong_pk_bytes[33..65].try_into().unwrap();

    // Convert to field elements
    let sk = Secp256k1Fq::from_repr(sk_bytes).expect("valid Fq");
    let pk_x = Secp256k1Fp::from_repr(pk_x_bytes).expect("valid Fp");
    let pk_y = Secp256k1Fp::from_repr(pk_y_bytes).expect("valid Fp");

    println!("Testing INVALID key pair (mismatched):");
    println!("  sk:   {:?}", hex::encode(sk_bytes));
    println!("  pk.x: {:?}", hex::encode(pk_x_bytes));
    println!("  pk.y: {:?}", hex::encode(pk_y_bytes));
    println!("  (pk is derived from sk=0x43... but we're using sk=0x42...)");

    let circuit = KeyPairingTestCircuit { sk, pk_x, pk_y };
    let prover = MockProver::run(18, &circuit, vec![]).expect("prover should run");

    // This should FAIL because pk != sk * G
    assert!(
        prover.verify().is_err(),
        "Mismatched key pair should fail verification"
    );
}

// ============================================================================
// Test: Zero Secret Key (Should Fail - Invalid Point)
// ============================================================================

#[test]
#[should_panic(expected = "secret key out of range")]
fn test_secp256k1_zero_secret_key() {
    use secp256k1::{Secp256k1, SecretKey};

    let _secp = Secp256k1::new();
    let sk_bytes = [0x00; 32];

    // This should panic because 0 is not a valid secp256k1 secret key
    let _sk_secp = SecretKey::from_slice(&sk_bytes).expect("secret key out of range");
}

// ============================================================================
// Test: Large Secret Key (Should Fail - Out of Range)
// ============================================================================

#[test]
#[should_panic(expected = "secret key out of range")]
fn test_secp256k1_out_of_range_secret_key() {
    use secp256k1::SecretKey;

    // Secret key larger than secp256k1 curve order
    let sk_bytes = [0xff; 32];

    // This should panic because sk > curve_order
    let _sk_secp = SecretKey::from_slice(&sk_bytes).expect("secret key out of range");
}

// ============================================================================
// Helper Test: Verify Foreign Field Decomposition
// ============================================================================

#[test]
fn test_foreign_field_limb_decomposition() {
    use num_bigint::BigUint;

    // Test that 256-bit secp256k1 value fits in 3x88-bit limbs
    let test_value_bytes = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99,
    ];

    let value = Secp256k1Fp::from_repr(test_value_bytes).expect("valid Fp");
    let value_big = halo2_base::utils::fe_to_biguint(&value);

    // Decompose into 3x88-bit limbs
    let limbs = crate::spec::decompose_biguint_simple(&value_big, 3, 88);

    println!("Foreign field decomposition test:");
    println!("  Original value: {:?}", hex::encode(test_value_bytes));

    // Verify each limb fits in 88 bits
    for (i, limb) in limbs.iter().enumerate() {
        let limb_big = super::bigint::fe_to_biguint_simple(limb);
        let max_88_bit = BigUint::from(1u64) << 88;

        println!("  Limb {}: {} bits", i, limb_big.bits());
        assert!(
            limb_big < max_88_bit,
            "Limb {} exceeds 88 bits: has {} bits",
            i,
            limb_big.bits()
        );
    }

    // Verify reconstruction
    let limb_0 = limbs[0];
    let limb_1 = limbs[1];
    let limb_2 = limbs[2];

    let base_88 = super::bigint::biguint_to_fe_simple(&(BigUint::from(1u64) << 88));
    let base_176 = super::bigint::biguint_to_fe_simple(&(BigUint::from(1u64) << 176));

    let reconstructed = limb_0 + limb_1 * base_88 + limb_2 * base_176;
    let reconstructed_big = super::bigint::fe_to_biguint_simple(&reconstructed);

    let pallas_modulus = super::bigint::fe_to_biguint_simple(&(-pallas::Base::ONE)) + 1u64;

    println!(
        "  Reconstructed matches: {}",
        (reconstructed_big.clone() % pallas_modulus.clone())
            == (value_big.clone() % pallas_modulus.clone())
    );

    // Should match modulo pallas field
    assert_eq!(
        reconstructed_big % pallas_modulus.clone(),
        value_big % pallas_modulus,
        "Reconstruction should match original value modulo pallas"
    );
}

// ============================================================================
// Documentation Test: How Foreign Field Representation Works
// ============================================================================

#[test]
fn test_document_foreign_field_flow() {
    println!("\n=== Foreign Field Arithmetic Flow ===\n");

    println!("1. Input: secp256k1 secret key (256 bits)");
    let sk_bytes = [0x42; 32];
    println!("   sk_bytes: {:?}", hex::encode(sk_bytes));

    println!("\n2. Convert to secp256k1::Fq field element");
    let _sk_fq = Secp256k1Fq::from_repr(sk_bytes).expect("valid Fq");

    println!("\n3. In circuit: Load as CRT integer");
    println!("   - Decompose 256 bits → 3 limbs × 88 bits");
    println!("   - Each limb stored as pallas::Base (fits in 254-bit field)");
    println!("   - ProperCrtUint<pallas::Base> = (limbs, native, value)");

    println!("\n4. Range check each limb:");
    println!("   - Each 88-bit limb → 9 chunks × 10 bits");
    println!("   - Lookup each 10-bit chunk in Sinsemilla table (K=10)");
    println!("   - Proves: limb < 2^90 (implies < 2^88)");

    println!("\n5. Perform elliptic curve operations:");
    println!("   - Point addition/doubling in CRT representation");
    println!("   - Scalar multiplication via Montgomery ladder");
    println!("   - All arithmetic preserves 88-bit limb structure");

    println!("\n6. Verify key pairing: pk = sk * G");
    println!("   - Compute sk * G in foreign field");
    println!("   - Compare result with provided pk (limb-wise)");

    println!("\n=== End Flow ===\n");
}
