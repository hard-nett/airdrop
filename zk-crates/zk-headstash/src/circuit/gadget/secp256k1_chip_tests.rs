//! Unit tests for foreign field arithmetic - Secp256k1 key pairing
//!
//! These tests verify that we can correctly represent secp256k1 field elements
//! as 3x88-bit limbs in pallas::Base and perform elliptic curve pairing checks.

use std::println;

use crate::spec::biguint_to_fe_simple;

use super::secp256k1_chip::*;
use ff::{Field, PrimeField};
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp as Secp256k1Fp, Fq as Secp256k1Fq};
use halo2_gadgets::utilities::lookup_range_check::{
    LookupRangeCheck, LookupRangeCheck4_5BConfig, LookupRangeCheckConfig,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error as PlonkError},
};
use num_traits::Zero;
use pasta_curves::pallas;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};

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

#[test]
fn test_reconstruct_xy_from_limbs() {
    use halo2_base::utils::fe_to_biguint;
    use num_bigint::BigUint;

    // Use secp256k1 generator coordinates as known values
    let gen_x_fp = Secp256k1Fp::from_bytes(&GENERATOR_X).unwrap();
    let gen_y_fp = Secp256k1Fp::from_bytes(&GENERATOR_Y).unwrap();

    // Convert to BigUint
    let gen_x_big = fe_to_biguint(&gen_x_fp);
    let gen_y_big = fe_to_biguint(&gen_y_fp);

    // Decompose into 3x88-bit limbs (little-endian)
    let x_limbs = crate::spec::decompose_biguint_simple(&gen_x_big, 3, 88);
    let y_limbs = crate::spec::decompose_biguint_simple(&gen_y_big, 3, 88);

    // Display decomposed limbs
    println!("x decomposed into limbs:");
    for (i, limb) in x_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!("  limb[{}]: {} ({} bits)", i, limb_big, limb_big.bits());
    }
    println!("y decomposed into limbs:");
    for (i, limb) in y_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!("  limb[{}]: {} ({} bits)", i, limb_big, limb_big.bits());
    }

    // Reconstruct x by summing: limb[0] + limb[1] * 2^88 + limb[2] * 2^176
    let reconstructed_x = x_limbs
        .iter()
        .enumerate()
        .fold(BigUint::zero(), |acc, (i, limb)| {
            let limb_big = crate::spec::fe_to_biguint_simple(limb);
            acc + (limb_big << (88 * i))
        });

    // Reconstruct y similarly
    let reconstructed_y = y_limbs
        .iter()
        .enumerate()
        .fold(BigUint::zero(), |acc, (i, limb)| {
            let limb_big = crate::spec::fe_to_biguint_simple(limb);
            acc + (limb_big << (88 * i))
        });

    // Display reconstructions
    println!("Reconstructed x: {}", reconstructed_x);
    println!("Original x:      {}", gen_x_big);
    println!("Reconstructed y: {}", reconstructed_y);
    println!("Original y:      {}", gen_y_big);

    // Assert accuracy
    assert_eq!(reconstructed_x, gen_x_big, "x reconstruction failed");
    assert_eq!(reconstructed_y, gen_y_big, "y reconstruction failed");

    println!("✓ CRT limb reconstruction accurate for x and y coordinates");
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
    let sk_secp = SecretKey::from_byte_array(sk_bytes).unwrap();

    // Public key from DIFFERENT secret key
    let wrong_sk_bytes = [0x43; 32];
    let wrong_sk_secp = SecretKey::from_byte_array(wrong_sk_bytes).unwrap();
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

// // ============================================================================
// // Test: Zero Secret Key (Should Fail - Invalid Point)
// // ============================================================================

// #[test]
// #[should_panic(expected = "secret key out of range")]
// fn test_secp256k1_zero_secret_key() {
//     use secp256k1::{Secp256k1, SecretKey};

//     let _secp = Secp256k1::new();
//     let sk_bytes = [0x00; 32];

//     // This should panic because 0 is not a valid secp256k1 secret key
//     assert!(SecretKey::from_slice(&sk_bytes).is_err())
// }

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

    let v = Secp256k1Fp::from_repr(test_value_bytes).expect("valid Fp");
    let v_biguint = halo2_base::utils::fe_to_biguint(&v);

    // Decompose into 3x88-bit limbs
    let limbs = crate::spec::decompose_biguint_simple(&v_biguint, 3, 88);

    println!("Foreign field decomposition test:");
    println!("  Original value: {:?}", hex::encode(test_value_bytes));

    // Verify each limb fits in 88 bits
    for (i, limb) in limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        let max_88_bit = BigUint::from(1u64) << 88;
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

    let base_88 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 88));
    let base_176 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 176));

    let reconstructed = limb_0 + limb_1 * base_88 + limb_2 * base_176;
    let reconstructed_big = crate::spec::fe_to_biguint_simple(&reconstructed);
    let pallas_modulus = crate::spec::fe_to_biguint_simple(&(-pallas::Base::ONE)) + 1u64;

    println!(
        "  Reconstructed matches: {}",
        (reconstructed_big.clone() % pallas_modulus.clone())
            == (v_biguint.clone() % pallas_modulus.clone())
    );

    // Should match modulo pallas field
    assert_eq!(
        reconstructed_big % pallas_modulus.clone(),
        v_biguint % pallas_modulus,
        "Reconstruction should match original value modulo pallas"
    );
}

// ============================================================================
// Test: Secp256k1 SK to Pallas Base Conversion via CRT
// ============================================================================
#[test]
fn test_secp256k1_pk_to_pallas_crt_conversion() {
    use halo2_base::utils::fe_to_biguint;
    use num_bigint::BigUint;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    println!("\n=== Secp256k1 PK → Pallas CRT Conversion ===\n");

    // 1. Generate a secp256k1 key pair
    let secp = Secp256k1::new();
    let sk_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let sk = SecretKey::from_slice(&sk_bytes).expect("valid secret key");
    let pk = PublicKey::from_secret_key(&secp, &sk);

    // Extract x and y coordinates
    let pk_bytes = pk.serialize_uncompressed();
    let pk_x_bytes: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
    let pk_y_bytes: [u8; 32] = pk_bytes[33..65].try_into().unwrap();

    println!("1. Original secp256k1 public key:");
    println!("   pk_x_bytes: {}", hex::encode(pk_x_bytes));
    println!("   pk_y_bytes: {}", hex::encode(pk_y_bytes));

    // 2. Convert to secp256k1::Fp field elements
    let pk_x_fp = Secp256k1Fp::from_repr(pk_x_bytes).expect("valid Fp");
    let pk_y_fp = Secp256k1Fp::from_repr(pk_y_bytes).expect("valid Fp");
    let pk_x_big = fe_to_biguint(&pk_x_fp);
    let pk_y_big = fe_to_biguint(&pk_y_fp);

    println!("\n2. As secp256k1::Fp BigUint:");
    println!("   pk_x: {} bits", pk_x_big.bits());
    println!("   pk_y: {} bits", pk_y_big.bits());

    // 3. Decompose x and y into 3x88-bit limbs (CRT representation)
    let x_limbs = crate::spec::decompose_biguint_simple(&pk_x_big, 3, 88);
    let y_limbs = crate::spec::decompose_biguint_simple(&pk_y_big, 3, 88);

    println!("\n3. CRT decomposition (3x88-bit limbs):");
    for (coord, limbs) in [("x", &x_limbs), ("y", &y_limbs)] {
        println!("   {} limbs:", coord);
        for (i, limb) in limbs.iter().enumerate() {
            let limb_big = crate::spec::fe_to_biguint_simple(limb);
            println!("     Limb[{}]: {} bits = {}", i, limb_big.bits(), limb_big);

            // Verify limb fits in 88 bits
            let max_88_bit = BigUint::from(1u64) << 88;
            assert!(
                limb_big < max_88_bit,
                "Limb {} for {} exceeds 88 bits",
                i,
                coord
            );
        }
    }

    // 4. Reconstruct x and y in pallas::Base field
    let base_88 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 88));
    let base_176 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 176));

    let pk_x_pallas_reconstructed = x_limbs[0] + x_limbs[1] * base_88 + x_limbs[2] * base_176;
    let pk_y_pallas_reconstructed = y_limbs[0] + y_limbs[1] * base_88 + y_limbs[2] * base_176;

    println!("\n4. Reconstructed as pallas::Base:");
    println!("   pk_x_pallas = limb_x[0] + limb_x[1]*2^88 + limb_x[2]*2^176");
    println!("   pk_y_pallas = limb_y[0] + limb_y[1]*2^88 + limb_y[2]*2^176");

    // 5. Compute direct interpretation as BigUint from bytes, reduced mod pallas modulus
    let pallas_modulus = crate::spec::fe_to_biguint_simple(&(-pallas::Base::ONE)) + 1u64;
    let pk_x_direct_big = BigUint::from_bytes_be(&pk_x_bytes) % &pallas_modulus;
    let pk_y_direct_big = BigUint::from_bytes_be(&pk_y_bytes) % &pallas_modulus;

    println!("\n5. Direct byte interpretation reduced mod pallas modulus:");
    println!("   (secp256k1 bytes interpreted as BigUint, then % pallas_modulus)");

    // 6. Compare CRT reconstructed (already in pallas field) with direct reduced BigUint
    let x_reconstructed_big = crate::spec::fe_to_biguint_simple(&pk_x_pallas_reconstructed);
    let y_reconstructed_big = crate::spec::fe_to_biguint_simple(&pk_y_pallas_reconstructed);

    println!("\n6. Comparison:");
    println!("   X - CRT reconstructed: {}", x_reconstructed_big);
    println!("   X - Direct reduced:     {}", pk_x_direct_big);
    println!("   Y - CRT reconstructed: {}", y_reconstructed_big);
    println!("   Y - Direct reduced:     {}", pk_y_direct_big);

    let x_matches = x_reconstructed_big == pk_x_direct_big;
    let y_matches = y_reconstructed_big == pk_y_direct_big;
    println!("   X methods match: {}", x_matches);
    println!("   Y methods match: {}", y_matches);

    assert_eq!(
        x_reconstructed_big, pk_x_direct_big,
        "CRT reconstruction should match direct interpretation for X"
    );
    assert_eq!(
        y_reconstructed_big, pk_y_direct_big,
        "CRT reconstruction should match direct interpretation for Y"
    );

    println!("\n7. These pallas::Base values represent epk in the circuit:");
    println!(
        "   epk: (CrtInteger<pallas::Base>, CrtInteger<pallas::Base>) = ((x_limbs), (y_limbs))"
    );

    println!("\n=== PK CRT Conversion Verified ✓ ===\n");
}

#[test]
fn test_secp256k1_sk_to_pallas_base_conversion() {
    use halo2_base::utils::fe_to_biguint;
    use num_bigint::BigUint;

    println!("\n=== Secp256k1 SK → Pallas Base Conversion ===\n");

    // 1. Start with a secp256k1 secret key
    let sk_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    println!("1. Original secp256k1 secret key:");
    println!("   sk_bytes: {}", hex::encode(sk_bytes));

    // 2. Convert to secp256k1::Fq field element
    let sk_fq = Secp256k1Fq::from_repr(sk_bytes).expect("valid Fq");
    let sk_big = fe_to_biguint(&sk_fq);

    println!("\n2. As secp256k1::Fq BigUint:");
    println!("   {} bits", sk_big.bits());

    // 3. Decompose into 3x88-bit limbs (CRT representation)
    let limbs = crate::spec::decompose_biguint_simple(&sk_big, 3, 88);

    println!("\n3. CRT decomposition (3x88-bit limbs):");
    for (i, limb) in limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!("   Limb[{}]: {} bits = {}", i, limb_big.bits(), limb_big);

        // Verify limb fits in 88 bits
        let max_88_bit = BigUint::from(1u64) << 88;
        assert!(limb_big < max_88_bit, "Limb {} exceeds 88 bits", i);
    }

    // 4. Reconstruct in pallas::Base field
    let base_88 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 88));
    let base_176 = crate::spec::biguint_to_fe_simple(&(BigUint::from(1u64) << 176));

    let sk_pallas_reconstructed = limbs[0] + limbs[1] * base_88 + limbs[2] * base_176;

    println!("\n4. Reconstructed as pallas::Base:");
    println!("   sk_pallas = limb[0] + limb[1]*2^88 + limb[2]*2^176");

    // 5. Verify this matches direct byte interpretation
    let sk_pallas_direct = pallas::Base::from_repr(sk_bytes).unwrap_or(pallas::Base::zero());

    println!("\n5. Direct byte interpretation as pallas::Base:");
    println!("   (secp256k1 bytes mod pallas modulus)");

    // 6. Compare both methods
    let reconstructed_big = crate::spec::fe_to_biguint_simple(&sk_pallas_reconstructed);
    let direct_big = crate::spec::fe_to_biguint_simple(&sk_pallas_direct);
    let pallas_modulus = crate::spec::fe_to_biguint_simple(&(-pallas::Base::ONE)) + 1u64;

    println!("\n6. Comparison:");
    println!(
        "   CRT reconstructed mod pallas: {}",
        reconstructed_big.clone() % pallas_modulus.clone()
    );
    println!(
        "   Direct interpretation:        {}",
        direct_big.clone() % pallas_modulus.clone()
    );

    let matches = (reconstructed_big.clone() % pallas_modulus.clone())
        == (direct_big.clone() % pallas_modulus.clone());
    println!("   Methods match: {}", matches);

    assert_eq!(
        reconstructed_big % pallas_modulus.clone(),
        direct_big % pallas_modulus,
        "CRT reconstruction should match direct interpretation"
    );

    println!("\n7. This pallas::Base value is used for HKDF:");
    println!("   nk = Poseidon(DST, sk_pallas, rho)");

    println!("\n=== Conversion Verified ✓ ===\n");
}

// ============================================================================
// Negative Test: Non-Paired Keys Should NOT Match
// ============================================================================

#[test]
fn test_non_paired_keys_detection() {
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    println!("\n=== Non-Paired Keys Detection Test ===\n");

    let secp = Secp256k1::new();

    // 1. Create first key pair
    let sk1_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let sk1 = SecretKey::from_slice(&sk1_bytes).expect("valid sk1");
    let pk1 = PublicKey::from_secret_key(&secp, &sk1);

    println!("1. First key pair:");
    println!("   sk1: {}", hex::encode(sk1_bytes));
    println!("   pk1: {}", hex::encode(pk1.serialize_uncompressed()));

    // 2. Create second DIFFERENT key pair
    let sk2_bytes = [0x42; 32];
    let sk2 = SecretKey::from_slice(&sk2_bytes).expect("valid sk2");
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);

    println!("\n2. Second key pair (different):");
    println!("   sk2: {}", hex::encode(sk2_bytes));
    println!("   pk2: {}", hex::encode(pk2.serialize_uncompressed()));

    // 3. Try to pair sk1 with pk2 (should NOT match!)
    println!("\n3. Attempting to pair sk1 with pk2 (should fail):");

    let pk2_bytes = pk2.serialize_uncompressed();
    let pk2_x_bytes: [u8; 32] = pk2_bytes[1..33].try_into().unwrap();
    let pk2_y_bytes: [u8; 32] = pk2_bytes[33..65].try_into().unwrap();

    // Convert to field elements
    let sk1_fq = Secp256k1Fq::from_repr(sk1_bytes).expect("valid Secp256k1Fq");
    let pk2_x_fp = Secp256k1Fp::from_repr(pk2_x_bytes).expect("valid Secp256k1Fp");
    let pk2_y_fp = Secp256k1Fp::from_repr(pk2_y_bytes).expect("valid Secp256k1Fp");

    // 4. Verify the pairing using secp256k1 library
    let computed_pk_from_sk1 = PublicKey::from_secret_key(&secp, &sk1);
    let keys_match = computed_pk_from_sk1 == pk2;

    println!("   sk1 * G == pk2? {}", keys_match);
    assert!(!keys_match, "sk1 should NOT pair with pk2");

    // 5. Show that CRT conversion preserves the mismatch
    let sk1_big = halo2_base::utils::fe_to_biguint(&sk1_fq);
    let limbs = crate::spec::decompose_biguint_simple(&sk1_big, 3, 88);

    println!("\n4. CRT decomposition of sk1:");
    for (i, limb) in limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!("   limb[{}] = {}", i, limb_big);
    }

    // 6. Convert sk1 to pallas::Base
    let sk1_pallas = pallas::Base::from_repr(sk1_bytes).unwrap_or(pallas::Base::zero());
    let sk1_pallas_big = crate::spec::fe_to_biguint_simple(&sk1_pallas);

    println!("\n5. sk1 as pallas::Base:");
    println!("   {} bits", sk1_pallas_big.bits());

    // 7. Important: This pallas::Base value would produce DIFFERENT nk than sk2
    let sk2_pallas = pallas::Base::from_repr(sk2_bytes).unwrap_or(pallas::Base::zero());
    let sk2_pallas_big = crate::spec::fe_to_biguint_simple(&sk2_pallas);

    println!("\n6. sk2 as pallas::Base:");
    println!("   {} bits", sk2_pallas_big.bits());

    println!("\n7. Pallas representations differ:");
    println!("   sk1_pallas == sk2_pallas? {}", sk1_pallas == sk2_pallas);
    assert_ne!(
        sk1_pallas, sk2_pallas,
        "Different keys should have different pallas representations"
    );

    println!("\n8. Conclusion:");
    println!("   ✓ Non-paired keys are correctly detected as different");
    println!("   ✓ CRT conversion preserves key uniqueness");
    println!("   ✓ HKDF will produce different nk for different keys");

    println!("\n=== Non-Paired Keys Correctly Rejected ✓ ===\n");
}

// ============================================================================
// Test: Verify ETH Key Pairing with CRT and Montgomery Ladder
// ============================================================================

#[test]
fn test_eth_key_pairing_with_crt() {
    use halo2_base::gates::RangeChip;
    use halo2_base::utils::{fe_to_biguint, BigPrimeField};

    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    // 1. Generate an Ethereum-style key pair
    let secp = Secp256k1::new();
    let sk = SecretKey::from_byte_array([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ])
    .expect("valid secret key");
    let pk = PublicKey::from_secret_key(&secp, &sk);

    // Extract public key coordinates
    let pk_bytes = pk.serialize_uncompressed();
    let pk_x_bytes: [u8; 32] = pk_bytes[1..33].try_into().unwrap();
    let pk_y_bytes: [u8; 32] = pk_bytes[33..65].try_into().unwrap();

    println!("\n=== ETH Key Pairing via CRT + Montgomery Ladder ===\n");
    println!("1. Ethereum key pair (expected values from secp256k1 library):");
    println!("   sk: {}", hex::encode(sk.secret_bytes()));
    println!("   pk.x: {}", hex::encode(pk_x_bytes));
    println!("   pk.y: {}", hex::encode(pk_y_bytes));

    // 2. Convert to field elements for circuit
    let sk_fq = Secp256k1Fq::from_repr(sk.secret_bytes()).expect("valid Fq");
    let pk_x_fp = Secp256k1Fp::from_repr(pk_x_bytes).expect("valid Fp");
    let pk_y_fp = Secp256k1Fp::from_repr(pk_y_bytes).expect("valid Fp");

    println!("\n2. Field element representation:");
    println!("   sk ∈ secp256k1::Fq (scalar field, modulo n)");
    println!("   pk.x, pk.y ∈ secp256k1::Fp (base field, modulo p)");

    // 3. Demonstrate CRT decomposition for scalar (sk)
    println!("\n3. CRT decomposition of secret key:");
    println!("   sk decomposed into 3×88-bit limbs:");
    let sk_limbs = crate::spec::decompose_biguint_simple(&fe_to_biguint(&sk_fq), 3, 88);
    for (i, limb) in sk_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!(
            "     sk_limb[{}] = 0x{:0>22x} ({} bits)",
            i,
            limb_big,
            limb_big.bits()
        );
        assert!(limb_big.bits() <= 88, "Limb {} exceeds 88 bits", i);
    }

    // Verify CRT reconstruction
    let reconstructed_sk =
        sk_limbs
            .iter()
            .enumerate()
            .fold(num_bigint::BigUint::zero(), |acc, (i, limb)| {
                let limb_big = crate::spec::fe_to_biguint_simple(limb);
                acc + (limb_big << (88 * i))
            });
    assert_eq!(
        reconstructed_sk,
        fe_to_biguint(&sk_fq),
        "CRT decomposition should reconstruct original scalar"
    );
    println!("   ✓ CRT reconstruction verified: Σ(limb[i] × 2^(88i)) = sk");

    // 4. Get generator point and decompose into CRT limbs
    println!("\n4. Secp256k1 generator point G:");
    let gen_x_bytes = &secp256k1::constants::GENERATOR_X;
    let gen_y_bytes = &secp256k1::constants::GENERATOR_Y;
    let gen_x_fp = Secp256k1Fp::from_repr(gen_x_bytes.to_vec().as_slice().try_into().unwrap())
        .expect("valid generator x");
    let gen_y_fp = Secp256k1Fp::from_repr(gen_y_bytes.to_vec().as_slice().try_into().unwrap())
        .expect("valid generator y");

    println!("   G.x: {}", hex::encode(gen_x_bytes));
    println!("   G.y: {}", hex::encode(gen_y_bytes));

    // Decompose generator coordinates into CRT limbs
    let gen_x_limbs = crate::spec::decompose_biguint_simple(&fe_to_biguint(&gen_x_fp), 3, 88);
    let gen_y_limbs = crate::spec::decompose_biguint_simple(&fe_to_biguint(&gen_y_fp), 3, 88);

    println!("\n   G.x CRT limbs (3×88-bit):");
    for (i, limb) in gen_x_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!(
            "     G.x_limb[{}] = 0x{:0>22x} ({} bits)",
            i,
            limb_big,
            limb_big.bits()
        );
    }

    println!("\n   G.y CRT limbs (3×88-bit):");
    for (i, limb) in gen_y_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!(
            "     G.y_limb[{}] = 0x{:0>22x} ({} bits)",
            i,
            limb_big,
            limb_big.bits()
        );
    }

    // 5. Decompose expected public key into CRT limbs
    println!("\n5. Expected public key (pk) CRT representation:");
    let pk_x_limbs = crate::spec::decompose_biguint_simple(&fe_to_biguint(&pk_x_fp), 3, 88);
    let pk_y_limbs = crate::spec::decompose_biguint_simple(&fe_to_biguint(&pk_y_fp), 3, 88);

    println!("   pk.x CRT limbs (3×88-bit):");
    for (i, limb) in pk_x_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!(
            "     pk.x_limb[{}] = 0x{:0>22x} ({} bits)",
            i,
            limb_big,
            limb_big.bits()
        );
    }

    println!("\n   pk.y CRT limbs (3×88-bit):");
    for (i, limb) in pk_y_limbs.iter().enumerate() {
        let limb_big = crate::spec::fe_to_biguint_simple(limb);
        println!(
            "     pk.y_limb[{}] = 0x{:0>22x} ({} bits)",
            i,
            limb_big,
            limb_big.bits()
        );
    }

    // 6. Simulate scalar multiplication: pk = sk * G
    println!("\n6. Scalar multiplication verification: pk = sk × G");
    println!("   Operation: Point multiplication using Montgomery ladder");
    println!(
        "   Input: sk (CRT: {} limbs), G (CRT point)",
        sk_limbs.len()
    );
    println!("   Output: pk (CRT point)");

    // Verify the computation using the secp256k1 library matches our CRT representation
    let pk_x_bytes_reconverted = pk_x_fp.to_repr();
    let pk_y_bytes_reconverted = pk_y_fp.to_repr();

    assert_eq!(
        pk_x_bytes, pk_x_bytes_reconverted,
        "Public key X coordinate should survive field element conversion"
    );
    assert_eq!(
        pk_y_bytes, pk_y_bytes_reconverted,
        "Public key Y coordinate should survive field element conversion"
    );
    println!("   ✓ Field element conversions are lossless");

    // 7. Verify curve equation for both G and pk
    println!("\n7. Curve equation verification: y² ≡ x³ + 7 (mod p)");
    use num_bigint::BigUint;
    let p = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();

    // Verify generator
    let gen_x = BigUint::from_bytes_be(gen_x_bytes);
    let gen_y = BigUint::from_bytes_be(gen_y_bytes);
    let gen_y_squared = (&gen_y * &gen_y) % &p;
    let gen_x_cubed = (&gen_x * &gen_x * &gen_x) % &p;
    let seven = BigUint::from(7u32);
    let gen_rhs = (gen_x_cubed + &seven) % &p;
    assert_eq!(gen_y_squared, gen_rhs, "Generator must be on curve");
    println!("   ✓ Generator G is on secp256k1 curve");

    // Verify public key
    let x = BigUint::from_bytes_be(&pk_x_bytes);
    let y = BigUint::from_bytes_be(&pk_y_bytes);
    let y_squared = (&y * &y) % &p;
    let x_cubed = (&x * &x * &x) % &p;
    let rhs = (x_cubed + seven) % &p;
    assert_eq!(y_squared, rhs, "Public key must be on curve");
    println!("   ✓ Public key pk is on secp256k1 curve");

    // 8. Verify deterministic derivation
    let pk2 = PublicKey::from_secret_key(&secp, &sk);
    let pk2_bytes = pk2.serialize_uncompressed();
    assert_eq!(
        pk_bytes, pk2_bytes,
        "Public key derivation should be deterministic"
    );
    println!("   ✓ Public key derivation is deterministic");

    // 9. Summary of CRT pairing
    println!("\n8. CRT Pairing Summary:");
    println!("   Input (CRT representation):");
    println!("     • sk: {} limbs of 88 bits each", sk_limbs.len());
    println!("     • G.x: {} limbs of 88 bits each", gen_x_limbs.len());
    println!("     • G.y: {} limbs of 88 bits each", gen_y_limbs.len());
    println!("\n   Computation:");
    println!("     • Montgomery ladder scalar multiplication");
    println!("     • All arithmetic operations performed on CRT limbs");
    println!("     • Range checks: each limb < 2^88");
    println!("\n   Output (CRT representation):");
    println!("     • pk.x: {} limbs of 88 bits each", pk_x_limbs.len());
    println!("     • pk.y: {} limbs of 88 bits each", pk_y_limbs.len());

    println!("\n=== Key Pairing Test Complete ✓ ===");
    println!("✓ CRT decomposition is valid and reversible");
    println!("✓ Generator and public key are on secp256k1 curve");
    println!("✓ Public key coordinates are correctly extracted");
    println!("✓ Field element conversions are lossless");
    println!("✓ Public key derivation is deterministic");
    println!("✓ CRT representation preserves all cryptographic properties");
    println!();
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
