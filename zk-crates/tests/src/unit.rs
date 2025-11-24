mod fields {
    mod secp256k1 {

        #[test]
        fn test_fp_div() {
            let a = Secp256k1Fp::from(1000u64);
            let b = Secp256k1Fp::from(10u64);
            let c_expected = a * b.invert().unwrap();

            let circuit = FpDivTestCircuit { a, b, c_expected };
            let prover = MockProver::run(17, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}

mod pairing {}
mod pre_proof {}
mod proof {}
mod nullifier {}
mod note_commitment {}
