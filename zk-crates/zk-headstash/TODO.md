# TODO

This will be where agentic progress is kept track of.

## Document Circuit In Spec:


## 1. Foundation: Set up foreign field arithmetic infrastructure

refactor chips from halo2-liib into non-abstracted framework version (raw halo2 lib implementation). we  dont want to use the format used in halo2-base or halo2-ecc. I want to implement my own monorepo by refactoring the functions from these crates into
the native halo2 formats. this means we dont make use of ctx, or any of the apis defined in the halo2-base or halo2-ecc crates, just rather refactoring their logic to standardize our implementation Ah, I understand! You want to refactor the core logic from halo2-lib into traditional halo2 chip format (using Chip trait, Layouter, Region, etc.) -
  not use their API abstractions.

### BigInt Module

- CRT Representation Types:
  - OverflowInteger<F> - limbs with possible overflow
  - ProperUint<F> - properly range-checked limbs
  - CrtInteger<F> - full CRT representation (truncation + native + value)
  - FixedOverflowInteger<F> - constant BigUint as limbs
- Utility Functions (avoiding halo2-base BigPrimeField trait):
  - decompose_biguint_simple() - decompose BigUint into limbs
  - fe_to_biguint_simple() - convert pallas::Base to BigUint
  - biguint_to_fe_simple() - convert BigUint to pallas::Base
  - modulus_simple<F>() - get modulus of any PrimeField
- BigIntChip: Basic structure for CRT operations (assign constants/witnesses)

### LookupRangeCheckConfig & LookupRangeCheckChip

- use existing implementation, ensure the config satisfies its extended use (currently used for ecc chip, we are adding support to constrain secp256k1 limbs onto this curve)

> q. do we define a second lookuprangecheck chip that uses 88bits for each limb? right now the one used for the sinsemilla & ecc chip uses 10 bits. if so will this impact the size of the circuit? can we reuse the right most column as needed?

## Secp256k1FpChip

- Refactor FpChip from halo2-lib (type defined in halo2-ecc/src/secp256k1/mod.rs,implementation exists in  halo2-ecc/src::fields::fp;)

## Secp256k1FqChip

- src/circuit/gadget/fq_chip.rs - Refactor FqChip from halo2-lib (type defined in halo2-ecc/src/secp256k1/mod.rs,implementation exists in  halo2-ecc/src::fields::fp;)

## 2. Key Pairing: Simplest foreign curve operation to test setup