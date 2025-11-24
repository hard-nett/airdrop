
- Define each of our [headstash suites implementations accurately](zk-crates/src/deploy/suite.rs), so that we can prepare circuit inputs and reuse specified logic in circuit library.

## STEP 2

 yes, lets implement the synthesize logic for our Cirucit now. lets ensure we are following the spec outlined, and also make use of the correct chips and configurations. we will
  need to first witness all of our private inputs we expect, and define all of the public input positions we also will have so we have a concrete location for writing the
  constraints throughout the rest of our session, then we want to impelement each step in our ciircuit spec, which you can find in the spec document and also is 1. foreign-field
  key pairing (secp256k1), 2. hkdf constraint as explained in the spec, 3. nullifier derivation integrity constraint. ensure we take into account the requirement config details for
  how we expect the inputs to exists for the forign field curbe for secp256 so we can implement this synthesise logic with precisoun and accuracy of the use of the pallas fiel
  element rangelookup check chip that has 10bit decomposition on our 3(88bit) piecies of the

## STEP 1

- [complete headstash circuit configuration](zk-crates/src/circuit.rs): assign `Secp256k1Config::configure` fp & fq advices: dedicated adivce colums, ensure we define it in the circuit library which columns are used for these values:

```
       fp_advices: [Column<Advice>; 3],
       fq_advices: [Column<Advice>; 3],
```

- we need to ensure we are using the correct existing logic wire into the foreign field chips to define the foreign field values during circuit synthesis, including the generator value for secp256k1 curve,
- finish constraining the hkdf keys for the nullifier within the circuit uysing the foriend field tooling 

## STEP 3

- [complete headstash circuit sythesisation](./zk-crates/src/circuit.rs):
  - foreign-field-keypairing constraint
  - `nk` derivation constraint
  - leaf knowledge of genesis-hashdomain-tree
