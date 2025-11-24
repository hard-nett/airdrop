
## STEP 2

- ensure we know the mapping of the headstash circuit (visualizer)
- ensure we will need to witness all of our private inputs we expect
- ensure we define all of the public input positions we also will have so we have a concrete location for writing the constraints throughout the rest of our session
- ensure  to impelement each constraint step in our ciircuit spec, which you can find in the spec document.
- ensure we Define each of our [headstash suites implementations accurately](zk-crates/src/deploy/suite.rs), so that we can prepare circuit inputs and reuse specified logic in circuit library.

 1. foreign-field key pairing (secp256k1),
 2. hkdf constraint as explained in the spec,
 3. nullifier derivation integrity constraint.

- ensure we take into account the requirement config details for how we expect the inputs to exists for the forign field curbe for secp256 so we can implement this synthesise logic with precisoun and accuracy of the use of the pallas field:
  - element rangelookup check chip that has 10bit decomposition on our 3(88bit) piecies of the

## STEP 1
  
- we need to ensure we are using the correct existing logic wire into the foreign field chips to define the foreign field values during circuit synthesis, including the generator value for secp256k1 curve,
- finish constraining the hkdf keys for the nullifier within the circuit uysing the foriend field tooling

## STEP 3

- [complete headstash circuit sythesisation](./zk-crates/src/circuit.rs):
  - foreign-field-keypairing constraint
  - `nk` derivation constraint
  - leaf knowledge of genesis-hashdomain-tree
