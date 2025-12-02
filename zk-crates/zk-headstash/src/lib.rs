// Recipient address defintions module
pub mod address;
// Main circuit config & structs with halo-2 circuit syntheszation implemented for a pallas curve native field
pub mod circuit;
// Varous constants resued throughout the implementation
pub mod constants;
// All involved keys struct definitions and trait/spec implementations
pub mod keys;
// Note struct definition & implementation of spec logic for nullifier derivation
pub mod note;
// Pseudo-Random-Function module.
pub mod prf_expand;
// Specification of headstash circuit miplement in rust
mod spec;

// Merkle tree struct definition (both for headstash and note commitment)
pub mod tree;
//
pub mod value;

// pub mod plume;
pub mod deploy;
pub mod example_circuits;

pub mod gen;
