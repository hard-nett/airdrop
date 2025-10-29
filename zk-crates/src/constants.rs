pub mod fixed_bases;
pub mod sinsemilla;

pub use self::sinsemilla::HeadstashHashDomains;

pub const DST_HKDF_JUBJUB: &[u8] = b"HEADSTASH-HKDF-REDJUBJUB";

/// SWU hash-to-curve personalization for the note commitment generator
pub const NOTE_COMMITMENT_PERSONALIZATION: &str = "terp.network:Headstash-NoteCommit";
/// SWU hash-to-curve personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &str = "terp.network:Headstash-gd";

pub const KEY_DERIVATION_DST_JUBJUB: &str = "terp.network:hkdf-jubjub";
/// $\mathsf{MerkleDepth^{Orchard}}$
pub const MERKLE_DEPTH_HEADSTASH: usize = 32;

/// $\ell^\mathsf{Orchard}_\mathsf{base}$
pub(crate) const L_ORCHARD_BASE: usize = 255;
