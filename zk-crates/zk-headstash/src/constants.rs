pub mod fixed_bases;
pub mod sinsemilla;

pub use self::sinsemilla::HeadstashHashDomains;

pub const DST_HKDF_JUBJUB: &[u8] = b"HEADSTASH-HKDF-REDJUBJUB";

/// SWU hash-to-curve personalization for the spending key base point and
/// the nullifier base point K^Orchard
pub const HEADSTASH_PERSONALIZATION: &str = "z.cash:Orchard";

/// SWU hash-to-curve personalization for the note commitment generator
pub const DST_CM: &str = "terp.network:Headstash-cm";
pub const DST_V: &str = "terp.network:Headstash-v";
pub const DST_HKDF: &[u8] = b"Hkdf-terp.network";

/// The Pallas scalar field modulus is $q = 2^{254} + \mathsf{t_q}$.
/// <https://github.com/zcash/pasta>
pub(crate) const T_Q: u128 = 45560315531506369815346746415080538113;

/// The Pallas base field modulus is $p = 2^{254} + \mathsf{t_p}$.
/// <https://github.com/zcash/pasta>
pub(crate) const T_P: u128 = 45560315531419706090280762371685220353;

/// $\mathsf{MerkleDepth^{Orchard}}$
pub const MERKLE_DEPTH_HEADSTASH: usize = 32;

/// $\ell^\mathsf{Orchard}_\mathsf{base}$
pub(crate) const L_ORCHARD_BASE: usize = 255;

/// $\ell^\mathsf{Orchard}_\mathsf{scalar}$
pub(crate) const L_ORCHARD_SCALAR: usize = 255;

/// $\ell_\mathsf{value}$
pub(crate) const L_VALUE: usize = 64;
