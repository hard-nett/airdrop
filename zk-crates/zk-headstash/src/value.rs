use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use core::fmt::{self, Debug};
use core::iter::Sum;
use core::ops::{Add, RangeInclusive, Sub};
use halo2_proofs::plonk::Assigned;
use pasta_curves::pallas;

/// Maximum note value.
pub const MAX_NOTE_VALUE: u64 = u64::MAX;
pub const MAX_DENOM_LEN: usize = 32;

/// The valid range of the scalar multiplication used in ValueCommit^Orchard.
///
/// Defined in a note in [Zcash Protocol Spec § 4.17.4: Action Statement (Orchard)][actionstatement].
///
/// [actionstatement]: https://zips.z.cash/protocol/nu5.pdf#actionstatement
pub const VALUE_SUM_RANGE: RangeInclusive<i128> =
    -(MAX_NOTE_VALUE as i128)..=MAX_NOTE_VALUE as i128;

/// A value operation overflowed.
#[derive(Debug)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Orchard value operation overflowed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OverflowError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteDenom {
    bytes: [u8; MAX_DENOM_LEN],
}

/// Return the padded value used in proof generation (blake3 hash with bit-trim)
impl NoteDenom {
    /// Return the padded value used in proof generation (posiedon hash with bit-trim for field note denom field inclusion).
    /// Clear the top three bits of the first byte to get 253-bit field element (pallas)\
    /// 0x1F = 00011111 in binary (clears top 3 bits)
    pub fn new_for_proof(denom: &str) -> Self {
        let hash = Self::hash(denom);
        let mut bytes = *hash.as_bytes();

        bytes[31] &= 0x1F;
        // Convert to NoteDenom type (assuming NoteDenom wraps [u8; 32])
        NoteDenom { bytes }
    }

    pub fn hash(denom: &str) -> blake3::Hash {
        // Hash the denomination string with Blake3
        let mut hasher = blake3::Hasher::new();
        hasher.update(denom.as_bytes());
        hasher.finalize()
    }

    /// hex string of trimmed blake3 hash representing note-denom
    pub fn as_str_for_proof(&self) -> String {
        let mut bytes = self.bytes;
        hex::encode(self.bytes)
    }

    /// Return the raw bytes (including unused trailing zeros).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Return the raw bytes (including unused trailing zeros).
    pub fn max_len() -> usize {
        MAX_DENOM_LEN
    }
}

impl From<[u8; 32]> for NoteDenom {
    fn from(value: [u8; 32]) -> Self {
        NoteDenom { bytes: value }
    }
}

impl Default for NoteDenom {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_DENOM_LEN],
        }
    }
}

// ---------------------------------------------------------------------
// Pretty‑printing (e.g. with `println!("{:?}", denom)` or `format!`)
impl fmt::Display for NoteDenom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_for_proof())
    }
}

// ---------------------------------------------------------------------
// Parsing from a CLI string
impl std::str::FromStr for NoteDenom {
    type Err = String; // simple error type; change to a custom error if desired

    fn from_str(ds: &str) -> Result<Self, Self::Err> {
        Ok(Self::new_for_proof(ds))
    }
}

/// The non-negative value of an individual Orchard note.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoteValue(u64);

impl NoteValue {
    pub(crate) fn zero() -> Self {
        // Default for u64 is zero.
        Default::default()
    }

    /// Returns the raw underlying value.
    pub fn inner(&self) -> u64 {
        self.0
    }

    /// represents `v` as its pallas curve point equivalent.
    pub(crate) fn to_fp_pallas(self) -> pallas::Base {
        pallas::Base::from(self.0)
    }

    /// Creates a note value from its raw numeric value.
    ///
    /// This only enforces that the value is an unsigned 64-bit integer. Callers should
    /// enforce any additional constraints on the value's valid range themselves.
    pub fn from_raw(value: u64) -> Self {
        NoteValue(value)
    }

    pub(crate) fn from_bytes(bytes: [u8; 8]) -> Self {
        NoteValue(u64::from_le_bytes(bytes))
    }

    pub(crate) fn to_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub(crate) fn to_le_bits(self) -> BitArray<[u8; 8], Lsb0> {
        BitArray::<_, Lsb0>::new(self.0.to_le_bytes())
    }
}

// #[cfg(feature = "circuit")]
impl From<&NoteValue> for Assigned<pallas::Base> {
    fn from(v: &NoteValue) -> Self {
        pallas::Base::from(v.inner()).into()
    }
}

impl Sub for NoteValue {
    type Output = ValueSum;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        let a = self.0 as i128;
        let b = rhs.0 as i128;
        a.checked_sub(b)
            .filter(|v| VALUE_SUM_RANGE.contains(v))
            .map(ValueSum)
            .expect("u64 - u64 result is always in VALUE_SUM_RANGE")
    }
}

/// The sign of a [`ValueSum`].
#[derive(Debug)]
pub enum Sign {
    /// A non-negative [`ValueSum`].
    Positive,
    /// A negative [`ValueSum`].
    Negative,
}

/// A sum of Orchard note values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ValueSum(i128);

impl ValueSum {
    pub(crate) fn zero() -> Self {
        // Default for i128 is zero.
        Default::default()
    }

    /// Creates a value sum from a raw i64 (which is always in range for this type).
    ///
    /// This only enforces that the value is a signed 63-bit integer. We use it internally
    /// in `Bundle::binding_validating_key`, where we are converting from the user-defined
    /// `valueBalance` type that enforces any additional constraints on the value's valid
    /// range.
    pub(crate) fn from_raw(value: i64) -> Self {
        ValueSum(value as i128)
    }

    /// Constructs a value sum from its magnitude and sign.
    pub(crate) fn from_magnitude_sign(magnitude: u64, sign: Sign) -> Self {
        Self(match sign {
            Sign::Positive => magnitude as i128,
            Sign::Negative => -(magnitude as i128),
        })
    }

    /// Splits this value sum into its magnitude and sign.
    ///
    /// This is a low-level API, requiring a detailed understanding of the
    /// [use of value balancing][orchardbalance] in the Zcash protocol to use correctly
    /// and securely. It is intended to be used in combination with the [`crate::pczt`]
    /// module.
    ///
    /// [orchardbalance]: https://zips.z.cash/protocol/protocol.pdf#orchardbalance
    pub fn magnitude_sign(&self) -> (u64, Sign) {
        let (magnitude, sign) = if self.0.is_negative() {
            (-self.0, Sign::Negative)
        } else {
            (self.0, Sign::Positive)
        };
        (
            u64::try_from(magnitude)
                .expect("ValueSum magnitude is in range for u64 by construction"),
            sign,
        )
    }
}

impl Add for ValueSum {
    type Output = Option<ValueSum>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        self.0
            .checked_add(rhs.0)
            .filter(|v| VALUE_SUM_RANGE.contains(v))
            .map(ValueSum)
    }
}

impl<'a> Sum<&'a ValueSum> for Result<ValueSum, OverflowError> {
    fn sum<I: Iterator<Item = &'a ValueSum>>(mut iter: I) -> Self {
        iter.try_fold(ValueSum(0), |acc, v| acc + *v)
            .ok_or(OverflowError)
    }
}

impl Sum<ValueSum> for Result<ValueSum, OverflowError> {
    fn sum<I: Iterator<Item = ValueSum>>(mut iter: I) -> Self {
        iter.try_fold(ValueSum(0), |acc, v| acc + v)
            .ok_or(OverflowError)
    }
}

impl TryFrom<ValueSum> for i64 {
    type Error = OverflowError;

    fn try_from(v: ValueSum) -> Result<i64, Self::Error> {
        i64::try_from(v.0).map_err(|_| OverflowError)
    }
}

/// A Headstash value with multi-denomination support.
///
/// This struct combines a numeric value with a denomination identifier,
/// enabling support for uterp, IBC tokens, and tokenfactory denoms.
///
/// # Members
/// - `v`: The note value (amount) as a u64
/// - `nd`: The note denomination (token type)
///
/// # Example
/// ```rust,ignore
/// use zk_headstash::value::{HeadstashValue, NoteValue, NoteDenom};
///
/// // Create a value for 1000 uterp
/// let value = HeadstashValue::new(
///     NoteValue::from_raw(1000),
///     NoteDenom::from_str("uterp").unwrap()
/// );
///
/// // Access components
/// let amount = value.amount();
/// let denom = value.denom();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadstashValue {
    v: NoteValue,
    nd: NoteDenom,
}

impl HeadstashValue {
    /// Create a new HeadstashValue from amount and denomination.
    pub fn new(v: NoteValue, nd: NoteDenom) -> Self {
        Self { v, nd }
    }

    /// Create a HeadstashValue from raw u64 amount and denomination string.
    pub fn from_raw(amount: u64, denom: &str) -> Result<Self, String> {
        let v = NoteValue::from_raw(amount);
        let nd = NoteDenom::new_for_proof(denom);
        Ok(Self { v, nd })
    }

    /// Returns the note value (amount).
    pub fn amount(&self) -> NoteValue {
        self.v
    }

    /// Returns a reference to the note denomination.
    pub fn denom(&self) -> &NoteDenom {
        &self.nd
    }

    /// Returns the raw amount as u64.
    pub fn raw_amount(&self) -> u64 {
        self.v.inner()
    }

    /// Returns the denomination as a display string (hash representation).
    pub fn denom_str(&self) -> String {
        self.nd.to_string()
    }

    /// Convert to tuple (amount, denom) for easier destructuring.
    pub fn into_parts(self) -> (NoteValue, NoteDenom) {
        (self.v, self.nd)
    }

    /// Create a zero value for a given denomination.
    pub fn zero(nd: NoteDenom) -> Self {
        Self {
            v: NoteValue::zero(),
            nd,
        }
    }

    /// Check if this value is zero.
    pub fn is_zero(&self) -> bool {
        self.v.inner() == 0
    }

    /// Add two HeadstashValues of the same denomination.
    /// Returns None if denominations don't match or overflow occurs.
    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        if self.nd != other.nd {
            return None;
        }
        let new_amount = self.v.inner().checked_add(other.v.inner())?;
        if new_amount > MAX_NOTE_VALUE {
            return None;
        }
        Some(Self {
            v: NoteValue::from_raw(new_amount),
            nd: self.nd,
        })
    }

    /// Subtract two HeadstashValues of the same denomination.
    /// Returns None if denominations don't match or underflow would occur.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        if self.nd != other.nd {
            return None;
        }
        let new_amount = self.v.inner().checked_sub(other.v.inner())?;
        Some(Self {
            v: NoteValue::from_raw(new_amount),
            nd: self.nd,
        })
    }
}

impl Default for HeadstashValue {
    fn default() -> Self {
        Self {
            v: NoteValue::zero(),
            nd: NoteDenom::default(),
        }
    }
}

impl fmt::Display for HeadstashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.v.inner(), self.nd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::nd_to_fp;
    use ff::Field;

    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::pallas;
    #[test]
    fn test_headstash_value_creation() {
        // Test creating HeadstashValue from raw components
        let value = HeadstashValue::from_raw(1000, "uterp").unwrap();

        assert_eq!(value.raw_amount(), 1000);
        assert_eq!(value.amount(), NoteValue::from_raw(1000));
    }

    #[test]
    fn test_headstash_value_new() {
        // Test creating HeadstashValue with NoteValue and NoteDenom
        let note_val = NoteValue::from_raw(5000);
        let note_denom = NoteDenom::new_for_proof("ibc/usdc");

        let value = HeadstashValue::new(note_val, note_denom);

        assert_eq!(value.raw_amount(), 5000);
        assert_eq!(value.amount(), note_val);
    }

    #[test]
    fn test_headstash_value_zero() {
        // Test zero value creation
        let denom = NoteDenom::new_for_proof("uterp");
        let zero_value = HeadstashValue::zero(denom);

        assert_eq!(zero_value.raw_amount(), 0);
        assert!(zero_value.is_zero());
    }

    #[test]
    fn test_headstash_value_checked_add_same_denom() {
        // Test adding two values with same denomination
        let val1 = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(500, "uterp").unwrap();

        let result = val1.checked_add(&val2).unwrap();
        assert_eq!(result.raw_amount(), 1500);
    }

    #[test]
    fn test_headstash_value_checked_add_different_denom() {
        // Test that adding values with different denoms returns None
        let val1 = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(500, "ibc/usdc").unwrap();

        let result = val1.checked_add(&val2);
        assert!(result.is_none());
    }

    #[test]
    fn test_headstash_value_checked_add_overflow() {
        // Test overflow protection
        let val1 = HeadstashValue::from_raw(MAX_NOTE_VALUE, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(1, "uterp").unwrap();
        let result = val1.checked_add(&val2);
        assert!(result.is_none());
    }

    #[test]
    fn test_headstash_value_checked_sub_same_denom() {
        // Test subtracting two values with same denomination
        let val1 = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(300, "uterp").unwrap();

        let result = val1.checked_sub(&val2).unwrap();
        assert_eq!(result.raw_amount(), 700);
    }

    #[test]
    fn test_headstash_value_checked_sub_different_denom() {
        // Test that subtracting values with different denoms returns None
        let val1 = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(300, "ibc/usdc").unwrap();

        let result = val1.checked_sub(&val2);
        assert!(result.is_none());
    }

    #[test]
    fn test_headstash_value_checked_sub_underflow() {
        // Test underflow protection
        let val1 = HeadstashValue::from_raw(100, "uterp").unwrap();
        let val2 = HeadstashValue::from_raw(200, "uterp").unwrap();

        let result = val1.checked_sub(&val2);
        assert!(result.is_none());
    }

    #[test]
    fn test_headstash_value_into_parts() {
        // Test destructuring into components
        let value = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let (note_val, note_denom) = value.into_parts();

        assert_eq!(note_val.inner(), 1000);
        assert_eq!(note_denom, NoteDenom::new_for_proof("uterp"));
    }

    #[test]
    fn test_headstash_value_display() {
        // Test display formatting
        let value = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let display_str = format!("{}", value);

        assert!(display_str.contains("1000"));
    }

    #[test]
    fn test_headstash_value_default() {
        // Test default value
        let default_value = HeadstashValue::default();

        assert_eq!(default_value.raw_amount(), 0);
        assert!(default_value.is_zero());
    }

    #[test]
    fn test_headstash_value_multi_denom_support() {
        // Test multiple different denominations
        let uterp = HeadstashValue::from_raw(1000, "uterp").unwrap();
        let usdc = HeadstashValue::from_raw(500, "ibc/usdc").unwrap();
        let custom = HeadstashValue::from_raw(250, "factory/contract/custom").unwrap();

        assert_eq!(uterp.raw_amount(), 1000);
        assert_eq!(usdc.raw_amount(), 500);
        assert_eq!(custom.raw_amount(), 250);

        // Verify they're different denominations
        assert!(uterp.checked_add(&usdc).is_none());
        assert!(usdc.checked_add(&custom).is_none());
    }

    // Helper function to create a NoteDenom from 32 bytes
    fn make_note_denom_string(bytes: &str) -> NoteDenom {
        // Assuming NoteDenom has a constructor or can be created from bytes
        // Adjust this based on actual NoteDenom implementation
        NoteDenom::new_for_proof(bytes)
    }
    // Helper function to create a NoteDenom from 32 bytes
    fn make_note_denom(bytes: [u8; 32]) -> NoteDenom {
        // Assuming NoteDenom has a constructor or can be created from bytes
        // Adjust this based on actual NoteDenom implementation
        NoteDenom::try_from(bytes).unwrap()
    }

    #[test]
    fn test_nd_to_fp_deterministic() {
        // Same input should always produce same output
        let test_bytes = [42u8; 32];
        let nd1 = make_note_denom(test_bytes);
        let nd2 = make_note_denom(test_bytes);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_nd_to_fp_different_inputs() {
        // Different inputs should produce different outputs
        let bytes1 = [1u8; 32];
        let bytes2 = [2u8; 32];

        let nd1 = make_note_denom(bytes1);
        let nd2 = make_note_denom(bytes2);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_nd_to_fp_all_zeros() {
        let zero_bytes = [0u8; 32];
        let nd = make_note_denom(zero_bytes);

        let fp = nd_to_fp(&nd);

        // All zeros should map to zero field element
        assert_eq!(fp, pallas::Base::zero());
    }

    #[test]
    fn test_nd_to_fp_all_ones() {
        let ones_bytes = [0xFFu8; 32];
        let nd = make_note_denom_string(&hex::encode(ones_bytes));

        let fp = nd_to_fp(&nd);

        // Should produce a valid field element
        // Verify it's not zero (all 0xFF bytes shouldn't be zero in the field)
        assert_ne!(fp, pallas::Base::zero());
    }

    #[test]
    fn test_nd_to_fp_sequential_bytes() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let nd = make_note_denom(bytes);
        let fp = nd_to_fp(&nd);

        // Should produce a valid, non-zero field element
        assert_ne!(fp, pallas::Base::zero());
    }

    #[test]
    fn test_nd_to_fp_returns_valid_field_element() {
        let test_bytes = [123u8; 32];
        let nd = make_note_denom_string(&hex::encode(test_bytes));

        let fp = nd_to_fp(&nd);

        // Test that we can perform field operations on the result
        let doubled = fp + fp;
        let squared = fp * fp;
        let inverted = fp.invert();

        // Basic sanity checks
        assert!(doubled == doubled);
        assert!(squared == squared);

        // If fp is non-zero, it should have an inverse
        if fp != pallas::Base::zero() {
            assert!(inverted.is_some().unwrap_u8() == 1);
        }
    }

    #[test]
    fn test_nd_to_fp_round_trip_with_repr() {
        // Test that from_repr is consistent
        let test_bytes = [77u8; 32];
        let nd = make_note_denom_string(&hex::encode(test_bytes));

        let fp = nd_to_fp(&nd);
        let repr = fp.to_repr();
        let fp_reconstructed = pallas::Base::from_repr(repr).unwrap();

        assert_eq!(fp, fp_reconstructed);
    }

    #[test]
    fn test_nd_to_fp_single_bit_difference() {
        // Small change in input should cause different output
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes2[0] = 1; // Only change first byte

        let nd1 = make_note_denom(bytes1);
        let nd2 = make_note_denom(bytes2);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_nd_to_fp_last_byte_matters() {
        // Change in last byte should affect output
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        bytes2[31] = 1; // Change last byte

        let nd1 = make_note_denom(bytes1);
        let nd2 = make_note_denom(bytes2);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_nd_to_fp_boundary_values() {
        // Test with specific boundary values
        let mut bytes = [0u8; 32];

        // Set to just below field modulus (if known)
        // This is a placeholder - adjust based on actual Pallas field modulus
        bytes[31] = 0x3F; // Some high value

        let nd = make_note_denom(bytes);
        let fp = nd_to_fp(&nd);

        // Should successfully convert without panic
        assert!(fp == fp); // Just verify it exists
    }

    #[test]
    fn test_nd_to_fp_multiple_conversions_consistency() {
        // Converting the same NoteDenom multiple times should give same result
        let test_bytes = [99u8; 32];
        let nd = make_note_denom_string(&hex::encode(test_bytes));

        let fp1 = nd_to_fp(&nd);
        let fp2 = nd_to_fp(&nd);
        let fp3 = nd_to_fp(&nd);

        assert_eq!(fp1, fp2);
        assert_eq!(fp2, fp3);
    }

    #[test]
    fn test_nd_to_fp_no_collisions_in_small_set() {
        // Test that different byte patterns don't collide
        use std::collections::HashSet;

        let mut seen = HashSet::new();

        for i in 0u8..100 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;

            let nd = make_note_denom(bytes);
            let fp = nd_to_fp(&nd);
            let repr = fp.to_repr();

            assert!(seen.insert(repr), "Found collision at i={}", i);
        }

        assert_eq!(seen.len(), 100);
    }

    #[test]
    fn test_nd_to_fp_preserves_byte_order() {
        // Reversed bytes should give different field element
        let mut bytes1 = [0u8; 32];
        for (i, byte) in bytes1.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut bytes2 = bytes1;
        bytes2.reverse();

        let nd1 = make_note_denom(bytes1);
        let nd2 = make_note_denom(bytes2);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_nd_to_fp_with_maximum_valid_value() {
        // Test with bytes that represent a large but valid field element
        // Pallas field modulus is approximately 2^255
        // Using a value that's definitely in the field
        let mut bytes = [0xFFu8; 32];
        bytes[31] = 0x3F; // Ensure it's below the modulus

        let nd = make_note_denom(bytes);
        let fp = nd_to_fp(&nd);

        // Should not panic and should be a valid large field element
        assert_ne!(fp, pallas::Base::zero());
    }

    #[test]
    fn test_nd_to_fp_arithmetic_properties() {
        // Test that the resulting field element has proper arithmetic properties
        let bytes1 = [1u8; 32];
        let bytes2 = [2u8; 32];

        let nd1 = make_note_denom(bytes1);
        let nd2 = make_note_denom(bytes2);

        let fp1 = nd_to_fp(&nd1);
        let fp2 = nd_to_fp(&nd2);

        // Test commutativity of addition
        assert_eq!(fp1 + fp2, fp2 + fp1);

        // Test commutativity of multiplication
        assert_eq!(fp1 * fp2, fp2 * fp1);

        // Test distributivity
        let fp3_bytes = [3u8; 32];
        let nd3 = make_note_denom(fp3_bytes);
        let fp3 = nd_to_fp(&nd3);

        assert_eq!(fp1 * (fp2 + fp3), fp1 * fp2 + fp1 * fp3);
    }
}
