use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use core::fmt::{self, Debug};
use core::iter::Sum;
use core::ops::{Add, RangeInclusive, Sub};
use halo2_proofs::plonk::Assigned;
use pasta_curves::pallas;

/// Maximum note value.
pub const MAX_NOTE_VALUE: u64 = u64::MAX;
pub const MAX_DENOM_LEN: usize = 128;

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
    len: u8, // stored as `u8` because `MAX_DENOM_LEN <= 255`
}

impl NoteDenom {
    /// Return the stored string as `&str`.
    pub fn as_str(&self) -> &str {
        // SAFETY: we only ever construct a `NoteDenom` from a valid UTF‑8
        // string (see `FromStr`), so this slice is always valid.
        let slice = &self.bytes[..self.len as usize];
        std::str::from_utf8(slice).expect("invalid UTF‑8 in NoteDenom")
    }

    /// Return the raw bytes (including unused trailing zeros).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
    /// Return the raw bytes (including unused trailing zeros).
    pub fn max_len() -> usize {
        MAX_DENOM_LEN
    }
    /// Return the raw bytes (including unused trailing zeros).
    pub fn len_inner(&self) -> usize {
        self.len as usize
    }
}

impl Default for NoteDenom {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_DENOM_LEN],
            len: 0,
        }
    }
}

// ---------------------------------------------------------------------
// Pretty‑printing (e.g. with `println!("{:?}", denom)` or `format!`)
impl fmt::Display for NoteDenom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------
// Parsing from a CLI string
impl std::str::FromStr for NoteDenom {
    type Err = String; // simple error type; change to a custom error if desired

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() > MAX_DENOM_LEN {
            return Err(format!(
                "denomination too long (max {} bytes): {}",
                MAX_DENOM_LEN, s
            ));
        }

        let mut arr = [0u8; MAX_DENOM_LEN];
        arr[..bytes.len()].copy_from_slice(bytes);

        Ok(NoteDenom {
            bytes: arr,
            len: bytes.len() as u8,
        })
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
