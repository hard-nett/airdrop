use aes::Aes256;
use core2::io::{self, Read, Write};
use ff::PrimeField;
use fpe::ff1::{BinaryNumeralString, FF1};
use group::GroupEncoding;
use jubjub::Scalar;
use pasta_curves::pallas;
use rand::RngCore;
use redjubjub::*;
use std::error::Error;
use subtle::{Choice, ConditionallySelectable, CtOption};
use zip32::{AccountId, DiversifierIndex};

use crate::prf_expand::PrfExpand;
use crate::spec::{
    NonIdentityPallasPoint, NonZeroPallasBase, NonZeroPallasScalar, PreparedNonIdentityBase,
    diversify_hash, extract_p, hkdr_jubjub, ka_orchard_prepared, prf_nf, to_base,
};

#[derive(Debug, Copy, Clone)]
pub struct EligibleSk(pub secp256k1::SecretKey);

impl EligibleSk {
    pub fn from_sk(sk: secp256k1::SecretKey) -> Self {
        Self(sk)
    }
    /// Build an `EligibleSk` from a hex string that represents a 32‑byte SECP‑256k1 secret key.
    ///
    /// # Example
    /// ```rust
    /// let sk = EligibleSk::new_from_sk("1a2b3c…"); // 64‑char hex
    /// ```
    ///
    /// The function will `panic!` if the string is not a valid 32‑byte hex value.
    /// Replace the `expect`/`panic!` with proper error handling if you need it.

    pub fn from_hex(hex_str: &str) -> Self {
        // 1️⃣ Decode the hex string into raw bytes (expect exactly 32 bytes).
        let bytes: [u8; 32] = hex_str
            .as_bytes()
            .try_into()
            .expect("slice conversion to [u8;32] should never fail");

        // 3️⃣ Convert the byte slice into a `SecretKey`.
        // `SecretKey::from_slice` returns a Result; we unwrap because the HKDF
        // mask guarantees the scalar is valid – adjust if you want graceful errors.
        let secp_sk = secp256k1::SecretKey::from_byte_array(bytes)
            .expect("invalid secp256k1 secret key material");

        // 4️⃣ Wrap and return.
        Self(secp_sk)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct JubJubKey(pub redjubjub::SigningKey<Binding>);

impl JubJubKey {
    pub fn derive_from_elig_sk(elig_sk: EligibleSk) -> Self {
        let ak: [u8; 32] = *elig_sk.0.as_ref();
        let scalar: Scalar = hkdr_jubjub(ak);
        let scalar_bytes: [u8; 32] = scalar.into();
        let signing_key = SigningKey::<Binding>::try_from(scalar_bytes)
            .expect("derived scalar must be a valid JubJub signing key");
        Self(signing_key)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct JubJubSignature(redjubjub::Signature<Binding>);

/// A spending key, from which all key material is derived.
///
/// $\mathsf{sk}$ as defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
#[derive(Debug, Copy, Clone)]
pub struct SpendingKey([u8; 32]);

impl subtle::ConstantTimeEq for SpendingKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(other.to_bytes())
    }
}

impl SpendingKey {
    /// Generates a random spending key.
    ///
    /// This is only used when generating dummy notes. Real spending keys should be
    /// derived according to [ZIP 32].
    ///
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub(crate) fn random(rng: &mut impl RngCore) -> Self {
        loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let sk = SpendingKey::from_bytes(bytes);
            if sk.is_some().into() {
                break sk.unwrap();
            }
        }
    }

    /// Constructs an Orchard spending key from uniformly-random bytes.
    ///
    /// Returns `None` if the bytes do not correspond to a valid Orchard spending key.
    pub fn from_bytes(sk: [u8; 32]) -> CtOption<Self> {
        let sk = SpendingKey(sk);
        // If ask = 0, discard this key. We call `derive_inner` rather than
        // `SpendAuthorizingKey::from` here because we only need to know
        // whether ask = 0; the adjustment to potentially negate ask is not
        // needed. Also, `from` would panic on ask = 0.
        // let ask = SpendAuthorizingKey::derive_inner(&sk);
        // If ivk is 0 or ⊥, discard this key.
        // let fvk = (&sk).into();
        // let external_ivk = KeyAgreementPrivateKey::derive_inner(&fvk);
        // let internal_ivk = KeyAgreementPrivateKey::derive_inner(&fvk.derive_internal());
        CtOption::new(
            sk,
            1.into(),
            // !(ask.is_zero() | external_ivk.is_none() | internal_ivk.is_none()),
        )
    }

    /// Returns the raw bytes of the spending key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    ///// Derives the Orchard spending key for the given seed, coin type, and account.
    // pub fn from_zip32_seed(
    //     seed: &[u8],
    //     coin_type: u32,
    //     account: AccountId,
    // ) -> Result<Self, zip32::Error> {
    //     if coin_type >= (1 << 31) {
    //         return Err(zip32::Error::InvalidChildIndex(coin_type));
    //     }

    //     // Call zip32 logic
    //     let path = &[
    //         ChildIndex::hardened(ZIP32_PURPOSE),
    //         ChildIndex::hardened(coin_type),
    //         ChildIndex::hardened(account.into()),
    //     ];
    //     ExtendedSpendingKey::from_path(seed, path).map(|esk| esk.sk())
    // }
}

/// A key used to derive [`Nullifier`]s from [`Note`]s.
///
/// $\mathsf{nk}$ as defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [`Nullifier`]: crate::note::Nullifier
/// [`Note`]: crate::note::Note
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NullifierDerivingKey(pallas::Base);

impl NullifierDerivingKey {
    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl NullifierDerivingKey {
    pub fn prf_nf(&self, rho: pallas::Base) -> pallas::Base {
        prf_nf(self.0, rho)
    }

    /// Converts this nullifier deriving key to its serialized form.
    pub fn to_bytes(self) -> [u8; 32] {
        <[u8; 32]>::from(self.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let nk_bytes = <[u8; 32]>::try_from(bytes).ok()?;
        let nk = pallas::Base::from_repr(nk_bytes).map(NullifierDerivingKey);
        if nk.is_some().into() {
            Some(nk.unwrap())
        } else {
            None
        }
    }
}

impl From<&SpendingKey> for NullifierDerivingKey {
    fn from(sk: &SpendingKey) -> Self {
        NullifierDerivingKey(to_base(PrfExpand::ORCHARD_NK.with(&sk.0)))
    }
}

// /// A key that provides the capability to derive a sequence of diversifiers.
// ///
// /// $\mathsf{dk}$ as defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
// pub(crate) struct DiversifierKey([u8; 32]);

// impl DiversifierKey {
//     /// Returns the diversifier at the given index.
//     pub fn get(&self, j: impl Into<DiversifierIndex>) -> Diversifier {
//         let ff = FF1::<Aes256>::new(&self.0, 2).expect("valid radix");
//         let enc = ff
//             .encrypt(
//                 &[],
//                 &BinaryNumeralString::from_bytes_le(j.into().as_bytes()),
//             )
//             .unwrap();
//         Diversifier(enc.to_bytes_le().try_into().unwrap())
//     }

//     /// Returns the diversifier index obtained by decrypting the diversifier.
//     pub fn diversifier_index(&self, d: &Diversifier) -> DiversifierIndex {
//         let ff = FF1::<Aes256>::new(&self.0, 2).expect("valid radix");
//         let dec = ff
//             .decrypt(&[], &BinaryNumeralString::from_bytes_le(d.as_array()))
//             .unwrap();
//         DiversifierIndex::from(<[u8; 11]>::try_from(dec.to_bytes_le()).unwrap())
//     }

//     /// Return the raw bytes of the diversifier key
//     pub fn to_bytes(&self) -> &[u8; 32] {
//         &self.0
//     }

//     /// Construct a diversifier key from bytes
//     pub fn from_bytes(bytes: [u8; 32]) -> Self {
//         DiversifierKey(bytes)
//     }
// }

/// A key that provides the capability to view incoming and outgoing transactions.
///
/// This key is useful anywhere you need to maintain accurate balance, but do not want the
/// ability to spend funds (such as a view-only wallet).
///
/// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
///
/// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FullViewingKey {
    // ak: SpendValidatingKey,
    nk: NullifierDerivingKey,
    // rivk: CommitIvkRandomness,
}

impl From<&SpendingKey> for FullViewingKey {
    fn from(sk: &SpendingKey) -> Self {
        FullViewingKey {
            // ak: (&SpendAuthorizingKey::from(sk)).into(),
            nk: sk.into(),
            // rivk: sk.into(),
        }
    }
}

// impl From<&ExtendedSpendingKey> for FullViewingKey {
//     fn from(extsk: &ExtendedSpendingKey) -> Self {
//         (&extsk.sk()).into()
//     }
// }

// impl From<FullViewingKey> for SpendValidatingKey {
//     fn from(fvk: FullViewingKey) -> Self {
//         fvk.ak
//     }
// }

// /// A key used to validate spend authorization signatures.
// ///
// /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// /// Note that this is $\mathsf{ak}^\mathbb{P}$, which by construction is equivalent to
// /// $\mathsf{ak}$ but stored here as a RedPallas verification key.
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// #[derive(Debug, Clone, PartialOrd, Ord)]
// pub struct SpendValidatingKey(redpallas::VerificationKey<SpendAuth>);

// impl From<&SpendAuthorizingKey> for SpendValidatingKey {
//     fn from(ask: &SpendAuthorizingKey) -> Self {
//         SpendValidatingKey((&ask.0).into())
//     }
// }

// impl From<&SpendValidatingKey> for pallas::Point {
//     fn from(spend_validating_key: &SpendValidatingKey) -> pallas::Point {
//         pallas::Point::from_bytes(&(&spend_validating_key.0).into()).unwrap()
//     }
// }

// impl PartialEq for SpendValidatingKey {
//     fn eq(&self, other: &Self) -> bool {
//         <[u8; 32]>::from(&self.0).eq(&<[u8; 32]>::from(&other.0))
//     }
// }

// impl Eq for SpendValidatingKey {}

// impl SpendValidatingKey {
//     /// Randomizes this spend validating key with the given `randomizer`.
//     pub fn randomize(&self, randomizer: &pallas::Scalar) -> redpallas::VerificationKey<SpendAuth> {
//         self.0.randomize(randomizer)
//     }

//     /// Converts this spend validating key to its serialized form,
//     /// I2LEOSP_256(ak).
//     #[cfg_attr(feature = "unstable-frost", visibility::make(pub))]
//     pub(crate) fn to_bytes(&self) -> [u8; 32] {
//         // This is correct because the wrapped point must have ỹ = 0, and
//         // so the point repr is the same as I2LEOSP of its x-coordinate.
//         let b = <[u8; 32]>::from(&self.0);
//         assert!(b[31] & 0x80 == 0);
//         b
//     }

//     /// Attempts to parse a byte slice as a spend validating key, `I2LEOSP_256(ak)`.
//     ///
//     /// Returns `None` if the given slice does not contain a valid spend validating key.
//     #[cfg_attr(feature = "unstable-frost", visibility::make(pub))]
//     pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
//         <[u8; 32]>::try_from(bytes)
//             .ok()
//             .and_then(|b| {
//                 // Structural validity checks for ak_P:
//                 // - The point must not be the identity
//                 //   (which for Pallas is canonically encoded as all-zeroes).
//                 // - The sign of the y-coordinate must be positive.
//                 if b != [0; 32] && b[31] & 0x80 == 0 {
//                     <redpallas::VerificationKey<SpendAuth>>::try_from(b).ok()
//                 } else {
//                     None
//                 }
//             })
//             .map(SpendValidatingKey)
//     }
// }

impl FullViewingKey {
    pub(crate) fn nk(&self) -> &NullifierDerivingKey {
        &self.nk
    }

    // /// Returns either `rivk` or `rivk_internal` based on `scope`.
    // pub(crate) fn rivk(&self, scope: Scope) -> CommitIvkRandomness {
    //     match scope {
    //         Scope::External => self.rivk,
    //         Scope::Internal => {
    //             let k = self.rivk.0.to_repr();
    //             let ak = self.ak.to_bytes();
    //             let nk = self.nk.to_bytes();
    //             CommitIvkRandomness(to_scalar(
    //                 PrfExpand::ORCHARD_RIVK_INTERNAL.with(&k, &ak, &nk),
    //             ))
    //         }
    //     }
    // }

    //     /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
    //     ///
    //     /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
    //     fn derive_dk_ovk(&self) -> (DiversifierKey, OutgoingViewingKey) {
    //         let k = self.rivk.0.to_repr();
    //         let b = [(&self.ak.0).into(), self.nk.0.to_repr()];
    //         let r = PrfExpand::ORCHARD_DK_OVK.with(&k, &b[0], &b[1]);
    //         (
    //             DiversifierKey(r[..32].try_into().unwrap()),
    //             OutgoingViewingKey(r[32..].try_into().unwrap()),
    //         )
    //     }

    //     /// Returns the payment address for this key at the given index.
    //     pub fn address_at(&self, j: impl Into<DiversifierIndex>, scope: Scope) -> Address {
    //         self.to_ivk(scope).address_at(j)
    //     }

    //     /// Returns the payment address for this key corresponding to the given diversifier.
    //     pub fn address(&self, d: Diversifier, scope: Scope) -> Address {
    //         // Shortcut: we don't need to derive DiversifierKey.
    //         match scope {
    //             Scope::External => KeyAgreementPrivateKey::from_fvk(self),
    //             Scope::Internal => KeyAgreementPrivateKey::from_fvk(&self.derive_internal()),
    //         }
    //         .address(d)
    //     }

    //     /// Returns the scope of the given address, or `None` if the address is not derived
    //     /// from this full viewing key.
    //     pub fn scope_for_address(&self, address: &Address) -> Option<Scope> {
    //         [Scope::External, Scope::Internal]
    //             .into_iter()
    //             .find(|scope| self.to_ivk(*scope).diversifier_index(address).is_some())
    //     }

    //     /// Serializes the full viewing key as specified in [Zcash Protocol Spec § 5.6.4.4: Orchard Raw Full Viewing Keys][orchardrawfullviewingkeys]
    //     ///
    //     /// [orchardrawfullviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardfullviewingkeyencoding
    //     pub fn write<W: std::fmt::Write>(&self, mut writer: W) -> io::Result<()> {
    //         writer.write_all(&self.to_bytes())
    //     }

    //     /// Parses a full viewing key from its "raw" encoding as specified in [Zcash Protocol Spec § 5.6.4.4: Orchard Raw Full Viewing Keys][orchardrawfullviewingkeys]
    //     ///
    //     /// [orchardrawfullviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardfullviewingkeyencoding
    //     pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
    //         let mut data = [0u8; 96];
    //         reader.read_exact(&mut data)?;

    //         Self::from_bytes(&data).ok_or_else(|| {
    //             io::Error::new(
    //                 io::ErrorKind::InvalidInput,
    //                 "Unable to deserialize a valid Orchard FullViewingKey from bytes",
    //             )
    //         })
    //     }

    //     /// Serializes the full viewing key as specified in [Zcash Protocol Spec § 5.6.4.4: Orchard Raw Full Viewing Keys][orchardrawfullviewingkeys]
    //     ///
    //     /// [orchardrawfullviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardfullviewingkeyencoding
    //     pub fn to_bytes(&self) -> [u8; 96] {
    //         let mut result = [0u8; 96];
    //         result[0..32].copy_from_slice(&<[u8; 32]>::from(self.ak.0.clone()));
    //         result[32..64].copy_from_slice(&self.nk.0.to_repr());
    //         result[64..96].copy_from_slice(&self.rivk.0.to_repr());
    //         result
    //     }

    //     /// Parses a full viewing key from its "raw" encoding as specified in [Zcash Protocol Spec § 5.6.4.4: Orchard Raw Full Viewing Keys][orchardrawfullviewingkeys]
    //     ///
    //     /// [orchardrawfullviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardfullviewingkeyencoding
    //     pub fn from_bytes(bytes: &[u8; 96]) -> Option<Self> {
    //         let ak = SpendValidatingKey::from_bytes(&bytes[..32])?;
    //         let nk = NullifierDerivingKey::from_bytes(&bytes[32..64])?;
    //         let rivk = CommitIvkRandomness::from_bytes(&bytes[64..])?;

    //         let fvk = FullViewingKey { ak, nk, rivk };

    //         // If either ivk is 0 or ⊥, this FVK is invalid.
    //         let _: NonZeroPallasBase = Option::from(KeyAgreementPrivateKey::derive_inner(&fvk))?;
    //         let _: NonZeroPallasBase =
    //             Option::from(KeyAgreementPrivateKey::derive_inner(&fvk.derive_internal()))?;

    //         Some(fvk)
    //     }

    //     /// Derives an internal full viewing key from a full viewing key, as specified in
    //     /// [ZIP32][orchardinternalfullviewingkey]. Internal use only.
    //     ///
    //     /// [orchardinternalfullviewingkey]: https://zips.z.cash/zip-0032#orchard-internal-key-derivation
    //     fn derive_internal(&self) -> Self {
    //         FullViewingKey {
    //             ak: self.ak.clone(),
    //             nk: self.nk,
    //             rivk: self.rivk(Scope::Internal),
    //         }
    //     }

    //     /// Derives an `IncomingViewingKey` for this full viewing key.
    //     pub fn to_ivk(&self, scope: Scope) -> IncomingViewingKey {
    //         match scope {
    //             Scope::External => IncomingViewingKey::from_fvk(self),
    //             Scope::Internal => IncomingViewingKey::from_fvk(&self.derive_internal()),
    //         }
    //     }

    //     /// Derives an `OutgoingViewingKey` for this full viewing key.
    //     pub fn to_ovk(&self, scope: Scope) -> OutgoingViewingKey {
    //         match scope {
    //             Scope::External => OutgoingViewingKey::from_fvk(self),
    //             Scope::Internal => OutgoingViewingKey::from_fvk(&self.derive_internal()),
    //         }
    //     }
}

// /// A key that provides the capability to detect and decrypt incoming notes from the block
// /// chain, without being able to spend the notes or detect when they are spent.
// ///
// /// This key is useful in situations where you only need the capability to detect inbound
// /// payments, such as merchant terminals.
// ///
// /// This key is not suitable for use on its own in a wallet, as it cannot maintain
// /// accurate balance. You should use a [`FullViewingKey`] instead.
// ///
// /// Defined in [Zcash Protocol Spec § 5.6.4.3: Orchard Raw Incoming Viewing Keys][orchardinviewingkeyencoding].
// ///
// /// [orchardinviewingkeyencoding]: https://zips.z.cash/protocol/nu5.pdf#orchardinviewingkeyencoding
// #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
// pub struct IncomingViewingKey {
//     dk: DiversifierKey,
//     ivk: KeyAgreementPrivateKey,
// }

// impl IncomingViewingKey {
//     /// Helper method.
//     fn from_fvk(fvk: &FullViewingKey) -> Self {
//         IncomingViewingKey {
//             dk: fvk.derive_dk_ovk().0,
//             ivk: KeyAgreementPrivateKey::from_fvk(fvk),
//         }
//     }
// }

// impl IncomingViewingKey {
//     /// Serializes an Orchard incoming viewing key to its raw encoding as specified in [Zcash Protocol Spec § 5.6.4.3: Orchard Raw Incoming Viewing Keys][orchardrawinviewingkeys]
//     ///
//     /// [orchardrawinviewingkeys]: https://zips.z.cash/protocol/protocol.pdf#orchardinviewingkeyencoding
//     pub fn to_bytes(&self) -> [u8; 64] {
//         let mut result = [0u8; 64];
//         result[..32].copy_from_slice(self.dk.to_bytes());
//         result[32..].copy_from_slice(&self.ivk.0.to_repr());
//         result
//     }

//     /// Parses an Orchard incoming viewing key from its raw encoding.
//     pub fn from_bytes(bytes: &[u8; 64]) -> CtOption<Self> {
//         NonZeroPallasBase::from_bytes(bytes[32..].try_into().unwrap()).map(|ivk| {
//             IncomingViewingKey {
//                 dk: DiversifierKey(bytes[..32].try_into().unwrap()),
//                 ivk: KeyAgreementPrivateKey(ivk.into()),
//             }
//         })
//     }

//     /// Checks whether the given address was derived from this incoming viewing
//     /// key, and returns the diversifier index used to derive the address if
//     /// so. Returns `None` if the address was not derived from this key.
//     pub fn diversifier_index(&self, addr: &Address) -> Option<DiversifierIndex> {
//         let j = self.dk.diversifier_index(&addr.diversifier());
//         if &self.address_at(j) == addr {
//             Some(j)
//         } else {
//             None
//         }
//     }

//     /// Returns the payment address for this key at the given index.
//     pub fn address_at(&self, j: impl Into<DiversifierIndex>) -> Address {
//         self.address(self.dk.get(j))
//     }

//     /// Returns the payment address for this key corresponding to the given diversifier.
//     pub fn address(&self, d: Diversifier) -> Address {
//         self.ivk.address(d)
//     }

//     /// Returns the [`PreparedIncomingViewingKey`] for this [`IncomingViewingKey`].
//     pub fn prepare(&self) -> PreparedIncomingViewingKey {
//         PreparedIncomingViewingKey::new(self)
//     }
// }

// /// A diversifier that can be used to derive a specific [`Address`] from a
// /// [`FullViewingKey`] or [`IncomingViewingKey`].
// ///
// /// $\mathsf{d}$ as defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// #[derive(Clone, Copy, Debug, PartialEq, Eq)]
// pub struct Diversifier([u8; 11]);

// impl Diversifier {
//     /// Reads a diversifier from a byte array.
//     pub fn from_bytes(d: [u8; 11]) -> Self {
//         Diversifier(d)
//     }

//     /// Returns the byte array corresponding to this diversifier.
//     pub fn as_array(&self) -> &[u8; 11] {
//         &self.0
//     }
// }

// /// An Orchard incoming viewing key that has been precomputed for trial decryption.
// #[derive(Clone, Debug)]
// pub struct PreparedIncomingViewingKey(PreparedNonZeroScalar);

// #[cfg(feature = "std")]
// impl memuse::DynamicUsage for PreparedIncomingViewingKey {
//     fn dynamic_usage(&self) -> usize {
//         self.0.dynamic_usage()
//     }

//     fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
//         self.0.dynamic_usage_bounds()
//     }
// }

// impl PreparedIncomingViewingKey {
//     /// Performs the necessary precomputations to use an `IncomingViewingKey` for note
//     /// decryption.
//     pub fn new(ivk: &IncomingViewingKey) -> Self {
//         Self::new_inner(&ivk.ivk)
//     }

//     fn new_inner(ivk: &KeyAgreementPrivateKey) -> Self {
//         Self(PreparedNonZeroScalar::new(&ivk.0))
//     }
// }

// /// The private key $\mathsf{ivk}$ used in $KA^{Orchard}$, for decrypting incoming notes.
// ///
// /// In Sapling this is what was encoded as an incoming viewing key. For Orchard, we store
// /// both this and [`DiversifierKey`] inside [`IncomingViewingKey`] for usability (to
// /// enable deriving the default address for an incoming viewing key), while this separate
// /// type represents $\mathsf{ivk}$.
// ///
// /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// ///
// /// # Implementation notes
// ///
// /// We store $\mathsf{ivk}$ in memory as a scalar instead of a base, so that we aren't
// /// incurring an expensive serialize-and-parse step every time we use it (e.g. for trial
// /// decryption of notes). When we actually want to serialize ivk, we're guaranteed to get
// /// a valid base field element encoding, because we always construct ivk from an integer
// /// in the correct range.
// #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
// struct KeyAgreementPrivateKey(NonZeroPallasScalar);

// impl KeyAgreementPrivateKey {
//     /// Derives `KeyAgreementPrivateKey` from fvk.
//     ///
//     /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
//     ///
//     /// [orchardkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#orchardkeycomponents
//     fn from_fvk(fvk: &FullViewingKey) -> Self {
//         // FullViewingKey cannot be constructed such that this unwrap would fail.
//         let ivk = KeyAgreementPrivateKey::derive_inner(fvk).unwrap();
//         KeyAgreementPrivateKey(ivk.into())
//     }
// }

// impl KeyAgreementPrivateKey {
//     /// Derives ivk from fvk. Internal use only, does not enforce all constraints.
//     ///
//     /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
//     ///
//     /// [orchardkeycomponents]: https://zips.z.cash/protocol/protocol.pdf#orchardkeycomponents
//     fn derive_inner(fvk: &FullViewingKey) -> CtOption<NonZeroPallasBase> {
//         let ak = extract_p(&pallas::Point::from_bytes(&(&fvk.ak.0).into()).unwrap());
//         commit_ivk(&ak, &fvk.nk.0, &fvk.rivk.0)
//             // sinsemilla::CommitDomain::short_commit returns a value in range
//             // [0..q_P] ∪ {⊥}:
//             // - sinsemilla::HashDomain::hash_to_point uses incomplete addition and
//             //   returns a point in P* ∪ {⊥}.
//             // - sinsemilla::CommitDomain::commit applies a final complete addition step
//             //   and returns a point in P ∪ {⊥}.
//             // - 0 is not a valid x-coordinate for any Pallas point.
//             // - sinsemilla::CommitDomain::short_commit calls extract_p_bottom, which
//             //   replaces the identity (which has no affine coordinates) with 0.
//             //
//             // Commit^ivk.Output is specified as [1..q_P] ∪ {⊥}, so we explicitly check
//             // for 0 and map it to None. Note that we are collapsing this case (which is
//             // rejected by the circuit) with ⊥ (which the circuit explicitly allows for
//             // efficiency); this is fine because we don't want users of the `orchard`
//             // crate to encounter either case (and it matches the behaviour described in
//             // Section 4.2.3 of the protocol spec when generating spending keys).
//             .and_then(NonZeroPallasBase::from_base)
//     }

//     /// Returns the payment address for this key corresponding to the given diversifier.
//     fn address(&self, d: Diversifier) -> Address {
//         let prepared_ivk = PreparedIncomingViewingKey::new_inner(self);
//         let pk_d = DiversifiedTransmissionKey::derive(&prepared_ivk, &d);
//         Address::from_parts(d, pk_d)
//     }
// }

// /// A key that provides the capability to recover outgoing transaction information from
// /// the block chain.
// ///
// /// This key is not suitable for use on its own in a wallet, as it cannot maintain
// /// accurate balance. You should use a [`FullViewingKey`] instead.
// ///
// /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// #[derive(Debug, Clone)]
// pub struct OutgoingViewingKey([u8; 32]);

// impl OutgoingViewingKey {
//     /// Helper method.
//     fn from_fvk(fvk: &FullViewingKey) -> Self {
//         fvk.derive_dk_ovk().1
//     }
// }

// impl From<[u8; 32]> for OutgoingViewingKey {
//     fn from(ovk: [u8; 32]) -> Self {
//         OutgoingViewingKey(ovk)
//     }
// }

// impl AsRef<[u8; 32]> for OutgoingViewingKey {
//     fn as_ref(&self) -> &[u8; 32] {
//         &self.0
//     }
// }

// /// The diversified transmission key for a given payment address.
// ///
// /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
// ///
// /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
// #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
// pub struct DiversifiedTransmissionKey(NonIdentityPallasPoint);

// impl DiversifiedTransmissionKey {
//     pub(crate) fn inner(&self) -> NonIdentityPallasPoint {
//         self.0
//     }
// }

// impl DiversifiedTransmissionKey {
//     /// Defined in [Zcash Protocol Spec § 4.2.3: Orchard Key Components][orchardkeycomponents].
//     ///
//     /// [orchardkeycomponents]: https://zips.z.cash/protocol/nu5.pdf#orchardkeycomponents
//     pub(crate) fn derive(ivk: &PreparedIncomingViewingKey, d: &Diversifier) -> Self {
//         let g_d = PreparedNonIdentityBase::new(diversify_hash(d.as_array()));
//         DiversifiedTransmissionKey(ka_orchard_prepared(&ivk.0, &g_d))
//     }

//     /// $abst_P(bytes)$
//     pub(crate) fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
//         crate::spec::NonIdentityPallasPoint::from_bytes(bytes).map(DiversifiedTransmissionKey)
//     }

//     /// $repr_P(self)$
//     pub(crate) fn to_bytes(self) -> [u8; 32] {
//         self.0.to_bytes()
//     }
// }

// impl ConditionallySelectable for DiversifiedTransmissionKey {
//     fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
//         DiversifiedTransmissionKey(crate::spec::NonIdentityPallasPoint::conditional_select(
//             &a.0, &b.0, choice,
//         ))
//     }
// }
