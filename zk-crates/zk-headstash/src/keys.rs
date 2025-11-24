use ff::PrimeField;

use pasta_curves::pallas;
use rand::RngCore;
use secp256k1::Secp256k1;
use subtle::{Choice, CtOption};

use crate::note::Rho;
use crate::prf_expand::PrfExpand;
use crate::spec::{esk_to_base, prf_nf, prf_pallas_m, to_base};
use crate::value::{NoteDenom, NoteValue};

#[derive(Debug, Copy, Clone)]
pub struct EligiblePk(pub secp256k1::PublicKey);

impl From<EligibleSk> for EligiblePk {
    fn from(sk: EligibleSk) -> Self {
        Self(sk.0.public_key(&Secp256k1::new()))
    }
}

#[derive(Debug, Copy, Clone)]
pub struct EligibleSk(pub secp256k1::SecretKey);

impl EligibleSk {
    pub fn from(sk: secp256k1::SecretKey) -> Self {
        Self(sk)
    }
    /// Build an `EligibleSk` from a hex string that represents a 32‑byte SECP‑256k1 secret key.
    ///
    /// # Example
    /// ```rust
    /// let sk = EligibleSk::from("1a2b3c…"); // 64‑char hex
    /// ```
    ///
    /// The function will `panic!` if the string is not a valid 32‑byte hex value.
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

    pub fn epk(&self) -> EligiblePk {
        EligiblePk(self.0.public_key(&Secp256k1::new()))
    }

    pub fn derive_pallas_equivalent(&self) -> pallas::Base {
        crate::spec::esk_to_base(self)
    }
}

/// The message signed by the JubJub Key
#[derive(Debug, Copy, Clone)]
pub struct NoteMessage(pallas::Base);

impl NoteMessage {
    pub fn derive(v: NoteValue, nd: NoteDenom, fdi: u64, esk: EligibleSk) -> Self {
        NoteMessage(prf_pallas_m(
            fdi.into(),
            v.inner().into(),
            crate::spec::nd_to_fp(&nd),
            esk_to_base(&esk),
        ))
    }

    /// Returns the raw underlying value.
    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

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
/// This is generated by the hashing of the following inputs:
/// - esk: the product of the 3*88-bit limbs,on the pallas curve
/// - rho: the private randomness used for nullifier and note commitment
/// - m: the h
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NullifierDerivingKey(pallas::Base);

impl NullifierDerivingKey {
    pub fn inner(&self) -> pallas::Base {
        self.0
    }
}

/// take the pallas point field representation of esk (plus other inputs for dst & blinding enhancements)
impl From<&EligibleSk> for NullifierDerivingKey {
    fn from(esk: &EligibleSk) -> Self {
        NullifierDerivingKey(to_base(
            PrfExpand::HEADSTASH_NK.with(&esk.derive_pallas_equivalent().to_repr()),
        ))
    }
}

impl NullifierDerivingKey {
    pub fn prf_nf(&self, rho: pallas::Base) -> pallas::Base {
        prf_nf(self.0, rho)
    }

    /// Derive nullifier key from esk & rho using HKDF.
    ///
    /// This performs the HKDF derivation outside the circuit:
    /// nk = Poseidon(DST_HKDF, e_sk_pallas, rho)
    ///
    /// Where e_sk_pallas is the secp256k1 secret key converted to pallas::Base.
    pub fn derive_from(esk: EligibleSk, rho: Rho) -> Self {
        // Convert secp256k1 secret key to pallas::Base representation
        let e_sk_pallas = crate::spec::esk_to_base(&esk);

        // Derive nk using HKDF: nk = H(DST, e_sk_pallas, rho)
        let nk = crate::spec::hdkf_pallas(e_sk_pallas, rho.into_inner());

        Self(nk)
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
    nk: NullifierDerivingKey,
}

impl From<&SpendingKey> for FullViewingKey {
    fn from(sk: &SpendingKey) -> Self {
        FullViewingKey { nk: sk.into() }
    }
}

impl FullViewingKey {
    pub(crate) fn nk(&self) -> &NullifierDerivingKey {
        &self.nk
    }
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
