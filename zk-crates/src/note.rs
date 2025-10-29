use cosmwasm_std::Addr;
use ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use rand::RngCore;
use subtle::CtOption;

pub(crate) mod commitment;
pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};
use crate::address::HeadstashAddr;
use crate::keys::{
    EligibleSk, FullViewingKey, JubJubKey, JubJubSignature, NullifierDerivingKey, SpendingKey,
};
use crate::prf_expand::PrfExpand;
use crate::spec::{NonZeroPallasScalar, prf_nf, to_base, to_scalar};
use crate::value::{NoteDenom, NoteValue};
use redjubjub::{Binding, SigningKey};

pub(crate) mod nullifier;
pub use self::nullifier::Nullifier;

/// The randomness used to construct a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rho(pallas::Base);

impl Rho {
    /// Deserialize the rho value from a byte array.
    ///
    /// This should only be used in cases where the components of a `Note` are being serialized and
    /// stored individually. Use [`Action::rho`] or [`CompactAction::rho`] to obtain the [`Rho`]
    /// value otherwise.
    ///
    /// [`Action::rho`]: crate::action::Action::rho
    /// [`CompactAction::rho`]: crate::note_encryption::CompactAction::rho
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(Rho)
    }
    /// Serialize the rho value to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
    /// Constructs the [`Rho`] value to be used to construct a new note from the revealed nullifier
    /// of the note being spent in the [`Action`] under construction.
    ///
    /// [`Action`]: crate::action::Action
    pub(crate) fn from_nf_old(nf: Nullifier) -> Self {
        Rho(nf.0)
    }

    pub fn into_inner(self) -> pallas::Base {
        self.0
    }
    /// Constructs the [`Rho`] value to be used to construct the first note claimed by an eligible headstash address.
    /// Creates H(elig_addr||nonce) to be used as bytes
    pub fn from_genesis(elig_addr: &str, nonce: u64) -> CtOption<Self> {
        let hash = blake3::hash(elig_addr.as_bytes());
        pallas::Base::from_repr(*hash.as_bytes()).map(Rho)
    }
}

/// The ZIP 212 seed randomness for a note.
#[derive(Copy, Clone, Debug)]
pub struct RandomSeed([u8; 32]);

impl RandomSeed {
    pub(crate) fn random(rng: &mut impl RngCore, rho: &Rho) -> Self {
        loop {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let rseed = RandomSeed::from_bytes(bytes, rho);
            if rseed.is_some().into() {
                break rseed.unwrap();
            }
        }
    }

    /// Reads a note's random seed from bytes, given the note's rho value.
    ///
    /// Returns `None` if the rho value is not for the same note as the seed.
    pub fn from_bytes(rseed: [u8; 32], rho: &Rho) -> CtOption<Self> {
        let rseed = RandomSeed(rseed);
        let esk = rseed.esk_inner(rho);
        CtOption::new(rseed, esk.is_some())
    }

    /// Returns the byte array corresponding to this seed.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub fn psi(&self, rho: &Rho) -> pallas::Base {
        to_base(PrfExpand::PSI.with(&self.0, &rho.to_bytes()))
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    fn esk_inner(&self, rho: &Rho) -> CtOption<NonZeroPallasScalar> {
        NonZeroPallasScalar::from_scalar(to_scalar(
            PrfExpand::ORCHARD_ESK.with(&self.0, &rho.to_bytes()),
        ))
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    fn esk(&self, rho: &Rho) -> NonZeroPallasScalar {
        // We can't construct a RandomSeed for which this unwrap fails.
        self.esk_inner(rho).unwrap()
    }

    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub fn rcm(&self, rho: &Rho) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(to_scalar(
            PrfExpand::ORCHARD_RCM.with(&self.0, &rho.to_bytes()),
        ))
    }
}

/// A discrete amount of funds received by an address.
#[derive(Debug, Copy, Clone)]
pub struct Note {
    /// The recipient of the funds. is a raw CanonicalAddr
    recipient: HeadstashAddr,
    /// The value of this note.
    v: NoteValue,
    /// The token denomination of this note
    nd: NoteDenom,
    /// A unique creation ID for this note.
    rho: Rho,
    /// The seed randomness for various note components.
    rseed: RandomSeed,
    /// The private key of the eligible_addr
    elig_sk: EligibleSk,
    /// The private key of the HKDF jubjub keypair
    jub_sk: JubJubKey,
    // /// The nullifier of this note
    // // jub_null: HeadstashAddr,
    // sig_jub: JubJubSignature,
    /// fixed_denomination_index of a genesis note (exists for genesis leaf uniqueness)
    fdi: u64,
    // /// H(amount‖denom‖fdi‖elig_sk)
    // m: HeadstashAddr,
}

// impl PartialEq for Note {
//     fn eq(&self, other: &Self) -> bool {
//         // Notes are canonically defined by their commitments.
//         ExtractedNoteCommitment::from(self.commitment())
//             .eq(&ExtractedNoteCommitment::from(other.commitment()))
//     }
// }

// impl Eq for Note {}

impl Note {
    /// Creates a `Note` from its component parts.
    ///
    /// Returns `None` if a valid [`NoteCommitment`] cannot be derived from the note.
    ///
    /// # Caveats
    ///
    /// This low-level constructor enforces that the provided arguments produce an
    /// internally valid `Note`. However, it allows notes to be constructed in a way that
    /// violates required security checks for note decryption, as specified in
    /// [Section 4.19] of the Zcash Protocol Specification. Users of this constructor
    /// should only call it with note components that have been fully validated by
    /// decrypting a received note according to [Section 4.19].
    ///
    /// [Section 4.19]: https://zips.z.cash/protocol/protocol.pdf#saplingandorchardinband
    pub fn from_parts(
        recipient: HeadstashAddr,
        v: NoteValue,
        nd: NoteDenom,
        fdi: u64,
        elig_sk: EligibleSk,
        jub_sk: JubJubKey,
        rho: Rho,
        rseed: RandomSeed,
    ) -> CtOption<Self> {
        let note = Note {
            recipient,
            v,
            rho,
            rseed,
            nd,
            elig_sk,
            jub_sk,
            fdi,
            // m: todo!(),
        };
        CtOption::new(note, note.commitment_inner().is_some())
    }

    /// Generates a new note.
    ///
    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    pub(crate) fn new(
        recipient: HeadstashAddr,
        value: NoteValue,
        rho: Rho,
        nd: NoteDenom,
        jub_sk: JubJubKey,
        fdi: u64,
        elig_sk: EligibleSk,
        mut rng: impl RngCore,
    ) -> Self {
        loop {
            let note = Note::from_parts(
                recipient,
                value,
                nd,
                fdi,
                elig_sk,
                jub_sk,
                rho,
                RandomSeed::random(&mut rng, &rho),
            );
            if note.is_some().into() {
                break note.unwrap();
            }
        }
    }

    // /// Generates a dummy spent note.
    // ///
    // /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    // ///
    // /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    // pub(crate) fn dummy(
    //     rng: &mut impl RngCore,
    //     rho: Option<Rho>,
    // ) -> (SpendingKey, FullViewingKey, Self) {
    //     let sk = SpendingKey::random(rng);
    //     let fvk: FullViewingKey = (&sk).into();
    //     let recipient = fvk.address_at(0u32, Scope::External);

    //     let note = Note::new(
    //         recipient,
    //         NoteValue::zero(),
    //         rho.unwrap_or_else(|| Rho::from_nf_old(Nullifier::dummy(rng))),
    //         rng,
    //     );

    //     (sk, fvk, note)
    // }

    /// Returns the recipient of this note.
    pub fn recipient(&self) -> HeadstashAddr {
        self.recipient
    }

    /// Returns the value of this note.
    pub fn value(&self) -> NoteValue {
        self.v
    }

    /// Returns the rseed value of this note.
    pub fn rseed(&self) -> &RandomSeed {
        &self.rseed
    }

    /// Derives the ephemeral secret key for this note.
    // pub(crate) fn esk(&self) -> EphemeralSecretKey {
    //     EphemeralSecretKey(self.rseed.esk(&self.rho))
    // }

    /// Returns rho of this note.
    pub fn rho(&self) -> Rho {
        self.rho
    }

    /// Derives the commitment to this note.
    ///
    /// Defined in [Zcash Protocol Spec § 3.2: Notes][notes].
    ///
    /// [notes]: https://zips.z.cash/protocol/nu5.pdf#notes
    pub fn commitment(&self) -> NoteCommitment {
        // `Note` will always have a note commitment by construction.
        self.commitment_inner().unwrap()
    }

    /// Derives the commitment to this note.
    ///
    /// This is the internal fallible API, used to check at construction time that the
    /// note has a commitment. Once you have a [`Note`] object, use `note.commitment()`
    /// instead.
    ///
    /// Defined in [Zcash Protocol Spec § 3.2: Notes][notes].
    ///
    /// [notes]: https://zips.z.cash/protocol/nu5.pdf#notes
    fn commitment_inner(&self) -> CtOption<NoteCommitment> {
        let g_d = self.recipient.to_bytes();

        NoteCommitment::derive(
            g_d,
            self.recipient.to_bytes(),
            self.v,
            self.rho.0,
            self.rseed.psi(&self.rho),
            self.rseed.rcm(&self.rho),
        )
    }

    /// Derives the nullifier for this note.
    pub fn nullifier(&self) -> Nullifier {
        Nullifier::derive(self.fdi, self.v, self.nd, self.elig_sk)
    }
}
