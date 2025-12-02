use cosmwasm_std::CanonicalAddr;
use ff::PrimeField;

use pasta_curves::{pallas, Fp};
use rand::RngCore;
use subtle::CtOption;
pub(crate) mod commitment;
pub mod scripts;
pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};
use crate::address::RecpAddr;
use crate::keys::{EligibleSk, NullifierDerivingKey, SpendingKey};
use crate::prf_expand::PrfExpand;
use crate::spec::{prf_nf, to_base, to_scalar, NonZeroPallasScalar};
use crate::value::{NoteDenom, NoteValue};

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
    pub fn random(rng: &mut impl RngCore, rho: &Rho) -> Self {
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
    /// The recp of the funds. is a raw CanonicalAddr
    recp: RecpAddr,
    /// The value of this note.
    v: NoteValue,
    /// The token denomination of this note
    nd: NoteDenom,
    /// A unique creation ID for this note.
    rho: Rho,
    /// The seed randomness for various note components.
    rseed: RandomSeed,
    esk: EligibleSk,
    /// fixed_denomination_index of a genesis note (exists for genesis leaf uniqueness)
    fdi: u64,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        // Notes are canonically defined by their commitments.
        ExtractedNoteCommitment::from(self.commitment())
            .eq(&ExtractedNoteCommitment::from(other.commitment()))
    }
}

impl Eq for Note {}

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
        recp: RecpAddr,
        v: NoteValue,
        nd: NoteDenom,
        fdi: u64,
        esk: EligibleSk,
        rho: Rho,
        rseed: RandomSeed,
    ) -> CtOption<Self> {
        let note = Note {
            recp,
            v,
            rho,
            rseed,
            nd,
            esk,
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
        recp: RecpAddr,
        value: NoteValue,
        nd: NoteDenom,
        fdi: u64,
        esk: EligibleSk,
        rho: Rho,
        mut rng: impl RngCore,
    ) -> Self {
        loop {
            let note = Note::from_parts(
                recp,
                value,
                nd,
                fdi,
                esk,
                rho,
                RandomSeed::random(&mut rng, &rho),
            );
            if note.is_some().into() {
                break note.unwrap();
            }
        }
    }

    /// Generates a dummy spent note.
    ///
    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    pub(crate) fn dummy(rng: &mut impl RngCore, rho: Option<Rho>) -> (EligibleSk, Self) {
        let sk = EligibleSk::random(rng);
        // let fvk: FullViewingKey = (&sk).into();

        let note = Note::new(
            RecpAddr::try_from(CanonicalAddr::from([43;32])).expect("dang"),
            NoteValue::zero(),
            NoteDenom::new_for_proof("I hope you got the necessary doguments and fucking permutations to suck on my shaved balls"),
            0,
            sk,
            rho.unwrap_or_else(|| Rho::from_nf_old(Nullifier::dummy(rng))),
              rng,
        );

        (sk, note)
    }

    /// Returns the recp of this note.
    pub fn recp(&self) -> RecpAddr {
        self.recp
    }

    /// Returns the value of this note.
    pub fn value(&self) -> NoteValue {
        self.v
    }

    /// Returns the rseed value of this note.
    pub fn rseed(&self) -> &RandomSeed {
        &self.rseed
    }

    // / Derives the ephemeral secret key for this note.
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
    fn commitment_inner(&self) -> CtOption<NoteCommitment> {
        // derive note commitment via: self.fdi,

        // self.esk.epk(),
        NoteCommitment::derive(
            self.recp.to_bytes(),
            self.v,
            Fp::from_repr(self.nd.as_bytes().try_into().unwrap()).expect("nd noteCommitment Fp"),
            Fp::from_u128(self.fdi.into()),
            self.esk,
            self.rho.0,
            self.rseed.psi(&self.rho),
            self.rseed.rcm(&self.rho),
        )
    }

    /// Derives the nullifier key for this note.
    pub fn nk(&self, rho: Rho) -> NullifierDerivingKey {
        NullifierDerivingKey::derive_from(self.esk, rho)
    }
    /// Derives the nullifier for this note.
    pub fn nullifier(&self) -> Nullifier {
        // fvk: &FullViewingKey
        Nullifier::derive(
            self.nk(self.rho()),
            self.rho.0,
            self.rseed.psi(&self.rho),
            self.commitment(),
        )
    }

    /// Derives the input to the hkdf function for the nullifier. Uses the posiedon hashing function
    pub fn message(&self) {}

    /// Derives m. Uses the posiedon hashing function
    pub fn derive_m(&self) -> pallas::Base {
        pallas::Base::one()
    }
}
