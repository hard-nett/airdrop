use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::{Api, CanonicalAddr};
use ff::{Field, PrimeField};
use pasta_curves::pallas;
use rand_core::OsRng;
use zk_crates::address::HeadstashAddr;
use zk_crates::keys::{FullViewingKey, NullifierDerivingKey, SpendingKey};
use zk_crates::note::{Note, NoteCommitment, Nullifier, RandomSeed, Rho};
use zk_crates::value::NoteValue;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // determine what fixed-value-note available to spend
    //  - load available note templates from incoming addr
    let mut rng = OsRng;

    // create nullifiers using blake3 plus randomess source
    let elig_addr = "DE4BAA02C4855872BBA5464749157D06151ED215C6FD39A07454344DE8D9A2BF";

    let recipient = HeadstashAddr::try_from(
        CanonicalAddr::from(blake3::hash(elig_addr.as_bytes()).as_bytes()).as_ref(),
    )?;
    let randomness1 = zk_crates::randomness::ultra_secure_random();
    let randomness2 = zk_crates::randomness::ultra_secure_random();

    // v == NoteValue - must be one of the fixed_denomination values
    // rho(p) == 256bit randomness involved in deriving nullifier. For genesis claim, this will be H(eligible_addr|| nonce)
    // rseed == ZIP 212 seed randomness for a note.
    // note == note to use to derive nullifier and note-commitment
    let v = NoteValue::from_raw(1_000_000);
    let rho = Rho::from_bytes(&pallas::Base::random(&mut rng).to_repr()).unwrap();
    let rseed = RandomSeed::from_bytes(randomness2, &rho).unwrap();
    let note = Note::from_parts(recipient, v, rho, rseed).unwrap();

    // sk ==  spending key === key claiming the note publicly.
    // nk == nullifier key. derived by PRF(sk([7]))
    // fvk == full viewing key
    // psi == pure randomness derived by sender from `rho(p)` as input
    let sk: subtle::CtOption<SpendingKey> = SpendingKey::from_bytes(randomness1);
    let nk = NullifierDerivingKey::from(&sk.unwrap());
    let fvk = FullViewingKey::from(&sk.unwrap());
    let psi = rseed.psi(&rho);

    // cm == note commitment
    // g_d == canonical pubkey bytes of recipient of this note
    // pk_d == diversified pubkey, which for headstashes (for now) is g_d
    //
    let g_d = recipient.to_bytes();
    let pk_d = g_d;
    let rcm = RandomSeed::from_bytes(randomness2, &rho).unwrap().rcm(&rho);
    let cm = NoteCommitment::derive(g_d, pk_d, v, rho.into_inner(), psi, rcm).unwrap();
    let nullifier = Nullifier::derive(&nk, rho.into_inner(), psi, cm);
    println!("nullifier: {:#?}", nullifier);

    println!("note.commitment(): {:#?}", note.commitment());
    println!("note.rho(): {:#?}", note.rho());
    println!("note.rseed(): {:#?}", note.rseed());
    println!("note.value(): {:#?}", note.value());
    println!("note.value(): {:#?}", note.value());
    println!("note.nullifier(fvk);: {:#?}", note.nullifier(&fvk));

    Ok(())
}
