use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::{Api, CanonicalAddr};
use redjubjub::VerificationKey;
use serde::Serialize;
use serde_json::{Value, json};

use crate::note::Note;
use crate::spec::extract_p;
use ff::PrimeField;

// The full note template (private fields are placeholders)
#[derive(Serialize, Debug, Clone)]
pub struct NoteTemplate {
    pub recp: String,
    pub m: String,
    pub elig_sk: String,
    pub jub_sk: String,
    pub sig_jub: String,
    pub fdi: u64,
    pub v: u64,
    pub nd: String,
    pub jub_null: String,
    pub jub_pk: String,
    pub ψ: String,
    pub note_cm: String,
}

impl From<NoteTemplate> for Value {
    fn from(nt: NoteTemplate) -> Self {
        json!({
            "recp":       nt.recp,
            "m":          nt.m,
            "elig_sk":    nt.elig_sk,
            "jub_sk":     nt.jub_sk,
            "sig_jub":    nt.sig_jub,
            "fdi":        nt.fdi,
            "v":     nt.v,
            "nd":      nt.nd,
            "jub_null":   nt.jub_null,
            "jub_pk":     nt.jub_pk,
            "ψ":          nt.ψ,
            "note_cm":    nt.note_cm
        })
    }
}

impl From<Note> for NoteTemplate {
    fn from(n: Note) -> Self {
        NoteTemplate {
            m: hex::encode(n.message().inner().to_repr()),
            elig_sk: hex::encode(n.elig_sk.0.secret_bytes()),
            jub_sk: hex::encode::<[u8; 32]>(n.jub_sk.0.into()),
            sig_jub: hex::encode::<[u8; 64]>(n.sign_jubjub().into()),
            fdi: n.fdi,
            v: n.v.inner(),
            nd: n.nd.as_str().into(),
            recp: mock_dependencies()
                .api
                .addr_humanize(&CanonicalAddr::from(n.recipient().to_bytes()))
                .unwrap()
                .to_string(),
            jub_null: hex::encode(n.nullifier().to_bytes()),
            jub_pk: hex::encode::<[u8; 32]>(VerificationKey::from(&n.jub_sk.0).into()),
            ψ: hex::encode(n.rho.to_bytes()),
            note_cm: hex::encode(extract_p(&n.commitment().0).to_repr()), // TODO: impl Serialize for full commitment values (x,y,z)
        }
    }
}

/// create composite key for O(1) lookups
impl NoteTemplate {
   pub fn composite_key(&self) -> String {
        format!("{}_{}_{}", self.v, self.nd, self.fdi)
    }
}
