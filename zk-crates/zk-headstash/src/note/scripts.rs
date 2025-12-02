use crate::note::Note;
use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::{Api, CanonicalAddr};
use ff::PrimeField;
use pasta_curves::arithmetic::CurveExt;
use serde::Serialize;
use serde_json::{json, Value};

// The full note template (private fields are placeholders)
#[derive(Serialize, Debug, Clone)]
pub struct NoteTemplate {
    // pub ψ: String,
    // pub epk: String,
    // pub esk: String,
    // pub nul_sk: String,
    // pub m: String,
    pub nd: String,
    pub fdi: u64,
    pub v: u64,
    pub recp: String,
    pub nul: String,
    pub note_cm: Vec<String>,
}

impl From<NoteTemplate> for Value {
    fn from(nt: NoteTemplate) -> Self {
        json!({
            // "epk":     nt.epk,
            // "esk":    nt.esk,
            // "m":          nt.m,
            // "ψ":          nt.ψ,
            // "nul_sk":     nt.nul_sk,
            "recp":       nt.recp,
            "fdi":        nt.fdi,
            "v":     nt.v,
            "nd":      nt.nd,
            "nul":   nt.nul,
            "note_cm":    nt.note_cm
        })
    }
}

impl From<Note> for NoteTemplate {
    fn from(n: Note) -> Self {
        let (px, py, pz) = n.commitment().0.jacobian_coordinates();
        //TODO: fix defining all values derived from esk.
        NoteTemplate {
            // m: hex::encode(n.message().inner().to_repr()),
            // epk: hex::encode::<[u8; 32]>(VerificationKey::from(&n.nul_sk.0).into()),
            // m: String::default(),
            // epk: String::default(),
            // esk: String::default(),
            // nul_sk: String::default(),
            // ψ: hex::encode(n.rho.to_bytes()),
            fdi: n.fdi,
            v: n.v.inner(),
            nd: n.nd.as_str_for_proof(),
            recp: mock_dependencies()
                .api
                .addr_humanize(&CanonicalAddr::from(n.recp().to_bytes()))
                .unwrap()
                .to_string(),
            nul: String::default(),
            note_cm: vec![
                hex::encode(px.to_repr()),
                hex::encode(py.to_repr()),
                hex::encode(pz.to_repr()),
            ],
        }
    }
}

/// create composite key for O(1) lookups
impl NoteTemplate {
    pub fn composite_key(&self) -> String {
        format!("{}_{}_{}", self.v, self.nd, self.fdi)
    }
}
