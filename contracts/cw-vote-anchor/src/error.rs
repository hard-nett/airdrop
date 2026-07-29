use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("unauthorized")]
    Unauthorized,

    #[error("session_id must be non-empty")]
    EmptySession,

    #[error("root must be exactly 32 bytes (Pallas Fp LE), got {got}")]
    BadRootLen { got: usize },

    #[error("anchor already set for session={session_id} height={height}")]
    AnchorExists { session_id: String, height: u64 },
}
