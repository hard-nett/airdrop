use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

/// Ceremony lifecycle status (string-stable for raw-query consumers).
#[cw_serde]
pub enum CeremonyStatus {
    Active,
    Closed,
}

impl CeremonyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CeremonyStatus::Active => "Active",
            CeremonyStatus::Closed => "Closed",
        }
    }
}

#[cw_serde]
pub struct InstantiateMsg {
    /// Optional admin (test / bootstrap). DAO path should call via proposal execute.
    pub admin: Option<String>,
    /// Default max nullifiers per MarkSpent call.
    #[serde(default = "default_max_nf")]
    pub max_nullifiers_per_mark: u32,
}

fn default_max_nf() -> u32 {
    8
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Start a ceremony (admin or future DAO proposal path).
    StartCeremony {
        session_id: String,
        domain: String,
        /// When false, Register is rejected.
        #[serde(default = "default_true")]
        registration_open: bool,
        /// Optional anchor policy / root hint (opaque product string).
        #[serde(default)]
        anchor_policy: Option<String>,
    },
    /// Close ceremony (no further spends / registrations).
    CloseCeremony { session_id: String },
    /// Participant self-register (eligibility product hooks later).
    Register { session_id: String },
    /// Admin can toggle registration window.
    SetRegistrationOpen {
        session_id: String,
        open: bool,
    },
}

fn default_true() -> bool {
    true
}

/// Privileged path: thin gate ConfirmExecution → chain sudo → MarkSpent.
/// Also usable from privileged execute if product wires permissioned keeper.
#[cw_serde]
pub enum SudoMsg {
    MarkSpent {
        domain: String,
        session_id: String,
        nullifiers: Vec<Binary>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},

    #[returns(CeremonyResponse)]
    Ceremony { session_id: String },

    #[returns(IsSpentResponse)]
    IsSpent {
        domain: String,
        session_id: String,
        nullifier: Binary,
    },

    #[returns(IsRegisteredResponse)]
    IsRegistered {
        session_id: String,
        addr: String,
    },

    /// Documented raw key bytes for ante raw-query consumers (V2).
    #[returns(RawSpentKeyResponse)]
    RawSpentKey {
        domain: String,
        session_id: String,
        nullifier: Binary,
    },
}

#[cw_serde]
pub struct ConfigResponse {
    pub admin: Option<String>,
    pub max_nullifiers_per_mark: u32,
}

#[cw_serde]
pub struct CeremonyInfo {
    pub session_id: String,
    pub domain: String,
    pub status: CeremonyStatus,
    pub registration_open: bool,
    pub anchor_policy: Option<String>,
}

#[cw_serde]
pub struct CeremonyResponse {
    pub ceremony: CeremonyInfo,
}

#[cw_serde]
pub struct IsSpentResponse {
    pub spent: bool,
}

#[cw_serde]
pub struct IsRegisteredResponse {
    pub registered: bool,
}

#[cw_serde]
pub struct RawSpentKeyResponse {
    /// Full storage key as used by cw-storage-plus Map under prefix `spent`
    /// for debugging; normative layout is also in `raw_keys` module / README.
    pub map_namespace: String,
    pub domain: String,
    pub session_id: String,
    pub nullifier: Binary,
}
