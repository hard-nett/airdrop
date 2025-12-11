use crate::wallet::wallet::HeadstashMetadata;
use crate::wallet::HeadstashWallet;
use crate::{Error, Network};

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use wasm_bindgen::prelude::*;

use zk_headstash::address::RecpAddr;
use zk_headstash::gen::headstash::snp::v1::SerializedNoteData;
use zk_headstash::keys::EligibleSk;
use zk_headstash::note::{Nullifier, Rho};
use zk_headstash::value::HeadstashValue;

/// HeadstashWallet - Database and state manager for MetaMask Snap plugin
///
/// This wallet is a database that maintains headstash note data indexed by headstash ID.
///
/// ## Architecture
///
/// ### headstash file index
/// we store one file per headstash instance per wallet.
/// this file contains the list of tokens allocated for a headstash, and a tally of spent fdi for each denom.
///
/// ### networking configuration
/// There are two main grpc connections, one to the headstash api networking layer for syncing data , and one to Terp Network (cosmos-grpc). We are able to
/// broadcast and retrieve data for both through a unified client api.
///
/// ### Proof generation
/// this snap does not create proofs, but rather serializes both the public (instances) & private values required by the headstash circuit,
/// and responds with exactly just the required data to be able to generate a proof. This acts like a secure enclave between a users secret key,
/// ensuring it never leaves or is exposed from the wallet.
///
/// ## Design Principles
///
/// 1. **No Secret Key Storage**: ESK only requested from MetaMask when needed for operations
/// 2. **Indexed Storage**: All data indexed by headstash contract address
/// 3. **gRPC Communication**: Reuses zcash-style gRPC patterns for headstash API
/// 4. **Minimal Friction**: Designed to minimize refactor effort from zcash wallet

/// # A Headstash Wallet for MetaMask Snap
///
/// ## Key Security Principles
///
/// 1. **No Secret Key Storage**: The wallet NEVER stores secret keys. Keys are only
///    requested from MetaMask when needed for specific operations.
/// 2. **Encrypted State**: All persistent state can be encrypted using MetaMask's
///    snap_manageState API for secure storage.

/// ## Creating a Wallet
///
/// ```javascript
/// const wallet = new WebWallet("main", "https://headstash-api.terp.network", 10);
/// ```
///
/// ## Discovering Headstashes
///
/// Before claiming, discover available headstashes via the market contract:
///
/// ```javascript
/// const headstashes = await wallet.discover_headstashes();
/// for (const headstash of headstashes) {
///     console.log(`Found: ${headstash.contract_addr}`);
/// }
/// ```
///
/// ## Generating Notes
///
/// Generate notes client-side from the Merkle tree:
///
/// ```javascript
/// // Request secret key from MetaMask
/// const esk = await snap.request({ method: "get_secret_key" });
///
/// await wallet.generate_notes_for_headstash(
///     "terp1contract123",
///     esk
/// );
/// ```
///
/// ## Claiming Allocations
///
/// Three pathways for claiming:
///
/// ### 1. Manual (pay your own gas)
/// ```javascript
/// await wallet.claim_via_manual(hid, esk, nullifier);
/// ```
///
/// ### 2. Feegrant (request gas from headstash-server)
/// ```javascript
/// await wallet.claim_via_feegrant(hid, esk, nullifier);
/// ```
///
/// ### 3. Smart Account (gasless via authenticator)
/// ```javascript
/// await wallet.claim_via_smart_account(hid, esk, nullifier);
/// ```
///
/// ## State Persistence
///
/// Serialize wallet state for MetaMask storage:
///
/// ```javascript
/// const state = await wallet.db_to_bytes();
/// await snap.request({
///     method: "snap_manageState",
///     params: { operation: "update", newState: { wallet: state } }
/// });
/// ```
///
#[wasm_bindgen]

pub struct WebWallet {
    inner: HeadstashWallet,
}

#[wasm_bindgen]
impl WebWallet {
    /// Create a new Headstash wallet instance
    ///
    /// # Arguments
    ///
    /// * `network` - Must be one of "main" or "test"
    /// * `headstash_api_url` - URL of the headstash-api server (e.g. https://headstash-api.terp.network)
    /// * `cosmos_grpc_url` - Optional Cosmos SDK gRPC endpoint for direct CosmWasm queries
    /// * `db_bytes` - (Optional) Serialized wallet database from previous session
    ///
    /// # Examples
    ///
    /// ```javascript
    /// const wallet = new WebWallet(
    ///     "main",
    ///     "https://headstash-api.terp.network",
    ///     "https://grpc.terp.network:9090"
    /// );
    /// ```
    #[wasm_bindgen(constructor)]
    pub async fn new(
        network: &str,
        headstash_api_url: &str,
        cosmos_grpc_url: Option<String>,
    ) -> Result<WebWallet, Error> {
        let network = Network::from_str(network)?;
        let inner = HeadstashWallet::new(network, Some(headstash_api_url)).await?;
        Ok(Self { inner })
    }

    /// Generate note data (nullifier, commitment, nk) from secret key and note inputs
    ///
    /// This is the core cryptographic operation that generates all public values
    /// needed to verify a headstash claim.
    ///
    /// # Arguments
    /// * `esk_hex` - Secret key in hex (32 bytes)
    /// * `rho_hex` - Randomness rho in hex (32 bytes)
    /// * `fdi` - Fixed denomination index (leaf position)
    /// * `recp_hex` - Recipient address in hex (32 bytes)
    /// * `v` - Value amount as string
    /// * `nd` - Note denomination (e.g., "uterp")
    /// * `rseed_hex` - Random seed in hex (32 bytes)
    ///
    /// # Returns
    /// JSON string with note data: `{ nk, nullifier, commitment, v, nd, fdi }`
    ///
    /// # Examples
    /// ```javascript
    /// const esk = await snap.request({ method: "get_secret_key" });
    /// const noteData = await wallet.gen_claim(
    ///     "temp_headstash_id",
    ///     esk,
    ///     rho_hex,
    ///     0,
    ///     recp_hex,
    ///     "1000000",
    ///     "uterp",
    ///     rseed_hex
    /// );
    /// console.log(JSON.parse(noteData));
    /// ```
    pub async fn gen_claim(
        &self,
        hid: String,
        nd: String,
        v: String,
        fdi: u64,
        recp_hex: String,
        esk_hex: String,
        rho_hex: String,
        rseed_hex: String,
    ) -> Result<String, Error> {
        // Generate note data
        let (nk, nullifier, cm) = self.inner.generate_note_data(
            EligibleSk::from_hex(&esk_hex),
            Rho::from_bytes(
                hex::decode(&rho_hex)
                    .map_err(|e| Error::KeyDecoding(format!("Invalid rho hex: {}", e)))?
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::KeyDecoding("Invalid rho length".into()))?,
            )
            .expect("rho from bytes"),
            HeadstashValue::from_raw(
                v.parse()
                    .map_err(|e| Error::KeyDecoding(format!("Invalid value: {}", e)))?,
                &nd,
                fdi,
            )
            .unwrap(),
            RecpAddr::new(
                hex::decode(&recp_hex)
                    .map_err(|e| Error::KeyDecoding(format!("Invalid recp hex: {}", e)))?
                    .try_into()
                    .expect("darn"),
            ),
            hex::decode(&rseed_hex)
                .map_err(|e| Error::KeyDecoding(format!("Invalid rseed hex: {}", e)))?
                .as_slice()
                .try_into()
                .map_err(|_| Error::KeyDecoding("Invalid rseed length".into()))?,
        )?;

        // Serialize as JSON
        let note_data = SerializedNoteData {
            nk: nk.to_bytes().to_vec(),
            nul: nullifier.to_bytes().to_vec(),
            cm: zk_headstash::note::ExtractedNoteCommitment::from(cm)
                .to_bytes()
                .to_vec(),
            v,
            nd,
            fdi,
            spent: false,
        };

        serde_json::to_string(&note_data)
            .map_err(|e| Error::KeyDecoding(format!("JSON serialization failed: {}", e)))
    }

    /// Claim via smart account (gasless via authenticator)
    ///
    /// This is the PRIMARY claim method for headstash allocations.
    /// Uses smart account authenticator for gasless transaction execution.
    ///
    /// # Arguments
    /// * `hid` - Contract address
    /// * `esk_hex` - Secret key in hex (from MetaMask)
    /// * `nullifier_hex` - Nullifier of the note to claim
    ///
    /// # Returns
    /// JSON string with claim response: `{ tx_hash, height, code, raw_log }`
    ///
    /// # Examples
    /// ```javascript
    /// const response = await wallet.claim_via_smart_account("terp1contract123", esk, nullifier_hex);
    /// const result = JSON.parse(response);
    /// console.log(`Claimed! TX: ${result.tx_hash}`);
    /// ```
    pub async fn claim_via_smart_account(
        &self,
        hid: String,
        esk_hex: String,
        nullifier_hex: String,
    ) -> Result<String, Error> {
        let esk = EligibleSk::from_hex(&esk_hex);
        let nfb = hex::decode(&nullifier_hex)
            .map_err(|e| Error::KeyDecoding(format!("Invalid nullifier hex: {}", e)))?;
        let nf = Nullifier::from_bytes(
            nfb.as_slice()
                .try_into()
                .map_err(|_| Error::KeyDecoding("Invalid nullifier length".into()))?,
        )
        .expect("nullifier from bytes");
        let hmd = HeadstashMetadata {
            nf,
            mr: todo!(),
            mp: todo!(),
            hv: todo!(),
            recp: todo!(),
        };

        let response = self
            .inner
            .claim_headstash_via_smart_account(hid, esk, hmd)
            .await?;

        serde_json::to_string(&response)
            .map_err(|e| Error::KeyDecoding(format!("JSON serialization failed: {}", e)))
    }

    // /// List all unspent notes for a headstash
    // ///
    // /// Returns a JSON string containing an array of unspent notes.
    // ///
    // /// # Arguments
    // /// * `hid` - Contract address of the headstash
    // ///
    // /// # Returns
    // /// JSON string with note data: `[{ nullifier, commitment, value_amount, value_denom, fdi, spent }]`
    // // pub async fn list_unspent_notes(&self, hid: String) -> Result<String, Error> {
    // //     let notes = self.inner.list_unspent_notes(&hid).await?;
    // //     let serialized: Vec<SerializedNote> = notes.iter().map(|n| n.into()).collect();
    // //     serde_json::to_string(&serialized)
    // //         .map_err(|e| Error::Js(format!("Serialization failed: {}", e).into()))
    // // }

    // /// List all spent notes for a headstash
    // ///
    // /// Returns a JSON string containing an array of spent notes.
    // ///
    // /// # Arguments
    // /// * `hid` - Contract address of the headstash
    // ///
    // /// # Returns
    // /// JSON string with note data
    // // pub async fn list_spent_notes(&self, hid: String) -> Result<String, Error> {
    // //     let notes = self.inner.list_spent_notes(&hid).await?;
    // //     let serialized: Vec<SerializedNote> = notes.iter().map(|n| n.into()).collect();
    // //     serde_json::to_string(&serialized)
    // //         .map_err(|e| Error::Js(format!("Serialization failed: {}", e).into()))
    // // }

    // /// Query headstash contract info via CosmWasm
    // ///
    // /// This uses the standard CosmWasm QueryWasmSmart to query headstash contract state.
    // ///
    // /// # Arguments
    // /// * `hid` - Contract address
    // /// * `query_msg` - JSON query message
    // ///
    // /// # Returns
    // /// JSON string with query response
    // ///
    // /// # Examples
    // /// ```javascript
    // /// const info = await wallet.query_headstash(
    // ///     "terp1contract123",
    // ///     JSON.stringify({ get_info: {} })
    // /// );
    // /// console.log(JSON.parse(info));
    // /// ```
    // // pub async fn query_headstash(
    // //     &self,
    // //     hid: String,
    // //     query_msg: String,
    // // ) -> Result<String, Error> {
    // //     let response: serde_json::Value = self
    // //         .inner
    // //         .query_headstash(&hid, &query_msg)
    // //         .await?;
    // //     serde_json::to_string(&response)
    // //         .map_err(|e| Error::Js(format!("Serialization failed: {}", e).into()))
    // // }

    // /// Get all headstash IDs we have notes for
    // ///
    // /// Returns a JSON array of headstash contract addresses.
    // ///
    // /// # Examples
    // /// ```javascript
    // /// const ids = await wallet.list_headstash_ids();
    // /// console.log(JSON.parse(ids)); // ["terp1contract123", "terp1contract456"]
    // /// ```
    // // pub async fn list_headstash_ids(&self) -> Result<String, Error> {
    // //     let ids = self.inner.list_headstash_ids().await?;
    // //     serde_json::to_string(&ids)
    // //         .map_err(|e| Error::Js(format!("Serialization failed: {}", e).into()))
    // // }

    // /// Upload nullifier state to headstash-api for cross-device sync
    // ///
    // /// This encrypts and uploads spent nullifier state to the API server.
    // ///
    // /// # Arguments
    // /// * `hid` - Contract address
    // /// * `recipient_pk_hex` - Public key to encrypt to (usually your own) in hex
    // /// * `sender_sk_hex` - Secret key for signing in hex
    // ///
    // /// # Examples
    // /// ```javascript
    // /// const esk = await snap.request({ method: "get_secret_key" });
    // /// const epk = derivePublicKey(esk);
    // /// await wallet.upload_nullifier_state("terp1contract123", epk, esk);
    // /// ```
    // // pub async fn upload_nullifier_state(
    // //     &self,
    // //     hid: String,
    // //     recipient_pk_hex: String,
    // //     sender_sk_hex: String,
    // // ) -> Result<(), Error> {
    // //     let recipient_pk = EligiblePk::from(
    // //         &hex::decode(&recipient_pk_hex)
    // //             .map_err(|e| Error::KeyDecoding(format!("Invalid recipient pk hex: {}", e)))?,
    // //     );
    // //     let sender_sk = EligibleSk::from_hex(&sender_sk_hex);

    // //     self.inner
    // //         .upload_nullifier_state(&hid, &recipient_pk, &sender_sk)
    // //         .await
    // // }

    // // / Download and sync nullifier state from headstash-api
    // // /
    // // / This downloads encrypted nullifier state from the API server and merges it into local storage.
    // // /
    // // / # Arguments
    // // / * `hid` - Contract address
    // // / * `recipient_sk_hex` - Secret key to decrypt with in hex
    // // / * `sender_pk_hex` - Expected sender's public key (for verification) in hex
    // // /
    // // / # Examples
    // // / ```javascript
    // // / const esk = await snap.request({ method: "get_secret_key" });
    // // / await wallet.download_and_sync_nullifier_state("terp1contract123", esk, sender_pk_hex);
    // // / ```
    // // pub async fn download_and_sync_nullifier_state(
    // //     &self,
    // //     hid: String,
    // //     recipient_sk_hex: String,
    // //     sender_pk_hex: String,
    // // ) -> Result<(), Error> {
    // //     let recipient_sk = EligibleSk::from_hex(&recipient_sk_hex);
    // //     let sender_pk = EligiblePk::from(
    // //         &hex::decode(&sender_pk_hex)
    // //             .map_err(|e| Error::KeyDecoding(format!("Invalid sender pk hex: {}", e)))?,
    // //     );

    // //     self.inner
    // //         .download_and_sync_nullifier_state(&hid, &recipient_sk, &sender_pk)
    // //         .await
    // // }

    // /// Serialize wallet database to bytes for MetaMask storage
    // ///
    // /// This should be used for persisting the wallet between sessions.
    // /// The resulting byte array can be stored via snap_manageState.
    // ///
    // /// # Returns
    // /// Byte array of serialized database
    // ///
    // /// # Examples
    // /// ```javascript
    // /// const state = await wallet.db_to_bytes();
    // /// await snap.request({
    // ///     method: "snap_manageState",
    // ///     params: {
    // ///         operation: "update",
    // ///         newState: { headstash_wallet: Array.from(state) }
    // ///     }
    // /// });
    // /// ```
    // pub async fn db_to_bytes(&self) -> Result<Box<[u8]>, Error> {
    //     // TODO: Implement actual serialization
    //     // For now, return empty bytes
    //     Ok(vec![].into_boxed_slice())
    // }
}

// // ============================================================================
// // Serialization Types for WASM
// // ============================================================================

// /// Serialized note data for JavaScript consumption
// #[derive(Serialize, Deserialize)]
// pub struct SerializedNote {
//     pub nf: Vec<u8>,
//     pub cm: Vec<u8>,
//     pub v: u64,
//     pub nd: Vec<u8>,
//     pub fdi: u64,
//     pub spent: bool,
// }

// impl From<&NoteData> for SerializedNote {
//     fn from(note: &NoteData) -> Self {
//         use zk_headstash::note::ExtractedNoteCommitment;
//         // Convert NoteCommitment to bytes
//         let commitment_bytes: [u8; 32] =
//             ExtractedNoteCommitment::from(note.commitment.clone()).to_bytes();

//         Self {
//             nf: note.nullifier.to_bytes().to_vec(),
//             cm: commitment_bytes.to_vec(),
//             v: note.hv.raw_amount(),
//             nd: note.hv.denom_str().into(),
//             fdi: note.fdi,
//             spent: note.spent,
//         }
//     }
// }
