use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tlsn_core::CryptoProvider;
use tokio::sync::Semaphore;

#[cfg(feature = "tee_quote")]
use crate::tee::Quote;
use crate::{auth::AuthorizationMode, config::NotarizationProperties};

/// Response object of the /info API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    /// Current version of notary-server
    pub version: String,
    /// Public key of the notary signing key
    pub public_key: String,
    /// Current git commit hash of notary-server
    pub git_commit_hash: String,
    /// Hardware attestation
    #[cfg(feature = "tee_quote")]
    pub quote: Quote,
}

/// Request query of the /notarize API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotarizationRequestQuery {
    /// Type of client (tcp or websocket)
    pub client_type: String,
    /// Maximum data that can be sent by the prover (optional)
    pub max_sent_data: Option<usize>,
    /// Maximum data that can be received by the prover (optional)
    pub max_recv_data: Option<usize>,
}

/// Global data that needs to be shared with the axum handlers
#[derive(Clone)]
pub struct NotaryGlobals {
    pub crypto_provider: Arc<CryptoProvider>,
    pub notarization_config: NotarizationProperties,
    /// Selected authorization mode if any
    pub authorization_mode: Option<AuthorizationMode>,
    /// A semaphore to acquire a permit for notarization
    pub semaphore: Arc<Semaphore>,
}

impl NotaryGlobals {
    pub fn new(
        crypto_provider: Arc<CryptoProvider>,
        notarization_config: NotarizationProperties,
        authorization_mode: Option<AuthorizationMode>,
        semaphore: Arc<Semaphore>,
    ) -> Self {
        Self {
            crypto_provider,
            notarization_config,
            authorization_mode,
            semaphore,
        }
    }
}
