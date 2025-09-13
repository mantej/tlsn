pub mod axum_websocket;
pub mod tcp;
pub mod websocket;

use axum::{
    body::Body,
    extract::{FromRequestParts, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use eyre::eyre;
use std::time::Duration;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::attestation::AttestationConfig;
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info};

use crate::{
    error::NotaryServerError,
    service::{
        axum_websocket::{header_eq, WebSocketUpgrade},
        tcp::{tcp_notarize, TcpUpgrade},
        websocket::websocket_notarize,
    },
    types::{NotarizationRequestQuery, NotaryGlobals},
};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
pub enum ProtocolUpgrade {
    Tcp(TcpUpgrade),
    Ws(WebSocketUpgrade),
}

impl<S> FromRequestParts<S> for ProtocolUpgrade
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract tcp connection for websocket client
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Ws(extractor))
        // Extract tcp connection for tcp client
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let extractor = TcpUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Tcp(extractor))
        } else {
            Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ))
        }
    }
}

/// Handler to upgrade protocol from http to either websocket or underlying tcp
/// depending on the type of client. Parameters are now passed directly in the
/// query string instead of using a session.
pub async fn upgrade_protocol(
    protocol_upgrade: ProtocolUpgrade,
    State(notary_globals): State<NotaryGlobals>,
    Query(params): Query<NotarizationRequestQuery>,
) -> Response {
    let permit = if let Ok(permit) = notary_globals.semaphore.clone().try_acquire_owned() {
        permit
    } else {
        // TODO: estimate the time more precisely to avoid unnecessary retries.
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Retry-After", 5)
            .body(Body::default())
            .expect("Builder should not fail");
    };

    info!("Received upgrade protocol request");
    
    // Validate max_sent_data and max_recv_data against global limits
    if let Some(max_sent) = params.max_sent_data {
        if max_sent > notary_globals.notarization_config.max_sent_data {
            let err_msg = format!(
                "Max sent data requested {} exceeds the global maximum threshold {}",
                max_sent, notary_globals.notarization_config.max_sent_data
            );
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    }
    
    if let Some(max_recv) = params.max_recv_data {
        if max_recv > notary_globals.notarization_config.max_recv_data {
            let err_msg = format!(
                "Max recv data requested {} exceeds the global maximum threshold {}",
                max_recv, notary_globals.notarization_config.max_recv_data
            );
            error!(err_msg);
            return NotaryServerError::BadProverRequest(err_msg).into_response();
        }
    }
    // This completes the HTTP Upgrade request and returns a successful response to
    // the client, meanwhile initiating the websocket or tcp connection
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| async move {
            websocket_notarize(socket, notary_globals).await;
            drop(permit);
        }),
        ProtocolUpgrade::Tcp(tcp) => tcp.on_upgrade(move |stream| async move {
            tcp_notarize(stream, notary_globals).await;
            drop(permit);
        }),
    }
}

/// Run the notarization
pub async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    notary_globals: NotaryGlobals,
) -> Result<(), NotaryServerError> {
    debug!("Starting notarization...");

    let crypto_provider = notary_globals.crypto_provider.clone();

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()));

    // If enabled, accepts any custom extensions from the prover.
    if notary_globals.notarization_config.allow_extensions {
        att_config_builder.extension_validator(|_| Ok(()));
    }

    let att_config = att_config_builder
        .build()
        .map_err(|err| NotaryServerError::Notarization(Box::new(err)))?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(notary_globals.notarization_config.max_sent_data)
                .max_recv_data(notary_globals.notarization_config.max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    #[allow(deprecated)]
    timeout(
        Duration::from_secs(notary_globals.notarization_config.timeout),
        Verifier::new(config).notarize(socket.compat(), &att_config),
    )
    .await
    .map_err(|_| eyre!("Timeout reached before notarization completes"))??;

    Ok(())
}
