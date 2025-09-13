use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eyre::eyre;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tracing::{debug, error, info, warn};

use crate::{
    error::NotaryServerError,
    security::ProxyValidator,
};

/// Query parameters for proxy connection
#[derive(Debug, Deserialize)]
pub struct ProxyQuery {
    /// Target hostname or IP
    #[serde(rename = "token")]
    pub target: String,
}

/// WebSocket proxy handler that forwards connections to target servers
pub async fn websocket_proxy(
    ws: AxumWebSocketUpgrade,
    Query(params): Query<ProxyQuery>,
    State(validator): State<Arc<ProxyValidator>>,
) -> Result<Response, NotaryServerError> {
    let target = params.target;
    
    // Parse target (can be host:port or just host, default to 443)
    let (host, port) = parse_target(&target)?;
    
    info!("WebSocket proxy request for {}:{}", host, port);

    // Validate the connection
    if let Err(e) = validator.validate_connection(&host, port) {
        warn!("Proxy connection denied for {}:{}: {}", host, port, e);
        return Err(NotaryServerError::BadProverRequest(format!(
            "Connection to {}:{} denied: {}", host, port, e
        )));
    }

    // Upgrade to WebSocket and handle the connection
    let response = ws.on_upgrade(move |socket| async move {
        if let Err(e) = handle_websocket_proxy(socket, host, port).await {
            error!("WebSocket proxy error: {}", e);
        }
    });

    Ok(response)
}

/// Parse target string into host and port
fn parse_target(target: &str) -> Result<(String, u16), NotaryServerError> {
    // Remove any protocol prefix if present
    let target = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);

    if let Some((host, port_str)) = target.split_once(':') {
        let port = port_str.parse::<u16>()
            .map_err(|_| NotaryServerError::BadProverRequest(
                format!("Invalid port number: {}", port_str)
            ))?;
        Ok((host.to_string(), port))
    } else {
        // Default to HTTPS port if no port specified
        Ok((target.to_string(), 443))
    }
}

/// Handle the WebSocket proxy connection
async fn handle_websocket_proxy(
    websocket: WebSocket,
    host: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    debug!("Establishing WebSocket proxy connection to {}:{}", host, port);

    // Handle the WebSocket connection directly using axum's WebSocket
    let (mut ws_sender, mut ws_receiver) = websocket.split();

    // Connect to target server with timeout
    let target_stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect(&format!("{}:{}", host, port))
    )
    .await
    .map_err(|_| eyre!("Connection timeout"))?
    .map_err(|e| eyre!("Failed to connect to target: {}", e))?;

    debug!("Connected to target server {}:{}", host, port);

    // Split target stream for bidirectional forwarding
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    // Forward WebSocket messages to target
    let ws_to_target = async {
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(axum::extract::ws::Message::Binary(data)) => {
                    if let Err(e) = target_writer.write_all(&data).await {
                        warn!("Failed to write to target: {}", e);
                        break;
                    }
                }
                Ok(axum::extract::ws::Message::Close(_)) => {
                    debug!("WebSocket closed by client");
                    break;
                }
                Ok(_) => {
                    // Ignore other message types (Text, Ping, Pong)
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
            }
        }
    };

    // Forward target responses to WebSocket
    let target_to_ws = async {
        let mut buffer = vec![0u8; 8192];
        
        loop {
            match target_reader.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Target connection closed");
                    break;
                }
                Ok(n) => {
                    let message = axum::extract::ws::Message::Binary(buffer[..n].to_vec().into());
                    if let Err(e) = ws_sender.send(message).await {
                        warn!("Failed to send to WebSocket: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("Failed to read from target: {}", e);
                    break;
                }
            }
        }
    };

    // Run both directions concurrently
    tokio::select! {
        _ = ws_to_target => debug!("WebSocket to target forwarding ended"),
        _ = target_to_ws => debug!("Target to WebSocket forwarding ended"),
    }

    info!("WebSocket proxy connection to {}:{} ended", host, port);
    Ok(())
}

/// Health check endpoint for the proxy
pub async fn proxy_health() -> impl IntoResponse {
    (StatusCode::OK, "WebSocket proxy is healthy")
}

/// Information endpoint for proxy configuration
pub async fn proxy_info(
    State(validator): State<Arc<ProxyValidator>>,
) -> impl IntoResponse {
    let config = validator.config();
    let info = serde_json::json!({
        "enabled": config.enabled,
        "allowed_hosts_count": config.allowed_hosts.len(),
        "allowed_ports": config.allowed_ports,
        "allow_localhost": config.allow_localhost,
        "allow_private_ips": config.allow_private_ips,
    });
    
    (StatusCode::OK, serde_json::to_string_pretty(&info).unwrap())
}

use futures_util::{SinkExt, StreamExt};
use axum::extract::ws::{WebSocketUpgrade as AxumWebSocketUpgrade, WebSocket};