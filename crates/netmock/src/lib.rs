//! TLS-backed mock peer transport for multi-node tests.
//!
//! The mock transport uses localhost TCP plus the same mutual TLS policy that
//! peer-to-peer traffic uses in production. This lets tests exercise client
//! certificate identity extraction and server certificate onion pinning without
//! depending on Tor.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use futures_util::Stream;
use keys::onion_hostname_from_public_key;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::CommonState;
use tokio_util::sync::CancellationToken;
use tracing::warn;
use transport::{PeerClient, PeerConnector};

/// SESSION_REGISTRIES tracks one local peer-session registry per mock onion.
static SESSION_REGISTRIES: OnceLock<Mutex<BTreeMap<String, transport::PeerSessionRegistry>>> =
    OnceLock::new();

fn session_registries() -> &'static Mutex<BTreeMap<String, transport::PeerSessionRegistry>> {
    SESSION_REGISTRIES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// MockPeerListener is a localhost TCP listener wrapped in peer TLS and yamux.
pub struct MockPeerListener {
    endpoint: String,
    local_addr: SocketAddr,
    local_onion: String,
    incoming: transport::PeerSessionIncoming,
    shutdown: CancellationToken,
    accept_task: tokio::task::JoinHandle<()>,
}

impl MockPeerListener {
    /// Return the `https://` endpoint used by clients to reach this listener.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Return the bound socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.local_addr)
    }

    /// Convert the listener into a tonic-compatible incoming stream.
    pub fn into_incoming(self) -> MockPeerIncoming {
        MockPeerIncoming {
            incoming: self.incoming,
            local_onion: self.local_onion,
            shutdown: self.shutdown,
            accept_task: Some(self.accept_task),
        }
    }
}

/// MockPeerIncoming keeps the accept loop alive for as long as tonic holds the
/// incoming stream.
pub struct MockPeerIncoming {
    incoming: transport::PeerSessionIncoming,
    local_onion: String,
    shutdown: CancellationToken,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl Stream for MockPeerIncoming {
    type Item = Result<transport::PeerSessionServerIo, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.incoming).poll_next(cx)
    }
}

impl Drop for MockPeerIncoming {
    fn drop(&mut self) {
        self.shutdown.cancel();
        let _ = self.accept_task.take();
        session_registries()
            .lock()
            .unwrap()
            .remove(&self.local_onion);
    }
}

/// Bind a TLS listener suitable for peer-to-peer gRPC tests.
pub async fn bind_peer_listener(server_priv: &SecretKey) -> Result<MockPeerListener> {
    let local_onion = onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(server_priv));
    let sessions = transport::PeerSessionRegistry::new(local_onion.clone());
    session_registries()
        .lock()
        .unwrap()
        .insert(local_onion.clone(), sessions.clone());

    let server_tls = tlsutil::build_peer_server_tls(server_priv)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    let endpoint = format!("https://{local_addr}");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();
    let accept_sessions = sessions.clone();

    let accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_signal.cancelled() => break,
                accept_result = listener.accept() => {
                    let (socket, _) = match accept_result {
                        Ok(socket) => socket,
                        Err(error) => {
                            warn!(%error, "mock peer listener accept failed");
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let sessions = accept_sessions.clone();
                    tokio::spawn(async move {
                        let result = async {
                            let tls_stream = acceptor.accept(socket).await.map_err(io::Error::other)?;
                            let peer_public_key =
                                peer_public_key_from_common_state(tls_stream.get_ref().1)
                                    .map_err(io::Error::other)?;
                            let peer_onion = onion_hostname_from_public_key(&peer_public_key);
                            sessions
                                .register_inbound_session(
                                    &peer_onion,
                                    peer_public_key,
                                    Box::new(tls_stream),
                                )
                                .await
                                .map_err(io::Error::other)
                        }
                        .await;
                        if let Err(error) = result {
                            warn!(%error, "failed to register inbound mock peer session");
                        }
                    });
                }
            }
        }
    });

    Ok(MockPeerListener {
        endpoint,
        local_addr,
        local_onion,
        incoming: sessions.take_incoming()?,
        shutdown,
        accept_task,
    })
}

/// MockPeerConnector resolves onion hostnames to localhost mock endpoints.
#[derive(Debug, Default)]
pub struct MockPeerConnector {
    endpoints: Arc<RwLock<BTreeMap<String, String>>>,
}

impl MockPeerConnector {
    /// Create an empty mock peer connector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a peer onion hostname with its mock `https://` endpoint.
    pub fn register_peer(&self, peer_onion: &str, endpoint: &str) {
        self.endpoints
            .write()
            .unwrap()
            .insert(peer_onion.to_string(), endpoint.to_string());
    }

    fn local_sessions(&self, client_private_key: &SecretKey) -> transport::PeerSessionRegistry {
        let local_onion =
            onion_hostname_from_public_key(&ed25519_dalek::PublicKey::from(client_private_key));
        let mut registries = session_registries().lock().unwrap();
        registries
            .entry(local_onion.clone())
            .or_insert_with(|| transport::PeerSessionRegistry::new(local_onion))
            .clone()
    }

    /// Return how many peers currently have one live outer session for this
    /// local node.
    pub fn connected_peer_count(&self, client_private_key: &SecretKey) -> usize {
        self.local_sessions(client_private_key)
            .connected_peer_count()
    }

    /// Return the live outer-session nonce for `peer_onion`, if any.
    pub fn session_nonce(&self, client_private_key: &SecretKey, peer_onion: &str) -> Option<u64> {
        self.local_sessions(client_private_key)
            .session_nonce(peer_onion)
    }

    /// Return whether the live outer session for `peer_onion` was initiated by
    /// the local node.
    pub fn session_initiated_by_us(
        &self,
        client_private_key: &SecretKey,
        peer_onion: &str,
    ) -> Option<bool> {
        self.local_sessions(client_private_key)
            .session_initiated_by_us(peer_onion)
    }

    /// Shut down the current outer session for `peer_onion`, if one exists.
    pub async fn shutdown_peer_session(&self, client_private_key: &SecretKey, peer_onion: &str) {
        self.local_sessions(client_private_key)
            .shutdown_peer(peer_onion)
            .await;
    }
}

#[async_trait]
impl PeerConnector for MockPeerConnector {
    async fn connect(
        &self,
        peer_onion: &str,
        client_private_key: &SecretKey,
    ) -> Result<PeerClient> {
        let sessions = self.local_sessions(client_private_key);
        if sessions.connected(peer_onion) {
            return Ok(sessions.client_for_peer(peer_onion));
        }

        let endpoint = self
            .endpoints
            .read()
            .unwrap()
            .get(peer_onion)
            .cloned()
            .ok_or_else(|| anyhow!("unknown peer onion: {peer_onion}"))?;
        let client_tls = tlsutil::build_peer_client_tls(peer_onion, client_private_key)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let server_name = ServerName::try_from(peer_onion.to_string())
            .map_err(|err| anyhow!("invalid peer onion {peer_onion:?}: {err}"))?;
        let socket_addr = endpoint.strip_prefix("https://").unwrap_or(&endpoint);
        let tcp_stream = TcpStream::connect(socket_addr).await?;
        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(io::Error::other)?;
        let peer_public_key = peer_public_key_from_common_state(tls_stream.get_ref().1)?;
        sessions
            .register_outbound_session(peer_onion, peer_public_key, Box::new(tls_stream))
            .await
    }

    fn connected(&self, peer_onion: &str, client_private_key: &SecretKey) -> bool {
        self.local_sessions(client_private_key)
            .connected(peer_onion)
    }

    fn session_nonce(&self, peer_onion: &str, client_private_key: &SecretKey) -> Option<u64> {
        self.local_sessions(client_private_key)
            .session_nonce(peer_onion)
    }

    fn set_opportunistic_session_capacity(&self, client_private_key: &SecretKey, capacity: usize) {
        self.local_sessions(client_private_key)
            .set_opportunistic_capacity(capacity);
    }

    fn set_durable_session_peers(&self, client_private_key: &SecretKey, durable_peers: &[String]) {
        self.local_sessions(client_private_key)
            .set_durable_peers(durable_peers);
    }
}

/// Extract the authenticated peer public key from one completed rustls session.
fn peer_public_key_from_common_state(state: &CommonState) -> Result<ed25519_dalek::PublicKey> {
    let peer_certificates = state
        .peer_certificates()
        .ok_or_else(|| anyhow!("peer TLS handshake omitted client certificate"))?;
    let end_entity = peer_certificates
        .first()
        .ok_or_else(|| anyhow!("peer TLS handshake omitted client certificate"))?;
    tlsutil::public_key_from_certificate_der(end_entity.as_ref())
}
