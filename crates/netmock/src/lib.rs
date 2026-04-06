//! TLS-backed mock peer transport for multi-node tests.
//!
//! The mock transport uses localhost TCP plus the same mutual TLS policy that
//! peer-to-peer traffic uses in production. This lets tests exercise client
//! certificate identity extraction and server certificate onion pinning without
//! depending on Tor.

use anyhow::Result;
use async_trait::async_trait;
use ed25519_dalek::SecretKey;
use futures_util::StreamExt;
use hyper_util::rt::TokioIo;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;
use transport::{PeerClient, PeerConnector};

/// MockPeerListener is a localhost TCP listener wrapped in peer TLS.
pub struct MockPeerListener {
    endpoint: String,
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl MockPeerListener {
    /// Return the `https://` endpoint used by clients to reach this listener.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Return the bound socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Convert the listener into a tonic-compatible incoming stream.
    pub fn into_incoming(
        self,
    ) -> impl tokio_stream::Stream<Item = Result<TlsStream<TcpStream>, io::Error>> {
        TcpListenerStream::new(self.listener).filter_map(move |result| {
            let acceptor = self.acceptor.clone();

            async move {
                match result {
                    Ok(socket) => match acceptor.accept(socket).await {
                        Ok(stream) => Some(Ok::<TlsStream<TcpStream>, io::Error>(stream)),
                        Err(err) => Some(Err(io::Error::other(err))),
                    },
                    Err(err) => Some(Err(err)),
                }
            }
        })
    }
}

/// Bind a TLS listener suitable for peer-to-peer gRPC tests.
pub async fn bind_peer_listener(server_priv: &SecretKey) -> Result<MockPeerListener> {
    let server_tls = tlsutil::build_peer_server_tls(server_priv)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("https://{}", listener.local_addr()?);

    Ok(MockPeerListener {
        endpoint,
        listener,
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_tls)),
    })
}

/// Connect to a mock peer server while pinning its expected onion hostname.
pub async fn connect_peer_channel(
    endpoint: &str,
    expected_server_onion: &str,
    client_priv: &SecretKey,
) -> Result<Channel> {
    let client_tls = tlsutil::build_peer_client_tls(expected_server_onion, client_priv)?;
    tlsutil::connect_channel(endpoint, client_tls).await
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
}

#[async_trait]
impl PeerConnector for MockPeerConnector {
    async fn connect(
        &self,
        peer_onion: &str,
        client_private_key: &SecretKey,
    ) -> Result<PeerClient> {
        self.endpoints
            .read()
            .unwrap()
            .get(peer_onion)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown peer onion: {peer_onion}"))?;
        let client_tls = tlsutil::build_peer_client_tls(peer_onion, client_private_key)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let server_name = ServerName::try_from(peer_onion.to_string())
            .map_err(|err| anyhow::anyhow!("invalid peer onion {peer_onion:?}: {err}"))?;
        let peer_onion = peer_onion.to_string();
        let endpoints = self.endpoints.clone();
        let channel = Endpoint::from_shared(format!("http://{peer_onion}:80"))?
            .connect_with_connector(service_fn(move |_| {
                let connector = connector.clone();
                let server_name = server_name.clone();
                let peer_onion = peer_onion.clone();
                let endpoints = endpoints.clone();

                async move {
                    let endpoint = endpoints
                        .read()
                        .unwrap()
                        .get(&peer_onion)
                        .cloned()
                        .ok_or_else(|| io::Error::other("unknown peer onion"))?;
                    let socket_addr = endpoint.strip_prefix("https://").unwrap_or(&endpoint);
                    let tcp_stream = TcpStream::connect(socket_addr).await?;
                    let tls_stream = connector
                        .connect(server_name, tcp_stream)
                        .await
                        .map_err(io::Error::other)?;

                    Ok::<_, io::Error>(TokioIo::new(tls_stream))
                }
            }))
            .await?;

        Ok(transport::configure_peer_client(PeerClient::new(channel)))
    }
}
