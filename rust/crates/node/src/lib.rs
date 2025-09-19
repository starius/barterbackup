//! Node orchestration: a single BarterBackup instance in Rust.
//!
//! This mirrors internal/bbnode in Go and exposes the same RPC services using tonic.
//! Networking is abstracted and will be provided by `netmock` and `nettor` crates.

use anyhow::Result;
use futures::FutureExt;
use protos::{bbrpc, clirpc};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

/// Node represents a single BarterBackup instance.
/// It implements both the peer-to-peer and local CLI services.
pub struct Node {
    master_priv: Vec<u8>,
    // Ed25519 private key in ed25519-dalek format.
    ed_kp: ed25519_dalek::Keypair,
    onion_addr: String,
    started_at: Arc<Mutex<Option<Instant>>>,
}

impl Node {
    /// Create a new node from a password/seed.
    pub fn new(seed: &str) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        let (kp, pubk) = keys::derive_ed25519_from_master(&master, "tor/onion/v3")?;
        // Compute Tor v3 onion address from the public key.
        let onion = torut::onion::OnionAddressV3::from(&(*pubk.as_bytes()))
            .to_string();
        Ok(Self {
            master_priv: master,
            ed_kp: kp,
            onion_addr: format!("{}.onion", onion),
            started_at: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns the onion address of the node.
    pub fn address(&self) -> &str { &self.onion_addr }

    /// Marks the node as started (used for uptime calculation).
    pub fn mark_started(&self) { *self.started_at.lock().unwrap() = Some(Instant::now()); }

    /// Return uptime in seconds since `mark_started`, or 0 if not started.
    fn uptime_seconds(&self) -> i64 {
        self.started_at
            .lock()
            .unwrap()
            .map(|t| Instant::now().duration_since(t).as_secs() as i64)
            .unwrap_or(0)
    }

    /// Returns a clone of the Ed25519 keypair.
    pub fn ed25519_keypair(&self) -> ed25519_dalek::Keypair { self.ed_kp.clone() }
}

// -------------------- clirpc --------------------

#[derive(Default)]
pub struct CliService {
    node: Arc<Node>,
}

impl CliService {
    pub fn new(node: Arc<Node>) -> Self { Self { node } }
}

#[tonic::async_trait]
impl clirpc::barter_backup_client_server::BarterBackupClient for CliService {
    async fn local_health_check(
        &self,
        _req: Request<clirpc::HealthCheckRequest>,
    ) -> Result<Response<clirpc::HealthCheckResponse>, Status> {
        let uptime = self.node.uptime_seconds();
        Ok(Response::new(clirpc::HealthCheckResponse {
            server_onion: self.node.address().to_string(),
            uptime_seconds: uptime,
        }))
    }

    // Other RPCs are intentionally left as stubs in this scaffold.
}

// -------------------- bbrpc --------------------

#[derive(Default)]
pub struct P2pService {
    node: Arc<Node>,
}

impl P2pService {
    pub fn new(node: Arc<Node>) -> Self { Self { node } }
}

#[tonic::async_trait]
impl bbrpc::barter_backup_server_server::BarterBackupServer for P2pService {
    async fn health_check(
        &self,
        _req: Request<bbrpc::HealthCheckRequest>,
    ) -> Result<Response<bbrpc::HealthCheckResponse>, Status> {
        // In Go, client_onion is inferred from the TLS client cert.
        // Here we leave it empty for now and return only server_onion.
        // TODO: When using rustls with client auth, plumb the peer cert via extensions
        // and compute the onion address from it.
        Ok(Response::new(bbrpc::HealthCheckResponse {
            client_onion: String::new(),
            server_onion: self.node.address().to_string(),
        }))
    }
}

// -------------------- simple test --------------------

#[cfg(test)]
mod tests {
    use super::*;
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::BarterBackupClientServer;

    #[tokio::test(flavor = "multi_thread")] 
    async fn local_healthcheck_reports_uptime_and_onion() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("password")?);
        node.mark_started();

        // Serve clirpc over a local TCP listener (tonic h2c).
        let svc = CliService::new(node.clone());
        let router = tonic::transport::Server::builder()
            .add_service(BarterBackupClientServer::new(svc));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let serve = router.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener));
        let server = tokio::spawn(serve);

        // Client connects without TLS (local-only test using h2c).
        let endpoint = format!("http://{}", addr);
        let channel = tonic::transport::Endpoint::from_shared(endpoint)?.connect().await?;
        let mut client = BarterBackupClientClient::new(channel);

        let r1 = client
            .local_health_check(clirpc::HealthCheckRequest {})
            .await?
            .into_inner();
        assert_eq!(r1.server_onion, node.address());

        tokio::time::sleep(Duration::from_millis(10)).await;
        let r2 = client
            .local_health_check(clirpc::HealthCheckRequest {})
            .await?
            .into_inner();
        assert_eq!(r2.server_onion, node.address());
        assert!(r2.uptime_seconds >= r1.uptime_seconds);

        server.abort();
        Ok(())
    }
}

