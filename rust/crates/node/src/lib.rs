//! Node orchestration: a single BarterBackup instance in Rust.
//!
//! This mirrors internal/bbnode in Go and exposes the same RPC services using tonic.
//! Networking is abstracted and will be provided by `netmock` and `nettor` crates.

use anyhow::Result;
use futures::{stream, Stream};
use protos::{bbrpc, clirpc};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::pin::Pin;
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
        // TODO: use torut/arti to compute the real v3 onion name.
        // For the prototype we use a stable placeholder derived from the pubkey bytes.
        let onion = hex::encode(pubk.as_bytes());
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

    /// Returns a reference to the Ed25519 keypair.
    pub fn ed25519_keypair(&self) -> &ed25519_dalek::Keypair { &self.ed_kp }
}

// -------------------- clirpc --------------------

pub struct CliService {
    node: Arc<Node>,
}

impl CliService {
    pub fn new(node: Arc<Node>) -> Self { Self { node } }
}

#[tonic::async_trait]
impl clirpc::barter_backup_client_server::BarterBackupClient for CliService {
    type ProposeContractStream = Pin<Box<dyn Stream<Item = Result<clirpc::ProposeContractUpdate, Status>> + Send + 'static>>;
    type CheckContractStream = Pin<Box<dyn Stream<Item = Result<clirpc::CheckContractUpdate, Status>> + Send + 'static>>;
    type RecoverContentStream = Pin<Box<dyn Stream<Item = Result<clirpc::RecoverContentUpdate, Status>> + Send + 'static>>;
    type CliChatStream = Pin<Box<dyn Stream<Item = Result<clirpc::ChatEvent, Status>> + Send + 'static>>;

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

    async fn unlock(
        &self,
        _request: Request<clirpc::UnlockRequest>,
    ) -> Result<Response<clirpc::UnlockResponse>, Status> {
        Err(Status::unimplemented("Unlock not implemented in prototype"))
    }

    async fn connect_peer(
        &self,
        _request: Request<clirpc::ConnectPeerRequest>,
    ) -> Result<Response<clirpc::ConnectPeerResponse>, Status> {
        Err(Status::unimplemented("ConnectPeer not implemented in prototype"))
    }

    async fn connected_peers(
        &self,
        _request: Request<clirpc::ConnectedPeersRequest>,
    ) -> Result<Response<clirpc::ConnectedPeersResponse>, Status> {
        Err(Status::unimplemented("ConnectedPeers not implemented in prototype"))
    }

    async fn set_file(
        &self,
        _request: Request<clirpc::SetFileRequest>,
    ) -> Result<Response<clirpc::SetFileResponse>, Status> {
        Err(Status::unimplemented("SetFile not implemented in prototype"))
    }

    async fn get_file(
        &self,
        _request: Request<clirpc::GetFileRequest>,
    ) -> Result<Response<clirpc::GetFileResponse>, Status> {
        Err(Status::unimplemented("GetFile not implemented in prototype"))
    }

    async fn list_files(
        &self,
        _request: Request<clirpc::ListFilesRequest>,
    ) -> Result<Response<clirpc::ListFilesResponse>, Status> {
        Err(Status::unimplemented("ListFiles not implemented in prototype"))
    }

    async fn set_storage_config(
        &self,
        _request: Request<clirpc::SetStorageConfigRequest>,
    ) -> Result<Response<clirpc::SetStorageConfigResponse>, Status> {
        Err(Status::unimplemented("SetStorageConfig not implemented in prototype"))
    }

    async fn get_storage_config(
        &self,
        _request: Request<clirpc::GetStorageConfigRequest>,
    ) -> Result<Response<clirpc::GetStorageConfigResponse>, Status> {
        Err(Status::unimplemented("GetStorageConfig not implemented in prototype"))
    }

    async fn get_contracts(
        &self,
        _request: Request<clirpc::GetContractsRequest>,
    ) -> Result<Response<clirpc::GetContractsResponse>, Status> {
        Err(Status::unimplemented("GetContracts not implemented in prototype"))
    }

    async fn propose_contract(
        &self,
        _request: Request<clirpc::ProposeContractRequest>,
    ) -> Result<Response<Self::ProposeContractStream>, Status> {
        let s = stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    async fn check_contract(
        &self,
        _request: Request<clirpc::CheckContractRequest>,
    ) -> Result<Response<Self::CheckContractStream>, Status> {
        let s = stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    async fn recover_content(
        &self,
        _request: Request<clirpc::RecoverContentRequest>,
    ) -> Result<Response<Self::RecoverContentStream>, Status> {
        let s = stream::empty();
        Ok(Response::new(Box::pin(s)))
    }

    async fn set_aead_key_for_peer(
        &self,
        _request: Request<clirpc::SetAeadKeyForPeerRequest>,
    ) -> Result<Response<clirpc::SetAeadKeyForPeerResponse>, Status> {
        Err(Status::unimplemented("SetAeadKeyForPeer not implemented in prototype"))
    }

    async fn cli_chat(
        &self,
        _request: Request<tonic::Streaming<clirpc::ChatAction>>,
    ) -> Result<Response<Self::CliChatStream>, Status> {
        let s = stream::empty();
        Ok(Response::new(Box::pin(s)))
    }
}

// -------------------- bbrpc --------------------

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

    async fn peer_exchange(
        &self,
        _request: Request<bbrpc::PeerExchangeRequest>,
    ) -> Result<Response<bbrpc::PeerExchangeResponse>, Status> {
        Err(Status::unimplemented("PeerExchange not implemented in prototype"))
    }

    async fn get_content_revision(
        &self,
        _request: Request<bbrpc::GetContentRevisionRequest>,
    ) -> Result<Response<bbrpc::GetContentRevisionResponse>, Status> {
        Err(Status::unimplemented("GetContentRevision not implemented in prototype"))
    }

    async fn set_content_revision(
        &self,
        _request: Request<bbrpc::SetContentRevisionRequest>,
    ) -> Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
        Err(Status::unimplemented("SetContentRevision not implemented in prototype"))
    }

    async fn download(
        &self,
        _request: Request<bbrpc::DownloadRequest>,
    ) -> Result<Response<bbrpc::DownloadResponse>, Status> {
        Err(Status::unimplemented("Download not implemented in prototype"))
    }

    async fn encrypted_download(
        &self,
        _request: Request<bbrpc::EncryptedDownloadRequest>,
    ) -> Result<Response<bbrpc::EncryptedDownloadResponse>, Status> {
        Err(Status::unimplemented("EncryptedDownload not implemented in prototype"))
    }

    async fn chat(
        &self,
        _request: Request<bbrpc::ChatRequest>,
    ) -> Result<Response<bbrpc::ChatResponse>, Status> {
        Err(Status::unimplemented("Chat not implemented in prototype"))
    }

    async fn encrypted_chat(
        &self,
        _request: Request<bbrpc::EncryptedChatRequest>,
    ) -> Result<Response<bbrpc::EncryptedChatResponse>, Status> {
        Err(Status::unimplemented("EncryptedChat not implemented in prototype"))
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
