//! Node orchestration for a single BarterBackup instance.
//!
//! The current implementation focuses on the local encrypted store and the RPC
//! surface that depends on it. Peer-to-peer contract management and Tor-backed
//! transport still need further work.

use anyhow::Result;
use futures::{stream, Stream};
use protos::{bbrpc, clirpc};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use storage::{Filesystem, StorageError, Store};
use tonic::{Code, Response, Status};

/// Node represents a single BarterBackup instance.
pub struct Node {
    /// ed25519_keypair is the deterministic node identity derived from the seed.
    ed25519_keypair: ed25519_dalek::Keypair,
    /// onion_address is the stable placeholder onion hostname for the node.
    onion_address: String,
    /// started_at tracks daemon uptime for local health checks.
    started_at: Mutex<Option<Instant>>,
    /// store holds the encrypted local content store when configured.
    store: Option<Mutex<Store>>,
    /// known_peers is the locally configured peer list.
    known_peers: Mutex<BTreeSet<String>>,
    /// storage_config is the current local storage policy snapshot.
    storage_config: Mutex<clirpc::StorageConfig>,
}

impl Node {
    /// Create a node identity without attaching a local encrypted store.
    pub fn new(seed: &str) -> Result<Self> {
        Self::build(seed, None)
    }

    /// Create a node identity with a local encrypted store.
    pub fn with_local_storage(seed: &str, filesystem: Arc<dyn Filesystem>) -> Result<Self> {
        Self::build(seed, Some(filesystem))
    }

    /// Return the node onion hostname.
    pub fn address(&self) -> &str {
        &self.onion_address
    }

    /// Mark the node as started so uptime can be reported.
    pub fn mark_started(&self) {
        *self.started_at.lock().unwrap() = Some(Instant::now());
    }

    /// Return the deterministic Ed25519 keypair.
    pub fn ed25519_keypair(&self) -> &ed25519_dalek::Keypair {
        &self.ed25519_keypair
    }

    /// Build a node, optionally attaching an encrypted local store.
    fn build(seed: &str, filesystem: Option<Arc<dyn Filesystem>>) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        let (keypair, public_key) = keys::derive_ed25519_from_master(&master, "tor/onion/v3")?;
        let onion_address = format!("{}.onion", hex::encode(public_key.as_bytes()));
        let store = filesystem
            .map(|filesystem| Store::new(filesystem, &master))
            .transpose()?
            .map(Mutex::new);

        Ok(Self {
            ed25519_keypair: keypair,
            onion_address,
            started_at: Mutex::new(None),
            store,
            known_peers: Mutex::new(BTreeSet::new()),
            storage_config: Mutex::new(clirpc::StorageConfig::default()),
        })
    }

    /// Return node uptime in whole seconds.
    fn uptime_seconds(&self) -> i64 {
        self.started_at
            .lock()
            .unwrap()
            .map(|started_at| Instant::now().duration_since(started_at).as_secs() as i64)
            .unwrap_or(0)
    }

    /// Run a synchronous operation against the encrypted store.
    fn with_store<T>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T, StorageError>,
    ) -> Result<T, Status> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("local store is not configured"))?;
        let mut store = store.lock().unwrap();
        operation(&mut store).map_err(map_storage_error)
    }

    /// Build the responder content summary for bbrpc.
    fn responder_content(&self) -> Result<Option<bbrpc::ContentInfo>, Status> {
        self.with_store(|store| {
            Ok(store.current_content().map(|current| bbrpc::ContentInfo {
                content_id: current.content_id.clone(),
                content_length: i64::try_from(current.blob_len).unwrap_or(i64::MAX),
            }))
        })
    }
}

/// CliService exposes the local daemon RPC surface.
pub struct CliService {
    /// node is the backing BarterBackup node.
    node: Arc<Node>,
}

impl CliService {
    /// Create a local CLI service bound to the provided node.
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }
}

#[tonic::async_trait]
impl clirpc::barter_backup_client_server::BarterBackupClient for CliService {
    /// ProposeContractStream is the streaming response for contract proposals.
    type ProposeContractStream = Pin<
        Box<
            dyn Stream<Item = Result<clirpc::ProposeContractUpdate, tonic::Status>>
                + Send
                + 'static,
        >,
    >;

    /// CheckContractStream is the streaming response for contract checks.
    type CheckContractStream = Pin<
        Box<dyn Stream<Item = Result<clirpc::CheckContractUpdate, tonic::Status>> + Send + 'static>,
    >;

    /// RecoverContentStream is the streaming response for recovery events.
    type RecoverContentStream = Pin<
        Box<
            dyn Stream<Item = Result<clirpc::RecoverContentUpdate, tonic::Status>> + Send + 'static,
        >,
    >;

    async fn local_health_check(
        &self,
        _request: tonic::Request<clirpc::HealthCheckRequest>,
    ) -> Result<tonic::Response<clirpc::HealthCheckResponse>, tonic::Status> {
        Ok(Response::new(clirpc::HealthCheckResponse {
            server_onion: self.node.address().to_string(),
            uptime_seconds: self.node.uptime_seconds(),
        }))
    }

    async fn unlock(
        &self,
        request: tonic::Request<clirpc::UnlockRequest>,
    ) -> Result<tonic::Response<clirpc::UnlockResponse>, tonic::Status> {
        if request.into_inner().main_password.is_empty() {
            return Err(Status::invalid_argument("main password is required"));
        }

        Ok(Response::new(clirpc::UnlockResponse {}))
    }

    async fn connect_peer(
        &self,
        request: tonic::Request<clirpc::ConnectPeerRequest>,
    ) -> Result<tonic::Response<clirpc::ConnectPeerResponse>, tonic::Status> {
        let request = request.into_inner();
        let peer = request
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }

        self.node
            .known_peers
            .lock()
            .unwrap()
            .insert(peer.onion_service_id);
        Ok(Response::new(clirpc::ConnectPeerResponse {}))
    }

    async fn connected_peers(
        &self,
        _request: tonic::Request<clirpc::ConnectedPeersRequest>,
    ) -> Result<tonic::Response<clirpc::ConnectedPeersResponse>, tonic::Status> {
        let connected_peers = self
            .node
            .known_peers
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(|onion_service_id| clirpc::Peer { onion_service_id })
            .collect();

        Ok(Response::new(clirpc::ConnectedPeersResponse {
            connected_peers,
            online_not_connected_peers: Vec::new(),
            offline_peers: Vec::new(),
        }))
    }

    async fn set_file(
        &self,
        request: tonic::Request<clirpc::SetFileRequest>,
    ) -> Result<tonic::Response<clirpc::SetFileResponse>, tonic::Status> {
        let request = request.into_inner();
        let file = request
            .file
            .ok_or_else(|| Status::invalid_argument("file is required"))?;
        if file.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }

        self.node
            .with_store(|store| store.set_file(&file.name, file.data))?;
        Ok(Response::new(clirpc::SetFileResponse {}))
    }

    async fn delete_file(
        &self,
        request: tonic::Request<clirpc::DeleteFileRequest>,
    ) -> Result<tonic::Response<clirpc::DeleteFileResponse>, tonic::Status> {
        let request = request.into_inner();
        if request.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }

        self.node
            .with_store(|store| store.delete_file(&request.name))?;
        Ok(Response::new(clirpc::DeleteFileResponse {}))
    }

    async fn get_file(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<tonic::Response<clirpc::GetFileResponse>, tonic::Status> {
        let request = request.into_inner();
        if request.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }

        let data = self
            .node
            .with_store(|store| store.get_file(&request.name))?;
        Ok(Response::new(clirpc::GetFileResponse {
            file: Some(clirpc::File {
                name: request.name,
                data,
            }),
        }))
    }

    async fn list_files(
        &self,
        _request: tonic::Request<clirpc::ListFilesRequest>,
    ) -> Result<tonic::Response<clirpc::ListFilesResponse>, tonic::Status> {
        let names = self.node.with_store(|store| Ok(store.list_files()))?;
        Ok(Response::new(clirpc::ListFilesResponse { name: names }))
    }

    async fn set_storage_config(
        &self,
        request: tonic::Request<clirpc::SetStorageConfigRequest>,
    ) -> Result<tonic::Response<clirpc::SetStorageConfigResponse>, tonic::Status> {
        let request = request.into_inner();
        let config = request
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;
        *self.node.storage_config.lock().unwrap() = config;
        Ok(Response::new(clirpc::SetStorageConfigResponse {}))
    }

    async fn get_storage_config(
        &self,
        _request: tonic::Request<clirpc::GetStorageConfigRequest>,
    ) -> Result<tonic::Response<clirpc::GetStorageConfigResponse>, tonic::Status> {
        let config = self.node.storage_config.lock().unwrap().clone();
        let our_content_bytes = self
            .node
            .with_store(|store| {
                Ok(store
                    .current_content()
                    .map(|current| i64::try_from(current.blob_len).unwrap_or(i64::MAX))
                    .unwrap_or(0))
            })
            .unwrap_or(0);

        Ok(Response::new(clirpc::GetStorageConfigResponse {
            config: Some(config),
            info: Some(clirpc::StorageInfo {
                online_peers_storage_obligations_bytes: 0,
                offline_peers_storage_obligations_bytes: 0,
                expired_offline_peers_storage_obligations_bytes: 0,
                our_content_bytes,
                maximum_peer_content_accepted_bytes: 0,
            }),
        }))
    }

    async fn get_contracts(
        &self,
        _request: tonic::Request<clirpc::GetContractsRequest>,
    ) -> Result<tonic::Response<clirpc::GetContractsResponse>, tonic::Status> {
        Ok(Response::new(clirpc::GetContractsResponse {
            contracts: Vec::new(),
        }))
    }

    async fn propose_contract(
        &self,
        _request: tonic::Request<clirpc::ProposeContractRequest>,
    ) -> Result<tonic::Response<Self::ProposeContractStream>, tonic::Status> {
        Ok(Response::new(Box::pin(stream::empty())))
    }

    async fn check_contract(
        &self,
        _request: tonic::Request<clirpc::CheckContractRequest>,
    ) -> Result<tonic::Response<Self::CheckContractStream>, tonic::Status> {
        Ok(Response::new(Box::pin(stream::empty())))
    }

    async fn recover_content(
        &self,
        _request: tonic::Request<clirpc::RecoverContentRequest>,
    ) -> Result<tonic::Response<Self::RecoverContentStream>, tonic::Status> {
        Ok(Response::new(Box::pin(stream::empty())))
    }
}

/// P2pService exposes the peer-to-peer RPC surface.
pub struct P2pService {
    /// node is the backing BarterBackup node.
    node: Arc<Node>,
}

impl P2pService {
    /// Create a peer-to-peer service bound to the provided node.
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }
}

#[tonic::async_trait]
impl bbrpc::barter_backup_server_server::BarterBackupServer for P2pService {
    async fn health_check(
        &self,
        _request: tonic::Request<bbrpc::HealthCheckRequest>,
    ) -> Result<tonic::Response<bbrpc::HealthCheckResponse>, tonic::Status> {
        Ok(Response::new(bbrpc::HealthCheckResponse {
            client_onion: String::new(),
            server_onion: self.node.address().to_string(),
        }))
    }

    async fn peer_exchange(
        &self,
        request: tonic::Request<bbrpc::PeerExchangeRequest>,
    ) -> Result<tonic::Response<bbrpc::PeerExchangeResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut known_peers = self.node.known_peers.lock().unwrap();
        for peer in request.peers {
            known_peers.insert(hex::encode(peer.onion_pubkey));
        }

        let peers = known_peers
            .iter()
            .cloned()
            .map(|hex_pubkey| bbrpc::Peer {
                onion_pubkey: hex::decode(hex_pubkey).unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(bbrpc::PeerExchangeResponse { peers }))
    }

    async fn get_content_revision(
        &self,
        _request: tonic::Request<bbrpc::GetContentRevisionRequest>,
    ) -> Result<tonic::Response<bbrpc::GetContentRevisionResponse>, tonic::Status> {
        Ok(Response::new(bbrpc::GetContentRevisionResponse {
            requester_content: None,
            requester_remaining_seconds: 0,
            responder_content: self.node.responder_content()?,
        }))
    }

    async fn set_content_revision(
        &self,
        _request: tonic::Request<bbrpc::SetContentRevisionRequest>,
    ) -> Result<tonic::Response<bbrpc::SetContentRevisionResponse>, tonic::Status> {
        Err(Status::unimplemented(
            "SetContentRevision still needs peer identity plumbing",
        ))
    }

    async fn download(
        &self,
        request: tonic::Request<bbrpc::DownloadRequest>,
    ) -> Result<tonic::Response<bbrpc::DownloadResponse>, tonic::Status> {
        let request = request.into_inner();
        if request.content_id.is_empty() {
            return Err(Status::invalid_argument("content_id is required"));
        }
        if request.offset < 0 {
            return Err(Status::invalid_argument("offset must be non-negative"));
        }

        let blob = self
            .node
            .with_store(|store| store.read_blob_by_id(&request.content_id))?;
        let total_length = i64::try_from(blob.len()).unwrap_or(i64::MAX);
        let offset = usize::try_from(request.offset)
            .map_err(|_| Status::invalid_argument("offset is too large"))?;
        if offset > blob.len() {
            return Err(Status::out_of_range("offset is past the end of the blob"));
        }

        let sha256 = Sha256::digest(&blob).to_vec();
        let raw_bytes = bbrpc::RawBytes {
            value: blob[offset..].to_vec(),
        };
        Ok(Response::new(bbrpc::DownloadResponse {
            total_length,
            sha256,
            section: Some(bbrpc::download_response::Section::RawBytes(raw_bytes)),
        }))
    }
}

/// Convert a storage-layer error into a gRPC status code.
fn map_storage_error(error: StorageError) -> Status {
    match error {
        StorageError::InvalidFileName => Status::invalid_argument("file name is required"),
        StorageError::FileNotFound => Status::not_found("file not found"),
        StorageError::CannotDeleteLastFile => {
            Status::failed_precondition("cannot delete the last file")
        }
        StorageError::RecoveryRequired(message) => Status::failed_precondition(message),
        other => Status::new(Code::Internal, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protos::bbrpc::barter_backup_server_server::BarterBackupServer;
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::{
        BarterBackupClient, BarterBackupClientServer,
    };
    use std::time::Duration;
    use tonic::transport::Endpoint;

    /// Spawn an h2c local CLI server for integration-style node tests.
    async fn spawn_cli_server(
        node: Arc<Node>,
    ) -> anyhow::Result<(
        BarterBackupClientClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    )> {
        let service = CliService::new(node);
        let router =
            tonic::transport::Server::builder().add_service(BarterBackupClientServer::new(service));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(
            router.serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        let channel = Endpoint::from_shared(format!("http://{address}"))?
            .connect()
            .await?;

        Ok((BarterBackupClientClient::new(channel), handle))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_healthcheck_reports_uptime_and_onion() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("password")?);
        node.mark_started();
        let (mut client, server) = spawn_cli_server(node.clone()).await?;

        let first = client
            .local_health_check(clirpc::HealthCheckRequest {})
            .await?
            .into_inner();
        assert_eq!(first.server_onion, node.address());

        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = client
            .local_health_check(clirpc::HealthCheckRequest {})
            .await?
            .into_inner();
        assert!(second.uptime_seconds >= first.uptime_seconds);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_file_rpc_round_trip_uses_encrypted_store() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("password", filesystem)?);
        let (mut client, server) = spawn_cli_server(node.clone()).await?;

        client
            .set_file(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            })
            .await?;

        let listed = client
            .list_files(clirpc::ListFilesRequest {})
            .await?
            .into_inner();
        assert_eq!(listed.name, vec!["alpha.txt".to_string()]);

        let fetched = client
            .get_file(clirpc::GetFileRequest {
                name: "alpha.txt".to_string(),
            })
            .await?
            .into_inner()
            .file
            .unwrap();
        assert_eq!(fetched.data, b"alpha-body".to_vec());

        let delete_last = client
            .delete_file(clirpc::DeleteFileRequest {
                name: "alpha.txt".to_string(),
            })
            .await
            .unwrap_err();
        assert_eq!(delete_last.code(), tonic::Code::FailedPrecondition);

        client
            .set_file(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "beta.txt".to_string(),
                    data: b"beta-body".to_vec(),
                }),
            })
            .await?;
        client
            .delete_file(clirpc::DeleteFileRequest {
                name: "alpha.txt".to_string(),
            })
            .await?;

        let listed = client
            .list_files(clirpc::ListFilesRequest {})
            .await?
            .into_inner();
        assert_eq!(listed.name, vec!["beta.txt".to_string()]);

        let storage_info = client
            .get_storage_config(clirpc::GetStorageConfigRequest {})
            .await?
            .into_inner()
            .info
            .unwrap();
        assert!(storage_info.our_content_bytes > 0);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_revision_and_download_reflect_current_blob() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("password", filesystem)?);
        let cli = CliService::new(node.clone());
        let p2p = P2pService::new(node.clone());

        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
            }),
        }))
        .await?;

        let revision = p2p
            .get_content_revision(tonic::Request::new(bbrpc::GetContentRevisionRequest {}))
            .await?
            .into_inner();
        let responder = revision.responder_content.unwrap();
        assert!(!responder.content_id.is_empty());
        assert!(responder.content_length > 0);

        let download = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id.clone(),
                offset: 0,
                reference_content_id: Vec::new(),
            }))
            .await?
            .into_inner();
        assert_eq!(download.total_length, responder.content_length);

        match download.section.unwrap() {
            bbrpc::download_response::Section::RawBytes(raw_bytes) => {
                assert!(raw_bytes.value.starts_with(content::HEADER_MAGIC));
            }
            bbrpc::download_response::Section::Reference(_) => {
                panic!("download unexpectedly returned a reference section");
            }
        }

        Ok(())
    }
}
