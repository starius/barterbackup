//! Node orchestration for a single BarterBackup instance.
//!
//! The current implementation focuses on the local encrypted store and the RPC
//! surface that depends on it. Peer-to-peer contract management and Tor-backed
//! transport still need further work.

use anyhow::Result;
use clock::{Clock, SystemClock, Timestamp};
use futures::{stream, Stream};
use protos::{bbrpc, clirpc};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use storage::{Filesystem, StorageError, Store};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Code, Response, Status};
use transport::PeerConnector;

const MAX_PEER_CONTENT_BYTES: i64 = 4 * 1024 * 1024;

/// PeerIdentity describes the authenticated peer that issued a request.
struct PeerIdentity {
    /// public_key is the Ed25519 key presented in the peer certificate.
    public_key: ed25519_dalek::PublicKey,
    /// onion_address is the Tor v3 hostname derived from `public_key`.
    onion_address: String,
}

/// Node represents a single BarterBackup instance.
pub struct Node {
    /// ed25519_keypair is the deterministic node identity derived from the seed.
    ed25519_keypair: ed25519_dalek::Keypair,
    /// onion_address is the stable Tor v3 hostname for the node identity key.
    onion_address: String,
    /// clock provides deterministic wall-clock time for scheduling and tests.
    clock: Arc<dyn Clock>,
    /// started_at tracks daemon uptime for local health checks.
    started_at: Mutex<Option<Timestamp>>,
    /// store holds the encrypted local content store when configured.
    store: Option<Mutex<Store>>,
    /// known_peers is the locally configured peer list.
    known_peers: Mutex<BTreeSet<String>>,
    /// storage_config is the current local storage policy snapshot.
    storage_config: Mutex<clirpc::StorageConfig>,
    /// peer_connector dials other nodes when peer sync is enabled.
    peer_connector: Mutex<Option<Arc<dyn PeerConnector>>>,
}

impl Node {
    /// Create a node identity without attaching a local encrypted store.
    pub fn new(seed: &str) -> Result<Self> {
        Self::build(seed, None, Arc::new(SystemClock))
    }

    /// Create a node identity with a local encrypted store.
    pub fn with_local_storage(seed: &str, filesystem: Arc<dyn Filesystem>) -> Result<Self> {
        Self::build(seed, Some(filesystem), Arc::new(SystemClock))
    }

    /// Create a node identity with a local encrypted store and explicit clock.
    pub fn with_local_storage_and_clock(
        seed: &str,
        filesystem: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Self::build(seed, Some(filesystem), clock)
    }

    /// Return the node onion hostname.
    pub fn address(&self) -> &str {
        &self.onion_address
    }

    /// Mark the node as started so uptime can be reported.
    pub fn mark_started(&self) {
        *self.started_at.lock().unwrap() = Some(self.clock.now());
    }

    /// Return the deterministic Ed25519 keypair.
    pub fn ed25519_keypair(&self) -> &ed25519_dalek::Keypair {
        &self.ed25519_keypair
    }

    /// Build a node, optionally attaching an encrypted local store.
    fn build(
        seed: &str,
        filesystem: Option<Arc<dyn Filesystem>>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        let (keypair, public_key) = keys::derive_ed25519_from_master(&master, "tor/onion/v3")?;
        let onion_address = keys::onion_hostname_from_public_key(&public_key);
        let store = filesystem
            .map(|filesystem| Store::new_with_time_source(filesystem, &master, clock.clone()))
            .transpose()?
            .map(Mutex::new);

        Ok(Self {
            ed25519_keypair: keypair,
            onion_address,
            clock,
            started_at: Mutex::new(None),
            store,
            known_peers: Mutex::new(BTreeSet::new()),
            storage_config: Mutex::new(clirpc::StorageConfig::default()),
            peer_connector: Mutex::new(None),
        })
    }

    /// Return node uptime in whole seconds.
    fn uptime_seconds(&self) -> i64 {
        self.started_at
            .lock()
            .unwrap()
            .map(|started_at| self.clock.now().secs.saturating_sub(started_at.secs) as i64)
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

    /// Install the outbound peer connector used for peer synchronization.
    pub fn set_peer_connector(&self, peer_connector: Arc<dyn PeerConnector>) {
        *self.peer_connector.lock().unwrap() = Some(peer_connector);
    }

    /// Extract the authenticated peer identity from the request TLS state.
    fn peer_identity_from_request<T>(
        &self,
        request: &tonic::Request<T>,
    ) -> Result<PeerIdentity, Status> {
        let tls_info = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let peer_certificates = tls_info
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let end_entity = peer_certificates
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let public_key = clitls::public_key_from_certificate_der(end_entity.as_ref())
            .map_err(|_| Status::unauthenticated("client certificate required"))?;

        Ok(PeerIdentity {
            onion_address: keys::onion_hostname_from_public_key(&public_key),
            public_key,
        })
    }

    /// Build a responder-side view of the caller's stored content, if any.
    fn requester_content(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<Option<bbrpc::ContentInfo>, Status> {
        self.with_store(|store| {
            let peer = store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
            let Some(peer) = peer else {
                return Ok(None);
            };
            if peer.content_id.is_empty() {
                return Ok(None);
            }

            match store.read_blob_by_id(&peer.content_id) {
                Ok(blob) => Ok(Some(bbrpc::ContentInfo {
                    content_id: peer.content_id,
                    content_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                })),
                Err(StorageError::FileNotFound) => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    /// Connect to another peer using the configured outbound transport.
    async fn connect_peer_client(&self, peer_onion: &str) -> Result<transport::PeerClient, Status> {
        let connector = self
            .peer_connector
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Status::failed_precondition("peer connector is not configured"))?;
        connector
            .connect(peer_onion, &self.ed25519_keypair.secret)
            .await
            .map_err(|error| Status::unavailable(format!("connect peer: {error}")))
    }

    /// Download an encrypted blob from a peer and verify the advertised hash.
    async fn download_peer_blob(
        &self,
        peer_onion: &str,
        content_id: &[u8],
    ) -> Result<Vec<u8>, Status> {
        let mut client = self.connect_peer_client(peer_onion).await?;
        let response = client
            .download(bbrpc::DownloadRequest {
                content_id: content_id.to_vec(),
                offset: 0,
                reference_content_id: Vec::new(),
            })
            .await
            .map_err(|error| Status::unavailable(format!("download peer content: {error}")))?
            .into_inner();
        if response.total_length < 0 {
            return Err(Status::internal("peer returned a negative content length"));
        }

        // The current protocol implementation serves whole blobs as raw bytes.
        let raw_bytes = match response.section {
            Some(bbrpc::download_response::Section::RawBytes(raw_bytes)) => raw_bytes.value,
            Some(bbrpc::download_response::Section::Reference(_)) => {
                return Err(Status::unimplemented(
                    "reference sections are not supported yet",
                ));
            }
            None => return Err(Status::internal("peer returned no content section")),
        };
        if i64::try_from(raw_bytes.len()).unwrap_or(i64::MAX) != response.total_length {
            return Err(Status::internal("peer returned a short content blob"));
        }

        let actual_hash = Sha256::digest(&raw_bytes);
        if actual_hash.as_slice() != response.sha256.as_slice() {
            return Err(Status::data_loss("peer content hash mismatch"));
        }

        Ok(raw_bytes)
    }

    /// Remove an unreferenced foreign blob once no peer metadata points to it.
    fn remove_unused_foreign_blob(&self, content_id: &[u8]) -> Result<(), Status> {
        self.with_store(|store| {
            if store
                .current_content_id()
                .is_some_and(|current| current == content_id)
            {
                return Ok(());
            }
            if store
                .peers()
                .iter()
                .any(|peer| peer.content_id.as_slice() == content_id)
            {
                return Ok(());
            }

            match store.remove_content_blob(content_id) {
                Ok(()) | Err(StorageError::FileNotFound) => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    /// Report whether a peer-visible content id is already stored locally.
    fn has_content_blob(&self, content_id: &[u8]) -> Result<bool, Status> {
        self.with_store(|store| Ok(store.has_content_blob(content_id)))
    }

    /// Mirror or clear the latest advertised content for a peer.
    async fn sync_peer_content_info(
        &self,
        peer_onion: &str,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_info: Option<&bbrpc::ContentInfo>,
    ) -> Result<(), Status> {
        let previous_content_id = self.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes())
                .map(|peer| peer.content_id)
                .filter(|content_id| !content_id.is_empty()))
        })?;

        match content_info {
            Some(content_info) => {
                if !self.has_content_blob(&content_info.content_id)? {
                    let blob = self
                        .download_peer_blob(peer_onion, &content_info.content_id)
                        .await?;
                    self.with_store(|store| {
                        store.write_content_blob(&content_info.content_id, &blob)
                    })?;
                }
                self.with_store(|store| {
                    store.set_peer_content_id(peer_public_key.as_bytes(), &content_info.content_id)
                })?;
                if let Some(previous_content_id) = previous_content_id {
                    if previous_content_id != content_info.content_id {
                        self.remove_unused_foreign_blob(&previous_content_id)?;
                    }
                }
            }
            None => {
                self.with_store(|store| store.clear_peer_content_id(peer_public_key.as_bytes()))?;
                if let Some(previous_content_id) = previous_content_id {
                    self.remove_unused_foreign_blob(&previous_content_id)?;
                }
            }
        }

        Ok(())
    }

    /// Return the persisted score state for a peer.
    fn peer_score_state(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<(i64, i64), Status> {
        self.with_store(|store| {
            let peer = store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
            Ok(peer
                .map(|peer| (peer.score_seconds, peer.score_measured_at))
                .unwrap_or((0, 0)))
        })
    }

    /// Persist the updated score state for a peer.
    fn update_peer_score(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        passed: bool,
    ) -> Result<i64, Status> {
        let (score_seconds, measured_at) = self.peer_score_state(peer_public_key)?;
        let now_secs = i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX);
        let elapsed = if measured_at > 0 {
            now_secs.saturating_sub(measured_at)
        } else {
            0
        };
        let new_score = if passed {
            score_seconds.saturating_add(elapsed)
        } else {
            score_seconds.saturating_sub(elapsed)
        };

        self.with_store(|store| {
            store.set_peer_score(peer_public_key.as_bytes(), new_score, now_secs)
        })?;
        Ok(new_score)
    }

    /// Choose a deterministic sample section inside a content blob.
    fn sample_section(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_id: &[u8],
        blob_len: usize,
    ) -> (usize, usize) {
        const SAMPLE_LEN: usize = 16 * 1024;

        if blob_len == 0 {
            return (0, 0);
        }
        let section_len = SAMPLE_LEN.min(blob_len);

        // Hash peer identity, revision, and current time so repeated checks
        // move across the blob while remaining deterministic in tests.
        let mut hasher = Sha256::new();
        hasher.update(peer_public_key.as_bytes());
        hasher.update(content_id);
        hasher.update(self.clock.now().secs.to_le_bytes());
        let digest = hasher.finalize();
        let mut offset_bytes = [0u8; 8];
        offset_bytes.copy_from_slice(&digest[..8]);
        let max_offset = blob_len - section_len;
        let offset = if max_offset == 0 {
            0
        } else {
            (u64::from_le_bytes(offset_bytes) as usize) % (max_offset + 1)
        };

        (offset, section_len)
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
        let known_peers = self.node.known_peers.lock().unwrap().clone();
        let contracts = self.node.with_store(|store| {
            let peers = store.peers();
            let mut contracts = Vec::new();

            for known_peer in &known_peers {
                let peer_public_key = match keys::public_key_from_onion_hostname(known_peer) {
                    Ok(peer_public_key) => peer_public_key,
                    Err(_) => continue,
                };
                let peer = peers
                    .iter()
                    .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
                let their_content_length = peer
                    .and_then(|peer| {
                        if peer.content_id.is_empty() {
                            None
                        } else {
                            store.read_blob_by_id(&peer.content_id).ok()
                        }
                    })
                    .map(|blob| i64::try_from(blob.len()).unwrap_or(i64::MAX))
                    .unwrap_or(0);

                contracts.push(clirpc::ContractInfo {
                    peer: Some(clirpc::Peer {
                        onion_service_id: known_peer.clone(),
                    }),
                    our_content_synced: false,
                    our_remaining_seconds: 0,
                    their_remaining_seconds: peer.map(|peer| peer.score_seconds).unwrap_or(0),
                    their_content_length,
                    online: false,
                });
            }

            Ok(contracts)
        })?;

        Ok(Response::new(clirpc::GetContractsResponse { contracts }))
    }

    async fn propose_contract(
        &self,
        _request: tonic::Request<clirpc::ProposeContractRequest>,
    ) -> Result<tonic::Response<Self::ProposeContractStream>, tonic::Status> {
        Ok(Response::new(Box::pin(stream::empty())))
    }

    async fn check_contract(
        &self,
        request: tonic::Request<clirpc::CheckContractRequest>,
    ) -> Result<tonic::Response<Self::CheckContractStream>, tonic::Status> {
        let peer = request
            .into_inner()
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }
        let peer_public_key = keys::public_key_from_onion_hostname(&peer.onion_service_id)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;

        let mut updates = vec![Ok(clirpc::CheckContractUpdate {
            state: clirpc::ContractState::ConnectingToPeer as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        })];

        let mut client = self
            .node
            .connect_peer_client(&peer.onion_service_id)
            .await?;
        let revision = client
            .get_content_revision(bbrpc::GetContentRevisionRequest {})
            .await
            .map_err(|error| Status::unavailable(format!("get content revision: {error}")))?
            .into_inner();
        self.node
            .sync_peer_content_info(
                &peer.onion_service_id,
                &peer_public_key,
                revision.responder_content.as_ref(),
            )
            .await?;

        updates.push(Ok(clirpc::CheckContractUpdate {
            state: clirpc::ContractState::CheckingContents as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        }));

        let Some(our_content) = self.node.responder_content()? else {
            self.node.update_peer_score(&peer_public_key, true)?;
            updates.push(Ok(clirpc::CheckContractUpdate {
                state: clirpc::ContractState::Completed as i32,
                success: true,
                our_content_length: 0,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            }));
            return Ok(Response::new(Box::pin(stream::iter(updates))));
        };

        if revision
            .requester_content
            .as_ref()
            .map(|content_info| content_info.content_id.as_slice())
            != Some(our_content.content_id.as_slice())
        {
            self.node.update_peer_score(&peer_public_key, false)?;
            updates.push(Ok(clirpc::CheckContractUpdate {
                state: clirpc::ContractState::OurContentRevisionMissing as i32,
                success: false,
                our_content_length: our_content.content_length,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            }));
            return Ok(Response::new(Box::pin(stream::iter(updates))));
        }

        let local_blob = self.node.with_store(|store| store.current_blob())?;
        let (section_offset, section_length) =
            self.node
                .sample_section(&peer_public_key, &our_content.content_id, local_blob.len());
        let download = client
            .download(bbrpc::DownloadRequest {
                content_id: our_content.content_id.clone(),
                offset: i64::try_from(section_offset).unwrap_or(i64::MAX),
                reference_content_id: Vec::new(),
            })
            .await
            .map_err(|error| Status::unavailable(format!("download sampled section: {error}")))?
            .into_inner();
        let expected_hash = Sha256::digest(&local_blob);
        let passed = download.sha256.as_slice() == expected_hash.as_slice()
            && matches!(
                download.section,
                Some(bbrpc::download_response::Section::RawBytes(ref raw_bytes))
                    if raw_bytes.value.len() >= section_length
                        && raw_bytes.value[..section_length]
                            == local_blob[section_offset..section_offset + section_length]
            );
        self.node.update_peer_score(&peer_public_key, passed)?;
        updates.push(Ok(clirpc::CheckContractUpdate {
            state: if passed {
                clirpc::ContractState::Completed as i32
            } else {
                clirpc::ContractState::InvalidContentReturned as i32
            },
            success: passed,
            our_content_length: our_content.content_length,
            our_content_section_offset: i64::try_from(section_offset).unwrap_or(i64::MAX),
            our_content_section_length: i64::try_from(section_length).unwrap_or(i64::MAX),
        }));

        Ok(Response::new(Box::pin(stream::iter(updates))))
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
        request: tonic::Request<bbrpc::HealthCheckRequest>,
    ) -> Result<tonic::Response<bbrpc::HealthCheckResponse>, tonic::Status> {
        let peer_identity = self.node.peer_identity_from_request(&request)?;
        Ok(Response::new(bbrpc::HealthCheckResponse {
            client_onion: peer_identity.onion_address,
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
        request: tonic::Request<bbrpc::GetContentRevisionRequest>,
    ) -> Result<tonic::Response<bbrpc::GetContentRevisionResponse>, tonic::Status> {
        let requester_content = self
            .node
            .peer_identity_from_request(&request)
            .ok()
            .map(|peer_identity| self.node.requester_content(&peer_identity.public_key))
            .transpose()?
            .flatten();
        Ok(Response::new(bbrpc::GetContentRevisionResponse {
            requester_content,
            requester_remaining_seconds: 0,
            responder_content: self.node.responder_content()?,
        }))
    }

    async fn set_content_revision(
        &self,
        request: tonic::Request<bbrpc::SetContentRevisionRequest>,
    ) -> Result<tonic::Response<bbrpc::SetContentRevisionResponse>, tonic::Status> {
        let peer_identity = self.node.peer_identity_from_request(&request)?;
        let requester_content = request.into_inner().requester_content;
        if let Some(content_info) = requester_content.as_ref() {
            if content_info.content_length <= 0 {
                return Err(Status::invalid_argument("content length must be positive"));
            }
            if content_info.content_length > MAX_PEER_CONTENT_BYTES {
                return Err(Status::invalid_argument("content is too large"));
            }
            if content_info.content_id.is_empty() {
                return Err(Status::invalid_argument("content id is required"));
            }
        }

        self.node
            .sync_peer_content_info(
                &peer_identity.onion_address,
                &peer_identity.public_key,
                requester_content.as_ref(),
            )
            .await?;

        Ok(Response::new(bbrpc::SetContentRevisionResponse {}))
    }

    async fn download(
        &self,
        request: tonic::Request<bbrpc::DownloadRequest>,
    ) -> Result<tonic::Response<bbrpc::DownloadResponse>, tonic::Status> {
        let peer_identity = self.node.peer_identity_from_request(&request).ok();
        let request = request.into_inner();
        if request.content_id.is_empty() {
            return Err(Status::invalid_argument("content_id is required"));
        }
        if request.offset < 0 {
            return Err(Status::invalid_argument("offset must be non-negative"));
        }

        let offset = usize::try_from(request.offset)
            .map_err(|_| Status::invalid_argument("offset is too large"))?;
        let current_content_id = self.node.with_store(|store| {
            Ok(store
                .current_content_id()
                .map(|content_id| content_id.to_vec()))
        })?;
        let allowed = current_content_id
            .as_ref()
            .is_some_and(|content_id| content_id.as_slice() == request.content_id.as_slice())
            || peer_identity
                .as_ref()
                .map(|peer_identity| self.node.requester_content(&peer_identity.public_key))
                .transpose()?
                .flatten()
                .is_some_and(|content_info| content_info.content_id == request.content_id);
        if !allowed {
            return Err(Status::not_found("content not found"));
        }

        let blob = self
            .node
            .with_store(|store| store.read_blob_by_id(&request.content_id))?;
        if offset > blob.len() {
            return Err(Status::out_of_range("offset is past the end of the blob"));
        }

        let sha256 = Sha256::digest(&blob).to_vec();
        let raw_bytes = bbrpc::RawBytes {
            value: blob[offset..].to_vec(),
        };
        Ok(Response::new(bbrpc::DownloadResponse {
            total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
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
    use clock::{ManualClock, Timestamp};
    use futures::TryStreamExt;
    use protos::bbrpc::barter_backup_server_client::BarterBackupServerClient;
    use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::{
        BarterBackupClient, BarterBackupClientServer,
    };
    use std::sync::Arc;
    use std::time::Duration;
    use tonic::transport::Endpoint;
    use transport::PeerConnector;

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

    /// Spawn a TLS-protected p2p server for integration-style node tests.
    async fn spawn_p2p_server(
        node: Arc<Node>,
    ) -> anyhow::Result<(
        String,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    )> {
        let service = P2pService::new(node.clone());
        let listener = netmock::bind_peer_listener(&node.ed25519_keypair().secret).await?;
        let endpoint = listener.endpoint().to_string();
        let router =
            tonic::transport::Server::builder().add_service(BarterBackupServerServer::new(service));
        let handle = tokio::spawn(router.serve_with_incoming(listener.into_incoming()));

        Ok((endpoint, handle))
    }

    /// Spawn a p2p server and register its endpoint in the shared mock connector.
    async fn spawn_registered_p2p_server(
        node: Arc<Node>,
        connector: &netmock::MockPeerConnector,
    ) -> anyhow::Result<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>> {
        let (endpoint, handle) = spawn_p2p_server(node.clone()).await?;
        connector.register_peer(node.address(), &endpoint);
        Ok(handle)
    }

    /// Connect a peer client to a mock p2p server.
    async fn connect_p2p_client(
        client_node: Arc<Node>,
        server_node: Arc<Node>,
        connector: &netmock::MockPeerConnector,
    ) -> anyhow::Result<BarterBackupServerClient<tonic::transport::Channel>> {
        let client_secret = &client_node.ed25519_keypair().secret;
        connector
            .connect(server_node.address(), client_secret)
            .await
    }

    /// Return the persisted score for `peer_onion` from the node store.
    fn peer_score_seconds(node: &Node, peer_onion: &str) -> anyhow::Result<i64> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)?;
        let score = node.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes())
                .map(|peer| peer.score_seconds)
                .unwrap_or(0))
        })?;

        Ok(score)
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
    async fn p2p_healthcheck_reports_authenticated_onions() -> anyhow::Result<()> {
        let server_node = Arc::new(Node::new("server-password")?);
        let client_node = Arc::new(Node::new("client-password")?);
        let (endpoint, server) = spawn_p2p_server(server_node.clone()).await?;
        let client_secret = &client_node.ed25519_keypair().secret;
        let channel =
            netmock::connect_peer_channel(&endpoint, server_node.address(), client_secret).await?;
        let mut client = BarterBackupServerClient::new(channel);

        let response = client
            .health_check(bbrpc::HealthCheckRequest {})
            .await?
            .into_inner();
        assert_eq!(response.client_onion, client_node.address());
        assert_eq!(response.server_onion, server_node.address());

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
        let server_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let server_node = Arc::new(Node::with_local_storage("password", server_filesystem)?);
        let client_node = Arc::new(Node::new("client-password")?);
        let cli = CliService::new(server_node.clone());
        let connector = Arc::new(netmock::MockPeerConnector::new());

        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
            }),
        }))
        .await?;

        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
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

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_content_revision_downloads_and_tracks_peer_blob() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester", requester_filesystem)?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage("responder", responder_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        let mut requester_to_responder = connect_p2p_client(
            requester_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;

        let requester_content = requester_node.responder_content()?.unwrap();
        requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let revision = requester_to_responder
            .get_content_revision(bbrpc::GetContentRevisionRequest {})
            .await?
            .into_inner();
        assert_eq!(revision.requester_content, Some(requester_content.clone()));

        let requester_blob = requester_node.with_store(|store| store.current_blob())?;
        let mirrored_blob = responder_node
            .with_store(|store| store.read_blob_by_id(&requester_content.content_id))?;
        assert_eq!(mirrored_blob, requester_blob);

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_hides_other_peers_content() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester", requester_filesystem)?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage("responder", responder_filesystem)?);
        let other_node = Arc::new(Node::new("other")?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        other_node.set_peer_connector(connector.clone());

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        let mut requester_to_responder = connect_p2p_client(
            requester_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let mut other_to_responder = connect_p2p_client(
            other_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;

        let requester_content = requester_node.responder_content()?.unwrap();
        requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let error = other_to_responder
            .download(bbrpc::DownloadRequest {
                content_id: requester_content.content_id.clone(),
                offset: 0,
                reference_content_id: Vec::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_uses_manual_time_for_scores() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage_and_clock(
            "responder",
            responder_filesystem,
            responder_clock.clone(),
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node
            .known_peers
            .lock()
            .unwrap()
            .insert(responder_node.address().to_string());

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        let mut requester_to_responder = connect_p2p_client(
            requester_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;
        requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(requester_node.responder_content()?.unwrap()),
            })
            .await?;

        let first_updates = requester_cli
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(
            first_updates.last().map(|update| update.success),
            Some(true)
        );
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            0
        );

        requester_clock.advance(Duration::from_secs(3_600));
        let second_updates = requester_cli
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(
            second_updates.last().map(|update| update.success),
            Some(true)
        );
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            3_600
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_penalizes_missing_our_content() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage_and_clock(
            "responder",
            responder_filesystem,
            responder_clock.clone(),
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node
            .known_peers
            .lock()
            .unwrap()
            .insert(responder_node.address().to_string());

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        let mut requester_to_responder = connect_p2p_client(
            requester_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;
        requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(requester_node.responder_content()?.unwrap()),
            })
            .await?;

        requester_clock.advance(Duration::from_secs(3_600));
        requester_cli
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            0
        );

        let requester_public_key = keys::public_key_from_onion_hostname(requester_node.address())?;
        responder_node.with_store(|store| store.remove_peer(requester_public_key.as_bytes()))?;

        requester_clock.advance(Duration::from_secs(1_800));
        let failed_updates = requester_cli
            .check_contract(tonic::Request::new(clirpc::CheckContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(
            failed_updates.last().map(|update| update.state),
            Some(clirpc::ContractState::OurContentRevisionMissing as i32)
        );
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            -1_800
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }
}
