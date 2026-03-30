//! Node orchestration for a single BarterBackup instance.
//!
//! The current implementation focuses on the local encrypted store and the RPC
//! surface that depends on it. Peer-to-peer contract management and Tor-backed
//! transport still need further work.

use anyhow::Result;
use clock::{Clock, SystemClock, Timestamp};
use content::CONTENT_ID_LEN;
use futures::{stream, Stream};
use protos::{bbrpc, clirpc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use storage::{Filesystem, StorageError, Store};
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Code, Response, Status};
use tracing::{info, warn};
use transport::PeerConnector;

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

/// Return the peer-content size limit as an `i64` for protobuf comparisons.
fn max_peer_content_bytes_i64() -> i64 {
    i64::try_from(transport::MAX_PEER_CONTENT_BYTES).unwrap_or(i64::MAX)
}

/// Validate one peer-visible content identifier.
fn validate_peer_content_id(content_id: &[u8]) -> Result<(), Status> {
    if content_id.len() != CONTENT_ID_LEN {
        return Err(Status::invalid_argument("content id has an invalid length"));
    }

    Ok(())
}

/// Validate one peer-visible content descriptor before we trust its sizes.
fn validate_peer_content_info(content_info: &bbrpc::ContentInfo) -> Result<(), Status> {
    if content_info.content_length <= 0 {
        return Err(Status::invalid_argument("content length must be positive"));
    }
    if content_info.content_length > max_peer_content_bytes_i64() {
        return Err(Status::invalid_argument("content is too large"));
    }
    validate_peer_content_id(&content_info.content_id)?;

    Ok(())
}

/// Return one content id as hex for structured logs.
fn content_id_hex(content_id: &[u8]) -> String {
    hex::encode(content_id)
}

/// MirroredBlobState reports whether a cached peer blob is present or needs refresh.
enum MirroredBlobState {
    /// Present means the cached mirrored blob is valid and usable.
    Present,
    /// Missing means no cached mirrored blob exists yet.
    Missing,
    /// Corrupt means a wrapped mirrored blob exists but failed local validation.
    Corrupt,
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
        let known_peers = store
            .as_ref()
            .map(|store| {
                store
                    .lock()
                    .unwrap()
                    .peers()
                    .into_iter()
                    .filter_map(|peer| {
                        ed25519_dalek::PublicKey::from_bytes(&peer.onion_pubkey)
                            .ok()
                            .map(|public_key| keys::onion_hostname_from_public_key(&public_key))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            ed25519_keypair: keypair,
            onion_address,
            clock,
            started_at: Mutex::new(None),
            store,
            known_peers: Mutex::new(known_peers),
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
        let content = self.with_store(|store| {
            Ok(store.current_content().map(|current| bbrpc::ContentInfo {
                content_id: current.content_id.clone(),
                content_length: i64::try_from(current.blob_len).unwrap_or(i64::MAX),
            }))
        })?;

        if content
            .as_ref()
            .is_some_and(|content_info| content_info.content_length > max_peer_content_bytes_i64())
        {
            return Err(Status::failed_precondition(
                "current content exceeds the peer transport limit",
            ));
        }

        Ok(content)
    }

    /// Install the outbound peer connector used for peer synchronization.
    pub fn set_peer_connector(&self, peer_connector: Arc<dyn PeerConnector>) {
        *self.peer_connector.lock().unwrap() = Some(peer_connector);
    }

    /// Add a peer onion hostname to the configured peer set.
    pub fn add_known_peer(&self, peer_onion: &str) -> Result<(), Status> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        self.with_store(|store| store.ensure_peer(peer_public_key.as_bytes()))
            .or_else(|error| {
                if error.code() == Code::FailedPrecondition {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        self.known_peers
            .lock()
            .unwrap()
            .insert(peer_onion.to_string());
        Ok(())
    }

    /// Return the configured peer onion hostnames in deterministic order.
    pub fn known_peers(&self) -> Vec<String> {
        self.known_peers.lock().unwrap().iter().cloned().collect()
    }

    /// Return the current local content info, if one exists.
    pub fn current_content_info(&self) -> Result<Option<bbrpc::ContentInfo>, Status> {
        self.responder_content()
    }

    /// Return the mirrored content id currently tracked for one peer.
    pub fn mirrored_peer_content_id(&self, peer_onion: &str) -> Result<Option<Vec<u8>>, Status> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;

        self.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes())
                .map(|peer| peer.content_id)
                .filter(|content_id| !content_id.is_empty()))
        })
    }

    /// Extract the authenticated peer identity from the request TLS state.
    fn peer_identity_from_request<T>(
        &self,
        request: &tonic::Request<T>,
    ) -> Result<PeerIdentity, Status> {
        let peer_certificates = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .and_then(|tls_info| tls_info.peer_certs())
            .or_else(|| {
                request
                    .extensions()
                    .get::<TlsConnectInfo<()>>()
                    .and_then(|tls_info| tls_info.peer_certs())
            })
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

            match store.read_mirrored_blob(&peer.content_id) {
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
        let client = tokio::time::timeout(
            transport::PEER_CONNECT_TIMEOUT,
            connector.connect(peer_onion, &self.ed25519_keypair.secret),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("connect peer timed out"))?
        .map_err(|error| Status::unavailable(format!("connect peer: {error}")))?;

        Ok(transport::configure_peer_client(client))
    }

    /// Run one peer RPC under the shared timeout policy.
    async fn peer_rpc<T, F>(
        &self,
        peer_onion: &str,
        operation: &'static str,
        future: F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<Response<T>, tonic::Status>>,
    {
        match tokio::time::timeout(transport::PEER_RPC_TIMEOUT, future).await {
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(error)) => Err(Status::unavailable(format!(
                "{operation} from {peer_onion}: {error}"
            ))),
            Err(_) => Err(Status::deadline_exceeded(format!(
                "{operation} from {peer_onion} timed out"
            ))),
        }
    }

    /// Download an encrypted blob from a peer and verify the advertised hash.
    async fn download_peer_blob(
        &self,
        peer_onion: &str,
        content_id: &[u8],
        expected_length: i64,
    ) -> Result<Vec<u8>, Status> {
        validate_peer_content_id(content_id)?;
        if expected_length <= 0 {
            return Err(Status::invalid_argument(
                "expected content length must be positive",
            ));
        }
        if expected_length > max_peer_content_bytes_i64() {
            return Err(Status::invalid_argument("expected content is too large"));
        }

        let mut client = self.connect_peer_client(peer_onion).await?;
        let response = self
            .peer_rpc(
                peer_onion,
                "download peer content",
                client.download(bbrpc::DownloadRequest {
                    content_id: content_id.to_vec(),
                    offset: 0,
                    reference_content_id: Vec::new(),
                }),
            )
            .await?;
        if response.total_length < 0 {
            return Err(Status::internal("peer returned a negative content length"));
        }
        if response.total_length > max_peer_content_bytes_i64() {
            return Err(Status::resource_exhausted(
                "peer returned content larger than the transport limit",
            ));
        }
        if response.total_length != expected_length {
            return Err(Status::data_loss(
                "peer returned a different content length than advertised",
            ));
        }
        if response.sha256.len() != 32 {
            return Err(Status::data_loss("peer returned an invalid content hash"));
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

            match store.remove_mirrored_blob(content_id) {
                Ok(()) | Err(StorageError::FileNotFound) => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    /// Report whether a valid mirrored peer blob is already stored locally.
    fn has_mirrored_blob(&self, content_id: &[u8]) -> Result<bool, Status> {
        self.with_store(|store| store.has_mirrored_blob(content_id))
    }

    /// Report whether a mirrored peer blob is present, missing, or corrupt.
    fn mirrored_blob_state(&self, content_id: &[u8]) -> Result<MirroredBlobState, Status> {
        self.with_store(|store| match store.has_mirrored_blob(content_id) {
            Ok(true) => Ok(MirroredBlobState::Present),
            Ok(false) => Ok(MirroredBlobState::Missing),
            Err(StorageError::RecoveryRequired(_)) => {
                let _ = store.remove_mirrored_blob(content_id);
                Ok(MirroredBlobState::Corrupt)
            }
            Err(error) => Err(error),
        })
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
                validate_peer_content_info(content_info)?;
                let content_id = content_id_hex(&content_info.content_id);
                let mirrored_state = self.mirrored_blob_state(&content_info.content_id)?;

                // Refresh the mirrored blob whenever it is missing or locally
                // corrupted so the peer cache never depends on stale bytes.
                if matches!(
                    mirrored_state,
                    MirroredBlobState::Missing | MirroredBlobState::Corrupt
                ) {
                    if matches!(mirrored_state, MirroredBlobState::Corrupt) {
                        warn!(
                            peer = %peer_onion,
                            content_id = %content_id,
                            "discarded corrupt mirrored peer blob before refresh"
                        );
                    }
                    let blob = self
                        .download_peer_blob(
                            peer_onion,
                            &content_info.content_id,
                            content_info.content_length,
                        )
                        .await?;
                    self.with_store(|store| {
                        store.write_mirrored_blob(&content_info.content_id, &blob)
                    })?;
                    info!(
                        peer = %peer_onion,
                        content_id = %content_id,
                        content_length = content_info.content_length,
                        downloaded_bytes = blob.len(),
                        "refreshed mirrored peer blob"
                    );
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
                let previous_content_id_hex = previous_content_id
                    .as_ref()
                    .map(|content_id| content_id_hex(content_id))
                    .unwrap_or_default();
                self.with_store(|store| store.clear_peer_content_id(peer_public_key.as_bytes()))?;
                if let Some(previous_content_id) = previous_content_id {
                    self.remove_unused_foreign_blob(&previous_content_id)?;
                }
                info!(
                    peer = %peer_onion,
                    previous_content_id = %previous_content_id_hex,
                    "cleared mirrored peer content"
                );
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

    /// Parse a content id into the ordering tuple used for recovery.
    fn revision_key(&self, content_id: &[u8]) -> Result<(u64, u64, u32, u32), Status> {
        self.with_store(|store| {
            let revision = store.parse_content_id(content_id)?;
            Ok((
                revision.sequence,
                revision.created_at_secs,
                revision.created_at_nanos,
                revision.metadata_ciphertext_len,
            ))
        })
    }

    /// Restore an encrypted blob as our current local content.
    fn restore_current_blob(&self, blob: &[u8]) -> Result<(), Status> {
        self.with_store(|store| store.restore_current_content_blob(blob))
    }

    /// Return the stored blob length for a peer's mirrored content, if any.
    fn mirrored_peer_content_length(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<i64, Status> {
        self.with_store(|store| {
            let peer = store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
            let Some(peer) = peer else {
                return Ok(0);
            };
            if peer.content_id.is_empty() {
                return Ok(0);
            }

            match store.read_mirrored_blob(&peer.content_id) {
                Ok(blob) => Ok(i64::try_from(blob.len()).unwrap_or(i64::MAX)),
                Err(StorageError::FileNotFound) => Ok(0),
                Err(error) => Err(error),
            }
        })
    }

    /// Report whether our current local content matches the peer's advertised
    /// copy of our revision.
    fn our_content_synced_with_peer(
        &self,
        peer_view_of_our_content: Option<&bbrpc::ContentInfo>,
    ) -> Result<bool, Status> {
        let our_content = self.responder_content()?;
        Ok(match (our_content.as_ref(), peer_view_of_our_content) {
            (None, None) => true,
            (Some(our_content), Some(peer_content)) => {
                our_content.content_id == peer_content.content_id
            }
            _ => false,
        })
    }

    /// Build the connected-peer response by probing each configured peer.
    pub async fn connected_peers_response(&self) -> Result<clirpc::ConnectedPeersResponse, Status> {
        let mut connected_peers = Vec::new();
        let mut offline_peers = Vec::new();

        for peer_onion in self.known_peers() {
            let is_online = match self.connect_peer_client(&peer_onion).await {
                Ok(mut client) => client
                    .health_check(bbrpc::HealthCheckRequest {})
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            let peer = clirpc::Peer {
                onion_service_id: peer_onion,
            };
            if is_online {
                connected_peers.push(peer);
            } else {
                offline_peers.push(peer);
            }
        }

        Ok(clirpc::ConnectedPeersResponse {
            connected_peers,
            online_not_connected_peers: Vec::new(),
            offline_peers,
        })
    }

    /// Build a live contract snapshot for the configured peers.
    pub async fn get_contracts_response(&self) -> Result<clirpc::GetContractsResponse, Status> {
        let mut contracts = Vec::new();

        for peer_onion in self.known_peers() {
            let peer_public_key = match keys::public_key_from_onion_hostname(&peer_onion) {
                Ok(peer_public_key) => peer_public_key,
                Err(_) => continue,
            };
            let mut online = false;
            let mut our_content_synced = false;
            let mut our_remaining_seconds = 0;

            // Probe the peer live so the contract view reflects reachability
            // and can opportunistically refresh mirrored peer blobs.
            if let Ok(mut client) = self.connect_peer_client(&peer_onion).await {
                if let Ok(revision) = self
                    .peer_rpc(
                        &peer_onion,
                        "get content revision",
                        client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                    )
                    .await
                {
                    online = true;
                    our_remaining_seconds = revision.requester_remaining_seconds;
                    our_content_synced =
                        self.our_content_synced_with_peer(revision.requester_content.as_ref())?;
                    if let Err(error) = self
                        .sync_peer_content_info(
                            &peer_onion,
                            &peer_public_key,
                            revision.responder_content.as_ref(),
                        )
                        .await
                    {
                        warn!(
                            peer = %peer_onion,
                            %error,
                            "failed to refresh mirrored peer content while building contracts"
                        );
                    }
                }
            }

            contracts.push(clirpc::ContractInfo {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion,
                }),
                our_content_synced,
                our_remaining_seconds,
                their_remaining_seconds: self.peer_score_state(&peer_public_key)?.0,
                their_content_length: self.mirrored_peer_content_length(&peer_public_key)?,
                online,
            });
        }

        Ok(clirpc::GetContractsResponse { contracts })
    }

    /// Propose or renew a contract with one peer and report the progress
    /// updates that should be streamed to the caller.
    pub async fn propose_contract_updates(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::ProposeContractUpdate>, Status> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let mut updates = vec![clirpc::ProposeContractUpdate {
            state: clirpc::ContractState::ConnectingToPeer as i32,
            success: false,
            their_content_length: 0,
            their_content_downloaded_bytes: 0,
            our_content_length: 0,
            our_content_uploaded_bytes: 0,
        }];

        // Query the peer's live contract state before deciding what needs to
        // be synchronized in either direction.
        let mut client = self.connect_peer_client(peer_onion).await?;
        let revision = self
            .peer_rpc(
                peer_onion,
                "get content revision",
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await?;
        let their_content_length = revision
            .responder_content
            .as_ref()
            .map(|content_info| content_info.content_length)
            .unwrap_or(0);
        let downloaded_their_content = revision
            .responder_content
            .as_ref()
            .filter(|content_info| {
                self.has_mirrored_blob(&content_info.content_id)
                    .map(|present| !present)
                    .unwrap_or(false)
            })
            .map(|content_info| content_info.content_length)
            .unwrap_or(0);
        self.sync_peer_content_info(
            peer_onion,
            &peer_public_key,
            revision.responder_content.as_ref(),
        )
        .await?;

        updates.push(clirpc::ProposeContractUpdate {
            state: clirpc::ContractState::ProposingContract as i32,
            success: false,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length: 0,
            our_content_uploaded_bytes: 0,
        });

        // Upload our current revision only when the peer does not already hold
        // the exact same content identifier.
        let our_content = self.responder_content()?;
        let our_content_length = our_content
            .as_ref()
            .map(|content_info| content_info.content_length)
            .unwrap_or(0);
        let mut uploaded_our_content = 0;
        let peer_has_our_content = revision
            .requester_content
            .as_ref()
            .map(|content_info| content_info.content_id.clone());
        let desired_content_id = our_content
            .as_ref()
            .map(|content_info| content_info.content_id.clone());
        if peer_has_our_content != desired_content_id {
            self.peer_rpc(
                peer_onion,
                "set content revision",
                client.set_content_revision(bbrpc::SetContentRevisionRequest {
                    requester_content: our_content.clone(),
                }),
            )
            .await?;
            uploaded_our_content = our_content_length;
        }

        updates.push(clirpc::ProposeContractUpdate {
            state: clirpc::ContractState::SyncingContents as i32,
            success: false,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes: uploaded_our_content,
        });
        updates.push(clirpc::ProposeContractUpdate {
            state: clirpc::ContractState::Completed as i32,
            success: true,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes: uploaded_our_content,
        });

        info!(
            peer = %peer_onion,
            their_content_length,
            their_content_downloaded_bytes = downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes = uploaded_our_content,
            "peer contract proposal completed"
        );

        Ok(updates)
    }

    /// Verify a peer contract, update the peer score, and return the streamed
    /// progress updates that describe the check.
    pub async fn check_contract_updates(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::CheckContractUpdate>, Status> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let mut updates = vec![clirpc::CheckContractUpdate {
            state: clirpc::ContractState::ConnectingToPeer as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        }];

        // Refresh the peer's advertised content before validating their copy of
        // our own revision.
        let mut client = self.connect_peer_client(peer_onion).await?;
        let revision = self
            .peer_rpc(
                peer_onion,
                "get content revision",
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await?;
        self.sync_peer_content_info(
            peer_onion,
            &peer_public_key,
            revision.responder_content.as_ref(),
        )
        .await?;

        updates.push(clirpc::CheckContractUpdate {
            state: clirpc::ContractState::CheckingContents as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        });

        let Some(our_content) = self.responder_content()? else {
            let new_score = self.update_peer_score(&peer_public_key, true)?;
            updates.push(clirpc::CheckContractUpdate {
                state: clirpc::ContractState::Completed as i32,
                success: true,
                our_content_length: 0,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            });
            info!(
                peer = %peer_onion,
                success = true,
                new_score_seconds = new_score,
                "peer contract check completed without local content"
            );
            return Ok(updates);
        };

        if revision
            .requester_content
            .as_ref()
            .map(|content_info| content_info.content_id.as_slice())
            != Some(our_content.content_id.as_slice())
        {
            let new_score = self.update_peer_score(&peer_public_key, false)?;
            updates.push(clirpc::CheckContractUpdate {
                state: clirpc::ContractState::OurContentRevisionMissing as i32,
                success: false,
                our_content_length: our_content.content_length,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            });
            warn!(
                peer = %peer_onion,
                success = false,
                new_score_seconds = new_score,
                our_content_length = our_content.content_length,
                "peer contract check found our revision missing"
            );
            return Ok(updates);
        }

        // Sample a deterministic section of our current encrypted blob and
        // verify the peer returns exactly the same bytes and whole-blob hash.
        let local_blob = self.with_store(|store| store.current_blob())?;
        let (section_offset, section_length) =
            self.sample_section(&peer_public_key, &our_content.content_id, local_blob.len());
        let download = self
            .peer_rpc(
                peer_onion,
                "download sampled section",
                client.download(bbrpc::DownloadRequest {
                    content_id: our_content.content_id.clone(),
                    offset: i64::try_from(section_offset).unwrap_or(i64::MAX),
                    reference_content_id: Vec::new(),
                }),
            )
            .await?;
        let expected_hash = Sha256::digest(&local_blob);
        let expected_total_length = i64::try_from(local_blob.len()).unwrap_or(i64::MAX);
        let passed = download.total_length == expected_total_length
            && download.sha256.as_slice() == expected_hash.as_slice()
            && matches!(
                download.section,
                Some(bbrpc::download_response::Section::RawBytes(ref raw_bytes))
                    if raw_bytes.value.len() >= section_length
                        && raw_bytes.value[..section_length]
                            == local_blob[section_offset..section_offset + section_length]
            );
        let new_score = self.update_peer_score(&peer_public_key, passed)?;
        updates.push(clirpc::CheckContractUpdate {
            state: if passed {
                clirpc::ContractState::Completed as i32
            } else {
                clirpc::ContractState::InvalidContentReturned as i32
            },
            success: passed,
            our_content_length: our_content.content_length,
            our_content_section_offset: i64::try_from(section_offset).unwrap_or(i64::MAX),
            our_content_section_length: i64::try_from(section_length).unwrap_or(i64::MAX),
        });

        if passed {
            info!(
                peer = %peer_onion,
                success = true,
                new_score_seconds = new_score,
                our_content_length = our_content.content_length,
                section_offset,
                section_length,
                "peer contract check completed"
            );
        } else {
            warn!(
                peer = %peer_onion,
                success = false,
                new_score_seconds = new_score,
                our_content_length = our_content.content_length,
                section_offset,
                section_length,
                "peer contract check returned invalid content"
            );
        }

        Ok(updates)
    }

    /// Discover the newest recoverable content revision across known peers and
    /// return the recovery summary that should be streamed to the caller.
    pub async fn recover_content_update(&self) -> Result<clirpc::RecoverContentUpdate, Status> {
        #[derive(Clone)]
        struct Candidate {
            /// key orders content revisions without downloading full bodies.
            key: (u64, u64, u32, u32),
            /// content_id is the recoverable encrypted revision identifier.
            content_id: Vec<u8>,
            /// content_length is the encrypted blob length advertised by peers.
            content_length: i64,
            /// peers are the peers that reported the same candidate revision.
            peers: Vec<String>,
        }

        let mut candidates = BTreeMap::<Vec<u8>, Candidate>::new();
        let mut peers_with_any_versions = 0i64;

        // Ask every known peer which version of our content it holds and keep
        // only the metadata needed to pick the newest revision.
        for peer_onion in self.known_peers() {
            let mut client = match self.connect_peer_client(&peer_onion).await {
                Ok(client) => client,
                Err(_) => continue,
            };
            let revision = match self
                .peer_rpc(
                    &peer_onion,
                    "get content revision",
                    client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                )
                .await
            {
                Ok(revision) => revision,
                Err(_) => continue,
            };
            let Some(content_info) = revision.requester_content else {
                continue;
            };
            let key = match self.revision_key(&content_info.content_id) {
                Ok(key) => key,
                Err(_) => continue,
            };

            peers_with_any_versions += 1;
            candidates
                .entry(content_info.content_id.clone())
                .and_modify(|candidate| candidate.peers.push(peer_onion.clone()))
                .or_insert(Candidate {
                    key,
                    content_id: content_info.content_id,
                    content_length: content_info.content_length,
                    peers: vec![peer_onion],
                });
        }

        // Download the single newest candidate only when it is newer than our
        // current local revision.
        let most_recent = candidates
            .values()
            .max_by_key(|candidate| candidate.key)
            .cloned();
        let mut most_recent_downloaded_bytes = 0i64;
        let mut most_recent_downloaded_files = 0i64;
        let mut recovered_most_recent_version = false;

        if let Some(candidate) = most_recent.as_ref() {
            let current_content = self.responder_content()?;
            let already_current = current_content
                .as_ref()
                .is_some_and(|content_info| content_info.content_id == candidate.content_id);
            if already_current {
                recovered_most_recent_version = true;
            } else {
                // Try every peer that advertised the newest revision so one
                // broken replica cannot block recovery from another copy.
                let mut last_error = None;
                for source_peer in &candidate.peers {
                    match self
                        .download_peer_blob(
                            source_peer,
                            &candidate.content_id,
                            candidate.content_length,
                        )
                        .await
                    {
                        Ok(blob) => {
                            self.restore_current_blob(&blob)?;
                            most_recent_downloaded_bytes =
                                i64::try_from(blob.len()).unwrap_or(i64::MAX);
                            most_recent_downloaded_files = self.with_store(|store| {
                                Ok(i64::try_from(store.list_files().len()).unwrap_or(i64::MAX))
                            })?;
                            recovered_most_recent_version = true;
                            last_error = None;
                            info!(
                                source_peer = %source_peer,
                                content_id = %content_id_hex(&candidate.content_id),
                                candidate_peer_count = candidate.peers.len(),
                                content_length = candidate.content_length,
                                downloaded_bytes = most_recent_downloaded_bytes,
                                "recovered latest content from peer"
                            );
                            break;
                        }
                        Err(error) => {
                            warn!(
                                peer = %source_peer,
                                content_id = %content_id_hex(&candidate.content_id),
                                %error,
                                "recovery download from peer failed"
                            );
                            last_error = Some(error);
                        }
                    }
                }
                if let Some(error) = last_error {
                    return Err(error);
                }
            }

            if already_current {
                info!(
                    content_id = %content_id_hex(&candidate.content_id),
                    candidate_peer_count = candidate.peers.len(),
                    content_length = candidate.content_length,
                    "latest recoverable content was already current"
                );
            }
        }

        Ok(clirpc::RecoverContentUpdate {
            most_recent_content_id: most_recent
                .as_ref()
                .map(|candidate| candidate.content_id.clone())
                .unwrap_or_default(),
            most_recent_ts: most_recent
                .as_ref()
                .map(|candidate| i64::try_from(candidate.key.1).unwrap_or(i64::MAX))
                .unwrap_or(0),
            most_recent_ts_ns: most_recent
                .as_ref()
                .map(|candidate| i64::from(candidate.key.2))
                .unwrap_or(0),
            most_recent_length: most_recent
                .as_ref()
                .map(|candidate| candidate.content_length)
                .unwrap_or(0),
            num_peers_with_most_recent_version: most_recent
                .as_ref()
                .map(|candidate| i64::try_from(candidate.peers.len()).unwrap_or(i64::MAX))
                .unwrap_or(0),
            total_versions_found: i64::try_from(candidates.len()).unwrap_or(i64::MAX),
            num_peers_with_any_versions: peers_with_any_versions,
            most_recent_downloaded_bytes,
            most_recent_downloaded_files,
            total_downloaded_bytes: most_recent_downloaded_bytes,
            recovered_most_recent_version,
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

        self.node.add_known_peer(&peer.onion_service_id)?;
        Ok(Response::new(clirpc::ConnectPeerResponse {}))
    }

    async fn connected_peers(
        &self,
        _request: tonic::Request<clirpc::ConnectedPeersRequest>,
    ) -> Result<tonic::Response<clirpc::ConnectedPeersResponse>, tonic::Status> {
        Ok(Response::new(self.node.connected_peers_response().await?))
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
        Ok(Response::new(self.node.get_contracts_response().await?))
    }

    async fn propose_contract(
        &self,
        request: tonic::Request<clirpc::ProposeContractRequest>,
    ) -> Result<tonic::Response<Self::ProposeContractStream>, tonic::Status> {
        let peer = request
            .into_inner()
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }
        let updates = self
            .node
            .propose_contract_updates(&peer.onion_service_id)
            .await?
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();

        Ok(Response::new(Box::pin(stream::iter(updates))))
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
        let updates = self
            .node
            .check_contract_updates(&peer.onion_service_id)
            .await?
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();

        Ok(Response::new(Box::pin(stream::iter(updates))))
    }

    async fn recover_content(
        &self,
        _request: tonic::Request<clirpc::RecoverContentRequest>,
    ) -> Result<tonic::Response<Self::RecoverContentStream>, tonic::Status> {
        let update = self.node.recover_content_update().await?;
        Ok(Response::new(Box::pin(stream::iter(vec![Ok(update)]))))
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
        for peer in request.peers {
            let public_key = match ed25519_dalek::PublicKey::from_bytes(&peer.onion_pubkey) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
            self.node
                .add_known_peer(&keys::onion_hostname_from_public_key(&public_key))?;
        }

        let peers = self
            .node
            .known_peers()
            .iter()
            .cloned()
            .filter_map(|peer_onion| {
                keys::public_key_from_onion_hostname(&peer_onion)
                    .ok()
                    .map(|public_key| bbrpc::Peer {
                        onion_pubkey: public_key.to_bytes().to_vec(),
                    })
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
            validate_peer_content_info(content_info)?;
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
        validate_peer_content_id(&request.content_id)?;
        if request.offset < 0 {
            return Err(Status::invalid_argument("offset must be non-negative"));
        }
        if !request.reference_content_id.is_empty() {
            return Err(Status::invalid_argument(
                "reference_content_id is not supported",
            ));
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

        let blob = if current_content_id
            .as_ref()
            .is_some_and(|content_id| content_id.as_slice() == request.content_id.as_slice())
        {
            self.node.with_store(|store| store.current_blob())?
        } else {
            self.node
                .with_store(|store| store.read_mirrored_blob(&request.content_id))?
        };
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
    use async_trait::async_trait;
    use clock::{ManualClock, Timestamp};
    use futures::TryStreamExt;
    use protos::bbrpc::barter_backup_server_client::BarterBackupServerClient;
    use protos::bbrpc::barter_backup_server_server::BarterBackupServerServer;
    use protos::clirpc::barter_backup_client_client::BarterBackupClientClient;
    use protos::clirpc::barter_backup_client_server::{
        BarterBackupClient, BarterBackupClientServer,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::RwLock;
    use std::time::Duration;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Endpoint;
    use tonic::{Request, Response};
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
        let router = tonic::transport::Server::builder().add_service(
            BarterBackupServerServer::new(service)
                .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
        );
        let handle = tokio::spawn(router.serve_with_incoming(listener.into_incoming()));

        Ok((endpoint, handle))
    }

    /// DownloadBehavior defines how a static peer answers download requests.
    #[derive(Clone)]
    enum DownloadBehavior {
        /// Response returns a fixed download response payload.
        Response(bbrpc::DownloadResponse),
    }

    /// StaticPeerService serves fixed revision and download responses.
    #[derive(Clone)]
    struct StaticPeerService {
        /// revision_response is returned from GetContentRevision.
        revision_response: bbrpc::GetContentRevisionResponse,
        /// download_behavior controls Download responses.
        download_behavior: DownloadBehavior,
    }

    impl StaticPeerService {
        /// Create a static service with the provided responses.
        fn new(
            revision_response: bbrpc::GetContentRevisionResponse,
            download_behavior: DownloadBehavior,
        ) -> Self {
            Self {
                revision_response,
                download_behavior,
            }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for StaticPeerService {
        async fn health_check(
            &self,
            _request: Request<bbrpc::HealthCheckRequest>,
        ) -> std::result::Result<Response<bbrpc::HealthCheckResponse>, Status> {
            Ok(Response::new(bbrpc::HealthCheckResponse {
                client_onion: String::new(),
                server_onion: String::new(),
            }))
        }

        async fn peer_exchange(
            &self,
            _request: Request<bbrpc::PeerExchangeRequest>,
        ) -> std::result::Result<Response<bbrpc::PeerExchangeResponse>, Status> {
            Err(Status::unimplemented(
                "peer exchange is not used in this test",
            ))
        }

        async fn get_content_revision(
            &self,
            _request: Request<bbrpc::GetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::GetContentRevisionResponse>, Status> {
            Ok(Response::new(self.revision_response.clone()))
        }

        async fn set_content_revision(
            &self,
            _request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            Ok(Response::new(bbrpc::SetContentRevisionResponse {}))
        }

        async fn download(
            &self,
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            match &self.download_behavior {
                DownloadBehavior::Response(response) => Ok(Response::new(response.clone())),
            }
        }
    }

    /// PlainPeerConnector resolves peers to local h2c test servers.
    #[derive(Debug, Default)]
    struct PlainPeerConnector {
        /// endpoints maps onion hostnames to plain HTTP endpoints.
        endpoints: RwLock<BTreeMap<String, String>>,
    }

    impl PlainPeerConnector {
        /// Create an empty plain connector.
        fn new() -> Self {
            Self::default()
        }

        /// Register one peer endpoint.
        fn register_peer(&self, peer_onion: &str, endpoint: &str) {
            self.endpoints
                .write()
                .unwrap()
                .insert(peer_onion.to_string(), endpoint.to_string());
        }
    }

    #[async_trait]
    impl PeerConnector for PlainPeerConnector {
        async fn connect(
            &self,
            peer_onion: &str,
            _client_private_key: &ed25519_dalek::SecretKey,
        ) -> anyhow::Result<transport::PeerClient> {
            let endpoint = self
                .endpoints
                .read()
                .unwrap()
                .get(peer_onion)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown peer onion: {peer_onion}"))?;
            let channel = Endpoint::from_shared(endpoint)?.connect().await?;

            Ok(transport::configure_peer_client(
                transport::PeerClient::new(channel),
            ))
        }
    }

    /// Spawn a plain h2c peer server for adversarial tests.
    async fn spawn_plain_peer_server<S>(
        service: S,
    ) -> anyhow::Result<(
        String,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    )>
    where
        S: bbrpc::barter_backup_server_server::BarterBackupServer + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let handle = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(
                    BarterBackupServerServer::new(service)
                        .max_decoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
                        .max_encoding_message_size(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES),
                )
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );

        Ok((format!("http://{address}"), handle))
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

    /// Return the current content info and encrypted blob from a node.
    fn current_content_snapshot(node: &Node) -> anyhow::Result<(bbrpc::ContentInfo, Vec<u8>)> {
        let content_info = node
            .responder_content()?
            .ok_or_else(|| anyhow::anyhow!("node has no current content"))?;
        let blob = node.with_store(|store| store.current_blob())?;

        Ok((content_info, blob))
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

    #[test]
    fn known_peers_persist_across_restart() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer = Node::new("persisted-peer")?;
        let first = Node::with_local_storage("owner", filesystem.clone())?;
        first.add_known_peer(peer.address())?;

        let reloaded = Node::with_local_storage("owner", filesystem)?;
        assert_eq!(reloaded.known_peers(), vec![peer.address().to_string()]);
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
    async fn download_peer_blob_rejects_malformed_responses() -> anyhow::Result<()> {
        struct Case {
            /// name is the subtest label.
            name: &'static str,
            /// response is returned by the static peer.
            response: bbrpc::DownloadResponse,
            /// expected_length is the length advertised before download starts.
            expected_length: i64,
            /// expected_code is the gRPC status mapped by the node.
            expected_code: Code,
        }

        let cases = vec![
            Case {
                name: "negative length",
                response: bbrpc::DownloadResponse {
                    total_length: -1,
                    sha256: vec![0u8; 32],
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 4,
                expected_code: Code::Internal,
            },
            Case {
                name: "missing section",
                response: bbrpc::DownloadResponse {
                    total_length: 4,
                    sha256: Sha256::digest(b"blob").to_vec(),
                    section: None,
                },
                expected_length: 4,
                expected_code: Code::Internal,
            },
            Case {
                name: "reference section",
                response: bbrpc::DownloadResponse {
                    total_length: 4,
                    sha256: Sha256::digest(b"blob").to_vec(),
                    section: Some(bbrpc::download_response::Section::Reference(
                        bbrpc::Reference {
                            offset_in_reference: 0,
                            length: 4,
                        },
                    )),
                },
                expected_length: 4,
                expected_code: Code::Unimplemented,
            },
            Case {
                name: "short blob",
                response: bbrpc::DownloadResponse {
                    total_length: 5,
                    sha256: Sha256::digest(b"blob").to_vec(),
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 5,
                expected_code: Code::Internal,
            },
            Case {
                name: "hash mismatch",
                response: bbrpc::DownloadResponse {
                    total_length: 4,
                    sha256: vec![0u8; 32],
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 4,
                expected_code: Code::DataLoss,
            },
            Case {
                name: "invalid hash length",
                response: bbrpc::DownloadResponse {
                    total_length: 4,
                    sha256: vec![0u8; 31],
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 4,
                expected_code: Code::DataLoss,
            },
            Case {
                name: "unexpected total length",
                response: bbrpc::DownloadResponse {
                    total_length: 4,
                    sha256: Sha256::digest(b"blob").to_vec(),
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 5,
                expected_code: Code::DataLoss,
            },
            Case {
                name: "oversized length",
                response: bbrpc::DownloadResponse {
                    total_length: max_peer_content_bytes_i64() + 1,
                    sha256: vec![0u8; 32],
                    section: Some(bbrpc::download_response::Section::RawBytes(
                        bbrpc::RawBytes {
                            value: b"blob".to_vec(),
                        },
                    )),
                },
                expected_length: 4,
                expected_code: Code::ResourceExhausted,
            },
        ];

        for case in cases {
            let node = Arc::new(Node::new("download-client")?);
            let peer_identity = Node::new(case.name)?;
            let connector = Arc::new(PlainPeerConnector::new());
            node.set_peer_connector(connector.clone());
            let static_service = StaticPeerService::new(
                bbrpc::GetContentRevisionResponse::default(),
                DownloadBehavior::Response(case.response),
            );
            let (endpoint, server) = spawn_plain_peer_server(static_service).await?;
            connector.register_peer(peer_identity.address(), &endpoint);

            let content_id = vec![0x44; CONTENT_ID_LEN];
            let error = node
                .download_peer_blob(peer_identity.address(), &content_id, case.expected_length)
                .await
                .unwrap_err();
            assert_eq!(error.code(), case.expected_code, "case {}", case.name);

            server.abort();
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connected_peers_classifies_online_and_offline_nodes() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester", requester_filesystem)?);
        let online_node = Arc::new(Node::new("online-peer")?);
        let offline_node = Arc::new(Node::new("offline-peer")?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(online_node.address())?;
        requester_node.add_known_peer(offline_node.address())?;

        let online_server =
            spawn_registered_p2p_server(online_node.clone(), connector.as_ref()).await?;
        let cli = CliService::new(requester_node.clone());

        let response = cli
            .connected_peers(tonic::Request::new(clirpc::ConnectedPeersRequest {}))
            .await?
            .into_inner();
        assert_eq!(
            response
                .connected_peers
                .into_iter()
                .map(|peer| peer.onion_service_id)
                .collect::<Vec<_>>(),
            vec![online_node.address().to_string()]
        );
        assert_eq!(
            response
                .offline_peers
                .into_iter()
                .map(|peer| peer.onion_service_id)
                .collect::<Vec<_>>(),
            vec![offline_node.address().to_string()]
        );

        online_server.abort();
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
            .with_store(|store| store.read_mirrored_blob(&requester_content.content_id))?;
        assert_eq!(mirrored_blob, requester_blob);

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn corrupted_mirrored_blob_is_redownloaded_on_next_sync() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester-refresh", requester_filesystem)?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage("responder-refresh", responder_filesystem.clone())?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        responder_node.add_known_peer(requester_node.address())?;

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

        // Corrupt the locally wrapped mirrored file so the next sync has to
        // discard it and re-download a clean copy from the peer.
        let mirrored_file = responder_filesystem
            .list()?
            .into_iter()
            .find(|name| name != ".peer-state.v1")
            .ok_or_else(|| anyhow::anyhow!("missing mirrored file"))?;
        let mut wrapped = responder_filesystem.read(&mirrored_file)?;
        wrapped[0] ^= 0x01;
        responder_filesystem.write_atomic(&mirrored_file, &wrapped)?;
        assert!(responder_node
            .with_store(|store| store.read_mirrored_blob(&requester_content.content_id))
            .is_err());

        let updates = responder_node
            .propose_contract_updates(requester_node.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(
            responder_node
                .with_store(|store| store.read_mirrored_blob(&requester_content.content_id))?,
            requester_node.with_store(|store| store.current_blob())?
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_content_revision_rejects_invalid_content_info() -> anyhow::Result<()> {
        struct Case {
            /// name is the subtest label.
            name: &'static str,
            /// content is the invalid requester content.
            content: bbrpc::ContentInfo,
        }

        let cases = vec![
            Case {
                name: "zero length",
                content: bbrpc::ContentInfo {
                    content_id: vec![0x11; CONTENT_ID_LEN],
                    content_length: 0,
                },
            },
            Case {
                name: "too large",
                content: bbrpc::ContentInfo {
                    content_id: vec![0x22; CONTENT_ID_LEN],
                    content_length: max_peer_content_bytes_i64() + 1,
                },
            },
            Case {
                name: "bad id length",
                content: bbrpc::ContentInfo {
                    content_id: vec![0x33; CONTENT_ID_LEN - 1],
                    content_length: 1,
                },
            },
        ];

        for case in cases {
            let responder_node = Arc::new(Node::with_local_storage(
                &format!("responder-{}", case.name),
                Arc::new(storage::MemoryFilesystem::new()),
            )?);
            let requester_node = Arc::new(Node::new(&format!("requester-{}", case.name))?);
            let connector = Arc::new(netmock::MockPeerConnector::new());
            let responder_server =
                spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
            let mut client =
                connect_p2p_client(requester_node, responder_node, connector.as_ref()).await?;

            let error = client
                .set_content_revision(bbrpc::SetContentRevisionRequest {
                    requester_content: Some(case.content.clone()),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument, "case {}", case.name);

            responder_server.abort();
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_reference_requests() -> anyhow::Result<()> {
        let server_node = Arc::new(Node::with_local_storage(
            "download-reference-server",
            Arc::new(storage::MemoryFilesystem::new()),
        )?);
        let client_node = Arc::new(Node::new("download-reference-client")?);
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
        let responder = p2p
            .get_content_revision(tonic::Request::new(bbrpc::GetContentRevisionRequest {}))
            .await?
            .into_inner()
            .responder_content
            .unwrap();

        let error = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id,
                offset: 0,
                reference_content_id: vec![0x55; CONTENT_ID_LEN],
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_message_limit_rejects_oversized_download_message() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("download-limit-client")?);
        let peer_identity = Node::new("download-limit-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        let oversized = vec![0u8; transport::PEER_GRPC_MESSAGE_LIMIT_BYTES + 1];
        let static_service = StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: max_peer_content_bytes_i64(),
                sha256: vec![0u8; 32],
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes { value: oversized },
                )),
            }),
        );
        let (endpoint, server) = spawn_plain_peer_server(static_service).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let content_id = vec![0x66; CONTENT_ID_LEN];
        let error = node
            .download_peer_blob(
                peer_identity.address(),
                &content_id,
                max_peer_content_bytes_i64(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);

        server.abort();
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
    async fn get_contracts_reports_live_sync_state() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester", requester_filesystem)?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage("responder", responder_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(responder_node.address())?;

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
        requester_cli
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;

        let contracts = requester_cli
            .get_contracts(tonic::Request::new(clirpc::GetContractsRequest {}))
            .await?
            .into_inner()
            .contracts;
        assert_eq!(contracts.len(), 1);
        assert!(contracts[0].online);
        assert!(contracts[0].our_content_synced);

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

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_rejects_wrong_total_length() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "contract-owner",
            filesystem,
            clock.clone(),
        )?);
        let peer_identity = Node::new("malicious-contract-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        node.add_known_peer(peer_identity.address())?;

        // Create one local revision that the peer will claim to hold.
        CliService::new(node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(node.as_ref())?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 0, 10))?;

        // Return the right sampled bytes and hash but lie about total_length.
        let static_service = StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_content: Some(content_info.clone()),
                requester_remaining_seconds: 0,
                responder_content: None,
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX) + 1,
                sha256: Sha256::digest(&blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob.clone(),
                    },
                )),
            }),
        );
        let (endpoint, server) = spawn_plain_peer_server(static_service).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let updates = node.check_contract_updates(peer_identity.address()).await?;
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::ContractState::InvalidContentReturned as i32)
        );
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            -90
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_syncs_both_sides() -> anyhow::Result<()> {
        let left_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let left_node = Arc::new(Node::with_local_storage("left", left_filesystem)?);
        let right_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let right_node = Arc::new(Node::with_local_storage("right", right_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        left_node.set_peer_connector(connector.clone());
        right_node.set_peer_connector(connector.clone());
        left_node
            .known_peers
            .lock()
            .unwrap()
            .insert(right_node.address().to_string());

        let left_cli = CliService::new(left_node.clone());
        let right_cli = CliService::new(right_node.clone());
        left_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "left.txt".to_string(),
                    data: b"left-body".to_vec(),
                }),
            }))
            .await?;
        right_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "right.txt".to_string(),
                    data: b"right-body".to_vec(),
                }),
            }))
            .await?;

        let left_server =
            spawn_registered_p2p_server(left_node.clone(), connector.as_ref()).await?;
        let right_server =
            spawn_registered_p2p_server(right_node.clone(), connector.as_ref()).await?;
        let updates = left_cli
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: right_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));

        let right_content = right_node.responder_content()?.unwrap();
        let mirrored_right_blob =
            left_node.with_store(|store| store.read_mirrored_blob(&right_content.content_id))?;
        assert_eq!(
            mirrored_right_blob,
            right_node.with_store(|store| store.current_blob())?
        );

        let left_content = left_node.responder_content()?.unwrap();
        let left_public_key = keys::public_key_from_onion_hostname(left_node.address())?;
        let right_peer_entry = right_node.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == left_public_key.as_bytes()))
        })?;
        assert_eq!(
            right_peer_entry.map(|peer| peer.content_id),
            Some(left_content.content_id)
        );

        left_server.abort();
        right_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_selects_latest_peer_version() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage("owner", owner_filesystem)?);
        let peer_a_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_a = Arc::new(Node::with_local_storage("peer-a", peer_a_filesystem)?);
        let peer_b_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_b = Arc::new(Node::with_local_storage("peer-b", peer_b_filesystem)?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage("owner", recovered_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner_node.set_peer_connector(connector.clone());
        peer_a.set_peer_connector(connector.clone());
        peer_b.set_peer_connector(connector.clone());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(peer_a.address().to_string());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(peer_b.address().to_string());

        let owner_cli = CliService::new(owner_node.clone());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-1".to_vec(),
                }),
            }))
            .await?;

        let owner_server =
            spawn_registered_p2p_server(owner_node.clone(), connector.as_ref()).await?;
        let peer_a_server = spawn_registered_p2p_server(peer_a.clone(), connector.as_ref()).await?;
        let peer_b_server = spawn_registered_p2p_server(peer_b.clone(), connector.as_ref()).await?;
        let mut owner_to_a =
            connect_p2p_client(owner_node.clone(), peer_a.clone(), connector.as_ref()).await?;
        let mut owner_to_b =
            connect_p2p_client(owner_node.clone(), peer_b.clone(), connector.as_ref()).await?;
        let version_1 = owner_node.responder_content()?.unwrap();
        owner_to_a
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(version_1.clone()),
            })
            .await?;
        owner_to_b
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(version_1.clone()),
            })
            .await?;

        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-2".to_vec(),
                }),
            }))
            .await?;
        let version_2 = owner_node.responder_content()?.unwrap();
        owner_to_a
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(version_2.clone()),
            })
            .await?;

        let recovered_cli = CliService::new(recovered_node.clone());
        let updates = recovered_cli
            .recover_content(tonic::Request::new(clirpc::RecoverContentRequest {}))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        let final_update = updates.last().unwrap();
        assert_eq!(final_update.most_recent_content_id, version_2.content_id);
        assert_eq!(final_update.num_peers_with_most_recent_version, 1);
        assert_eq!(final_update.total_versions_found, 2);
        assert_eq!(final_update.num_peers_with_any_versions, 2);
        assert!(final_update.recovered_most_recent_version);

        let recovered_file = recovered_node.with_store(|store| store.get_file("alpha.txt"))?;
        assert_eq!(recovered_file, b"version-2".to_vec());

        peer_b_server.abort();
        peer_a_server.abort();
        owner_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_tries_next_peer_after_bad_download() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage("recover-owner", owner_filesystem)?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "recover-owner",
            recovered_filesystem,
        )?);
        let bad_peer_identity = Node::new("recover-bad-peer")?;
        let good_peer_identity = Node::new("recover-good-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(bad_peer_identity.address().to_string());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(good_peer_identity.address().to_string());

        // Create one recoverable revision on an owner node using the same seed.
        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"latest-body".to_vec(),
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(owner_node.as_ref())?;
        let revision_response = bbrpc::GetContentRevisionResponse {
            requester_content: Some(content_info.clone()),
            requester_remaining_seconds: 0,
            responder_content: None,
        };

        // The first peer advertises the right revision but serves a corrupt
        // blob, while the second peer serves the same revision correctly.
        let bad_service = StaticPeerService::new(
            revision_response.clone(),
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                sha256: vec![0u8; 32],
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob.clone(),
                    },
                )),
            }),
        );
        let good_service = StaticPeerService::new(
            revision_response,
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob.clone(),
                    },
                )),
            }),
        );
        let (bad_endpoint, bad_server) = spawn_plain_peer_server(bad_service).await?;
        let (good_endpoint, good_server) = spawn_plain_peer_server(good_service).await?;
        connector.register_peer(bad_peer_identity.address(), &bad_endpoint);
        connector.register_peer(good_peer_identity.address(), &good_endpoint);

        let update = recovered_node.recover_content_update().await?;
        assert!(update.recovered_most_recent_version);
        assert_eq!(update.num_peers_with_most_recent_version, 2);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"latest-body".to_vec()
        );

        bad_server.abort();
        good_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn repeated_successful_checks_accumulate_long_term_score() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-long-term",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage_and_clock(
            "responder-long-term",
            responder_filesystem,
            responder_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(responder_node.address())?;

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
        requester_cli
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;

        for _ in 0..3 {
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
            requester_clock.advance(Duration::from_secs(30 * 24 * 60 * 60));
        }

        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            60 * 24 * 60 * 60
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stale_peer_can_recover_and_rebuild_score() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(2_000, 0).unwrap()));
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(2_000, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-stale",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage_and_clock(
            "responder-stale",
            responder_filesystem,
            responder_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(responder_node.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-v1".to_vec(),
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        requester_cli
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
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

        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-v2".to_vec(),
                }),
            }))
            .await?;
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
            failed_updates.last().map(|update| update.success),
            Some(false)
        );
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            -1_800
        );

        requester_cli
            .propose_contract(tonic::Request::new(clirpc::ProposeContractRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        requester_clock.advance(Duration::from_secs(3_600));
        let recovered_updates = requester_cli
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
            recovered_updates.last().map(|update| update.success),
            Some(true)
        );
        assert_eq!(
            peer_score_seconds(&requester_node, responder_node.address())?,
            1_800
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }
}
