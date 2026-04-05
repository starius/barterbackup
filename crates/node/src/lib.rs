//! Node orchestration for a single BarterBackup instance.
//!
//! The current implementation focuses on the local encrypted store and the RPC
//! surface that depends on it. Peer-to-peer contract management and Tor-backed
//! transport still need further work.

mod builtin_peers;

use anyhow::Result;
use clock::{Clock, SystemClock, Timestamp};
use content::CONTENT_ID_LEN;
use futures::{stream, Stream};
use protos::{bbrpc, clirpc, storedpb};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

/// DEFAULT_ALLOCATED_STORAGE_FOR_PEERS is the default peer-cache budget.
const DEFAULT_ALLOCATED_STORAGE_FOR_PEERS: i64 = 1024 * 1024 * 1024;

/// MAX_TRACKED_PEERS is the maximum number of peers kept in metadata.
const MAX_TRACKED_PEERS: usize = 1024;

/// StorageClass splits mirrored peer blobs into reserved and best-effort sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageClass {
    /// Reserved blobs belong to peers whose score is currently above zero.
    Reserved,
    /// BestEffort blobs belong only to peers whose score is zero or negative.
    BestEffort,
}

/// PeerBlobReference is one peer's reference to one mirrored blob.
#[derive(Clone, Debug)]
struct PeerBlobReference {
    /// peer_public_key identifies the peer that references the blob.
    peer_public_key: Vec<u8>,
    /// score_seconds is the peer's persisted score from our perspective.
    score_seconds: i64,
    /// score_measured_at is when `score_seconds` was last updated.
    score_measured_at: i64,
}

/// MirroredBlobUsage groups all peer references to one locally cached blob.
#[derive(Clone, Debug)]
struct MirroredBlobUsage {
    /// content_id identifies the mirrored blob.
    content_id: Vec<u8>,
    /// blob_len is the locally stored encrypted blob length.
    blob_len: i64,
    /// references are the peers that currently point at this blob.
    references: Vec<PeerBlobReference>,
}

/// StorageAdmission describes whether a new mirrored blob can be kept locally.
enum StorageAdmission {
    /// Store keeps the new blob and evicts the listed best-effort blobs first.
    Store { evict_content_ids: Vec<Vec<u8>> },
    /// TrackOnly remembers the peer's latest content id without caching bytes.
    TrackOnly,
}

/// PeerAdmissionPlan describes how peer-capacity enforcement handles a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerAdmissionPlan {
    /// Admit keeps the candidate peer and optionally evicts one existing peer.
    Admit { evicted_public_key: Option<Vec<u8>> },
    /// Reject leaves the current peer set unchanged.
    Reject,
}

/// Build the default local storage policy.
fn default_storage_config() -> clirpc::StorageConfig {
    clirpc::StorageConfig {
        allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
        min_replicas: 0,
    }
}

/// Return the effective peer priority from persisted origin, score, and direction.
fn peer_priority(origin: i32, score_seconds: i64, first_contact_direction: i32) -> u8 {
    if origin == storedpb::PeerOrigin::Manual as i32 {
        5
    } else if score_seconds > 0 {
        4
    } else if origin == storedpb::PeerOrigin::BuiltIn as i32 {
        3
    } else if first_contact_direction == storedpb::FirstContactDirection::Outbound as i32 {
        2
    } else if first_contact_direction == storedpb::FirstContactDirection::Inbound as i32 {
        1
    } else {
        0
    }
}

/// Return the deterministic eviction order for one tracked peer.
fn peer_eviction_order_key(peer: &storedpb::Peer) -> (u8, i64, i64, Vec<u8>) {
    (
        peer_priority(
            peer.origin,
            peer.score_seconds,
            peer.first_contact_direction,
        ),
        peer.score_seconds,
        peer.score_measured_at,
        peer.onion_pubkey.clone(),
    )
}

/// Plan whether one candidate peer may join the tracked peer set.
fn plan_peer_admission(
    existing_peers: &[storedpb::Peer],
    candidate_public_key: &[u8],
    candidate_origin: i32,
    candidate_score_seconds: i64,
    candidate_first_contact_direction: i32,
    capacity: usize,
) -> PeerAdmissionPlan {
    if existing_peers
        .iter()
        .any(|peer| peer.onion_pubkey.as_slice() == candidate_public_key)
    {
        return PeerAdmissionPlan::Admit {
            evicted_public_key: None,
        };
    }
    if existing_peers.len() < capacity {
        return PeerAdmissionPlan::Admit {
            evicted_public_key: None,
        };
    }

    let candidate_priority = peer_priority(
        candidate_origin,
        candidate_score_seconds,
        candidate_first_contact_direction,
    );
    let Some(worst_peer) = existing_peers
        .iter()
        .min_by_key(|peer| peer_eviction_order_key(peer))
    else {
        return PeerAdmissionPlan::Reject;
    };
    let worst_priority = peer_priority(
        worst_peer.origin,
        worst_peer.score_seconds,
        worst_peer.first_contact_direction,
    );
    if candidate_priority <= worst_priority {
        return PeerAdmissionPlan::Reject;
    }

    PeerAdmissionPlan::Admit {
        evicted_public_key: Some(worst_peer.onion_pubkey.clone()),
    }
}

/// Classify one peer score into reserved or best-effort storage.
fn storage_class(score_seconds: i64) -> StorageClass {
    if score_seconds > 0 {
        StorageClass::Reserved
    } else {
        StorageClass::BestEffort
    }
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

/// Return the compiled built-in peer list as owned strings.
fn built_in_peers() -> Vec<String> {
    builtin_peers::BUILTIN_PEERS
        .iter()
        .map(|peer| (*peer).to_string())
        .collect()
}

/// Merge built-in peers with additional live peers for source export.
fn merged_export_peers(additional_peers: &[String]) -> Vec<String> {
    let mut peers = BTreeSet::new();
    peers.extend(built_in_peers());
    peers.extend(additional_peers.iter().cloned());
    peers.into_iter().collect()
}

/// Render the full Rust source file that defines the built-in peer list.
fn render_built_in_peer_source(peers: &[String]) -> String {
    let mut source = String::from(
        "//! Built-in bootstrap peers compiled into the binary.\n\
         //!\n\
         //! Operators can regenerate this file from a live node with the hidden\n\
         //! `bbcli export-built-in-peers` command.\n\n\
         /// BUILTIN_PEERS is the compiled bootstrap peer list.\n\
         pub const BUILTIN_PEERS: &[&str] = &[\n",
    );

    for peer in peers {
        source.push_str("    \"");
        source.push_str(peer);
        source.push_str("\",\n");
    }

    source.push_str("];\n");
    source
}

/// Return one persisted peer origin as a storedpb enum value.
fn peer_origin_code(built_in: bool, manual: bool) -> i32 {
    if manual {
        storedpb::PeerOrigin::Manual as i32
    } else if built_in {
        storedpb::PeerOrigin::BuiltIn as i32
    } else {
        storedpb::PeerOrigin::Discovered as i32
    }
}

/// Return the newest locally cached peer content summary, including legacy fallback.
fn peer_latest_cached_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.latest_cached_content.clone().or_else(|| {
        (peer.latest_known_content.is_none() && !peer.content_id.is_empty()).then(|| {
            storedpb::PeerContent {
                content_id: peer.content_id.clone(),
                content_length: 0,
            }
        })
    })
}

/// Return the newest known peer content summary, including legacy fallback.
fn peer_latest_known_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.latest_known_content.clone().or_else(|| {
        (!peer.content_id.is_empty()).then(|| storedpb::PeerContent {
            content_id: peer.content_id.clone(),
            content_length: 0,
        })
    })
}

/// Convert one stored peer-content summary into the RPC content shape.
fn rpc_content_info(content: storedpb::PeerContent) -> bbrpc::ContentInfo {
    bbrpc::ContentInfo {
        content_id: content.content_id,
        content_length: content.content_length,
    }
}

/// Return whether the observed recovery candidates imply a divergent timeline.
fn recovery_candidates_diverge(candidates: &[RecoveryCandidate]) -> bool {
    for (index, left) in candidates.iter().enumerate() {
        for right in &candidates[index + 1..] {
            if left.key.0 == right.key.0 && left.content_id != right.content_id {
                return true;
            }
            if left.key.0 < right.key.0 && (left.key.1, left.key.2) > (right.key.1, right.key.2) {
                return true;
            }
            if right.key.0 < left.key.0 && (right.key.1, right.key.2) > (left.key.1, left.key.2) {
                return true;
            }
        }
    }

    false
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

/// RecoveryCandidate is one peer-visible revision seen during recovery.
#[derive(Clone)]
struct RecoveryCandidate {
    /// key orders content revisions without downloading full bodies.
    key: (u64, u64, u32, u32),
    /// content_id is the recoverable encrypted revision identifier.
    content_id: Vec<u8>,
    /// content_length is the encrypted blob length advertised by peers.
    content_length: i64,
    /// peers are the peers that reported the same candidate revision.
    peers: Vec<String>,
}

impl Node {
    /// Create a node identity without attaching a local encrypted store.
    pub fn new(seed: &str) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(&master, None, Arc::new(SystemClock))
    }

    /// Create a node identity with a local encrypted store.
    pub fn with_local_storage(seed: &str, filesystem: Arc<dyn Filesystem>) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(&master, Some(filesystem), Arc::new(SystemClock))
    }

    /// Create a node identity with a local encrypted store and explicit clock.
    pub fn with_local_storage_and_clock(
        seed: &str,
        filesystem: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(&master, Some(filesystem), clock)
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

    /// Create a node identity from already-derived master material in tests.
    #[cfg(test)]
    fn new_for_tests_from_master(master_priv: &[u8]) -> Result<Self> {
        Self::build_from_master(master_priv, None, Arc::new(SystemClock))
    }

    /// Build a node, optionally attaching an encrypted local store.
    fn build_from_master(
        master_priv: &[u8],
        filesystem: Option<Arc<dyn Filesystem>>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let (keypair, public_key) = keys::derive_ed25519_from_master(master_priv, "tor/onion/v3")?;
        let onion_address = keys::onion_hostname_from_public_key(&public_key);
        let store = filesystem
            .map(|filesystem| Store::new_with_time_source(filesystem, master_priv, clock.clone()))
            .transpose()?
            .map(Mutex::new);
        let built_in_peer_list = built_in_peers();
        let node = Self {
            ed25519_keypair: keypair,
            onion_address,
            clock,
            started_at: Mutex::new(None),
            store,
            known_peers: Mutex::new(BTreeSet::new()),
            storage_config: Mutex::new(default_storage_config()),
            peer_connector: Mutex::new(None),
        };

        if node.store.is_some() {
            node.trim_tracked_peers_to_capacity()?;
            node.purge_self_peer_metadata()?;
            node.refresh_known_peers_from_store()?;
            for peer_onion in built_in_peer_list {
                if let Err(error) =
                    node.add_known_peer_with_origin(&peer_onion, peer_origin_code(true, false))
                {
                    warn!(peer = %peer_onion, %error, "failed to admit built-in peer");
                }
            }
        } else {
            let mut known_peers = node.known_peers.lock().unwrap();
            known_peers.extend(built_in_peer_list);
        }

        Ok(node)
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

    /// Convert one public key byte slice into an onion hostname.
    fn onion_from_public_key_bytes(&self, public_key: &[u8]) -> Result<String, Status> {
        let public_key = ed25519_dalek::PublicKey::from_bytes(public_key)
            .map_err(|_| Status::invalid_argument("peer public key is invalid"))?;
        Ok(keys::onion_hostname_from_public_key(&public_key))
    }

    /// Report whether `peer_onion` identifies the local node itself.
    fn is_our_onion(&self, peer_onion: &str) -> bool {
        peer_onion == self.address()
    }

    /// Report whether `peer_public_key` belongs to the local node itself.
    fn is_our_public_key(&self, peer_public_key: &ed25519_dalek::PublicKey) -> bool {
        peer_public_key == &self.ed25519_keypair.public
    }

    /// Return one clear error for self-peer contract attempts.
    fn self_peer_error(&self) -> Status {
        Status::failed_precondition("local node cannot act as its own peer")
    }

    /// Return the tracked peer metadata currently persisted in the store.
    fn tracked_peers(&self) -> Result<Vec<storedpb::Peer>, Status> {
        self.with_store(|store| Ok(store.peers()))
    }

    /// Report whether one peer is already tracked in persisted metadata.
    fn is_tracked_peer(&self, peer_public_key: &ed25519_dalek::PublicKey) -> Result<bool, Status> {
        Ok(self
            .tracked_peers()?
            .into_iter()
            .any(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes()))
    }

    /// Replace the cached known-peer list with what is currently persisted.
    fn refresh_known_peers_from_store(&self) -> Result<(), Status> {
        let tracked_peers = self.tracked_peers()?;
        let known_peers = tracked_peers
            .into_iter()
            .filter_map(|peer| self.onion_from_public_key_bytes(&peer.onion_pubkey).ok())
            .filter(|peer_onion| !self.is_our_onion(peer_onion))
            .collect::<BTreeSet<_>>();
        *self.known_peers.lock().unwrap() = known_peers;
        Ok(())
    }

    /// Remove any stale persisted self-peer metadata left by older versions.
    fn purge_self_peer_metadata(&self) -> Result<(), Status> {
        let Some(store_mutex) = self.store.as_ref() else {
            return Ok(());
        };
        let self_public_key = self.ed25519_keypair.public.to_bytes().to_vec();

        let evicted_cached_content_id = {
            let mut store = store_mutex.lock().unwrap();
            let peers = store.peers();
            let Some(peer) = peers
                .into_iter()
                .find(|peer| peer.onion_pubkey == self_public_key)
            else {
                return Ok(());
            };

            let evicted_cached_content_id =
                peer_latest_cached_content(&peer).map(|content| content.content_id);
            store
                .remove_peer(&self_public_key)
                .map_err(map_storage_error)?;
            evicted_cached_content_id
        };

        if let Some(content_id) = evicted_cached_content_id {
            self.remove_unused_foreign_blob(&content_id)?;
        }

        Ok(())
    }

    /// Trim any overflow from old peer metadata down to the configured capacity.
    fn trim_tracked_peers_to_capacity(&self) -> Result<(), Status> {
        self.trim_tracked_peers_to_capacity_with_limit(MAX_TRACKED_PEERS)
    }

    /// Trim any overflow from old peer metadata down to the provided capacity.
    fn trim_tracked_peers_to_capacity_with_limit(&self, capacity: usize) -> Result<(), Status> {
        let Some(store_mutex) = self.store.as_ref() else {
            return Ok(());
        };
        let mut evicted_cached_content_ids = Vec::<Vec<u8>>::new();
        {
            let mut store = store_mutex.lock().unwrap();
            let mut peers = store.peers();
            if peers.len() <= capacity {
                return Ok(());
            }

            peers.sort_by_key(peer_eviction_order_key);
            let overflow = peers.len().saturating_sub(capacity);
            for peer in peers.into_iter().take(overflow) {
                if let Some(cached_content) = peer_latest_cached_content(&peer) {
                    evicted_cached_content_ids.push(cached_content.content_id);
                }
                store
                    .remove_peer(&peer.onion_pubkey)
                    .map_err(map_storage_error)?;
            }
        }

        for content_id in evicted_cached_content_ids {
            self.remove_unused_foreign_blob(&content_id)?;
        }

        Ok(())
    }

    /// Admit or upgrade one tracked peer under the priority-based capacity policy.
    fn track_peer_identity(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        origin: i32,
        first_contact_direction: i32,
    ) -> Result<(), Status> {
        self.track_peer_identity_with_capacity(
            peer_public_key,
            origin,
            first_contact_direction,
            MAX_TRACKED_PEERS,
        )
    }

    /// Admit or upgrade one tracked peer under the provided capacity limit.
    fn track_peer_identity_with_capacity(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        origin: i32,
        first_contact_direction: i32,
        capacity: usize,
    ) -> Result<(), Status> {
        let peer_onion = keys::onion_hostname_from_public_key(peer_public_key);
        let Some(store_mutex) = self.store.as_ref() else {
            self.known_peers.lock().unwrap().insert(peer_onion);
            return Ok(());
        };

        let mut evicted_onion = None;
        let mut evicted_cached_content_id = None;
        {
            let mut store = store_mutex.lock().unwrap();
            let peers = store.peers();
            match plan_peer_admission(
                &peers,
                peer_public_key.as_bytes(),
                origin,
                0,
                first_contact_direction,
                capacity,
            ) {
                PeerAdmissionPlan::Reject => {
                    return Err(Status::resource_exhausted(format!(
                        "peer capacity reached; refusing to track {peer_onion}"
                    )));
                }
                PeerAdmissionPlan::Admit { evicted_public_key } => {
                    if let Some(evicted_public_key) = evicted_public_key {
                        let evicted_peer = peers
                            .into_iter()
                            .find(|peer| peer.onion_pubkey == evicted_public_key)
                            .ok_or_else(|| Status::internal("missing peer chosen for eviction"))?;
                        evicted_onion =
                            Some(self.onion_from_public_key_bytes(&evicted_public_key)?);
                        evicted_cached_content_id = peer_latest_cached_content(&evicted_peer)
                            .map(|content| content.content_id);
                        store
                            .remove_peer(&evicted_public_key)
                            .map_err(map_storage_error)?;
                    }
                    store
                        .ensure_peer_with_origin(peer_public_key.as_bytes(), origin)
                        .map_err(map_storage_error)?;
                    if first_contact_direction != storedpb::FirstContactDirection::Unknown as i32 {
                        store
                            .set_peer_first_contact_direction(
                                peer_public_key.as_bytes(),
                                first_contact_direction,
                            )
                            .map_err(map_storage_error)?;
                    }
                }
            }
        }

        let mut known_peers = self.known_peers.lock().unwrap();
        if let Some(evicted_onion) = evicted_onion {
            known_peers.remove(&evicted_onion);
        }
        known_peers.insert(peer_onion);
        drop(known_peers);

        if let Some(evicted_cached_content_id) = evicted_cached_content_id {
            self.remove_unused_foreign_blob(&evicted_cached_content_id)?;
        }

        Ok(())
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
        self.add_known_peer_with_origin(peer_onion, peer_origin_code(false, true))
    }

    /// Add a peer onion hostname to the configured peer set with an explicit origin.
    fn add_known_peer_with_origin(&self, peer_onion: &str, origin: i32) -> Result<(), Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        self.track_peer_identity(
            &peer_public_key,
            origin,
            storedpb::FirstContactDirection::Unknown as i32,
        )
    }

    /// Return the configured peer onion hostnames in deterministic order.
    pub fn known_peers(&self) -> Vec<String> {
        self.known_peers.lock().unwrap().iter().cloned().collect()
    }

    /// Render the full built-in peer source file from built-ins plus live peers.
    pub async fn export_built_in_peer_source(&self) -> Result<String, Status> {
        let connected_peers = self.connected_peers_response().await?;
        let live_peers = connected_peers
            .connected_peers
            .into_iter()
            .map(|peer| peer.onion_service_id)
            .collect::<Vec<_>>();

        Ok(render_built_in_peer_source(&merged_export_peers(
            &live_peers,
        )))
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
                .and_then(|peer| peer_latest_cached_content(&peer))
                .map(|content| content.content_id))
        })
    }

    /// Return the newest known and newest cached summaries for one peer.
    fn mirrored_peer_revision_state(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<(Option<storedpb::PeerContent>, Option<storedpb::PeerContent>), Status> {
        self.with_store(|store| {
            let peer = store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
            Ok(peer
                .map(|peer| {
                    (
                        peer_latest_known_content(&peer),
                        peer_latest_cached_content(&peer),
                    )
                })
                .unwrap_or((None, None)))
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
        let public_key = tlsutil::public_key_from_certificate_der(end_entity.as_ref())
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
            let Some(cached_content) = peer_latest_cached_content(&peer) else {
                return Ok(None);
            };

            match store.read_mirrored_blob(&cached_content.content_id) {
                Ok(blob) => Ok(Some(bbrpc::ContentInfo {
                    content_id: cached_content.content_id,
                    content_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                })),
                Err(StorageError::FileNotFound) => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    /// Build a responder-side view of the newest requester revision we know exists.
    fn requester_latest_known_content(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<Option<bbrpc::ContentInfo>, Status> {
        self.with_store(|store| {
            let peer = store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes());
            Ok(peer
                .and_then(|peer| peer_latest_known_content(&peer))
                .map(rpc_content_info))
        })
    }

    /// Connect to another peer using the configured outbound transport.
    async fn connect_peer_client(&self, peer_onion: &str) -> Result<transport::PeerClient, Status> {
        self.connect_peer_client_with_timeout(peer_onion, transport::PEER_CONNECT_TIMEOUT)
            .await
    }

    /// Connect to another peer using the configured outbound transport and one
    /// explicit dial timeout.
    async fn connect_peer_client_with_timeout(
        &self,
        peer_onion: &str,
        connect_timeout: Duration,
    ) -> Result<transport::PeerClient, Status> {
        let connector = self
            .peer_connector
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| Status::failed_precondition("peer connector is not configured"))?;
        let client = tokio::time::timeout(
            connect_timeout,
            connector.connect(peer_onion, &self.ed25519_keypair.secret),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("connect peer timed out"))?
        .map_err(|error| Status::unavailable(format!("connect peer: {error}")))?;
        if !self.is_our_onion(peer_onion) {
            let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
                .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
            self.track_peer_identity(
                &peer_public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Outbound as i32,
            )?;
        }

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
        self.peer_rpc_with_timeout(peer_onion, operation, transport::PEER_RPC_TIMEOUT, future)
            .await
    }

    /// Run one peer RPC under one explicit timeout budget.
    async fn peer_rpc_with_timeout<T, F>(
        &self,
        peer_onion: &str,
        operation: &'static str,
        rpc_timeout: Duration,
        future: F,
    ) -> Result<T, Status>
    where
        F: Future<Output = Result<Response<T>, tonic::Status>>,
    {
        match tokio::time::timeout(rpc_timeout, future).await {
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(error)) => Err(Status::new(
                error.code(),
                format!("{operation} from {peer_onion}: {}", error.message()),
            )),
            Err(_) => Err(Status::deadline_exceeded(format!(
                "{operation} from {peer_onion} timed out"
            ))),
        }
    }

    /// Run one whole peer workflow with reconnect-and-retry under a shared
    /// operation budget.
    async fn retry_peer_operation<T, F, Fut>(
        &self,
        _peer_onion: &str,
        policy: transport::PeerRetryPolicy,
        mut operation: F,
    ) -> Result<T, Status>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Status>>,
    {
        let started_at = tokio::time::Instant::now();
        let mut retry_attempt = 0u32;

        loop {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) if transport::is_retryable_peer_status(&error) => {
                    retry_attempt = retry_attempt.saturating_add(1);
                    let backoff = policy.backoff_for_attempt(retry_attempt);
                    if started_at.elapsed().saturating_add(backoff) > policy.total_budget {
                        return Err(error);
                    }
                    tokio::time::sleep(backoff).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Run a peer health check against the node's own public onion address.
    pub async fn self_peer_health_check(&self) -> Result<bbrpc::HealthCheckResponse, Status> {
        let mut client = self.connect_peer_client(self.address()).await?;
        self.peer_rpc(
            self.address(),
            "self peer health check",
            client.health_check(bbrpc::HealthCheckRequest {}),
        )
        .await
    }

    /// Probe one peer for recovery metadata with reconnect-and-retry.
    async fn recovery_revision_from_peer(
        &self,
        peer_onion: &str,
    ) -> Result<bbrpc::GetContentRevisionResponse, Status> {
        let policy =
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::RecoveryProbe);
        self.retry_peer_operation(peer_onion, policy, || async move {
            let mut client = self
                .connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
                .await?;
            self.peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await
        })
        .await
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

    /// Download one peer blob under the shared recovery retry policy.
    async fn download_recoverable_peer_blob(
        &self,
        peer_onion: &str,
        content_id: &[u8],
        expected_length: i64,
    ) -> Result<Vec<u8>, Status> {
        let content_id = content_id.to_vec();
        self.retry_peer_operation(
            peer_onion,
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::RecoveryDownload),
            || self.download_peer_blob(peer_onion, &content_id, expected_length),
        )
        .await
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
            if store.peers().iter().any(|peer| {
                peer_latest_cached_content(peer)
                    .is_some_and(|content| content.content_id.as_slice() == content_id)
            }) {
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

    /// Return the configured peer-storage budget in bytes.
    fn storage_budget_bytes(&self) -> i64 {
        self.storage_config
            .lock()
            .unwrap()
            .allocated_storage_for_peers
            .max(0)
    }

    /// Group all currently cached mirrored blobs with the peers that reference them.
    fn mirrored_blob_usage(&self) -> Result<Vec<MirroredBlobUsage>, Status> {
        self.with_store(|store| {
            let mut lengths = BTreeMap::<Vec<u8>, i64>::new();
            let mut usage = BTreeMap::<Vec<u8>, MirroredBlobUsage>::new();

            // Reuse one decrypted length per content id so shared mirrored blobs
            // are accounted only once while still tracking all peer references.
            for peer in store.peers() {
                let Some(cached_content) = peer_latest_cached_content(&peer) else {
                    continue;
                };

                let blob_len = if let Some(blob_len) = lengths.get(&cached_content.content_id) {
                    *blob_len
                } else {
                    let blob_len = match store.read_mirrored_blob(&cached_content.content_id) {
                        Ok(blob) => i64::try_from(blob.len()).unwrap_or(i64::MAX),
                        Err(StorageError::FileNotFound)
                        | Err(StorageError::RecoveryRequired(_)) => 0,
                        Err(error) => return Err(error),
                    };
                    lengths.insert(cached_content.content_id.clone(), blob_len);
                    blob_len
                };
                if blob_len == 0 {
                    continue;
                }

                usage
                    .entry(cached_content.content_id.clone())
                    .or_insert_with(|| MirroredBlobUsage {
                        content_id: cached_content.content_id.clone(),
                        blob_len,
                        references: Vec::new(),
                    });
                usage
                    .get_mut(&cached_content.content_id)
                    .expect("usage entry was just inserted")
                    .references
                    .push(PeerBlobReference {
                        peer_public_key: peer.onion_pubkey,
                        score_seconds: peer.score_seconds,
                        score_measured_at: peer.score_measured_at,
                    });
            }

            Ok(usage.into_values().collect())
        })
    }

    /// Compute the largest peer blob we can still accept under the storage policy.
    fn maximum_peer_content_accepted_bytes(&self) -> Result<i64, Status> {
        let budget = self.storage_budget_bytes();
        let protected_used = self
            .mirrored_blob_usage()?
            .into_iter()
            .filter(|usage| {
                usage.references.iter().any(|reference| {
                    storage_class(reference.score_seconds) == StorageClass::Reserved
                })
            })
            .fold(0i64, |used, usage| used.saturating_add(usage.blob_len));

        Ok((budget.saturating_sub(protected_used))
            .max(0)
            .min(max_peer_content_bytes_i64()))
    }

    /// Plan whether a new mirrored blob can be stored and which blobs to evict first.
    fn plan_mirrored_blob_storage(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        previous_content_id: Option<&[u8]>,
        new_content_id: &[u8],
        new_content_length: i64,
    ) -> Result<StorageAdmission, Status> {
        let budget = self.storage_budget_bytes();
        if new_content_length <= 0 {
            return Err(Status::invalid_argument(
                "peer content length must be positive",
            ));
        }
        if new_content_length > max_peer_content_bytes_i64() {
            return Err(Status::resource_exhausted("peer content is too large"));
        }

        let current_score = self.peer_score_state(peer_public_key)?.0;
        let incoming_class = storage_class(current_score);
        let peer_key = peer_public_key.as_bytes();
        let mut total_used = 0i64;
        let mut protected_used = 0i64;
        let mut evictable = Vec::<(Vec<u8>, i64, i64, i64)>::new();

        // Model the storage set after the peer metadata is updated so we can
        // replace one peer's old revision with its new one in a single step.
        for usage in self.mirrored_blob_usage()? {
            if usage.content_id == new_content_id {
                return Ok(StorageAdmission::Store {
                    evict_content_ids: Vec::new(),
                });
            }

            let remaining_references = usage
                .references
                .into_iter()
                .filter(|reference| {
                    !(reference.peer_public_key.as_slice() == peer_key
                        && previous_content_id
                            .is_some_and(|previous| previous == usage.content_id.as_slice()))
                })
                .collect::<Vec<_>>();
            if remaining_references.is_empty() {
                continue;
            }

            total_used = total_used.saturating_add(usage.blob_len);
            if remaining_references
                .iter()
                .any(|reference| storage_class(reference.score_seconds) == StorageClass::Reserved)
            {
                protected_used = protected_used.saturating_add(usage.blob_len);
            } else {
                let best_score = remaining_references
                    .iter()
                    .map(|reference| reference.score_seconds)
                    .max()
                    .unwrap_or_default();
                let newest_measurement = remaining_references
                    .iter()
                    .map(|reference| reference.score_measured_at)
                    .max()
                    .unwrap_or_default();
                evictable.push((
                    usage.content_id,
                    usage.blob_len,
                    best_score,
                    newest_measurement,
                ));
            }
        }

        // Positive-score peers reserve storage first; if reserved content alone
        // would exceed the budget, we can only track the latest revision.
        if incoming_class == StorageClass::Reserved
            && protected_used.saturating_add(new_content_length) > budget
        {
            return Ok(StorageAdmission::TrackOnly);
        }

        // Evict the worst best-effort blobs first until the new blob fits.
        evictable.sort_by(|left, right| {
            left.2
                .cmp(&right.2)
                .then(left.3.cmp(&right.3))
                .then(left.1.cmp(&right.1))
                .then(left.0.cmp(&right.0))
        });

        let mut evict_content_ids = Vec::new();
        for (content_id, blob_len, _, _) in evictable {
            if total_used.saturating_add(new_content_length) <= budget {
                break;
            }
            total_used = total_used.saturating_sub(blob_len);
            evict_content_ids.push(content_id);
        }

        if total_used.saturating_add(new_content_length) > budget {
            return Ok(StorageAdmission::TrackOnly);
        }

        Ok(StorageAdmission::Store { evict_content_ids })
    }

    /// Remove mirrored blobs that were selected as evictable best-effort cache entries.
    fn evict_mirrored_blobs(&self, content_ids: &[Vec<u8>]) -> Result<(), Status> {
        self.with_store(|store| {
            for content_id in content_ids {
                match store.remove_mirrored_blob(content_id) {
                    Ok(()) | Err(StorageError::FileNotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })
    }

    /// Mirror or clear the latest advertised content for a peer.
    async fn sync_peer_content_info(
        &self,
        peer_onion: &str,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_info: Option<&bbrpc::ContentInfo>,
    ) -> Result<(), Status> {
        if !self.is_tracked_peer(peer_public_key)? {
            return Err(Status::resource_exhausted(format!(
                "peer capacity reached; refusing to mirror {peer_onion}"
            )));
        }
        let (_, previous_cached_content) = self.mirrored_peer_revision_state(peer_public_key)?;
        let previous_cached_content_id = previous_cached_content
            .as_ref()
            .map(|content| content.content_id.clone());

        match content_info {
            Some(content_info) => {
                validate_peer_content_info(content_info)?;
                let content_id = content_id_hex(&content_info.content_id);
                let mirrored_state = self.mirrored_blob_state(&content_info.content_id)?;
                let mut storage_error = None;
                let current_score = self.peer_score_state(peer_public_key)?.0;
                let next_cached_content;

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
                    match self.plan_mirrored_blob_storage(
                        peer_public_key,
                        previous_cached_content_id.as_deref(),
                        &content_info.content_id,
                        content_info.content_length,
                    )? {
                        StorageAdmission::Store { evict_content_ids } => {
                            if !evict_content_ids.is_empty() {
                                self.evict_mirrored_blobs(&evict_content_ids)?;
                                info!(
                                    peer = %peer_onion,
                                    evicted_blob_count = evict_content_ids.len(),
                                    "evicted best-effort mirrored peer blobs to make room"
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
                            next_cached_content = Some(storedpb::PeerContent {
                                content_id: content_info.content_id.clone(),
                                content_length: content_info.content_length,
                            });
                        }
                        StorageAdmission::TrackOnly => {
                            next_cached_content =
                                previous_cached_content.clone().filter(|cached_content| {
                                    cached_content.content_id != content_info.content_id
                                        && storage_class(current_score) == StorageClass::Reserved
                                });
                            warn!(
                                peer = %peer_onion,
                                content_id = %content_id,
                                content_length = content_info.content_length,
                                allocated_storage_for_peers = self.storage_budget_bytes(),
                                maximum_peer_content_accepted_bytes = self.maximum_peer_content_accepted_bytes()?,
                                "tracked peer revision without caching the blob because the storage budget was exhausted"
                            );
                            storage_error = Some(Status::resource_exhausted(
                                "peer storage budget was exhausted",
                            ));
                        }
                    }
                } else {
                    next_cached_content = Some(storedpb::PeerContent {
                        content_id: content_info.content_id.clone(),
                        content_length: content_info.content_length,
                    });
                }
                self.with_store(|store| {
                    store.set_peer_content_state(
                        peer_public_key.as_bytes(),
                        Some(&content_info.content_id),
                        Some(content_info.content_length),
                        next_cached_content
                            .as_ref()
                            .map(|content| content.content_id.as_slice()),
                        next_cached_content
                            .as_ref()
                            .map(|content| content.content_length),
                    )
                })?;
                if let Some(previous_cached_content_id) = previous_cached_content_id {
                    let still_cached = next_cached_content
                        .as_ref()
                        .is_some_and(|content| content.content_id == previous_cached_content_id);
                    if !still_cached {
                        self.remove_unused_foreign_blob(&previous_cached_content_id)?;
                    }
                }
                if let Some(error) = storage_error {
                    return Err(error);
                }
            }
            None => {
                let previous_content_id_hex = previous_cached_content_id
                    .as_ref()
                    .map(|content_id| content_id_hex(content_id))
                    .unwrap_or_default();
                self.with_store(|store| store.clear_peer_content_id(peer_public_key.as_bytes()))?;
                if let Some(previous_content_id) = previous_cached_content_id {
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
        if !self.is_tracked_peer(peer_public_key)? {
            return Err(Status::failed_precondition("peer is not tracked"));
        }
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

    /// Return the unresolved active conflict, if any.
    fn active_conflict(&self) -> Result<Option<storedpb::ActiveConflict>, Status> {
        self.with_store(|store| Ok(store.active_conflict()))
    }

    /// Return the archived conflict revisions.
    fn archived_conflicts(&self) -> Result<Vec<storedpb::ConflictRevision>, Status> {
        self.with_store(|store| Ok(store.archived_conflicts()))
    }

    /// Build one conflict revision summary from a decoded local or peer blob.
    fn conflict_revision_from_blob(
        &self,
        content_id: &[u8],
        content_length: i64,
        blob: &[u8],
        source_peer_onion: &str,
        source_is_local: bool,
    ) -> Result<storedpb::ConflictRevision, Status> {
        let revision = self.revision_key(content_id)?;
        let file_count = self.with_store(|store| {
            Ok(i64::try_from(store.decode_revision_files(blob)?.len()).unwrap_or(i64::MAX))
        })?;

        Ok(storedpb::ConflictRevision {
            content_id: content_id.to_vec(),
            created_at: i64::try_from(revision.1).unwrap_or(i64::MAX),
            created_at_ns: i64::from(revision.2),
            content_length,
            file_count,
            source_peer_onion: source_peer_onion.to_string(),
            source_is_local,
            resolved_at: 0,
            resolved_at_ns: 0,
        })
    }

    /// Build one conflict revision summary for the current local active blob.
    fn current_conflict_revision(&self) -> Result<Option<storedpb::ConflictRevision>, Status> {
        self.with_store(|store| {
            let Some(current) = store.current_content() else {
                return Ok(None);
            };
            let blob = store.current_blob()?;
            let file_count =
                i64::try_from(store.decode_revision_files(&blob)?.len()).unwrap_or(i64::MAX);
            Ok(Some(storedpb::ConflictRevision {
                content_id: current.content_id.clone(),
                created_at: i64::try_from(current.revision.created_at_secs).unwrap_or(i64::MAX),
                created_at_ns: i64::from(current.revision.created_at_nanos),
                content_length: i64::try_from(current.blob_len).unwrap_or(i64::MAX),
                file_count,
                source_peer_onion: String::new(),
                source_is_local: true,
                resolved_at: 0,
                resolved_at_ns: 0,
            }))
        })
    }

    /// Persist the unresolved conflict revisions and log concrete resolution help.
    async fn register_conflict_candidates(
        &self,
        candidates: &[RecoveryCandidate],
    ) -> Result<(), Status> {
        if let Some(current_revision) = self.current_conflict_revision()? {
            self.with_store(|store| store.ensure_active_conflict_revision(current_revision))?;
        }

        for candidate in candidates {
            let (blob, source_peer) = match self
                .with_store(|store| store.read_revision_blob(&candidate.content_id))
            {
                Ok(blob) => (blob, String::new()),
                Err(error) if error.code() == Code::NotFound => {
                    let mut last_error = None;
                    let mut downloaded = None;
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
                                self.with_store(|store| {
                                    store.write_mirrored_blob(&candidate.content_id, &blob)
                                })?;
                                downloaded = Some((blob, source_peer.clone()));
                                last_error = None;
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    match downloaded {
                        Some(downloaded) => downloaded,
                        None => return Err(last_error.expect("download loop must record an error")),
                    }
                }
                Err(error) => return Err(error),
            };
            let revision = self.conflict_revision_from_blob(
                &candidate.content_id,
                candidate.content_length,
                &blob,
                &source_peer,
                false,
            )?;
            self.with_store(|store| store.ensure_active_conflict_revision(revision))?;
        }

        if let Some(active_conflict) = self.active_conflict()? {
            let revision_ids = active_conflict
                .revisions
                .iter()
                .map(|revision| hex::encode(&revision.content_id))
                .collect::<Vec<_>>();
            warn!(
                revision_ids = ?revision_ids,
                "detected a divergent revision history; inspect with `bbcli list-conflicts`, check out a revision with `bbcli checkout-revision <content-id> <out-dir>`, and resolve with `bbcli resolve-conflict <content-id>`"
            );
        }

        Ok(())
    }

    /// Return an operator-facing error if unresolved conflicts block file commands.
    fn ensure_no_active_conflict(&self) -> Result<(), Status> {
        let Some(active_conflict) = self.active_conflict()? else {
            return Ok(());
        };
        let revisions = active_conflict
            .revisions
            .iter()
            .map(|revision| {
                format!(
                    "{} ts={}.{:09} size={} files={}",
                    hex::encode(&revision.content_id),
                    revision.created_at,
                    revision.created_at_ns,
                    revision.content_length,
                    revision.file_count
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        Err(Status::failed_precondition(format!(
            "resolve the active conflict first with `bbcli list-conflicts`, `bbcli checkout-revision <content-id> <out-dir>`, and `bbcli resolve-conflict <content-id>`; revisions: {revisions}"
        )))
    }

    /// Convert one stored conflict revision into the CLI response shape.
    fn conflict_revision_info(
        &self,
        revision: storedpb::ConflictRevision,
        unresolved: bool,
    ) -> clirpc::ConflictRevisionInfo {
        clirpc::ConflictRevisionInfo {
            content_id: revision.content_id,
            created_at: revision.created_at,
            created_at_ns: revision.created_at_ns,
            content_length: revision.content_length,
            file_count: revision.file_count,
            source_peer_onion: revision.source_peer_onion,
            source_is_local: revision.source_is_local,
            unresolved,
            resolved_at: revision.resolved_at,
            resolved_at_ns: revision.resolved_at_ns,
        }
    }

    /// Build the list-conflicts response for unresolved and archived revisions.
    fn list_conflicts_response(&self) -> Result<clirpc::ListConflictsResponse, Status> {
        let mut revisions = Vec::new();
        if let Some(active_conflict) = self.active_conflict()? {
            revisions.extend(
                active_conflict
                    .revisions
                    .into_iter()
                    .map(|revision| self.conflict_revision_info(revision, true)),
            );
        }
        revisions.extend(
            self.archived_conflicts()?
                .into_iter()
                .map(|revision| self.conflict_revision_info(revision, false)),
        );
        revisions.sort_by(|left, right| {
            left.unresolved
                .cmp(&right.unresolved)
                .reverse()
                .then(left.created_at.cmp(&right.created_at))
                .then(left.created_at_ns.cmp(&right.created_at_ns))
                .then(left.content_id.cmp(&right.content_id))
        });
        Ok(clirpc::ListConflictsResponse { revisions })
    }

    /// Decode one conflicted or archived revision into a checkout response.
    fn checkout_revision_response(
        &self,
        content_id: &[u8],
    ) -> Result<clirpc::CheckoutRevisionResponse, Status> {
        let files = self.with_store(|store| store.read_revision_files(content_id))?;
        Ok(clirpc::CheckoutRevisionResponse {
            file: files
                .into_iter()
                .map(|file| clirpc::File {
                    name: file.name,
                    data: file.data,
                })
                .collect(),
        })
    }

    /// Resolve the active conflict and keep the selected revision as current.
    fn resolve_conflict(&self, content_id: &[u8]) -> Result<(), Status> {
        let now = self.clock.now();
        let current_revision = self.current_conflict_revision()?;
        if current_revision
            .as_ref()
            .is_some_and(|revision| revision.content_id.as_slice() != content_id)
        {
            self.with_store(|store| {
                let current_blob = store.current_blob()?;
                store.write_mirrored_blob(
                    current_revision
                        .as_ref()
                        .expect("checked above")
                        .content_id
                        .as_slice(),
                    &current_blob,
                )
            })?;
        }
        let selected_blob = self.with_store(|store| store.read_revision_blob(content_id))?;
        self.restore_current_blob(&selected_blob)?;
        self.with_store(|store| {
            store.resolve_active_conflict(
                content_id,
                i64::try_from(now.secs).unwrap_or(i64::MAX),
                i64::from(now.nanos),
            )?;
            Ok(())
        })?;
        Ok(())
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
            let Some(cached_content) = peer_latest_cached_content(&peer) else {
                return Ok(0);
            };

            match store.read_mirrored_blob(&cached_content.content_id) {
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
            if self.is_our_onion(&peer_onion) {
                continue;
            }
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
            if self.is_our_onion(&peer_onion) {
                continue;
            }
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
            let (their_latest_known_content, their_latest_cached_content) =
                self.mirrored_peer_revision_state(&peer_public_key)?;

            contracts.push(clirpc::ContractInfo {
                peer: Some(clirpc::Peer {
                    onion_service_id: peer_onion,
                }),
                our_content_synced,
                our_remaining_seconds,
                their_remaining_seconds: self.peer_score_state(&peer_public_key)?.0,
                their_content_length: self.mirrored_peer_content_length(&peer_public_key)?,
                online,
                their_latest_known_content_id: their_latest_known_content
                    .as_ref()
                    .map(|content| content.content_id.clone())
                    .unwrap_or_default(),
                their_latest_known_content_length: their_latest_known_content
                    .as_ref()
                    .map(|content| content.content_length)
                    .unwrap_or(0),
                their_latest_cached_content_id: their_latest_cached_content
                    .as_ref()
                    .map(|content| content.content_id.clone())
                    .unwrap_or_default(),
                their_latest_cached_content_length: their_latest_cached_content
                    .as_ref()
                    .map(|content| content.content_length)
                    .unwrap_or(0),
            });
        }

        Ok(clirpc::GetContractsResponse { contracts })
    }

    /// Build the derived storage view shown by the local CLI.
    pub async fn storage_info(&self) -> Result<clirpc::StorageInfo, Status> {
        let contracts = self.get_contracts_response().await?;
        let mut online_obligations = 0i64;
        let mut offline_obligations = 0i64;
        let mut expired_offline_obligations = 0i64;

        // Split mirrored-peer usage by live reachability and by whether the
        // peer has expired into best-effort storage from our perspective.
        for contract in contracts.contracts {
            let content_bytes = contract.their_content_length.max(0);
            if contract.online && contract.our_content_synced {
                online_obligations = online_obligations.saturating_add(content_bytes);
            } else {
                offline_obligations = offline_obligations.saturating_add(content_bytes);
                if contract.their_remaining_seconds < 0 {
                    expired_offline_obligations =
                        expired_offline_obligations.saturating_add(content_bytes);
                }
            }
        }

        let our_content_bytes = self.with_store(|store| {
            Ok(store
                .current_content()
                .map(|current| i64::try_from(current.blob_len).unwrap_or(i64::MAX))
                .unwrap_or(0))
        })?;

        Ok(clirpc::StorageInfo {
            online_peers_storage_obligations_bytes: online_obligations,
            offline_peers_storage_obligations_bytes: offline_obligations,
            expired_offline_peers_storage_obligations_bytes: expired_offline_obligations,
            our_content_bytes,
            maximum_peer_content_accepted_bytes: self.maximum_peer_content_accepted_bytes()?,
        })
    }

    /// Propose or renew a contract with one peer and report the progress
    /// updates that should be streamed to the caller.
    pub async fn propose_contract_updates(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::ProposeContractUpdate>, Status> {
        self.retry_peer_operation(
            peer_onion,
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Proposal),
            || self.propose_contract_updates_once(peer_onion),
        )
        .await
    }

    /// Perform one proposal attempt against a peer without any outer retry
    /// loop.
    async fn propose_contract_updates_once(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::ProposeContractUpdate>, Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
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
        let policy = transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Proposal);
        let mut client = self
            .connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
            .await?;
        let revision = self
            .peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
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
            self.peer_rpc_with_timeout(
                peer_onion,
                "set content revision",
                policy.rpc_timeout,
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
        self.retry_peer_operation(
            peer_onion,
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Check),
            || self.check_contract_updates_once(peer_onion),
        )
        .await
    }

    /// Perform one contract-check attempt against a peer without any outer
    /// retry loop.
    async fn check_contract_updates_once(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::CheckContractUpdate>, Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
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
        let policy = transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Check);
        let mut client = self
            .connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
            .await?;
        let revision = self
            .peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
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
            .peer_rpc_with_timeout(
                peer_onion,
                "download sampled section",
                policy.rpc_timeout,
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
        let mut known_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut recoverable_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut peers_with_any_versions = 0i64;

        // Ask every known peer which version of our content it knows about and
        // which version it can actually serve right now.
        for peer_onion in self.known_peers() {
            if self.is_our_onion(&peer_onion) {
                continue;
            }
            let revision = match self.recovery_revision_from_peer(&peer_onion).await {
                Ok(revision) => revision,
                Err(_) => continue,
            };
            if let Some(content_info) = revision
                .requester_latest_known_content
                .clone()
                .or_else(|| revision.requester_content.clone())
            {
                let key = match self.revision_key(&content_info.content_id) {
                    Ok(key) => key,
                    Err(_) => continue,
                };

                peers_with_any_versions += 1;
                known_candidates
                    .entry(content_info.content_id.clone())
                    .and_modify(|candidate| candidate.peers.push(peer_onion.clone()))
                    .or_insert(RecoveryCandidate {
                        key,
                        content_id: content_info.content_id,
                        content_length: content_info.content_length,
                        peers: vec![peer_onion.clone()],
                    });
            }

            if let Some(content_info) = revision.requester_content {
                let key = match self.revision_key(&content_info.content_id) {
                    Ok(key) => key,
                    Err(_) => continue,
                };

                recoverable_candidates
                    .entry(content_info.content_id.clone())
                    .and_modify(|candidate| candidate.peers.push(peer_onion.clone()))
                    .or_insert(RecoveryCandidate {
                        key,
                        content_id: content_info.content_id,
                        content_length: content_info.content_length,
                        peers: vec![peer_onion],
                    });
            }
        }

        let current_content = self.responder_content()?;
        let mut divergence_candidates =
            recoverable_candidates.values().cloned().collect::<Vec<_>>();
        if let Some(current_content) = current_content.as_ref() {
            if let Ok(key) = self.revision_key(&current_content.content_id) {
                if divergence_candidates
                    .iter()
                    .all(|candidate| candidate.content_id != current_content.content_id)
                {
                    divergence_candidates.push(RecoveryCandidate {
                        key,
                        content_id: current_content.content_id.clone(),
                        content_length: current_content.content_length,
                        peers: Vec::new(),
                    });
                }
            }
        }

        // Pick both the newest known revision and the newest revision that at
        // least one peer can still serve.
        let most_recent = known_candidates
            .values()
            .max_by_key(|candidate| candidate.key)
            .cloned();
        let freshest_recoverable = recoverable_candidates
            .values()
            .max_by_key(|candidate| candidate.key)
            .cloned();
        let mut most_recent_downloaded_bytes = 0i64;
        let mut most_recent_downloaded_files = 0i64;
        let mut recovered_most_recent_version = false;
        let mut recovered_fallback_version = false;

        if recovery_candidates_diverge(&divergence_candidates) {
            let tracked_candidates = recoverable_candidates.values().cloned().collect::<Vec<_>>();
            self.register_conflict_candidates(&tracked_candidates)
                .await?;
        } else if self.active_conflict()?.is_none() {
            if let Some(candidate) = freshest_recoverable.as_ref() {
                let already_current = current_content
                    .as_ref()
                    .is_some_and(|content_info| content_info.content_id == candidate.content_id);
                recovered_fallback_version = most_recent
                    .as_ref()
                    .is_some_and(|most_recent| most_recent.content_id != candidate.content_id);
                if already_current {
                    recovered_most_recent_version = !recovered_fallback_version;
                } else {
                    // Try every peer that advertised the newest revision so one
                    // broken replica cannot block recovery from another copy.
                    let mut last_error = None;
                    for source_peer in &candidate.peers {
                        match self
                            .download_recoverable_peer_blob(
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
                                recovered_most_recent_version = !recovered_fallback_version;
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
            total_versions_found: i64::try_from(known_candidates.len()).unwrap_or(i64::MAX),
            num_peers_with_any_versions: peers_with_any_versions,
            most_recent_downloaded_bytes,
            most_recent_downloaded_files,
            total_downloaded_bytes: most_recent_downloaded_bytes,
            recovered_most_recent_version,
            freshest_recoverable_content_id: freshest_recoverable
                .as_ref()
                .map(|candidate| candidate.content_id.clone())
                .unwrap_or_default(),
            freshest_recoverable_ts: freshest_recoverable
                .as_ref()
                .map(|candidate| i64::try_from(candidate.key.1).unwrap_or(i64::MAX))
                .unwrap_or(0),
            freshest_recoverable_ts_ns: freshest_recoverable
                .as_ref()
                .map(|candidate| i64::from(candidate.key.2))
                .unwrap_or(0),
            freshest_recoverable_length: freshest_recoverable
                .as_ref()
                .map(|candidate| candidate.content_length)
                .unwrap_or(0),
            num_peers_with_freshest_recoverable_version: freshest_recoverable
                .as_ref()
                .map(|candidate| i64::try_from(candidate.peers.len()).unwrap_or(i64::MAX))
                .unwrap_or(0),
            recovered_fallback_version,
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
            peer_runtime_state: clirpc::PeerRuntimeState::Unknown as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: clirpc::SelfPeerCheckState::Unknown as i32,
            self_peer_check_error: String::new(),
        }))
    }

    async fn init(
        &self,
        request: tonic::Request<clirpc::InitRequest>,
    ) -> Result<tonic::Response<clirpc::InitResponse>, tonic::Status> {
        if request.into_inner().main_password.is_empty() {
            return Err(Status::invalid_argument("main password is required"));
        }

        Err(Status::failed_precondition(
            "initialization is only supported by the daemon",
        ))
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

    async fn stop(
        &self,
        _request: tonic::Request<clirpc::StopRequest>,
    ) -> Result<tonic::Response<clirpc::StopResponse>, tonic::Status> {
        Err(Status::failed_precondition(
            "graceful stop is only supported by the daemon",
        ))
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

    async fn export_built_in_peers(
        &self,
        _request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<tonic::Response<clirpc::ExportBuiltInPeersResponse>, tonic::Status> {
        Ok(Response::new(clirpc::ExportBuiltInPeersResponse {
            rust_source: self.node.export_built_in_peer_source().await?,
        }))
    }

    async fn list_conflicts(
        &self,
        _request: tonic::Request<clirpc::ListConflictsRequest>,
    ) -> Result<tonic::Response<clirpc::ListConflictsResponse>, tonic::Status> {
        Ok(Response::new(self.node.list_conflicts_response()?))
    }

    async fn checkout_revision(
        &self,
        request: tonic::Request<clirpc::CheckoutRevisionRequest>,
    ) -> Result<tonic::Response<clirpc::CheckoutRevisionResponse>, tonic::Status> {
        let request = request.into_inner();
        validate_peer_content_id(&request.content_id)?;
        Ok(Response::new(
            self.node.checkout_revision_response(&request.content_id)?,
        ))
    }

    async fn resolve_conflict(
        &self,
        request: tonic::Request<clirpc::ResolveConflictRequest>,
    ) -> Result<tonic::Response<clirpc::ResolveConflictResponse>, tonic::Status> {
        let request = request.into_inner();
        validate_peer_content_id(&request.content_id)?;
        self.node.resolve_conflict(&request.content_id)?;
        Ok(Response::new(clirpc::ResolveConflictResponse {}))
    }

    async fn set_file(
        &self,
        request: tonic::Request<clirpc::SetFileRequest>,
    ) -> Result<tonic::Response<clirpc::SetFileResponse>, tonic::Status> {
        self.node.ensure_no_active_conflict()?;
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
        self.node.ensure_no_active_conflict()?;
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
        self.node.ensure_no_active_conflict()?;
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
        self.node.ensure_no_active_conflict()?;
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
        if config.allocated_storage_for_peers < 0 {
            return Err(Status::invalid_argument(
                "allocated_storage_for_peers must be non-negative",
            ));
        }
        if config.min_replicas < 0 {
            return Err(Status::invalid_argument(
                "min_replicas must be non-negative",
            ));
        }
        *self.node.storage_config.lock().unwrap() = config;
        Ok(Response::new(clirpc::SetStorageConfigResponse {}))
    }

    async fn get_storage_config(
        &self,
        _request: tonic::Request<clirpc::GetStorageConfigRequest>,
    ) -> Result<tonic::Response<clirpc::GetStorageConfigResponse>, tonic::Status> {
        let config = *self.node.storage_config.lock().unwrap();

        Ok(Response::new(clirpc::GetStorageConfigResponse {
            config: Some(config),
            info: Some(self.node.storage_info().await?),
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
        let peer_identity = self.node.peer_identity_from_request(&request)?;
        if self.node.is_our_public_key(&peer_identity.public_key) {
            return Err(self.node.self_peer_error());
        }
        self.node.track_peer_identity(
            &peer_identity.public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Inbound as i32,
        )?;
        let request = request.into_inner();
        for peer in request.peers {
            let public_key = match ed25519_dalek::PublicKey::from_bytes(&peer.onion_pubkey) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
            let peer_onion = keys::onion_hostname_from_public_key(&public_key);
            if let Err(error) = self
                .node
                .add_known_peer_with_origin(&peer_onion, peer_origin_code(false, false))
            {
                warn!(peer = %peer_onion, %error, "skipped discovered peer during peer exchange");
            }
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
        let peer_identity = self.node.peer_identity_from_request(&request).ok();
        if let Some(peer_identity) = peer_identity.as_ref() {
            if self.node.is_our_public_key(&peer_identity.public_key) {
                return Err(self.node.self_peer_error());
            }
            self.node.track_peer_identity(
                &peer_identity.public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
            )?;
        }
        let requester_content = peer_identity
            .as_ref()
            .map(|peer_identity| self.node.requester_content(&peer_identity.public_key))
            .transpose()?
            .flatten();
        let requester_latest_known_content = peer_identity
            .as_ref()
            .map(|peer_identity| {
                self.node
                    .requester_latest_known_content(&peer_identity.public_key)
            })
            .transpose()?
            .flatten();
        Ok(Response::new(bbrpc::GetContentRevisionResponse {
            requester_content,
            requester_remaining_seconds: 0,
            responder_content: self.node.responder_content()?,
            requester_latest_known_content,
        }))
    }

    async fn set_content_revision(
        &self,
        request: tonic::Request<bbrpc::SetContentRevisionRequest>,
    ) -> Result<tonic::Response<bbrpc::SetContentRevisionResponse>, tonic::Status> {
        let peer_identity = self.node.peer_identity_from_request(&request)?;
        if self.node.is_our_public_key(&peer_identity.public_key) {
            return Err(self.node.self_peer_error());
        }
        self.node.track_peer_identity(
            &peer_identity.public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Inbound as i32,
        )?;
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
        if let Some(peer_identity) = peer_identity.as_ref() {
            if self.node.is_our_public_key(&peer_identity.public_key) {
                return Err(self.node.self_peer_error());
            }
            self.node.track_peer_identity(
                &peer_identity.public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
            )?;
        }
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, RwLock};
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

    /// FlakyPeerConnector fails the first few dials before delegating to a real
    /// connector.
    struct FlakyPeerConnector {
        /// delegate handles successful connections once the injected failures end.
        delegate: Arc<dyn PeerConnector>,
        /// remaining_failures counts how many dial attempts should still fail.
        remaining_failures: AtomicUsize,
        /// dial_count records how many total dial attempts were made.
        dial_count: AtomicUsize,
    }

    impl FlakyPeerConnector {
        /// Create a connector that fails `remaining_failures` dial attempts.
        fn new(delegate: Arc<dyn PeerConnector>, remaining_failures: usize) -> Self {
            Self {
                delegate,
                remaining_failures: AtomicUsize::new(remaining_failures),
                dial_count: AtomicUsize::new(0),
            }
        }

        /// Report how many total dial attempts were made.
        fn dial_count(&self) -> usize {
            self.dial_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PeerConnector for FlakyPeerConnector {
        async fn connect(
            &self,
            peer_onion: &str,
            client_private_key: &ed25519_dalek::SecretKey,
        ) -> anyhow::Result<transport::PeerClient> {
            self.dial_count.fetch_add(1, Ordering::SeqCst);
            let remaining = self.remaining_failures.load(Ordering::SeqCst);
            if remaining > 0 {
                self.remaining_failures.fetch_sub(1, Ordering::SeqCst);
                anyhow::bail!("temporary transport error");
            }

            self.delegate.connect(peer_onion, client_private_key).await
        }
    }

    /// TransientSetAckState tracks one peer's requester-content state for
    /// ambiguous `SetContentRevision` retries.
    #[derive(Default)]
    struct TransientSetAckState {
        /// requester_content records the latest requester content accepted.
        requester_content: Mutex<Option<bbrpc::ContentInfo>>,
        /// fail_first_set flips one applied set operation into a retryable error.
        fail_first_set: AtomicBool,
        /// set_call_count records how many set requests the service observed.
        set_call_count: AtomicUsize,
    }

    impl TransientSetAckState {
        /// Create state that fails the first set request after applying it.
        fn new() -> Self {
            Self {
                requester_content: Mutex::new(None),
                fail_first_set: AtomicBool::new(true),
                set_call_count: AtomicUsize::new(0),
            }
        }

        /// Return how many set requests the service observed.
        fn set_call_count(&self) -> usize {
            self.set_call_count.load(Ordering::SeqCst)
        }

        /// Return the latest requester content accepted by the service.
        fn requester_content(&self) -> Option<bbrpc::ContentInfo> {
            self.requester_content.lock().unwrap().clone()
        }
    }

    /// TransientSetAckPeerService applies the first set request but returns a
    /// retryable error so the caller must refresh live peer state.
    #[derive(Clone)]
    struct TransientSetAckPeerService {
        /// state stores the applied requester revision and call counters.
        state: Arc<TransientSetAckState>,
    }

    impl TransientSetAckPeerService {
        /// Create a service backed by shared retry state.
        fn new(state: Arc<TransientSetAckState>) -> Self {
            Self { state }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for TransientSetAckPeerService {
        async fn health_check(
            &self,
            _request: Request<bbrpc::HealthCheckRequest>,
        ) -> std::result::Result<Response<bbrpc::HealthCheckResponse>, Status> {
            Ok(Response::new(bbrpc::HealthCheckResponse::default()))
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
            Ok(Response::new(bbrpc::GetContentRevisionResponse {
                requester_content: self.state.requester_content(),
                requester_remaining_seconds: 0,
                responder_content: None,
                requester_latest_known_content: self.state.requester_content(),
            }))
        }

        async fn set_content_revision(
            &self,
            request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            self.state.set_call_count.fetch_add(1, Ordering::SeqCst);
            *self.state.requester_content.lock().unwrap() = request.into_inner().requester_content;

            if self.state.fail_first_set.swap(false, Ordering::SeqCst) {
                return Err(Status::unavailable("transient after apply"));
            }

            Ok(Response::new(bbrpc::SetContentRevisionResponse {}))
        }

        async fn download(
            &self,
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            Err(Status::unimplemented("download is not used in this test"))
        }
    }

    /// TransientDownloadState controls one peer that fails the first sampled
    /// download before returning valid content.
    struct TransientDownloadState {
        /// fail_first_download flips the first sampled download into a retryable error.
        fail_first_download: AtomicBool,
        /// download_call_count records how many sampled downloads were attempted.
        download_call_count: AtomicUsize,
        /// requester_content is the local revision the peer claims to store.
        requester_content: bbrpc::ContentInfo,
        /// blob is the exact encrypted content returned after the transient failure.
        blob: Vec<u8>,
    }

    impl TransientDownloadState {
        /// Create download state for one requester content revision and blob.
        fn new(requester_content: bbrpc::ContentInfo, blob: Vec<u8>) -> Self {
            Self {
                fail_first_download: AtomicBool::new(true),
                download_call_count: AtomicUsize::new(0),
                requester_content,
                blob,
            }
        }

        /// Report how many sampled downloads the peer observed.
        fn download_call_count(&self) -> usize {
            self.download_call_count.load(Ordering::SeqCst)
        }
    }

    /// TransientDownloadPeerService fails the first sampled download with a
    /// retryable error and succeeds on the next attempt.
    #[derive(Clone)]
    struct TransientDownloadPeerService {
        /// state stores the advertised revision and transient download behavior.
        state: Arc<TransientDownloadState>,
    }

    impl TransientDownloadPeerService {
        /// Create a service backed by shared transient download state.
        fn new(state: Arc<TransientDownloadState>) -> Self {
            Self { state }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for TransientDownloadPeerService {
        async fn health_check(
            &self,
            _request: Request<bbrpc::HealthCheckRequest>,
        ) -> std::result::Result<Response<bbrpc::HealthCheckResponse>, Status> {
            Ok(Response::new(bbrpc::HealthCheckResponse::default()))
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
            Ok(Response::new(bbrpc::GetContentRevisionResponse {
                requester_content: Some(self.state.requester_content.clone()),
                requester_remaining_seconds: 0,
                responder_content: None,
                requester_latest_known_content: Some(self.state.requester_content.clone()),
            }))
        }

        async fn set_content_revision(
            &self,
            _request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            Err(Status::unimplemented(
                "set content revision is not used in this test",
            ))
        }

        async fn download(
            &self,
            request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            self.state
                .download_call_count
                .fetch_add(1, Ordering::SeqCst);
            if self.state.fail_first_download.swap(false, Ordering::SeqCst) {
                return Err(Status::unavailable("transient sampled download failure"));
            }
            let request = request.into_inner();
            if request.offset < 0 {
                return Err(Status::invalid_argument("offset must be non-negative"));
            }
            let offset = usize::try_from(request.offset)
                .map_err(|_| Status::invalid_argument("offset is too large"))?;
            let sampled = self
                .state
                .blob
                .get(offset..)
                .ok_or_else(|| Status::invalid_argument("offset is too large"))?
                .to_vec();

            Ok(Response::new(bbrpc::DownloadResponse {
                total_length: i64::try_from(self.state.blob.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&self.state.blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes { value: sampled },
                )),
            }))
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

    /// Report whether one mirrored peer blob is currently cached locally.
    fn cached_peer_blob(node: &Node, content_id: &[u8]) -> anyhow::Result<bool> {
        Ok(node.with_store(|store| store.has_mirrored_blob(content_id))?)
    }

    /// Return the persisted peer entry for one onion identifier.
    fn peer_entry(node: &Node, peer_onion: &str) -> anyhow::Result<Option<storedpb::Peer>> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)?;
        Ok(node.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes()))
        })?)
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
    async fn self_health_check_does_not_track_the_local_node() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("self-health", filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        node.set_peer_connector(connector.clone());
        let server = spawn_registered_p2p_server(node.clone(), connector.as_ref()).await?;

        let response = node.self_peer_health_check().await?;
        assert_eq!(response.client_onion, node.address());
        assert_eq!(response.server_onion, node.address());
        assert!(node.known_peers().is_empty());

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
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;
        let persisted_peer = reloaded.with_store(|store| {
            Ok(store.peers().into_iter().find(|stored_peer| {
                stored_peer.onion_pubkey.as_slice() == peer_public_key.as_bytes()
            }))
        })?;
        assert_eq!(
            persisted_peer.map(|peer| peer.origin),
            Some(storedpb::PeerOrigin::Manual as i32)
        );
        Ok(())
    }

    #[test]
    fn add_known_peer_rejects_our_own_onion() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("self-peer", filesystem)?;
        let error = node.add_known_peer(node.address()).unwrap_err();

        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.message(), "local node cannot act as its own peer");
        Ok(())
    }

    #[test]
    fn restart_prunes_stale_self_peer_metadata() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let first = Node::with_local_storage("self-prune", filesystem.clone())?;
        let self_public_key = first.ed25519_keypair().public.to_bytes().to_vec();
        first.with_store(|store| {
            store.ensure_peer_with_origin(&self_public_key, storedpb::PeerOrigin::Manual as i32)?;
            Ok(())
        })?;

        let reloaded = Node::with_local_storage("self-prune", filesystem)?;
        assert!(reloaded.known_peers().is_empty());
        let persisted_self = reloaded.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey == self_public_key))
        })?;
        assert!(persisted_self.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_rejects_the_local_node_as_peer() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("self-propose", filesystem)?;
        let error = node
            .propose_contract_updates(node.address())
            .await
            .unwrap_err();

        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.message(), "local node cannot act as its own peer");
        Ok(())
    }

    #[test]
    fn merged_export_peers_deduplicates_and_sorts() {
        let peers = merged_export_peers(&[
            "z.onion".to_string(),
            "a.onion".to_string(),
            "z.onion".to_string(),
        ]);

        assert_eq!(peers, vec!["a.onion".to_string(), "z.onion".to_string()]);
    }

    #[test]
    fn rendered_built_in_peer_source_contains_peer_entries() {
        let source =
            render_built_in_peer_source(&["alpha.onion".to_string(), "beta.onion".to_string()]);

        assert!(source.contains("pub const BUILTIN_PEERS"));
        assert!(source.contains("\"alpha.onion\""));
        assert!(source.contains("\"beta.onion\""));
    }

    #[test]
    fn master_constructor_matches_seed_constructor() -> anyhow::Result<()> {
        let seed = "test-master-constructor";
        let master = keys::derive_master_priv(seed);
        let from_seed = Node::new(seed)?;
        let from_master = Node::new_for_tests_from_master(&master)?;

        assert_eq!(from_master.address(), from_seed.address());
        assert_eq!(
            from_master.ed25519_keypair().public,
            from_seed.ed25519_keypair().public
        );
        Ok(())
    }

    /// Build deterministic master material for synthetic node tests.
    fn test_master_priv(label: &str) -> [u8; 64] {
        let first = Sha256::digest(format!("test-master:first:{label}").as_bytes());
        let second = Sha256::digest(format!("test-master:second:{label}").as_bytes());
        let mut master = [0u8; 64];
        master[..32].copy_from_slice(first.as_slice());
        master[32..].copy_from_slice(second.as_slice());
        master
    }

    /// Build one stored peer entry for priority-policy tests.
    fn test_peer(
        seed: &str,
        origin: i32,
        score_seconds: i64,
        first_contact_direction: i32,
    ) -> storedpb::Peer {
        let master = test_master_priv(seed);
        let identity = Node::new_for_tests_from_master(&master).unwrap();

        storedpb::Peer {
            onion_pubkey: identity.ed25519_keypair().public.to_bytes().to_vec(),
            score_seconds,
            score_measured_at: 0,
            content_id: Vec::new(),
            latest_known_content: None,
            latest_cached_content: None,
            origin,
            first_contact_direction,
        }
    }

    #[test]
    fn peer_priority_follows_product_order() {
        assert!(
            peer_priority(
                storedpb::PeerOrigin::Manual as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                1,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
        assert!(
            peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                1,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                storedpb::PeerOrigin::BuiltIn as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
        assert!(
            peer_priority(
                storedpb::PeerOrigin::BuiltIn as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Outbound as i32,
            )
        );
        assert!(
            peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Outbound as i32,
            ) > peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Inbound as i32,
            )
        );
        assert!(
            peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Inbound as i32,
            ) > peer_priority(
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
    }

    #[test]
    fn plan_peer_admission_only_evicts_strictly_lower_priority_peers() {
        let inbound_peer = test_peer(
            "priority-inbound",
            storedpb::PeerOrigin::Discovered as i32,
            0,
            storedpb::FirstContactDirection::Inbound as i32,
        );
        let reserved_peer = test_peer(
            "priority-reserved",
            storedpb::PeerOrigin::Discovered as i32,
            10,
            storedpb::FirstContactDirection::Unknown as i32,
        );
        let outbound_candidate = test_peer(
            "priority-outbound",
            storedpb::PeerOrigin::Discovered as i32,
            0,
            storedpb::FirstContactDirection::Outbound as i32,
        );
        let equal_inbound_candidate = test_peer(
            "priority-inbound-equal",
            storedpb::PeerOrigin::Discovered as i32,
            0,
            storedpb::FirstContactDirection::Inbound as i32,
        );
        let built_in_candidate = test_peer(
            "priority-built-in",
            storedpb::PeerOrigin::BuiltIn as i32,
            0,
            storedpb::FirstContactDirection::Unknown as i32,
        );

        assert_eq!(
            plan_peer_admission(
                std::slice::from_ref(&inbound_peer),
                &outbound_candidate.onion_pubkey,
                outbound_candidate.origin,
                outbound_candidate.score_seconds,
                outbound_candidate.first_contact_direction,
                1,
            ),
            PeerAdmissionPlan::Admit {
                evicted_public_key: Some(inbound_peer.onion_pubkey.clone()),
            }
        );
        assert_eq!(
            plan_peer_admission(
                std::slice::from_ref(&inbound_peer),
                &equal_inbound_candidate.onion_pubkey,
                equal_inbound_candidate.origin,
                equal_inbound_candidate.score_seconds,
                equal_inbound_candidate.first_contact_direction,
                1,
            ),
            PeerAdmissionPlan::Reject
        );
        assert_eq!(
            plan_peer_admission(
                std::slice::from_ref(&reserved_peer),
                &built_in_candidate.onion_pubkey,
                built_in_candidate.origin,
                built_in_candidate.score_seconds,
                built_in_candidate.first_contact_direction,
                1,
            ),
            PeerAdmissionPlan::Reject
        );
    }

    #[test]
    fn manual_peer_displaces_inbound_peer_at_capacity() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("manual-capacity-owner", filesystem)?;
        let capacity = 8;

        for index in 0..capacity {
            let master = test_master_priv(&format!("manual-capacity-inbound-{index}"));
            let inbound = Node::new_for_tests_from_master(&master)?;
            let inbound_public_key = keys::public_key_from_onion_hostname(inbound.address())?;
            node.track_peer_identity_with_capacity(
                &inbound_public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
                capacity,
            )?;
        }
        assert_eq!(node.known_peers().len(), capacity);

        let manual_master = test_master_priv("manual-capacity-good");
        let manual_peer = Node::new_for_tests_from_master(&manual_master)?;
        let manual_public_key = keys::public_key_from_onion_hostname(manual_peer.address())?;
        node.track_peer_identity_with_capacity(
            &manual_public_key,
            storedpb::PeerOrigin::Manual as i32,
            storedpb::FirstContactDirection::Unknown as i32,
            capacity,
        )?;

        let known_peers = node.known_peers();
        assert_eq!(known_peers.len(), capacity);
        assert!(known_peers.contains(&manual_peer.address().to_string()));
        Ok(())
    }

    #[test]
    fn inbound_eclipse_peers_cannot_displace_priority_peers() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("eclipse-owner", filesystem)?;
        let capacity = 16;

        let manual_master = test_master_priv("eclipse-manual");
        let manual_peer = Node::new_for_tests_from_master(&manual_master)?;
        let manual_public_key = keys::public_key_from_onion_hostname(manual_peer.address())?;
        node.track_peer_identity_with_capacity(
            &manual_public_key,
            storedpb::PeerOrigin::Manual as i32,
            storedpb::FirstContactDirection::Unknown as i32,
            capacity,
        )?;

        let reserved_master = test_master_priv("eclipse-reserved");
        let reserved_peer = Node::new_for_tests_from_master(&reserved_master)?;
        let reserved_public_key = keys::public_key_from_onion_hostname(reserved_peer.address())?;
        node.track_peer_identity_with_capacity(
            &reserved_public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Outbound as i32,
            capacity,
        )?;
        node.with_store(|store| store.set_peer_score(reserved_public_key.as_bytes(), 100, 1))?;

        let built_in_master = test_master_priv("eclipse-built-in");
        let built_in_peer = Node::new_for_tests_from_master(&built_in_master)?;
        let built_in_public_key = keys::public_key_from_onion_hostname(built_in_peer.address())?;
        node.track_peer_identity_with_capacity(
            &built_in_public_key,
            storedpb::PeerOrigin::BuiltIn as i32,
            storedpb::FirstContactDirection::Unknown as i32,
            capacity,
        )?;

        let outbound_master = test_master_priv("eclipse-outbound");
        let outbound_peer = Node::new_for_tests_from_master(&outbound_master)?;
        let outbound_public_key = keys::public_key_from_onion_hostname(outbound_peer.address())?;
        node.track_peer_identity_with_capacity(
            &outbound_public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Outbound as i32,
            capacity,
        )?;

        for index in 0..(capacity - 4) {
            let master = test_master_priv(&format!("eclipse-inbound-{index}"));
            let inbound = Node::new_for_tests_from_master(&master)?;
            let inbound_public_key = keys::public_key_from_onion_hostname(inbound.address())?;
            node.track_peer_identity_with_capacity(
                &inbound_public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
                capacity,
            )?;
        }
        assert_eq!(node.known_peers().len(), capacity);

        for index in 0..32 {
            let master = test_master_priv(&format!("eclipse-extra-{index}"));
            let inbound = Node::new_for_tests_from_master(&master)?;
            let inbound_public_key = keys::public_key_from_onion_hostname(inbound.address())?;
            let error = node
                .track_peer_identity_with_capacity(
                    &inbound_public_key,
                    peer_origin_code(false, false),
                    storedpb::FirstContactDirection::Inbound as i32,
                    capacity,
                )
                .unwrap_err();
            assert_eq!(error.code(), Code::ResourceExhausted);
        }

        let known_peers = node.known_peers();
        assert_eq!(known_peers.len(), capacity);
        assert!(known_peers.contains(&manual_peer.address().to_string()));
        assert!(known_peers.contains(&reserved_peer.address().to_string()));
        assert!(known_peers.contains(&built_in_peer.address().to_string()));
        assert!(known_peers.contains(&outbound_peer.address().to_string()));
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
    async fn set_content_revision_rejects_the_local_node_as_peer() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("self-set-content", filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        node.set_peer_connector(connector.clone());
        let server = spawn_registered_p2p_server(node.clone(), connector.as_ref()).await?;
        let mut client = connect_p2p_client(node.clone(), node.clone(), connector.as_ref()).await?;

        let error = client
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.message(), "local node cannot act as its own peer");

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn corrupted_mirrored_blob_is_redownloaded_on_next_sync() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-refresh",
            requester_filesystem,
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage(
            "responder-refresh",
            responder_filesystem.clone(),
        )?);
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
        assert_eq!(error.code(), Code::OutOfRange);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_rpc_preserves_terminal_status_codes() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("peer-rpc-status-codes")?);

        let not_found = node
            .peer_rpc(
                "peer.example.onion",
                "download peer content",
                std::future::ready(Err::<Response<bbrpc::HealthCheckResponse>, Status>(
                    Status::not_found("content missing"),
                )),
            )
            .await
            .unwrap_err();
        assert_eq!(not_found.code(), Code::NotFound);
        assert_eq!(
            not_found.message(),
            "download peer content from peer.example.onion: content missing"
        );

        let invalid_argument = node
            .peer_rpc(
                "peer.example.onion",
                "get content revision",
                std::future::ready(Err::<Response<bbrpc::HealthCheckResponse>, Status>(
                    Status::invalid_argument("bad request"),
                )),
            )
            .await
            .unwrap_err();
        assert_eq!(invalid_argument.code(), Code::InvalidArgument);
        assert_eq!(
            invalid_argument.message(),
            "get content revision from peer.example.onion: bad request"
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_rpc_timeout_remains_deadline_exceeded() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("peer-rpc-timeout")?);

        let error = node
            .peer_rpc("peer.example.onion", "check contract", async move {
                tokio::time::sleep(transport::PEER_RPC_TIMEOUT + Duration::from_millis(25)).await;
                Ok::<Response<bbrpc::HealthCheckResponse>, Status>(Response::new(
                    bbrpc::HealthCheckResponse::default(),
                ))
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::DeadlineExceeded);
        assert_eq!(
            error.message(),
            "check contract from peer.example.onion timed out"
        );

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
    async fn get_content_revision_hides_other_peers_metadata() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage("requester", requester_filesystem)?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage("responder", responder_filesystem)?);
        let other_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let other_node = Arc::new(Node::with_local_storage("other", other_filesystem)?);
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

        let revision = other_to_responder
            .get_content_revision(bbrpc::GetContentRevisionRequest {})
            .await?
            .into_inner();
        assert_eq!(revision.requester_content, None);
        assert_eq!(revision.requester_latest_known_content, None);

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
        assert_eq!(
            contracts[0].their_latest_known_content_id,
            contracts[0].their_latest_cached_content_id
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn positive_score_peer_can_evict_best_effort_cache() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage("local-budget", local_filesystem)?);
        let best_effort_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::MemoryFilesystem::new());
        let best_effort_node = Arc::new(Node::with_local_storage(
            "best-effort-peer",
            best_effort_filesystem,
        )?);
        let reserved_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let reserved_node = Arc::new(Node::with_local_storage(
            "reserved-peer",
            reserved_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        best_effort_node.set_peer_connector(connector.clone());
        reserved_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(best_effort_node.address())?;
        local_node.add_known_peer(reserved_node.address())?;

        let best_effort_cli = CliService::new(best_effort_node.clone());
        best_effort_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;
        let reserved_cli = CliService::new(reserved_node.clone());
        reserved_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"bravo-body".to_vec(),
                }),
            }))
            .await?;

        let best_effort_server =
            spawn_registered_p2p_server(best_effort_node.clone(), connector.as_ref()).await?;
        let reserved_server =
            spawn_registered_p2p_server(reserved_node.clone(), connector.as_ref()).await?;

        local_node
            .propose_contract_updates(best_effort_node.address())
            .await?;
        let best_effort_content = best_effort_node.current_content_info()?.unwrap();
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &best_effort_content.content_id
        )?);

        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: best_effort_content.content_length,
            min_replicas: 0,
        };
        let reserved_public_key = keys::public_key_from_onion_hostname(reserved_node.address())?;
        local_node
            .with_store(|store| store.set_peer_score(reserved_public_key.as_bytes(), 10, 100))?;

        local_node
            .propose_contract_updates(reserved_node.address())
            .await?;
        let reserved_content = reserved_node.current_content_info()?.unwrap();
        assert!(!cached_peer_blob(
            local_node.as_ref(),
            &best_effort_content.content_id
        )?);
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &reserved_content.content_id
        )?);
        assert_eq!(
            local_node.mirrored_peer_content_id(best_effort_node.address())?,
            Some(best_effort_content.content_id.clone())
        );

        best_effort_server.abort();
        reserved_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn over_budget_peer_is_tracked_without_cached_blob() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "local-track-only",
            local_filesystem,
        )?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage(
            "remote-track-only",
            remote_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(remote_node.address())?;
        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: 1,
            min_replicas: 0,
        };

        let remote_cli = CliService::new(remote_node.clone());
        remote_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"this blob is too large for one byte".to_vec(),
                }),
            }))
            .await?;

        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        let error = local_node
            .propose_contract_updates(remote_node.address())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);

        let remote_content = remote_node.current_content_info()?.unwrap();
        assert_eq!(
            local_node.mirrored_peer_content_id(remote_node.address())?,
            None
        );
        assert!(!cached_peer_blob(
            local_node.as_ref(),
            &remote_content.content_id
        )?);
        let peer = peer_entry(local_node.as_ref(), remote_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer entry"))?;
        assert_eq!(
            peer.latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(remote_content.content_id.clone())
        );
        assert!(peer.latest_cached_content.is_none());

        remote_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reserved_peer_keeps_previous_cached_revision_when_newest_wont_fit(
    ) -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "local-reserved",
            local_filesystem,
        )?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage(
            "remote-reserved",
            remote_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(remote_node.address())?;

        let remote_cli = CliService::new(remote_node.clone());
        remote_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"small".to_vec(),
                }),
            }))
            .await?;

        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        local_node
            .propose_contract_updates(remote_node.address())
            .await?;
        let version_1 = remote_node.current_content_info()?.unwrap();
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &version_1.content_id
        )?);

        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: version_1.content_length,
            min_replicas: 0,
        };
        let remote_public_key = keys::public_key_from_onion_hostname(remote_node.address())?;
        local_node
            .with_store(|store| store.set_peer_score(remote_public_key.as_bytes(), 10, 100))?;

        remote_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b'x'; 1024 * 1024],
                }),
            }))
            .await?;
        let version_2 = remote_node.current_content_info()?.unwrap();
        assert!(version_2.content_length > version_1.content_length);

        let error = local_node
            .propose_contract_updates(remote_node.address())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &version_1.content_id
        )?);
        assert!(!cached_peer_blob(
            local_node.as_ref(),
            &version_2.content_id
        )?);

        let peer = peer_entry(local_node.as_ref(), remote_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer entry"))?;
        assert_eq!(
            peer.latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(version_2.content_id.clone())
        );
        assert_eq!(
            peer.latest_cached_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(version_1.content_id.clone())
        );

        remote_server.abort();
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
    async fn check_contract_retries_transient_download_without_double_scoring() -> anyhow::Result<()>
    {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-check-retry",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let peer_identity = Node::new("check-retry-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(peer_identity.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let requester_content = requester_node.responder_content()?.unwrap();
        let requester_blob = requester_node.with_store(|store| store.current_blob())?;
        let service_state = Arc::new(TransientDownloadState::new(
            requester_content.clone(),
            requester_blob,
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(TransientDownloadPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        requester_node.with_store(|store| {
            store.set_peer_score(
                peer_public_key.as_bytes(),
                0,
                i64::try_from(requester_clock.now().secs).unwrap_or(i64::MAX),
            )
        })?;

        requester_clock.advance(Duration::from_secs(3_600));
        let updates = requester_node
            .check_contract_updates(peer_identity.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(service_state.download_call_count(), 2);
        assert_eq!(
            peer_score_seconds(requester_node.as_ref(), peer_identity.address())?,
            3_600
        );

        server.abort();
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
                requester_latest_known_content: Some(content_info.clone()),
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
            right_peer_entry
                .and_then(|peer| peer.latest_cached_content.map(|content| content.content_id)),
            Some(left_content.content_id)
        );

        left_server.abort();
        right_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_retries_after_transient_connect_failures() -> anyhow::Result<()> {
        let left_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let left_node = Arc::new(Node::with_local_storage("left-retry", left_filesystem)?);
        let right_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let right_node = Arc::new(Node::with_local_storage("right-retry", right_filesystem)?);
        let base_connector = Arc::new(netmock::MockPeerConnector::new());
        let flaky_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 2));
        left_node.set_peer_connector(flaky_connector.clone());
        right_node.set_peer_connector(base_connector.clone());

        let left_cli = CliService::new(left_node.clone());
        left_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "left.txt".to_string(),
                    data: b"left-body".to_vec(),
                }),
            }))
            .await?;

        let left_server =
            spawn_registered_p2p_server(left_node.clone(), base_connector.as_ref()).await?;
        let right_server =
            spawn_registered_p2p_server(right_node.clone(), base_connector.as_ref()).await?;

        let updates = left_node
            .propose_contract_updates(right_node.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(flaky_connector.dial_count(), 3);

        let left_content = left_node.responder_content()?.unwrap();
        let left_public_key = keys::public_key_from_onion_hostname(left_node.address())?;
        let right_peer_entry = right_node.with_store(|store| {
            Ok(store
                .peers()
                .into_iter()
                .find(|peer| peer.onion_pubkey.as_slice() == left_public_key.as_bytes()))
        })?;
        assert_eq!(
            right_peer_entry
                .and_then(|peer| peer.latest_cached_content.map(|content| content.content_id)),
            Some(left_content.content_id)
        );

        left_server.abort();
        right_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_refreshes_state_after_ambiguous_set_error() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage("proposal-refresh", filesystem)?);
        let peer_identity = Node::new("proposal-refresh-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());

        let cli = CliService::new(node.clone());
        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
            }),
        }))
        .await?;

        let service_state = Arc::new(TransientSetAckState::new());
        let (endpoint, server) =
            spawn_plain_peer_server(TransientSetAckPeerService::new(service_state.clone())).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let updates = node
            .propose_contract_updates(peer_identity.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(service_state.set_call_count(), 1);
        assert_eq!(service_state.requester_content(), node.responder_content()?,);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_retries_transient_probe_failures() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage(
            "recover-retry-owner",
            owner_filesystem,
        )?);
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_node = Arc::new(Node::with_local_storage(
            "recover-retry-peer",
            peer_filesystem,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "recover-retry-owner",
            recovered_filesystem,
        )?);
        let base_connector = Arc::new(netmock::MockPeerConnector::new());
        let flaky_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 2));
        owner_node.set_peer_connector(base_connector.clone());
        peer_node.set_peer_connector(base_connector.clone());
        recovered_node.set_peer_connector(flaky_connector.clone());
        recovered_node.add_known_peer(peer_node.address())?;

        let owner_cli = CliService::new(owner_node.clone());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let owner_server =
            spawn_registered_p2p_server(owner_node.clone(), base_connector.as_ref()).await?;
        let peer_server =
            spawn_registered_p2p_server(peer_node.clone(), base_connector.as_ref()).await?;
        let mut owner_to_peer = connect_p2p_client(
            owner_node.clone(),
            peer_node.clone(),
            base_connector.as_ref(),
        )
        .await?;
        owner_to_peer
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                requester_content: Some(owner_node.responder_content()?.unwrap()),
            })
            .await?;

        let update = recovered_node.recover_content_update().await?;
        assert!(update.recovered_most_recent_version);
        assert!(flaky_connector.dial_count() >= 4);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        owner_server.abort();
        peer_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_retries_transient_download_failure() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage(
            "recover-download-owner",
            owner_filesystem,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "recover-download-owner",
            recovered_filesystem,
        )?);
        let peer_identity = Node::new("recover-download-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node.add_known_peer(peer_identity.address())?;

        let owner_cli = CliService::new(owner_node.clone());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                }),
            }))
            .await?;

        let owner_content = owner_node.responder_content()?.unwrap();
        let owner_blob = owner_node.with_store(|store| store.current_blob())?;
        let service_state = Arc::new(TransientDownloadState::new(owner_content, owner_blob));
        let (endpoint, server) =
            spawn_plain_peer_server(TransientDownloadPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let update = recovered_node.recover_content_update().await?;
        assert!(update.recovered_most_recent_version);
        assert_eq!(service_state.download_call_count(), 2);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        server.abort();
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
        assert_eq!(
            final_update.freshest_recoverable_content_id,
            version_2.content_id
        );
        assert_eq!(final_update.num_peers_with_most_recent_version, 1);
        assert_eq!(final_update.num_peers_with_freshest_recoverable_version, 1);
        assert_eq!(final_update.total_versions_found, 2);
        assert_eq!(final_update.num_peers_with_any_versions, 2);
        assert!(final_update.recovered_most_recent_version);
        assert!(!final_update.recovered_fallback_version);

        let recovered_file = recovered_node.with_store(|store| store.get_file("alpha.txt"))?;
        assert_eq!(recovered_file, b"version-2".to_vec());

        peer_b_server.abort();
        peer_a_server.abort();
        owner_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_falls_back_to_newest_available_version() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage(
            "fallback-owner",
            owner_filesystem,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "fallback-owner",
            recovered_filesystem,
        )?);
        let stale_peer_identity = Node::new("fallback-stale-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(stale_peer_identity.address().to_string());

        let owner_cli = CliService::new(owner_node.clone());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-1".to_vec(),
                }),
            }))
            .await?;
        let version_1 = owner_node.responder_content()?.unwrap();
        let blob_1 = owner_node.with_store(|store| store.current_blob())?;

        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-2".to_vec(),
                }),
            }))
            .await?;
        let version_2 = owner_node.responder_content()?.unwrap();

        let stale_service = StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_content: Some(version_1.clone()),
                requester_remaining_seconds: 0,
                responder_content: None,
                requester_latest_known_content: Some(version_2.clone()),
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob_1.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob_1).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob_1.clone(),
                    },
                )),
            }),
        );
        let (endpoint, server) = spawn_plain_peer_server(stale_service).await?;
        connector.register_peer(stale_peer_identity.address(), &endpoint);

        let update = recovered_node.recover_content_update().await?;
        assert_eq!(update.most_recent_content_id, version_2.content_id);
        assert_eq!(update.freshest_recoverable_content_id, version_1.content_id);
        assert_eq!(update.num_peers_with_most_recent_version, 1);
        assert_eq!(update.num_peers_with_freshest_recoverable_version, 1);
        assert!(!update.recovered_most_recent_version);
        assert!(update.recovered_fallback_version);

        let recovered_file = recovered_node.with_store(|store| store.get_file("alpha.txt"))?;
        assert_eq!(recovered_file, b"version-1".to_vec());

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn divergent_recovery_is_blocking_until_resolved() -> anyhow::Result<()> {
        let branch_a_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let branch_b_clock = Arc::new(ManualClock::new(Timestamp::new(200, 0).unwrap()));
        let branch_a_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let branch_a_node = Arc::new(Node::with_local_storage_and_clock(
            "conflict-owner",
            branch_a_filesystem,
            branch_a_clock,
        )?);
        let branch_b_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let branch_b_node = Arc::new(Node::with_local_storage_and_clock(
            "conflict-owner",
            branch_b_filesystem,
            branch_b_clock,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "conflict-owner",
            recovered_filesystem,
        )?);
        let peer_a_identity = Node::new("conflict-peer-a")?;
        let peer_b_identity = Node::new("conflict-peer-b")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(peer_a_identity.address().to_string());
        recovered_node
            .known_peers
            .lock()
            .unwrap()
            .insert(peer_b_identity.address().to_string());

        CliService::new(branch_a_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"branch-a".to_vec(),
                }),
            }))
            .await?;
        CliService::new(branch_b_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"branch-b".to_vec(),
                }),
            }))
            .await?;
        let (version_a, blob_a) = current_content_snapshot(branch_a_node.as_ref())?;
        let (version_b, blob_b) = current_content_snapshot(branch_b_node.as_ref())?;

        let (endpoint_a, server_a) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_content: Some(version_a.clone()),
                requester_remaining_seconds: 0,
                responder_content: None,
                requester_latest_known_content: Some(version_a.clone()),
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob_a.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob_a).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob_a.clone(),
                    },
                )),
            }),
        ))
        .await?;
        let (endpoint_b, server_b) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_content: Some(version_b.clone()),
                requester_remaining_seconds: 0,
                responder_content: None,
                requester_latest_known_content: Some(version_b.clone()),
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob_b.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob_b).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob_b.clone(),
                    },
                )),
            }),
        ))
        .await?;
        connector.register_peer(peer_a_identity.address(), &endpoint_a);
        connector.register_peer(peer_b_identity.address(), &endpoint_b);

        let update = recovered_node.recover_content_update().await?;
        assert!(!update.recovered_most_recent_version);
        assert_eq!(update.total_downloaded_bytes, 0);

        let cli = CliService::new(recovered_node.clone());
        let conflicts = cli
            .list_conflicts(tonic::Request::new(clirpc::ListConflictsRequest {}))
            .await?
            .into_inner()
            .revisions;
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.iter().all(|revision| revision.unresolved));

        let blocked = cli
            .list_files(tonic::Request::new(clirpc::ListFilesRequest {}))
            .await
            .unwrap_err();
        assert_eq!(blocked.code(), tonic::Code::FailedPrecondition);

        let checkout_a = cli
            .checkout_revision(tonic::Request::new(clirpc::CheckoutRevisionRequest {
                content_id: version_a.content_id.clone(),
            }))
            .await?
            .into_inner();
        assert_eq!(checkout_a.file.len(), 1);
        assert_eq!(checkout_a.file[0].data, b"branch-a".to_vec());

        cli.resolve_conflict(tonic::Request::new(clirpc::ResolveConflictRequest {
            content_id: version_b.content_id.clone(),
        }))
        .await?;
        let recovered_file = recovered_node.with_store(|store| store.get_file("alpha.txt"))?;
        assert_eq!(recovered_file, b"branch-b".to_vec());

        let archived = cli
            .list_conflicts(tonic::Request::new(clirpc::ListConflictsRequest {}))
            .await?
            .into_inner()
            .revisions;
        assert_eq!(archived.len(), 1);
        assert!(!archived[0].unresolved);
        assert!(archived[0].resolved_at > 0);

        let archived_checkout = cli
            .checkout_revision(tonic::Request::new(clirpc::CheckoutRevisionRequest {
                content_id: version_a.content_id.clone(),
            }))
            .await?
            .into_inner();
        assert_eq!(archived_checkout.file[0].data, b"branch-a".to_vec());

        server_b.abort();
        server_a.abort();
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
            requester_latest_known_content: Some(content_info.clone()),
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
