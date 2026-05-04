//! Node orchestration for a single BarterBackup instance.
//!
//! The node owns the local encrypted store, the local and peer RPC surfaces,
//! peer inventory and storage bookkeeping, and recovery and maintenance
//! helpers used by the daemon.

mod builtin_peers;

use anyhow::Result;
use clock::{Clock, SystemClock, Timestamp};
use content::{PlainFile, CONTENT_ID_LEN};
use futures::{stream, Stream};
use prost::Message;
use prost_types::Timestamp as ProtoTimestamp;
use protos::{bbrpc, clirpc, storedpb};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use storage::{CurrentContent, Filesystem, MetadataRollupOutcome, StorageError, Store};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::{Code, Response, Status};
use tracing::{debug, info, warn};
use transport::PeerConnector;

/// LOCAL_CLI_FILE_CHUNK_BYTES is the chunk size used for streamed local file RPCs.
const LOCAL_CLI_FILE_CHUNK_BYTES: usize = 256 * 1024;
/// PEER_SELECTION_BASE_WEIGHT is the baseline chance every eligible peer keeps.
const PEER_SELECTION_BASE_WEIGHT: u64 = 1;
/// PEER_SELECTION_PINNED_BY_US_BONUS strongly boosts peers pinned locally.
const PEER_SELECTION_PINNED_BY_US_BONUS: u64 = 48;
/// PEER_SELECTION_PINS_US_BONUS strongly boosts peers that most recently pinned us.
const PEER_SELECTION_PINS_US_BONUS: u64 = 32;
/// PEER_SELECTION_AVAILABILITY_BONUS_SCALE converts the smoothed success ratio into weight.
const PEER_SELECTION_AVAILABILITY_BONUS_SCALE: u64 = 40;
/// PEER_SELECTION_AGE_STEP_SECS grants one age bonus per observed day.
const PEER_SELECTION_AGE_STEP_SECS: i64 = 86_400;
/// PEER_SELECTION_MAX_AGE_BONUS caps the age contribution to keep it moderate.
const PEER_SELECTION_MAX_AGE_BONUS: u64 = 30;

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
    /// peer_score_observation_started_at marks when local peer observation
    /// most recently became valid for score accounting.
    peer_score_observation_started_at: Mutex<Option<Timestamp>>,
    /// store holds the encrypted local content store when configured.
    store: Option<Arc<Mutex<Store>>>,
    /// peer_metadata_batcher coalesces low-value peer metadata writes.
    peer_metadata_batcher: Option<PeerMetadataBatcher>,
    /// known_peers is the locally configured peer list.
    known_peers: Mutex<BTreeSet<String>>,
    /// storage_config is the current local storage policy snapshot.
    storage_config: Mutex<clirpc::StorageConfig>,
    /// peer_connector dials other nodes when peer sync is enabled.
    peer_connector: Mutex<Option<Arc<dyn PeerConnector>>>,
    /// peer_client_cache reuses recent outbound peer clients across operations.
    peer_client_cache: Mutex<BTreeMap<String, CachedPeerClient>>,
    /// peer_exchange_last_attempt records the last in-memory peer exchange attempt.
    peer_exchange_last_attempt: Mutex<BTreeMap<String, i64>>,
    /// peer_live_recovery_probe_state tracks whether one live-contact recovery
    /// probe already ran for the current in-memory peer session.
    peer_live_recovery_probe_state: Mutex<BTreeMap<String, LiveRecoveryProbeState>>,
    /// recent_peer_failures stores the latest operator-facing failure summary per peer.
    recent_peer_failures: Mutex<BTreeMap<String, RecentPeerFailure>>,
}

/// LiveRecoveryProbeState records whether one peer already triggered the
/// best-effort live-contact recovery probe for the current in-memory session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveRecoveryProbeState {
    /// last_contact_at_secs is when the peer most recently had one live
    /// contact that refreshed this in-memory session state.
    last_contact_at_secs: i64,
    /// probe_in_progress reports whether one background or inline probe is
    /// already running for this peer session.
    probe_in_progress: bool,
    /// probe_completed reports whether one full probe already analyzed this
    /// peer session successfully.
    probe_completed: bool,
}

/// RecentPeerFailure is the latest operator-facing failure summary for one peer.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RecentPeerFailure {
    /// last_failure_at is when the failure occurred.
    last_failure_at: i64,
    /// last_error_class classifies the failure for local RPC output.
    last_error_class: i32,
    /// last_error_message stores the failure summary.
    last_error_message: String,
}

/// RecoverableRequesterRevisionSource explains which responder-side view
/// revealed an older requester revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoverableRequesterRevisionSource {
    /// LatestStored means the peer can still serve the older requester revision.
    LatestStored,
    /// LatestKnown means the peer only knows the older requester revision exists.
    LatestKnown,
}

/// RecoverableRequesterRevision is one older requester revision that must be
/// recovered before the owner can safely publish.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RecoverableRequesterRevision {
    /// content is the older requester revision metadata.
    content: bbrpc::ContentInfo,
    /// timestamp is the authenticated revision timestamp.
    timestamp: (i64, i64),
    /// source explains whether the peer can still serve the revision.
    source: RecoverableRequesterRevisionSource,
}

/// DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY is the default delay before
/// low-value peer metadata writes are flushed to disk.
pub const DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY: Duration = Duration::from_secs(60);

/// TIMER_LABEL_PEER_METADATA_FLUSH_DELAY names the delayed low-value peer
/// metadata flush timer exposed through the hidden test-clock interfaces.
pub const TIMER_LABEL_PEER_METADATA_FLUSH_DELAY: &str = "peer-metadata.flush-delay";

/// PendingPeerMetadataFlush tracks the currently scheduled delayed sidecar
/// flush for low-value peer metadata.
#[derive(Debug, Default)]
struct PendingPeerMetadataFlush {
    /// dirty reports whether in-memory peer metadata has unflushed low-value changes.
    dirty: bool,
    /// deadline is the next logical time at which the sidecar should flush.
    deadline: Option<Timestamp>,
    /// task_spawned reports whether the background flusher task already exists.
    task_spawned: bool,
    /// shutdown requests background task exit after any final synchronous flush.
    shutdown: bool,
}

/// PeerMetadataBatcher coalesces low-value peer metadata rewrites into delayed
/// sidecar flushes while preserving immediate writes for correctness-critical state.
struct PeerMetadataBatcher {
    inner: Arc<PeerMetadataBatcherInner>,
}

/// PeerMetadataBatcherInner holds the shared delayed-flush state.
struct PeerMetadataBatcherInner {
    /// store is the encrypted local store whose peer sidecar is being updated.
    store: Arc<Mutex<Store>>,
    /// clock provides the logical timer surface used by the delayed flusher.
    clock: Arc<dyn Clock>,
    /// flush_delay is the time low-value updates may remain in memory.
    flush_delay: Duration,
    /// pending tracks whether one delayed flush is currently armed.
    pending: Mutex<PendingPeerMetadataFlush>,
    /// notify wakes the background task when the schedule changes or shutdown starts.
    notify: Notify,
}

/// Return the peer-content size limit as an `i64` for protobuf comparisons.
fn max_peer_content_bytes_i64() -> i64 {
    i64::try_from(transport::MAX_PEER_CONTENT_BYTES).unwrap_or(i64::MAX)
}

/// DEFAULT_ALLOCATED_STORAGE_FOR_PEERS is the default peer-cache budget.
const DEFAULT_ALLOCATED_STORAGE_FOR_PEERS: i64 = 1024 * 1024 * 1024;
/// DEFAULT_MIN_REPLICAS is the default fresh-replica target for our content.
const DEFAULT_MIN_REPLICAS: i64 = 100;

/// MAX_TRACKED_PEERS is the maximum number of peers kept in metadata.
const MAX_TRACKED_PEERS: usize = 1024;

/// MAX_CACHED_PEER_CLIENTS bounds the in-memory outbound peer client cache.
const MAX_CACHED_PEER_CLIENTS: usize = 32;

/// PEER_CLIENT_CACHE_IDLE_TTL_SECS expires idle cached peer clients.
const PEER_CLIENT_CACHE_IDLE_TTL_SECS: i64 = 5 * 60;

/// PEER_EXCHANGE_COOLDOWN_SECS limits how often one peer exchange runs per peer.
const PEER_EXCHANGE_COOLDOWN_SECS: i64 = 5 * 60;

/// Convert one duration to a saturated millisecond count for local RPC output.
fn duration_to_millis_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// StorageClass splits mirrored peer blobs into reserved and best-effort sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageClass {
    /// Reserved blobs belong to peers whose score is currently above zero.
    Reserved,
    /// BestEffort blobs belong only to peers whose score is zero or negative.
    BestEffort,
}

/// PeerStorageProtectionClass classifies one peer's currently cached bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerStorageProtectionClass {
    /// None means the peer currently has no cached mirrored bytes locally.
    None,
    /// Pinned means cached bytes are protected by an operator pin.
    Pinned,
    /// Protected means cached bytes are protected by a positive peer score.
    Protected,
    /// Disposable means cached bytes are currently best-effort only.
    Disposable,
}

/// StorageAccounting aggregates deduplicated mirrored-blob usage by policy class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StorageAccounting {
    /// pinned_bytes are deduplicated cached bytes protected by pinned peers.
    pinned_bytes: i64,
    /// protected_bytes are deduplicated cached bytes protected by positive-score peers.
    protected_bytes: i64,
    /// disposable_bytes are deduplicated cached bytes referenced only by best-effort peers.
    disposable_bytes: i64,
    /// offline_blocking_bytes are protected bytes blocked by offline or stale peers.
    offline_blocking_bytes: i64,
    /// reclaimable_bytes are disposable bytes that may be dropped immediately.
    reclaimable_bytes: i64,
}

/// PeerBlobReference is one peer's reference to one mirrored blob.
#[derive(Clone, Debug)]
struct PeerBlobReference {
    /// peer_public_key identifies the peer that references the blob.
    peer_public_key: Vec<u8>,
    /// pinned_by_us reports whether the local operator pinned this peer.
    pinned_by_us: bool,
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

/// PeerStorageRuntimeState is the live peer-storage state we need for storage reporting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PeerStorageRuntimeState {
    /// online reports whether the peer answered the live storage probe.
    online: bool,
    /// our_content_synced reports whether the peer currently advertises our latest content.
    our_content_synced: bool,
}

/// StorageAdmission describes whether a new mirrored blob can be kept locally.
enum StorageAdmission {
    /// Store keeps the new blob and evicts the listed best-effort blobs first.
    Store { evict_content_ids: Vec<Vec<u8>> },
    /// TrackOnly remembers the peer's latest content id without caching bytes.
    TrackOnly,
}

/// SyncPeerContentResult reports how one responder handled requester content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncPeerContentResult {
    /// MirroredBytesCached means the sidecar and requester bytes are cached.
    MirroredBytesCached,
    /// SidecarOnly means only sidecar metadata was accepted locally.
    SidecarOnly,
}

/// CachedPeerClient keeps one reusable outbound peer client with its last use time.
#[derive(Clone)]
struct CachedPeerClient {
    /// client is the configured outbound gRPC peer client.
    client: transport::PeerClient,
    /// last_used_at_secs is the node clock second when this client was last reused.
    last_used_at_secs: i64,
}

/// PeerInventoryStatus reports the local daemon's current view of one peer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum PeerInventoryStatus {
    /// Connected means an outbound cached client is currently open.
    Connected,
    /// Online means the last completed transport interaction succeeded.
    Online,
    /// Offline means the last completed transport interaction failed or is unknown.
    Offline,
}

/// PeerInventoryEntry is one locally reported peer summary.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerInventoryEntry {
    /// onion_service_id is the peer onion hostname.
    onion_service_id: String,
    /// status is the current locally observed transport state.
    status: PeerInventoryStatus,
    /// pinned_by_us reports whether the local operator pinned this peer.
    pinned_by_us: bool,
    /// pins_us reports whether the peer most recently told us it pins us.
    pins_us: bool,
    /// has_storage reports whether persisted state indicates any storage relationship.
    has_storage: bool,
    /// score_seconds is the peer's current persisted score.
    score_seconds: i64,
    /// score_measured_at is when `score_seconds` was last updated.
    score_measured_at: i64,
    /// stored_content_bytes is the number of mirrored bytes currently cached locally.
    stored_content_bytes: i64,
    /// latest_known_content_length is the newest peer revision length we know exists.
    latest_known_content_length: i64,
    /// latest_cached_content_length is the newest peer revision length we currently cache.
    latest_cached_content_length: i64,
    /// stale_cache reports whether latest known and latest cached revisions differ.
    stale_cache: bool,
    /// storage_protection reports how the currently cached bytes are classified.
    storage_protection: PeerStorageProtectionClass,
    /// tracked_only reports whether only metadata for the newest revision is kept.
    tracked_only: bool,
    /// last_live_at is when the peer last responded successfully over the transport.
    last_live_at: i64,
    /// last_failure_at is when background maintenance last failed for this peer.
    last_failure_at: i64,
    /// last_error_class classifies the most recent background maintenance failure.
    last_error_class: i32,
    /// last_error_message is the latest background maintenance failure summary.
    last_error_message: String,
    /// consecutive_failures is the current background maintenance failure streak.
    consecutive_failures: i64,
    /// next_retry_at is when background maintenance is next scheduled to retry.
    next_retry_at: i64,
}

/// LocalPeerInventorySnapshot stores one peer's local sidecar-derived fields
/// for inventory rendering without re-entering the store mutex.
#[derive(Clone, Debug)]
struct LocalPeerInventorySnapshot {
    /// reachability is the last persisted reachability state for this peer.
    reachability: i32,
    /// pinned_by_us reports whether the local operator pinned this peer.
    pinned_by_us: bool,
    /// pins_us reports whether the peer most recently told us it pins us.
    pins_us: bool,
    /// has_storage reports whether persisted state indicates any storage relationship.
    has_storage: bool,
    /// score_seconds is the peer's current persisted score.
    score_seconds: i64,
    /// score_measured_at is when `score_seconds` was last updated.
    score_measured_at: i64,
    /// stored_content_bytes is the mirrored content length recorded in sidecar metadata.
    stored_content_bytes: i64,
    /// latest_known_content_length is the newest peer revision length we know exists.
    latest_known_content_length: i64,
    /// latest_cached_content_length is the newest peer revision length we currently cache.
    latest_cached_content_length: i64,
    /// stale_cache reports whether latest known and latest cached revisions differ.
    stale_cache: bool,
    /// storage_protection reports how the currently cached bytes are classified.
    storage_protection: PeerStorageProtectionClass,
    /// tracked_only reports whether only metadata for the newest revision is kept.
    tracked_only: bool,
    /// last_live_at is when the peer last responded successfully over the transport.
    last_live_at: i64,
}

/// PeerAdmissionPlan describes how peer-capacity enforcement handles a peer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerAdmissionPlan {
    /// Admit keeps the candidate peer and optionally evicts one existing peer.
    Admit { evicted_public_key: Option<Vec<u8>> },
    /// Reject leaves the current peer set unchanged.
    Reject,
}

/// BackgroundMaintenancePeerAction describes what one maintenance pass should
/// do with one known peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackgroundMaintenancePeerAction {
    /// peer_onion is the peer onion hostname to contact.
    pub peer_onion: String,
    /// propose reports whether the pass should run peer publication first.
    pub propose: bool,
    /// check reports whether the pass should run peer verification.
    pub check: bool,
}

/// BackgroundMaintenancePlan is one snapshot of automatic peer-maintenance
/// work derived from the current local state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackgroundMaintenancePlan {
    /// peer_actions lists the per-peer work in priority order.
    pub peer_actions: Vec<BackgroundMaintenancePeerAction>,
    /// fresh_replica_count is the number of currently verified fresh replicas
    /// for our active content revision.
    pub fresh_replica_count: i64,
    /// min_replicas_target is the configured minimum fresh replica target.
    pub min_replicas_target: i64,
}

/// PublicationCandidate is one eligible peer considered for replica refill.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PublicationCandidate {
    /// peer_onion is the peer onion hostname.
    peer_onion: String,
    /// pinned_by_us reports whether we pin this peer locally.
    pinned_by_us: bool,
    /// pins_us reports whether this peer most recently told us that it pins us.
    pins_us: bool,
    /// first_seen_at is when we first admitted this peer locally.
    first_seen_at: (i64, i64),
    /// successful_calls counts successful observed outbound interactions.
    successful_calls: i64,
    /// failed_calls counts failed observed outbound interactions.
    failed_calls: i64,
    /// stores_peer_data reports whether we currently cache this peer's bytes.
    stores_peer_data: bool,
}

/// LocalStoreSnapshot is the local encrypted-store state needed for one local
/// CLI state summary.
#[derive(Clone, Debug, PartialEq)]
struct LocalStoreSnapshot {
    /// current_content is the active local revision, if any.
    current_content: Option<CurrentContent>,
    /// tracked_peers is the persisted tracked peer metadata.
    tracked_peers: Vec<storedpb::Peer>,
    /// file_count is the number of logical user files in the active revision.
    file_count: i64,
    /// total_file_bytes is the total plaintext size of all logical user files.
    total_file_bytes: i64,
    /// node_initialized_at is the persisted generation boundary, if any.
    node_initialized_at: Option<(i64, i64)>,
    /// latest_recovered_revision is the newest merged older-lineage revision, if any.
    latest_recovered_revision: Option<storedpb::RecoveredRevision>,
    /// recovery_watermark is the persisted older-lineage watermark, if any.
    recovery_watermark: Option<(i64, i64)>,
    /// recovery_mode_enabled reports whether outgoing publication is blocked.
    recovery_mode_enabled: bool,
}

/// Build the default local storage policy.
fn default_storage_config() -> clirpc::StorageConfig {
    clirpc::StorageConfig {
        allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
        min_replicas: DEFAULT_MIN_REPLICAS,
    }
}

impl PeerMetadataBatcher {
    /// Build one delayed peer-metadata batcher.
    fn new(store: Arc<Mutex<Store>>, clock: Arc<dyn Clock>, flush_delay: Duration) -> Self {
        Self {
            inner: Arc::new(PeerMetadataBatcherInner {
                store,
                clock,
                flush_delay,
                pending: Mutex::new(PendingPeerMetadataFlush::default()),
                notify: Notify::new(),
            }),
        }
    }

    /// Stage one low-value reachability update in memory.
    fn set_peer_reachability(
        &self,
        onion_pubkey: &[u8],
        reachability: i32,
        last_live_at: Option<i64>,
    ) -> Result<(), Status> {
        let changed = self
            .inner
            .store
            .lock()
            .unwrap()
            .set_peer_reachability_pending(onion_pubkey, reachability, last_live_at)
            .map_err(map_storage_error)?;
        if changed {
            self.inner.schedule_flush();
        }
        Ok(())
    }

    /// Stage one low-value score update in memory.
    fn set_peer_score(
        &self,
        onion_pubkey: &[u8],
        score_seconds: i64,
        score_measured_at: i64,
    ) -> Result<(), Status> {
        let changed = self
            .inner
            .store
            .lock()
            .unwrap()
            .set_peer_score_pending(onion_pubkey, score_seconds, score_measured_at)
            .map_err(map_storage_error)?;
        if changed {
            self.inner.schedule_flush();
        }
        Ok(())
    }

    /// Stage one low-value remote pin-claim update in memory.
    fn set_peer_pins_us(&self, onion_pubkey: &[u8], pins_us: bool) -> Result<(), Status> {
        let changed = self
            .inner
            .store
            .lock()
            .unwrap()
            .set_peer_pins_us_pending(onion_pubkey, pins_us)
            .map_err(map_storage_error)?;
        if changed {
            self.inner.schedule_flush();
        }
        Ok(())
    }

    /// Stage one low-value last-verified-our-content update in memory.
    fn set_peer_last_verified_our_content(
        &self,
        onion_pubkey: &[u8],
        content_id: Option<&[u8]>,
        verified_at: Option<i64>,
    ) -> Result<(), Status> {
        let changed = self
            .inner
            .store
            .lock()
            .unwrap()
            .set_peer_last_verified_our_content_pending(onion_pubkey, content_id, verified_at)
            .map_err(map_storage_error)?;
        if changed {
            self.inner.schedule_flush();
        }
        Ok(())
    }

    /// Flush any pending low-value peer metadata immediately.
    fn flush_now(&self) -> Result<(), Status> {
        self.inner.flush_now()
    }
}

impl Drop for PeerMetadataBatcher {
    fn drop(&mut self) {
        self.inner.shutdown_and_flush();
    }
}

impl PeerMetadataBatcherInner {
    /// Schedule one delayed sidecar flush and start the background task if possible.
    fn schedule_flush(self: &Arc<Self>) {
        let mut pending = self.pending.lock().unwrap();
        pending.dirty = true;
        pending.deadline = Some(self.clock.now().advance(self.flush_delay));
        if !pending.task_spawned {
            if let Ok(handle) = Handle::try_current() {
                pending.task_spawned = true;
                let inner = Arc::clone(self);
                handle.spawn(async move {
                    inner.run().await;
                });
            }
        }
        drop(pending);
        self.notify.notify_waiters();
    }

    /// Run the delayed flusher until shutdown is requested.
    async fn run(self: Arc<Self>) {
        loop {
            let deadline = {
                let pending = self.pending.lock().unwrap();
                if pending.shutdown {
                    return;
                }
                pending.deadline
            };

            let Some(deadline) = deadline else {
                self.notify.notified().await;
                continue;
            };

            let now = self.clock.now();
            if now >= deadline {
                if let Err(error) = self.flush_due(now) {
                    warn!(%error, "failed to flush delayed peer metadata");
                }
                continue;
            }

            tokio::select! {
                _ = self.clock.wait_until(deadline, TIMER_LABEL_PEER_METADATA_FLUSH_DELAY) => {}
                _ = self.notify.notified() => {}
            }
        }
    }

    /// Flush the peer sidecar when the pending deadline has elapsed.
    fn flush_due(&self, now: Timestamp) -> Result<(), Status> {
        let should_flush = {
            let mut pending = self.pending.lock().unwrap();
            if pending.shutdown || !pending.dirty {
                return Ok(());
            }
            let Some(deadline) = pending.deadline else {
                return Ok(());
            };
            if now < deadline {
                return Ok(());
            }
            pending.dirty = false;
            pending.deadline = None;
            true
        };

        if !should_flush {
            return Ok(());
        }

        match self.store.lock().unwrap().flush_peer_state() {
            Ok(()) => Ok(()),
            Err(error) => {
                let retry_at = self.clock.now().advance(self.flush_delay);
                let mut pending = self.pending.lock().unwrap();
                if !pending.shutdown {
                    pending.dirty = true;
                    pending.deadline = Some(retry_at);
                }
                drop(pending);
                self.notify.notify_waiters();
                Err(map_storage_error(error))
            }
        }
    }

    /// Flush the peer sidecar immediately if low-value changes are pending.
    fn flush_now(&self) -> Result<(), Status> {
        let should_flush = {
            let mut pending = self.pending.lock().unwrap();
            if !pending.dirty {
                return Ok(());
            }
            pending.dirty = false;
            pending.deadline = None;
            true
        };

        if !should_flush {
            return Ok(());
        }

        match self.store.lock().unwrap().flush_peer_state() {
            Ok(()) => Ok(()),
            Err(error) => {
                let retry_at = self.clock.now().advance(self.flush_delay);
                let mut pending = self.pending.lock().unwrap();
                if !pending.shutdown {
                    pending.dirty = true;
                    pending.deadline = Some(retry_at);
                }
                drop(pending);
                self.notify.notify_waiters();
                Err(map_storage_error(error))
            }
        }
    }

    /// Request background exit and synchronously flush any remaining metadata.
    fn shutdown_and_flush(&self) {
        let should_flush = {
            let mut pending = self.pending.lock().unwrap();
            pending.shutdown = true;
            let should_flush = pending.dirty;
            pending.dirty = false;
            pending.deadline = None;
            should_flush
        };
        if should_flush {
            if let Err(error) = self.store.lock().unwrap().flush_peer_state() {
                warn!(%error, "failed to flush delayed peer metadata during shutdown");
            }
        }
        self.notify.notify_waiters();
    }
}

/// Return the current read-only peer resource policy exposed to operators.
pub fn resource_policy() -> clirpc::ResourcePolicy {
    let retry_policy =
        transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Proposal);

    clirpc::ResourcePolicy {
        max_peer_content_bytes: max_peer_content_bytes_i64(),
        peer_grpc_message_limit_bytes: i64::try_from(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES)
            .unwrap_or(i64::MAX),
        peer_connect_timeout_ms: duration_to_millis_i64(retry_policy.connect_timeout),
        peer_rpc_timeout_ms: duration_to_millis_i64(retry_policy.rpc_timeout),
        peer_operation_total_budget_ms: duration_to_millis_i64(retry_policy.total_budget),
        peer_retry_initial_backoff_ms: duration_to_millis_i64(retry_policy.initial_backoff),
        peer_retry_max_backoff_ms: duration_to_millis_i64(retry_policy.max_backoff),
        max_tracked_peers: i64::try_from(MAX_TRACKED_PEERS).unwrap_or(i64::MAX),
        max_cached_peer_clients: i64::try_from(MAX_CACHED_PEER_CLIENTS).unwrap_or(i64::MAX),
        chunking_supported: false,
    }
}

/// Return the effective peer priority from persisted origin, score, and direction.
fn peer_priority(
    pinned_by_us: bool,
    origin: i32,
    score_seconds: i64,
    first_contact_direction: i32,
) -> u8 {
    if pinned_by_us {
        6
    } else if origin == storedpb::PeerOrigin::Manual as i32 {
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
            peer.pinned_by_us,
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
    candidate_pinned_by_us: bool,
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
        candidate_pinned_by_us,
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
        worst_peer.pinned_by_us,
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
fn storage_class(pinned_by_us: bool, score_seconds: i64) -> StorageClass {
    if pinned_by_us || score_seconds > 0 {
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

/// Return the newest locally cached peer content summary.
fn peer_latest_cached_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.latest_cached_content.clone()
}

/// Return the newest known peer content summary.
fn peer_latest_known_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.latest_known_content.clone()
}

/// Return whether persisted metadata indicates any storage relationship.
fn peer_has_storage(peer: &storedpb::Peer) -> bool {
    peer.score_measured_at > 0
        || peer.score_seconds != 0
        || peer_latest_known_content(peer).is_some()
        || peer_latest_cached_content(peer).is_some()
        || peer_requester_latest_known_content(peer).is_some()
        || peer_requester_latest_stored_content(peer).is_some()
}

/// Classify the currently cached bytes for one tracked peer.
fn peer_storage_protection(peer: &storedpb::Peer) -> PeerStorageProtectionClass {
    if peer_latest_cached_content(peer).is_none() {
        PeerStorageProtectionClass::None
    } else if peer.pinned_by_us {
        PeerStorageProtectionClass::Pinned
    } else if peer.score_seconds > 0 {
        PeerStorageProtectionClass::Protected
    } else {
        PeerStorageProtectionClass::Disposable
    }
}

/// Report whether the peer is newest-known only with no cached bytes.
fn peer_is_tracked_only(peer: &storedpb::Peer) -> bool {
    peer_latest_known_content(peer).is_some() && peer_latest_cached_content(peer).is_none()
}

/// Return the newest requester revision this peer claims it can still return.
fn peer_requester_latest_stored_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.requester_latest_stored_content.clone()
}

/// Return the newest requester revision this peer claims to know about.
fn peer_requester_latest_known_content(peer: &storedpb::Peer) -> Option<storedpb::PeerContent> {
    peer.requester_latest_known_content.clone()
}

/// Compute one weighted-random selection score for a publication candidate.
fn publication_candidate_weight(candidate: &PublicationCandidate, now_secs: i64) -> u64 {
    let mut weight = PEER_SELECTION_BASE_WEIGHT;
    if candidate.pinned_by_us {
        weight = weight.saturating_add(PEER_SELECTION_PINNED_BY_US_BONUS);
    }
    if candidate.pins_us {
        weight = weight.saturating_add(PEER_SELECTION_PINS_US_BONUS);
    }

    let age_bonus = now_secs
        .saturating_sub(candidate.first_seen_at.0)
        .max(0)
        .checked_div(PEER_SELECTION_AGE_STEP_SECS)
        .unwrap_or(0);
    let age_bonus = u64::try_from(age_bonus)
        .unwrap_or(u64::MAX)
        .min(PEER_SELECTION_MAX_AGE_BONUS);
    weight = weight.saturating_add(age_bonus);

    let successes = u64::try_from(candidate.successful_calls.max(0)).unwrap_or(u64::MAX);
    let failures = u64::try_from(candidate.failed_calls.max(0)).unwrap_or(u64::MAX);
    let availability_denominator = successes.saturating_add(failures).saturating_add(2);
    let availability_bonus = successes
        .saturating_add(1)
        .saturating_mul(PEER_SELECTION_AVAILABILITY_BONUS_SCALE)
        .checked_div(availability_denominator.max(1))
        .unwrap_or(0);
    weight.saturating_add(availability_bonus)
}

/// Sample one weighted publication candidate index.
fn sample_weighted_publication_candidate<R: Rng + ?Sized>(
    candidates: &[PublicationCandidate],
    now_secs: i64,
    rng: &mut R,
) -> Option<usize> {
    let weights = candidates
        .iter()
        .map(|candidate| publication_candidate_weight(candidate, now_secs))
        .collect::<Vec<_>>();
    let total_weight = weights.iter().copied().fold(0u64, u64::saturating_add);
    if total_weight == 0 {
        return None;
    }

    let mut draw = rng.gen_range(0..total_weight);
    for (index, weight) in weights.into_iter().enumerate() {
        if draw < weight {
            return Some(index);
        }
        draw = draw.saturating_sub(weight);
    }
    Some(candidates.len().saturating_sub(1))
}

/// Select publication candidates without replacement under the weighting policy.
fn choose_publication_candidates<R: Rng + ?Sized>(
    candidates: &[PublicationCandidate],
    missing_replicas: usize,
    now_secs: i64,
    rng: &mut R,
) -> Vec<String> {
    fn draw_from_pool<R: Rng + ?Sized>(
        pool: &mut Vec<PublicationCandidate>,
        selected: &mut Vec<String>,
        remaining: &mut usize,
        now_secs: i64,
        rng: &mut R,
    ) {
        while *remaining > 0 && !pool.is_empty() {
            let Some(index) = sample_weighted_publication_candidate(pool, now_secs, rng) else {
                break;
            };
            let candidate = pool.remove(index);
            selected.push(candidate.peer_onion);
            *remaining = remaining.saturating_sub(1);
        }
    }

    let mut selected = Vec::new();
    let mut remaining = missing_replicas;
    let mut reciprocal = candidates
        .iter()
        .filter(|candidate| candidate.stores_peer_data)
        .cloned()
        .collect::<Vec<_>>();
    if !reciprocal.is_empty() {
        draw_from_pool(
            &mut reciprocal,
            &mut selected,
            &mut remaining,
            now_secs,
            rng,
        );
    }
    if remaining == 0 {
        return selected;
    }
    let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut pinned = candidates
        .iter()
        .filter(|candidate| !selected_set.contains(&candidate.peer_onion))
        .filter(|candidate| candidate.pinned_by_us || candidate.pins_us)
        .cloned()
        .collect::<Vec<_>>();
    if !pinned.is_empty() {
        draw_from_pool(&mut pinned, &mut selected, &mut remaining, now_secs, rng);
    }
    if remaining == 0 {
        return selected;
    }
    let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
    let mut others = candidates
        .iter()
        .filter(|candidate| !selected_set.contains(&candidate.peer_onion))
        .cloned()
        .collect::<Vec<_>>();
    draw_from_pool(&mut others, &mut selected, &mut remaining, now_secs, rng);
    selected
}

/// Convert one internal storage protection class into its CLI proto enum.
fn proto_peer_storage_protection(class: PeerStorageProtectionClass) -> i32 {
    match class {
        PeerStorageProtectionClass::None => clirpc::PeerStorageProtection::None as i32,
        PeerStorageProtectionClass::Pinned => clirpc::PeerStorageProtection::Pinned as i32,
        PeerStorageProtectionClass::Protected => clirpc::PeerStorageProtection::Protected as i32,
        PeerStorageProtectionClass::Disposable => clirpc::PeerStorageProtection::Disposable as i32,
    }
}

/// Translate one peer-publication storage outcome into the local CLI enum.
fn proto_publication_storage_result(
    result: bbrpc::SetContentRevisionStorageResult,
) -> clirpc::PublicationStorageResult {
    match result {
        bbrpc::SetContentRevisionStorageResult::Unknown => {
            clirpc::PublicationStorageResult::Unknown
        }
        bbrpc::SetContentRevisionStorageResult::MirroredBytesCached => {
            clirpc::PublicationStorageResult::MirroredBytesCached
        }
        bbrpc::SetContentRevisionStorageResult::SidecarOnly => {
            clirpc::PublicationStorageResult::SidecarOnly
        }
    }
}

/// Aggregate deduplicated mirrored-blob usage into operator-facing totals.
fn aggregate_storage_accounting(
    usage: &[MirroredBlobUsage],
    contract_state_by_peer: &BTreeMap<Vec<u8>, PeerStorageRuntimeState>,
) -> StorageAccounting {
    let mut accounting = StorageAccounting::default();

    for usage in usage {
        let protecting_references = usage
            .references
            .iter()
            .filter(|reference| {
                storage_class(reference.pinned_by_us, reference.score_seconds)
                    == StorageClass::Reserved
            })
            .collect::<Vec<_>>();
        let class = if protecting_references
            .iter()
            .any(|reference| reference.pinned_by_us)
        {
            PeerStorageProtectionClass::Pinned
        } else if !protecting_references.is_empty() {
            PeerStorageProtectionClass::Protected
        } else {
            PeerStorageProtectionClass::Disposable
        };

        match class {
            PeerStorageProtectionClass::Pinned => {
                accounting.pinned_bytes = accounting.pinned_bytes.saturating_add(usage.blob_len);
            }
            PeerStorageProtectionClass::Protected => {
                accounting.protected_bytes =
                    accounting.protected_bytes.saturating_add(usage.blob_len);
            }
            PeerStorageProtectionClass::Disposable => {
                accounting.disposable_bytes =
                    accounting.disposable_bytes.saturating_add(usage.blob_len);
                accounting.reclaimable_bytes =
                    accounting.reclaimable_bytes.saturating_add(usage.blob_len);
            }
            PeerStorageProtectionClass::None => {}
        }

        if !protecting_references.is_empty()
            && protecting_references.iter().all(|reference| {
                !contract_state_by_peer
                    .get(&reference.peer_public_key)
                    .is_some_and(|state| state.online && state.our_content_synced)
            })
        {
            accounting.offline_blocking_bytes = accounting
                .offline_blocking_bytes
                .saturating_add(usage.blob_len);
        }
    }

    accounting
}

/// Build threshold points for when fresh checked replica count would decay.
fn replica_horizon_points(expiry_seconds: &[Option<i64>]) -> Vec<clirpc::ReplicaHorizonPoint> {
    let mut finite = expiry_seconds
        .iter()
        .flatten()
        .copied()
        .map(|seconds| seconds.max(0))
        .collect::<Vec<_>>();
    finite.sort_unstable();

    let mut remaining = i64::try_from(expiry_seconds.len()).unwrap_or(i64::MAX);
    let pinned_floor = i64::try_from(
        expiry_seconds
            .iter()
            .filter(|expiry| expiry.is_none())
            .count(),
    )
    .unwrap_or(i64::MAX);
    let mut points = Vec::new();

    for seconds in finite {
        remaining = remaining.saturating_sub(1);
        points.push(clirpc::ReplicaHorizonPoint {
            remaining_fresh_replicas: remaining,
            seconds_until_threshold: seconds,
            never: false,
        });
    }

    let mut next_remaining = pinned_floor.saturating_sub(1);
    while next_remaining >= 0 {
        points.push(clirpc::ReplicaHorizonPoint {
            remaining_fresh_replicas: next_remaining,
            seconds_until_threshold: 0,
            never: true,
        });
        if next_remaining == 0 {
            break;
        }
        next_remaining = next_remaining.saturating_sub(1);
    }

    points
}

/// Return the arithmetic mean of the provided scores, saturating to i64.
fn mean_score_seconds(scores: &[i64]) -> i64 {
    if scores.is_empty() {
        return 0;
    }

    let total = scores.iter().fold(0i128, |running, score| {
        running.saturating_add(i128::from(*score))
    });
    let mean = total / i128::try_from(scores.len()).unwrap_or(i128::MAX);
    mean.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

/// Sum deduplicated cached mirrored-peer bytes from persisted sidecar metadata.
fn mirrored_total_size_bytes_from_tracked_peers(tracked_peers: &[storedpb::Peer]) -> i64 {
    let mut lengths = BTreeMap::<Vec<u8>, i64>::new();
    for peer in tracked_peers {
        let Some(cached_content) = peer_latest_cached_content(peer) else {
            continue;
        };
        if cached_content.content_length <= 0 {
            continue;
        }
        lengths
            .entry(cached_content.content_id.clone())
            .or_insert(cached_content.content_length);
    }

    lengths
        .into_values()
        .fold(0i64, |total, length| total.saturating_add(length.max(0)))
}

/// Return the group priority used when listing peers.
fn peer_inventory_group_rank(entry: &PeerInventoryEntry) -> u8 {
    if entry.has_storage {
        0
    } else if entry.status != PeerInventoryStatus::Offline {
        1
    } else {
        2
    }
}

/// Return the status priority used inside one peer listing group.
fn peer_inventory_status_rank(status: PeerInventoryStatus) -> u8 {
    match status {
        PeerInventoryStatus::Connected => 0,
        PeerInventoryStatus::Online => 1,
        PeerInventoryStatus::Offline => 2,
    }
}

/// Convert one internal peer status into the local RPC enum value.
fn proto_peer_status(status: PeerInventoryStatus) -> i32 {
    match status {
        PeerInventoryStatus::Connected => clirpc::PeerStatus::Connected as i32,
        PeerInventoryStatus::Online => clirpc::PeerStatus::Online as i32,
        PeerInventoryStatus::Offline => clirpc::PeerStatus::Offline as i32,
    }
}

/// Convert one stored peer-content summary into the RPC content shape.
fn rpc_content_info(content: storedpb::PeerContent) -> bbrpc::ContentInfo {
    bbrpc::ContentInfo {
        content_id: content.content_id,
        content_length: content.content_length,
    }
}

/// Encode one `(seconds, nanos)` pair as a protobuf timestamp.
fn proto_timestamp_from_parts(seconds: i64, nanos: i64) -> Result<ProtoTimestamp, Status> {
    if !(0..1_000_000_000).contains(&nanos) {
        return Err(Status::invalid_argument(
            "timestamp nanoseconds must be below one second",
        ));
    }

    Ok(ProtoTimestamp {
        seconds,
        nanos: i32::try_from(nanos)
            .map_err(|_| Status::invalid_argument("timestamp nanoseconds are out of range"))?,
    })
}

/// Encode one file mtime as a protobuf timestamp.
fn proto_timestamp_from_file_parts(seconds: u64, nanos: u32) -> ProtoTimestamp {
    ProtoTimestamp {
        seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
        nanos: i32::try_from(nanos).unwrap_or(i32::MAX),
    }
}

/// Decode one optional protobuf timestamp into integer parts.
fn timestamp_parts(timestamp: Option<&ProtoTimestamp>) -> Result<(u64, u32), Status> {
    let timestamp =
        timestamp.ok_or_else(|| Status::invalid_argument("file modified_at is required"))?;
    if timestamp.seconds < 0 {
        return Err(Status::invalid_argument(
            "file modified_at must not be negative",
        ));
    }
    if !(0..1_000_000_000).contains(&timestamp.nanos) {
        return Err(Status::invalid_argument(
            "file modified_at nanos must be below one second",
        ));
    }

    Ok((
        u64::try_from(timestamp.seconds)
            .map_err(|_| Status::invalid_argument("file modified_at is out of range"))?,
        u32::try_from(timestamp.nanos)
            .map_err(|_| Status::invalid_argument("file modified_at nanos is out of range"))?,
    ))
}

/// Decode one optional stored timestamp into integer parts.
fn optional_timestamp_parts(timestamp: Option<&ProtoTimestamp>) -> Option<(i64, i64)> {
    timestamp.map(|timestamp| (timestamp.seconds, i64::from(timestamp.nanos)))
}

/// Convert one stored file summary into the local RPC metadata shape.
fn rpc_file_info(file: storage::StoredFileInfo) -> clirpc::FileInfo {
    clirpc::FileInfo {
        name: file.name,
        size_bytes: file.size_bytes,
        modified_at: Some(
            proto_timestamp_from_parts(file.modified_at_secs, file.modified_at_nanos)
                .expect("stored file timestamps must be valid"),
        ),
    }
}

/// Convert one plaintext file into the metadata-only local RPC shape.
fn rpc_file_info_from_plain_file(file: &PlainFile) -> clirpc::FileInfo {
    clirpc::FileInfo {
        name: file.name.clone(),
        size_bytes: i64::try_from(file.data.len()).unwrap_or(i64::MAX),
        modified_at: Some(proto_timestamp_from_file_parts(
            file.modified_at_secs,
            file.modified_at_nanos,
        )),
    }
}

/// Split one plaintext file into local streamed download chunks.
fn get_file_chunks(file: PlainFile) -> Vec<Result<clirpc::GetFileChunk, Status>> {
    let mut chunks = vec![Ok(clirpc::GetFileChunk {
        chunk: Some(clirpc::get_file_chunk::Chunk::File(
            rpc_file_info_from_plain_file(&file),
        )),
    })];
    for data in file.data.chunks(LOCAL_CLI_FILE_CHUNK_BYTES) {
        chunks.push(Ok(clirpc::GetFileChunk {
            chunk: Some(clirpc::get_file_chunk::Chunk::Data(data.to_vec())),
        }));
    }
    chunks
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
#[derive(Clone, Debug)]
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

/// RecoveryPassSummary reports one automatic recovery pass and its result.
#[derive(Clone, Debug, Default)]
pub struct RecoveryPassSummary {
    /// total_versions_found is the number of unique requester revisions peers reported.
    pub total_versions_found: i64,
    /// peers_with_any_versions is the number of peers that reported any requester revision.
    pub peers_with_any_versions: i64,
    /// older_lineage_versions_found is the number of unique older-lineage revisions in scope.
    pub older_lineage_versions_found: i64,
    /// older_lineage_recoverable_versions_found is the number of unique older-lineage revisions
    /// that at least one peer could actually serve.
    pub older_lineage_recoverable_versions_found: i64,
    /// applied_versions is the number of recovered revisions merged locally.
    pub applied_versions: i64,
    /// downloaded_bytes is the total encrypted bytes fetched during recovery.
    pub downloaded_bytes: i64,
    /// added_files is the number of recovered files added under their original names.
    pub added_files: i64,
    /// renamed_files is the number of recovered files added under recovered names.
    pub renamed_files: i64,
    /// unchanged_files is the number of recovered files skipped as identical.
    pub unchanged_files: i64,
    /// newest_found_content_id is the newest requester revision observed from any peer.
    pub newest_found_content_id: Vec<u8>,
    /// newest_found_ts is newest_found_content_id's authenticated timestamp in Unix seconds.
    pub newest_found_ts: i64,
    /// newest_found_ts_ns is newest_found_content_id's authenticated sub-second nanoseconds.
    pub newest_found_ts_ns: i64,
    /// latest_applied_content_id is the newest older-lineage revision merged locally.
    pub latest_applied_content_id: Vec<u8>,
    /// latest_applied_ts is latest_applied_content_id's authenticated timestamp in Unix seconds.
    pub latest_applied_ts: i64,
    /// latest_applied_ts_ns is latest_applied_content_id's authenticated sub-second nanoseconds.
    pub latest_applied_ts_ns: i64,
    /// publication_blocked_reason explains why recovered local state still cannot publish.
    pub publication_blocked_reason: String,
}

/// RecoveryPassAccumulator accumulates one automatic recovery pass before the
/// final operator-facing summary is rendered.
#[derive(Clone, Debug, Default)]
struct RecoveryPassAccumulator {
    /// total_versions_found is the number of unique requester revisions peers reported.
    total_versions_found: i64,
    /// peers_with_any_versions is the number of peers that reported any requester revision.
    peers_with_any_versions: i64,
    /// older_lineage_versions_found is the number of unique older-lineage revisions in scope.
    older_lineage_versions_found: i64,
    /// older_lineage_recoverable_versions_found is the number of unique older-lineage revisions
    /// that at least one peer could actually serve.
    older_lineage_recoverable_versions_found: i64,
    /// applied_versions is the number of recovered revisions merged locally.
    applied_versions: i64,
    /// downloaded_bytes is the total encrypted bytes fetched during recovery.
    downloaded_bytes: i64,
    /// added_files is the number of recovered files added under their original names.
    added_files: i64,
    /// renamed_files is the number of recovered files added under recovered names.
    renamed_files: i64,
    /// unchanged_files is the number of recovered files skipped as identical.
    unchanged_files: i64,
    /// newest_found is the newest requester revision observed from any peer.
    newest_found: Option<RecoveryCandidate>,
    /// latest_applied is the newest older-lineage revision that was merged locally.
    latest_applied: Option<RecoveryCandidate>,
    /// publication_blocked_reason is set when the recovered local state is too large to publish.
    publication_blocked_reason: Option<String>,
}

impl Node {
    /// Create a node identity without attaching a local encrypted store.
    pub fn new(seed: &str) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(
            &master,
            None,
            Arc::new(SystemClock),
            DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
            None,
        )
    }

    /// Create a node identity with a local encrypted store.
    pub fn with_local_storage(seed: &str, filesystem: Arc<dyn Filesystem>) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(
            &master,
            Some(filesystem),
            Arc::new(SystemClock),
            DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
            None,
        )
    }

    /// Create a node identity with a local encrypted store and explicit clock.
    pub fn with_local_storage_and_clock(
        seed: &str,
        filesystem: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Self::with_local_storage_and_clock_and_flush_delay(
            seed,
            filesystem,
            clock,
            DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
        )
    }

    /// Create a node identity with a local encrypted store, explicit clock,
    /// and delayed low-value peer metadata flush policy.
    pub fn with_local_storage_and_clock_and_flush_delay(
        seed: &str,
        filesystem: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
        peer_metadata_flush_delay: Duration,
    ) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(
            &master,
            Some(filesystem),
            clock,
            peer_metadata_flush_delay,
            None,
        )
    }

    /// Create a node identity with a local encrypted store, explicit clock,
    /// delayed low-value peer metadata flush policy, and custom metadata-rollup
    /// sampling. This is intended for deterministic tests of metadata-only
    /// content rewrites.
    pub fn with_local_storage_and_clock_and_flush_delay_and_rollup_sampler(
        seed: &str,
        filesystem: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
        peer_metadata_flush_delay: Duration,
        metadata_rollup_delay_sampler: Arc<dyn Fn() -> Duration + Send + Sync>,
    ) -> Result<Self> {
        let master = keys::derive_master_priv(seed);
        Self::build_from_master(
            &master,
            Some(filesystem),
            clock,
            peer_metadata_flush_delay,
            Some(metadata_rollup_delay_sampler),
        )
    }

    /// Return the node onion hostname.
    pub fn address(&self) -> &str {
        &self.onion_address
    }

    /// Mark the node as started so uptime can be reported.
    pub fn mark_started(&self) {
        *self.started_at.lock().unwrap() = Some(self.clock.now());
    }

    /// Start a new local observation window for peer score accounting.
    pub fn start_peer_score_observation_window(&self) {
        *self.peer_score_observation_started_at.lock().unwrap() = Some(self.clock.now());
    }

    /// Suspend local observation for peer score accounting.
    pub fn suspend_peer_score_observation_window(&self) {
        *self.peer_score_observation_started_at.lock().unwrap() = None;
    }

    /// Return the deterministic Ed25519 keypair.
    pub fn ed25519_keypair(&self) -> &ed25519_dalek::Keypair {
        &self.ed25519_keypair
    }

    /// Return the current peer-score observation-window start in seconds.
    pub fn peer_score_observation_started_at_secs(&self) -> Option<i64> {
        self.peer_score_observation_started_at
            .lock()
            .unwrap()
            .map(|timestamp| i64::try_from(timestamp.secs).unwrap_or(i64::MAX))
    }

    /// Create a node identity from already-derived master material in tests.
    #[cfg(test)]
    fn new_for_tests_from_master(master_priv: &[u8]) -> Result<Self> {
        Self::build_from_master(
            master_priv,
            None,
            Arc::new(SystemClock),
            DEFAULT_LOW_VALUE_PEER_METADATA_FLUSH_DELAY,
            None,
        )
    }

    /// Build a node, optionally attaching an encrypted local store.
    fn build_from_master(
        master_priv: &[u8],
        filesystem: Option<Arc<dyn Filesystem>>,
        clock: Arc<dyn Clock>,
        peer_metadata_flush_delay: Duration,
        metadata_rollup_delay_sampler: Option<Arc<dyn Fn() -> Duration + Send + Sync>>,
    ) -> Result<Self> {
        let (keypair, public_key) = keys::derive_ed25519_from_master(master_priv, "tor/onion/v3")?;
        let onion_address = keys::onion_hostname_from_public_key(&public_key);
        let store = filesystem
            .map(|filesystem| match metadata_rollup_delay_sampler.clone() {
                Some(sampler) => Store::new_with_time_source_and_rollup_sampler(
                    filesystem,
                    master_priv,
                    clock.clone(),
                    sampler,
                ),
                None => Store::new_with_time_source(filesystem, master_priv, clock.clone()),
            })
            .transpose()?
            .map(|store| Arc::new(Mutex::new(store)));
        let peer_metadata_batcher = store.as_ref().map(|store| {
            PeerMetadataBatcher::new(store.clone(), clock.clone(), peer_metadata_flush_delay)
        });
        let built_in_peer_list = built_in_peers();
        let node = Self {
            ed25519_keypair: keypair,
            onion_address,
            clock: clock.clone(),
            started_at: Mutex::new(None),
            peer_score_observation_started_at: Mutex::new(Some(clock.now())),
            store,
            peer_metadata_batcher,
            known_peers: Mutex::new(BTreeSet::new()),
            storage_config: Mutex::new(default_storage_config()),
            peer_connector: Mutex::new(None),
            peer_client_cache: Mutex::new(BTreeMap::new()),
            peer_exchange_last_attempt: Mutex::new(BTreeMap::new()),
            peer_live_recovery_probe_state: Mutex::new(BTreeMap::new()),
            recent_peer_failures: Mutex::new(BTreeMap::new()),
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

    /// Flush any pending low-value peer metadata sidecar changes immediately.
    pub fn flush_pending_peer_metadata(&self) -> Result<(), Status> {
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(());
        };
        batcher.flush_now()
    }

    /// Rewrite the current local content with newer peer metadata when one
    /// delayed metadata-only rollup is due.
    pub fn run_metadata_rollup_pass(&self) -> Result<MetadataRollupOutcome, Status> {
        let due_at = self.with_store(|store| Ok(store.metadata_rollup_due_at()))?;
        let Some((due_secs, due_nanos)) = due_at else {
            return Ok(MetadataRollupOutcome::NotPending);
        };

        let now = self.clock.now();
        let now = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        if now < (due_secs, due_nanos) {
            return Ok(MetadataRollupOutcome::NotDue);
        }

        // Flush any coalesced low-value peer metadata first so the rewrite
        // rolls the newest sidecar state into the shared content revision.
        self.flush_pending_peer_metadata()?;
        let outcome = self.with_store(|store| store.roll_up_peer_metadata_if_due())?;
        if let MetadataRollupOutcome::Rewritten { content_id } = &outcome {
            info!(
                onion = %self.address(),
                content_id = %content_id_hex(content_id),
                "rewrote local content to roll up newer peer metadata"
            );
        }
        Ok(outcome)
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

    /// Return one clear error for self-peer storage attempts.
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

    /// Return whether the local operator currently pins one tracked peer.
    fn is_peer_pinned_by_us(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
    ) -> Result<bool, Status> {
        Ok(self
            .tracked_peers()?
            .into_iter()
            .find(|peer| peer.onion_pubkey.as_slice() == peer_public_key.as_bytes())
            .map(|peer| peer.pinned_by_us)
            .unwrap_or(false))
    }

    /// Return whether the local operator currently pins the peer onion.
    fn is_peer_onion_pinned_by_us(&self, peer_onion: &str) -> bool {
        let Ok(peer_public_key) = keys::public_key_from_onion_hostname(peer_onion) else {
            return false;
        };
        self.is_peer_pinned_by_us(&peer_public_key).unwrap_or(false)
    }

    /// Replace the cached known-peer list with what is currently persisted plus built-ins.
    fn refresh_known_peers_from_store(&self) -> Result<(), Status> {
        let tracked_peers = self.tracked_peers()?;
        let mut known_peers = tracked_peers
            .into_iter()
            .filter_map(|peer| self.onion_from_public_key_bytes(&peer.onion_pubkey).ok())
            .filter(|peer_onion| !self.is_our_onion(peer_onion))
            .collect::<BTreeSet<_>>();
        known_peers.extend(built_in_peers());
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

        info!("purged stale persisted self-peer metadata from local storage");

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
        let mut evicted_onions = Vec::<String>::new();
        {
            let mut store = store_mutex.lock().unwrap();
            let mut peers = store.peers();
            if peers.len() <= capacity {
                return Ok(());
            }

            peers.sort_by_key(peer_eviction_order_key);
            let overflow = peers.len().saturating_sub(capacity);
            for peer in peers.into_iter().take(overflow) {
                evicted_onions.push(self.onion_from_public_key_bytes(&peer.onion_pubkey)?);
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

        if !evicted_onions.is_empty() {
            info!(
                trimmed_peer_count = evicted_onions.len(),
                trimmed_peers = ?evicted_onions,
                capacity,
                "trimmed tracked peers to the configured capacity"
            );
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
                false,
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
            info!(
                admitted_peer = %peer_onion,
                evicted_peer = %evicted_onion,
                "evicted a tracked peer to admit a higher-priority peer"
            );
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

    /// Ensure one current local content revision exists and return its summary.
    fn ensure_responder_content(&self) -> Result<bbrpc::ContentInfo, Status> {
        self.with_store(|store| store.ensure_current_content())?;
        self.responder_content()?.ok_or_else(|| {
            Status::failed_precondition("local node has no current content to publish")
        })
    }

    /// Install the outbound peer connector used for peer synchronization.
    pub fn set_peer_connector(&self, peer_connector: Arc<dyn PeerConnector>) {
        *self.peer_connector.lock().unwrap() = Some(peer_connector);
    }

    /// Drop the active outbound peer connector and every cached peer session.
    ///
    /// The daemon uses this before replacing a live peer runtime so stale
    /// cached channels and their transport state cannot outlive the runtime
    /// they were created from.
    pub fn clear_peer_runtime_transport(&self) {
        *self.peer_connector.lock().unwrap() = None;
        self.peer_client_cache.lock().unwrap().clear();
        self.peer_exchange_last_attempt.lock().unwrap().clear();
        self.peer_live_recovery_probe_state.lock().unwrap().clear();
    }

    /// Return the current node-clock second for cache bookkeeping.
    fn cache_now_secs(&self) -> i64 {
        i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX)
    }

    /// Drop expired outbound peer clients and stale peer-exchange cooldown entries.
    fn prune_peer_runtime_state(&self, now_secs: i64) {
        self.peer_client_cache.lock().unwrap().retain(|_, entry| {
            now_secs.saturating_sub(entry.last_used_at_secs) <= PEER_CLIENT_CACHE_IDLE_TTL_SECS
        });
        self.peer_exchange_last_attempt
            .lock()
            .unwrap()
            .retain(|_, last_attempt| {
                now_secs.saturating_sub(*last_attempt) <= PEER_EXCHANGE_COOLDOWN_SECS
            });
        self.peer_live_recovery_probe_state
            .lock()
            .unwrap()
            .retain(|_, state| {
                state.probe_in_progress
                    || now_secs.saturating_sub(state.last_contact_at_secs)
                        <= PEER_CLIENT_CACHE_IDLE_TTL_SECS
            });
    }

    /// Mark one peer live-contact session and report whether one best-effort
    /// recovery probe should run for it now.
    fn begin_live_recovery_probe_if_due(&self, peer_onion: &str) -> bool {
        if self.is_our_onion(peer_onion) {
            return false;
        }

        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);
        let mut state_by_peer = self.peer_live_recovery_probe_state.lock().unwrap();
        let state = state_by_peer
            .entry(peer_onion.to_string())
            .or_insert(LiveRecoveryProbeState {
                last_contact_at_secs: now_secs,
                probe_in_progress: false,
                probe_completed: false,
            });
        state.last_contact_at_secs = now_secs;
        if state.probe_in_progress || state.probe_completed {
            return false;
        }

        state.probe_in_progress = true;
        true
    }

    /// Record that one live-contact recovery probe finished for the peer's
    /// current in-memory session.
    fn finish_live_recovery_probe(&self, peer_onion: &str, completed: bool) {
        if self.is_our_onion(peer_onion) {
            return;
        }

        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);
        let mut state_by_peer = self.peer_live_recovery_probe_state.lock().unwrap();
        let Some(state) = state_by_peer.get_mut(peer_onion) else {
            return;
        };
        state.last_contact_at_secs = now_secs;
        state.probe_in_progress = false;
        state.probe_completed = completed;
    }

    /// Probe one live peer contact for recoverable requester lineage.
    async fn run_live_recovery_probe_with_client(
        &self,
        peer_onion: &str,
        client: &mut transport::PeerClient,
    ) -> Result<(), Status> {
        let policy =
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::RecoveryProbe);
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let revision = self
            .peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await?;
        self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned)?;
        self.record_requester_revision_observation(&peer_public_key, &revision)?;
        self.maybe_exchange_peers_with_client(peer_onion, client)
            .await?;
        if let Some(recoverable_revision) = self.recoverable_requester_revision(&revision)? {
            info!(
                peer = %peer_onion,
                content_id = %content_id_hex(&recoverable_revision.content.content_id),
                timestamp_secs = recoverable_revision.timestamp.0,
                timestamp_nanos = recoverable_revision.timestamp.1,
                "running automatic recovery after a new live peer contact"
            );
            let recovery_update = self.run_recovery_pass().await?;
            info!(
                peer = %peer_onion,
                applied_versions = recovery_update.applied_versions,
                older_lineage_versions_found = recovery_update.older_lineage_versions_found,
                older_lineage_recoverable_versions_found = recovery_update
                    .older_lineage_recoverable_versions_found,
                "finished automatic recovery after a new live peer contact"
            );
        }

        Ok(())
    }

    /// Run one best-effort live-contact recovery probe on the provided client.
    async fn maybe_run_live_recovery_probe_with_client(
        &self,
        peer_onion: &str,
        client: &mut transport::PeerClient,
    ) {
        match self.publication_lineage_window() {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(error) => {
                warn!(
                    peer = %peer_onion,
                    %error,
                    "live peer-contact recovery probe skipped because lineage state is unavailable"
                );
                return;
            }
        }

        if !self.begin_live_recovery_probe_if_due(peer_onion) {
            return;
        }

        match self
            .run_live_recovery_probe_with_client(peer_onion, client)
            .await
        {
            Ok(()) => self.finish_live_recovery_probe(peer_onion, true),
            Err(error) => {
                self.finish_live_recovery_probe(peer_onion, false);
                let new_score = self.penalize_tracked_peer_probe_failure(peer_onion);
                warn!(
                    peer = %peer_onion,
                    new_score_seconds = new_score.unwrap_or_default(),
                    %error,
                    "live peer-contact recovery probe failed"
                );
            }
        }
    }

    /// Track and react to one authenticated inbound peer contact.
    fn note_authenticated_inbound_peer_contact(
        self: &Arc<Self>,
        peer_identity: &PeerIdentity,
    ) -> Result<(), Status> {
        if self.is_our_public_key(&peer_identity.public_key) {
            return Ok(());
        }

        self.track_peer_identity(
            &peer_identity.public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Inbound as i32,
        )?;
        self.note_peer_live(&peer_identity.onion_address)?;
        if !self.begin_live_recovery_probe_if_due(&peer_identity.onion_address) {
            return Ok(());
        }

        let node = Arc::clone(self);
        let peer_onion = peer_identity.onion_address.clone();
        tokio::spawn(async move {
            let policy =
                transport::PeerRetryPolicy::for_operation(transport::PeerOperation::RecoveryProbe);
            let result = node
                .retry_peer_operation(&peer_onion, policy, || async {
                    let mut client = node
                        .probe_peer_client_with_timeout(&peer_onion, policy.connect_timeout)
                        .await?;
                    node.run_live_recovery_probe_with_client(&peer_onion, &mut client)
                        .await
                })
                .await;
            match result {
                Ok(()) => node.finish_live_recovery_probe(&peer_onion, true),
                Err(error) => {
                    node.finish_live_recovery_probe(&peer_onion, false);
                    let new_score = node.penalize_tracked_peer_probe_failure(&peer_onion);
                    warn!(
                        peer = %peer_onion,
                        new_score_seconds = new_score.unwrap_or_default(),
                        %error,
                        "background live peer-contact recovery probe failed"
                    );
                }
            }
        });
        Ok(())
    }

    /// Decrease one tracked peer's score after a failed recovery probe.
    fn penalize_tracked_peer_probe_failure(&self, peer_onion: &str) -> Option<i64> {
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion).ok()?;
        self.update_peer_score(&peer_public_key, false).ok()
    }

    /// Return one cached outbound peer client when it is still inside the idle TTL.
    fn cached_peer_client(&self, peer_onion: &str) -> Option<transport::PeerClient> {
        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);

        let mut cache = self.peer_client_cache.lock().unwrap();
        let entry = cache.get_mut(peer_onion)?;
        entry.last_used_at_secs = now_secs;
        Some(entry.client.clone())
    }

    /// Report whether one cached outbound peer client is currently open.
    fn has_cached_peer_client(&self, peer_onion: &str) -> bool {
        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);
        self.peer_client_cache
            .lock()
            .unwrap()
            .contains_key(peer_onion)
    }

    /// Remember one outbound peer client in the bounded in-memory cache.
    fn remember_peer_client(&self, peer_onion: &str, client: &transport::PeerClient) {
        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);

        let mut cache = self.peer_client_cache.lock().unwrap();
        cache.insert(
            peer_onion.to_string(),
            CachedPeerClient {
                client: client.clone(),
                last_used_at_secs: now_secs,
            },
        );
        while cache.len() > MAX_CACHED_PEER_CLIENTS {
            let oldest_non_pinned = cache
                .iter()
                .filter(|(cached_peer_onion, _)| {
                    !self.is_peer_onion_pinned_by_us(cached_peer_onion)
                })
                .min_by_key(|(_, entry)| entry.last_used_at_secs)
                .map(|(peer_onion, _)| peer_onion.clone());
            let Some(oldest_key) = oldest_non_pinned.or_else(|| {
                cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used_at_secs)
                    .map(|(peer_onion, _)| peer_onion.clone())
            }) else {
                break;
            };
            cache.remove(&oldest_key);
        }
    }

    /// Evict one cached outbound peer client immediately.
    fn evict_cached_peer_client(&self, peer_onion: &str) {
        self.peer_client_cache.lock().unwrap().remove(peer_onion);
    }

    /// Persist a successful live transport interaction with one peer.
    fn note_peer_live(&self, peer_onion: &str) -> Result<(), Status> {
        if self.is_our_onion(peer_onion) {
            return Ok(());
        }
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(());
        };

        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        if !self.is_tracked_peer(&peer_public_key)? {
            return Ok(());
        }
        let now_secs = i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX);
        batcher.set_peer_reachability(
            peer_public_key.as_bytes(),
            storedpb::PeerReachability::Online as i32,
            Some(now_secs),
        )?;
        self.with_store(|store| store.record_peer_call_outcome(peer_public_key.as_bytes(), true))
    }

    /// Persist a failed live transport interaction with one peer.
    fn note_peer_offline(&self, peer_onion: &str) -> Result<(), Status> {
        if self.is_our_onion(peer_onion) {
            return Ok(());
        }
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(());
        };

        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        if !self.is_tracked_peer(&peer_public_key)? {
            return Ok(());
        }
        batcher.set_peer_reachability(
            peer_public_key.as_bytes(),
            storedpb::PeerReachability::Offline as i32,
            None,
        )?;
        self.with_store(|store| store.record_peer_call_outcome(peer_public_key.as_bytes(), false))
    }

    /// Classify one peer-operation failure for local operator-facing status.
    fn classify_recent_peer_failure(status: &Status) -> i32 {
        match status.code() {
            tonic::Code::DeadlineExceeded => clirpc::PeerFailureClass::Timeout as i32,
            tonic::Code::Unavailable => clirpc::PeerFailureClass::Transport as i32,
            tonic::Code::ResourceExhausted => {
                if status.message().contains("storage budget") {
                    clirpc::PeerFailureClass::StorageBudget as i32
                } else if status.message().contains("too large") {
                    clirpc::PeerFailureClass::Oversize as i32
                } else if status.message().contains("capacity reached") {
                    clirpc::PeerFailureClass::Capacity as i32
                } else {
                    clirpc::PeerFailureClass::Protocol as i32
                }
            }
            _ => clirpc::PeerFailureClass::Protocol as i32,
        }
    }

    /// Record one recent peer-operation failure for local operator status.
    fn note_recent_peer_failure(&self, peer_onion: &str, error: &Status) {
        if self.is_our_onion(peer_onion) {
            return;
        }
        let now_secs = i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX);
        self.recent_peer_failures.lock().unwrap().insert(
            peer_onion.to_string(),
            RecentPeerFailure {
                last_failure_at: now_secs,
                last_error_class: Self::classify_recent_peer_failure(error),
                last_error_message: error.message().to_string(),
            },
        );
    }

    /// Clear one recent peer-operation failure after a successful interaction.
    fn clear_recent_peer_failure(&self, peer_onion: &str) {
        self.recent_peer_failures.lock().unwrap().remove(peer_onion);
    }

    /// Return whether the peer-exchange cooldown has elapsed for one peer.
    fn peer_exchange_due(&self, peer_onion: &str) -> bool {
        let now_secs = self.cache_now_secs();
        self.prune_peer_runtime_state(now_secs);
        self.peer_exchange_last_attempt
            .lock()
            .unwrap()
            .get(peer_onion)
            .is_none_or(|last_attempt| {
                now_secs.saturating_sub(*last_attempt) >= PEER_EXCHANGE_COOLDOWN_SECS
            })
    }

    /// Record one peer-exchange attempt for cooldown tracking.
    fn note_peer_exchange_attempt(&self, peer_onion: &str) {
        self.peer_exchange_last_attempt
            .lock()
            .unwrap()
            .insert(peer_onion.to_string(), self.cache_now_secs());
    }

    /// Add a peer onion hostname to the configured peer set.
    pub fn add_known_peer(&self, peer_onion: &str) -> Result<(), Status> {
        self.add_known_peer_with_origin(peer_onion, peer_origin_code(false, true))
    }

    /// Track one peer and establish one immediate live contact to it.
    pub async fn connect_known_peer(&self, peer_onion: &str) -> Result<(), Status> {
        self.add_known_peer(peer_onion)?;
        let policy =
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::ConnectPeer);
        self.retry_peer_operation(peer_onion, policy, || async {
            let _client = self
                .connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
                .await?;
            Ok(())
        })
        .await
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

    /// Persist one operator pin for a tracked peer.
    pub fn pin_peer(&self, peer_onion: &str) -> Result<(), Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        if !self.is_tracked_peer(&peer_public_key)? {
            return Err(Status::failed_precondition(
                "peer is not tracked; connect it first",
            ));
        }

        self.with_store(|store| store.set_peer_pinned_by_us(peer_public_key.as_bytes(), true))
    }

    /// Remove one operator pin from a tracked peer.
    pub fn unpin_peer(&self, peer_onion: &str) -> Result<(), Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        if !self.is_tracked_peer(&peer_public_key)? {
            return Err(Status::failed_precondition(
                "peer is not tracked; connect it first",
            ));
        }

        self.with_store(|store| store.set_peer_pinned_by_us(peer_public_key.as_bytes(), false))
    }

    /// Build the peer-exchange request payload from the current known peer set.
    fn peer_exchange_request(&self) -> bbrpc::PeerExchangeRequest {
        bbrpc::PeerExchangeRequest {
            peers: self
                .known_peers()
                .into_iter()
                .filter_map(|peer_onion| {
                    keys::public_key_from_onion_hostname(&peer_onion)
                        .ok()
                        .map(|public_key| bbrpc::Peer {
                            onion_pubkey: public_key.to_bytes().to_vec(),
                        })
                })
                .collect(),
        }
    }

    /// Merge one peer-exchange response into the known peer set.
    fn merge_peer_exchange_response(
        &self,
        response: bbrpc::PeerExchangeResponse,
    ) -> Result<(), Status> {
        for peer in response.peers {
            let public_key = match ed25519_dalek::PublicKey::from_bytes(&peer.onion_pubkey) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
            if self.is_our_public_key(&public_key) {
                continue;
            }
            let peer_onion = keys::onion_hostname_from_public_key(&public_key);
            if let Err(error) =
                self.add_known_peer_with_origin(&peer_onion, peer_origin_code(false, false))
            {
                debug!(peer = %peer_onion, %error, "skipped discovered peer during peer exchange");
            }
        }

        Ok(())
    }

    /// Run one best-effort peer exchange after a successful live contact.
    async fn maybe_exchange_peers_with_client(
        &self,
        peer_onion: &str,
        client: &mut transport::PeerClient,
    ) -> Result<(), Status> {
        if !self.peer_exchange_due(peer_onion) {
            return Ok(());
        }

        let policy =
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::PeerExchange);
        match self
            .peer_rpc_with_timeout(
                peer_onion,
                "peer exchange",
                policy.rpc_timeout,
                client.peer_exchange(self.peer_exchange_request()),
            )
            .await
        {
            Ok(response) => {
                self.note_peer_exchange_attempt(peer_onion);
                self.merge_peer_exchange_response(response)?;
            }
            Err(error) if error.code() == Code::Unimplemented => {
                self.note_peer_exchange_attempt(peer_onion);
            }
            Err(error) if !transport::is_retryable_peer_status(&error) => {
                self.note_peer_exchange_attempt(peer_onion);
                warn!(
                    peer = %peer_onion,
                    code = ?error.code(),
                    message = %error.message(),
                    "peer exchange failed with a terminal status"
                );
            }
            Err(error) => {
                warn!(
                    peer = %peer_onion,
                    code = ?error.code(),
                    message = %error.message(),
                    "peer exchange failed with a retryable status"
                );
            }
        }

        Ok(())
    }

    /// Render the full built-in peer source file from built-ins plus live peers.
    pub async fn export_built_in_peer_source(&self) -> Result<String, Status> {
        let peers = self.peers_response()?;
        let live_peers = peers
            .peers
            .into_iter()
            .filter(|peer| {
                matches!(
                    clirpc::PeerStatus::try_from(peer.status),
                    Ok(clirpc::PeerStatus::Connected) | Ok(clirpc::PeerStatus::Online)
                )
            })
            .filter_map(|peer| peer.peer.map(|peer| peer.onion_service_id))
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

    /// Persist the latest requester revision view reported by a live peer.
    fn record_requester_revision_observation(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        revision: &bbrpc::GetContentRevisionResponse,
    ) -> Result<(), Status> {
        if !self.is_tracked_peer(peer_public_key)? {
            return Ok(());
        }
        self.with_store(|store| {
            store.set_peer_requester_revision_state(
                peer_public_key.as_bytes(),
                revision
                    .requester_latest_stored_content
                    .as_ref()
                    .map(|content| content.content_id.as_slice()),
                revision
                    .requester_latest_stored_content
                    .as_ref()
                    .map(|content| content.content_length),
                revision
                    .requester_latest_known_content
                    .as_ref()
                    .map(|content| content.content_id.as_slice()),
                revision
                    .requester_latest_known_content
                    .as_ref()
                    .map(|content| content.content_length),
            )
        })
    }

    /// Record that we started advertising one local revision to this peer.
    ///
    /// Returns the age in seconds of one older pending advertisement that was
    /// superseded before the peer downloaded it.
    fn record_requester_advertisement_attempt(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_info: &bbrpc::ContentInfo,
    ) -> Result<i64, Status> {
        let now = self.clock.now();
        self.with_store(|store| {
            store.note_peer_requester_advertisement(
                peer_public_key.as_bytes(),
                &content_info.content_id,
                content_info.content_length,
                (
                    i64::try_from(now.secs).unwrap_or(i64::MAX),
                    i64::from(now.nanos),
                ),
            )
        })
    }

    /// Record that this peer downloaded one revision we had advertised to it.
    fn record_requester_advertised_download(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_id: &[u8],
    ) -> Result<Option<i64>, Status> {
        let now = self.clock.now();
        self.with_store(|store| {
            store.note_peer_requester_downloaded_advertised_content(
                peer_public_key.as_bytes(),
                content_id,
                (
                    i64::try_from(now.secs).unwrap_or(i64::MAX),
                    i64::from(now.nanos),
                ),
            )
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
        self.connect_peer_client_with_timeout_and_tracking(peer_onion, connect_timeout, true)
            .await
    }

    /// Connect to another peer without mutating tracked-peer state.
    async fn probe_peer_client_with_timeout(
        &self,
        peer_onion: &str,
        connect_timeout: Duration,
    ) -> Result<transport::PeerClient, Status> {
        self.connect_peer_client_with_timeout_and_tracking_base(peer_onion, connect_timeout, false)
            .await
    }

    /// Connect to another peer with optional tracked-peer side effects and
    /// automatic live-contact recovery probing.
    async fn connect_peer_client_with_timeout_and_tracking(
        &self,
        peer_onion: &str,
        connect_timeout: Duration,
        track_peer: bool,
    ) -> Result<transport::PeerClient, Status> {
        let mut client = self
            .connect_peer_client_with_timeout_and_tracking_base(
                peer_onion,
                connect_timeout,
                track_peer,
            )
            .await?;
        if track_peer {
            self.maybe_run_live_recovery_probe_with_client(peer_onion, &mut client)
                .await;
        }
        Ok(client)
    }

    /// Connect to another peer with optional tracked-peer side effects but
    /// without any automatic live-contact recovery probing.
    async fn connect_peer_client_with_timeout_and_tracking_base(
        &self,
        peer_onion: &str,
        connect_timeout: Duration,
        track_peer: bool,
    ) -> Result<transport::PeerClient, Status> {
        if track_peer {
            if let Some(client) = self.cached_peer_client(peer_onion) {
                return Ok(client);
            }
        }

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
        if track_peer && !self.is_our_onion(peer_onion) {
            let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
                .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
            self.track_peer_identity(
                &peer_public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Outbound as i32,
            )?;
            self.note_peer_live(peer_onion)?;
        }

        let client = transport::configure_peer_client(client);
        if track_peer {
            self.remember_peer_client(peer_onion, &client);
        }
        Ok(client)
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
            Ok(Err(error)) => {
                let message = format!("{operation} from {peer_onion}: {}", error.message());
                let status = if error.details().is_empty() {
                    Status::new(error.code(), message)
                } else {
                    Status::with_details(error.code(), message, error.details().to_vec().into())
                };
                if transport::is_retryable_peer_status(&status) {
                    self.evict_cached_peer_client(peer_onion);
                }
                Err(status)
            }
            Err(_) => {
                self.evict_cached_peer_client(peer_onion);
                Err(Status::deadline_exceeded(format!(
                    "{operation} from {peer_onion} timed out"
                )))
            }
        }
    }

    /// Run one whole peer workflow with reconnect-and-retry under a shared
    /// operation budget.
    async fn retry_peer_operation<T, F, Fut>(
        &self,
        peer_onion: &str,
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
                Ok(result) => {
                    self.clear_recent_peer_failure(peer_onion);
                    return Ok(result);
                }
                Err(error) if transport::is_retryable_peer_status(&error) => {
                    retry_attempt = retry_attempt.saturating_add(1);
                    let backoff = policy.backoff_for_attempt(retry_attempt);
                    if started_at.elapsed().saturating_add(backoff) > policy.total_budget {
                        self.note_recent_peer_failure(peer_onion, &error);
                        let _ = self.note_peer_offline(peer_onion);
                        return Err(error);
                    }
                    tokio::time::sleep(backoff).await;
                }
                Err(error) => {
                    self.note_recent_peer_failure(peer_onion, &error);
                    return Err(error);
                }
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
        match self
            .retry_peer_operation(peer_onion, policy, || async move {
                let mut client = self
                    .probe_peer_client_with_timeout(peer_onion, policy.connect_timeout)
                    .await?;
                let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
                    .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
                let revision = self
                    .peer_rpc_with_timeout(
                        peer_onion,
                        "get content revision",
                        policy.rpc_timeout,
                        client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                    )
                    .await?;
                self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned)?;
                self.record_requester_revision_observation(&peer_public_key, &revision)?;
                self.maybe_exchange_peers_with_client(peer_onion, &mut client)
                    .await?;
                Ok(revision)
            })
            .await
        {
            Ok(revision) => Ok(revision),
            Err(error) if transport::is_retryable_peer_status(&error) => {
                let new_score = self.penalize_tracked_peer_probe_failure(peer_onion);
                warn!(
                    peer = %peer_onion,
                    new_score_seconds = new_score.unwrap_or_default(),
                    %error,
                    "background recovery probe exhausted retries"
                );
                Err(error)
            }
            Err(error) => Err(error),
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

        let mut client = self
            .probe_peer_client_with_timeout(peer_onion, transport::PEER_CONNECT_TIMEOUT)
            .await?;
        let response = self
            .peer_rpc(
                peer_onion,
                "download peer content",
                client.download(bbrpc::DownloadRequest {
                    content_id: content_id.to_vec(),
                    offset: 0,
                    length: expected_length,
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

        let raw_bytes = match response.section {
            Some(bbrpc::download_response::Section::RawBytes(raw_bytes)) => raw_bytes.value,
            Some(bbrpc::download_response::Section::Reference(_)) => {
                return Err(Status::unimplemented(
                    "reference sections are not supported yet",
                ));
            }
            None => return Err(Status::internal("peer returned no content section")),
        };
        if i64::try_from(raw_bytes.len()).unwrap_or(i64::MAX) != expected_length {
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
        let content_id_hex = content_id_hex(content_id);
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
                Ok(()) => {
                    info!(
                        content_id = %content_id_hex,
                        "removed unreferenced mirrored peer blob"
                    );
                    Ok(())
                }
                Err(StorageError::FileNotFound) => Ok(()),
                Err(error) => Err(error),
            }
        })
    }

    /// Report whether a mirrored peer blob is present, missing, or corrupt.
    fn mirrored_blob_state(&self, content_id: &[u8]) -> Result<MirroredBlobState, Status> {
        self.with_store(|store| match store.has_mirrored_blob(content_id) {
            Ok(true) => Ok(MirroredBlobState::Present),
            Ok(false) => Ok(MirroredBlobState::Missing),
            Err(StorageError::RecoveryRequired(_)) => {
                let _ = store.remove_mirrored_blob(content_id);
                warn!(
                    content_id = %content_id_hex(content_id),
                    "removed a corrupt mirrored peer blob during local recovery"
                );
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
                        pinned_by_us: peer.pinned_by_us,
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
                    storage_class(reference.pinned_by_us, reference.score_seconds)
                        == StorageClass::Reserved
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
        let incoming_allocation = max_peer_content_bytes_i64();

        let current_score = self.peer_score_state(peer_public_key)?.0;
        let pinned_by_us = self.is_peer_pinned_by_us(peer_public_key)?;
        let incoming_class = storage_class(pinned_by_us, current_score);
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
            if remaining_references.iter().any(|reference| {
                storage_class(reference.pinned_by_us, reference.score_seconds)
                    == StorageClass::Reserved
            }) {
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
            && protected_used.saturating_add(incoming_allocation) > budget
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
            if total_used.saturating_add(incoming_allocation) <= budget {
                break;
            }
            total_used = total_used.saturating_sub(blob_len);
            evict_content_ids.push(content_id);
        }

        if total_used.saturating_add(incoming_allocation) > budget {
            return Ok(StorageAdmission::TrackOnly);
        }

        Ok(StorageAdmission::Store { evict_content_ids })
    }

    /// Remove mirrored blobs that were selected as evictable best-effort cache entries.
    fn evict_mirrored_blobs(&self, content_ids: &[Vec<u8>]) -> Result<(), Status> {
        self.with_store(|store| {
            let mut evicted_content_ids = Vec::new();
            for content_id in content_ids {
                match store.remove_mirrored_blob(content_id) {
                    Ok(()) => {
                        evicted_content_ids.push(content_id_hex(content_id));
                    }
                    Err(StorageError::FileNotFound) => {}
                    Err(error) => return Err(error),
                }
            }
            if !evicted_content_ids.is_empty() {
                info!(
                    evicted_blob_count = evicted_content_ids.len(),
                    evicted_content_ids = ?evicted_content_ids,
                    "evicted best-effort mirrored peer blobs to stay within the storage budget"
                );
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
    ) -> Result<SyncPeerContentResult, Status> {
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
                let current_score = self.peer_score_state(peer_public_key)?.0;
                let pinned_by_us = self.is_peer_pinned_by_us(peer_public_key)?;
                let next_cached_content;
                let storage_result;

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
                            storage_result = SyncPeerContentResult::MirroredBytesCached;
                        }
                        StorageAdmission::TrackOnly => {
                            next_cached_content =
                                previous_cached_content.clone().filter(|cached_content| {
                                    cached_content.content_id != content_info.content_id
                                        && storage_class(pinned_by_us, current_score)
                                            == StorageClass::Reserved
                                });
                            warn!(
                                peer = %peer_onion,
                                content_id = %content_id,
                                content_length = content_info.content_length,
                                allocated_storage_for_peers = self.storage_budget_bytes(),
                                maximum_peer_content_accepted_bytes = self.maximum_peer_content_accepted_bytes()?,
                                "tracked peer revision without caching the blob because the storage budget was exhausted"
                            );
                            storage_result = SyncPeerContentResult::SidecarOnly;
                        }
                    }
                } else {
                    next_cached_content = Some(storedpb::PeerContent {
                        content_id: content_info.content_id.clone(),
                        content_length: content_info.content_length,
                    });
                    storage_result = SyncPeerContentResult::MirroredBytesCached;
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
                return Ok(storage_result);
            }
            None => {
                return Ok(if previous_cached_content_id.is_some() {
                    SyncPeerContentResult::MirroredBytesCached
                } else {
                    SyncPeerContentResult::SidecarOnly
                });
            }
        }
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

    /// Persist the latest remote claim about whether this peer pins us.
    fn record_remote_pin_claim(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        pins_us: bool,
    ) -> Result<(), Status> {
        if !self.is_tracked_peer(peer_public_key)? {
            return Ok(());
        }
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(());
        };
        batcher.set_peer_pins_us(peer_public_key.as_bytes(), pins_us)
    }

    /// Persist which current local revision this peer most recently passed a
    /// verification for.
    fn record_verified_our_content(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        content_id: Option<&[u8]>,
    ) -> Result<(), Status> {
        if !self.is_tracked_peer(peer_public_key)? {
            return Ok(());
        }
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(());
        };
        let verified_at =
            content_id.map(|_| i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX));
        batcher.set_peer_last_verified_our_content(
            peer_public_key.as_bytes(),
            content_id,
            verified_at,
        )
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
        let elapsed = self.observed_peer_score_elapsed_secs(measured_at, now_secs);
        let new_score = if passed {
            score_seconds.saturating_add(elapsed)
        } else {
            score_seconds.saturating_sub(elapsed)
        };
        let Some(batcher) = &self.peer_metadata_batcher else {
            return Ok(new_score);
        };
        batcher.set_peer_score(peer_public_key.as_bytes(), new_score, now_secs)?;
        Ok(new_score)
    }

    /// Adjust the persisted score state for a peer by one direct delta.
    fn adjust_peer_score_direct(
        &self,
        peer_public_key: &ed25519_dalek::PublicKey,
        delta_seconds: i64,
    ) -> Result<Option<i64>, Status> {
        if delta_seconds == 0 || !self.is_tracked_peer(peer_public_key)? {
            return Ok(None);
        }
        let (score_seconds, _) = self.peer_score_state(peer_public_key)?;
        let now_secs = i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX);
        let new_score = score_seconds.saturating_add(delta_seconds);
        if let Some(batcher) = &self.peer_metadata_batcher {
            batcher.set_peer_score(peer_public_key.as_bytes(), new_score, now_secs)?;
        } else {
            self.with_store(|store| {
                store.set_peer_score(peer_public_key.as_bytes(), new_score, now_secs)
            })?;
        }
        Ok(Some(new_score))
    }

    /// Return the elapsed score-accounting interval visible to this node.
    fn observed_peer_score_elapsed_secs(&self, measured_at: i64, now_secs: i64) -> i64 {
        if measured_at <= 0 {
            return 0;
        }
        let Some(observation_started_at) = self.peer_score_observation_started_at_secs() else {
            return 0;
        };
        let effective_start = measured_at.max(observation_started_at);
        now_secs.saturating_sub(effective_start)
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

        // Hash peer identity, revision, and current time so repeated checks
        // move across the blob while remaining deterministic in tests.
        let mut hasher = Sha256::new();
        hasher.update(peer_public_key.as_bytes());
        hasher.update(content_id);
        hasher.update(self.clock.now().secs.to_le_bytes());
        let digest = hasher.finalize();
        let mut offset_bytes = [0u8; 8];
        offset_bytes.copy_from_slice(&digest[..8]);
        let offset = (u64::from_le_bytes(offset_bytes) as usize) % blob_len;
        let section_len = SAMPLE_LEN.min(blob_len - offset);

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

    /// Return the authenticated timestamp encoded in one content identifier.
    fn content_info_timestamp(
        &self,
        content_info: &bbrpc::ContentInfo,
    ) -> Result<(i64, i64), Status> {
        let (_, secs, nanos, _) = self.revision_key(&content_info.content_id)?;
        Ok((i64::try_from(secs).unwrap_or(i64::MAX), i64::from(nanos)))
    }

    /// Decode one machine-readable set-content failure from gRPC status details.
    fn set_content_revision_failure(status: &Status) -> Option<bbrpc::SetContentRevisionFailure> {
        (!status.details().is_empty())
            .then(|| bbrpc::SetContentRevisionFailure::decode(status.details()).ok())
            .flatten()
    }

    /// Build one failed-precondition status with a machine-readable set-content failure reason.
    fn set_content_revision_failure_status(
        reason: bbrpc::SetContentRevisionFailureReason,
        message: impl Into<String>,
    ) -> Status {
        Status::with_details(
            Code::FailedPrecondition,
            message.into(),
            bbrpc::SetContentRevisionFailure {
                reason: reason as i32,
            }
            .encode_to_vec()
            .into(),
        )
    }

    /// Return the local recovery generation boundary and recovery watermark.
    fn publication_lineage_window(
        &self,
    ) -> Result<Option<((i64, i64), Option<(i64, i64)>)>, Status> {
        self.with_store(|store| {
            Ok(store
                .node_initialized_at()
                .map(|node_initialized_at| (node_initialized_at, store.recovery_watermark())))
        })
    }

    /// Report whether one authenticated revision timestamp still requires recovery.
    fn timestamp_requires_recovery(
        &self,
        timestamp: (i64, i64),
        node_initialized_at: (i64, i64),
        recovery_watermark: Option<(i64, i64)>,
    ) -> bool {
        timestamp < node_initialized_at
            && recovery_watermark.is_none_or(|watermark| timestamp > watermark)
    }

    /// Select one requester revision from a peer response that must be recovered
    /// before owner-side publication may proceed.
    fn recoverable_requester_revision(
        &self,
        revision: &bbrpc::GetContentRevisionResponse,
    ) -> Result<Option<RecoverableRequesterRevision>, Status> {
        let Some((node_initialized_at, recovery_watermark)) = self.publication_lineage_window()?
        else {
            return Ok(None);
        };

        if let Some(content_info) = revision.requester_latest_stored_content.as_ref() {
            let timestamp = self.content_info_timestamp(content_info)?;
            if self.timestamp_requires_recovery(timestamp, node_initialized_at, recovery_watermark)
            {
                return Ok(Some(RecoverableRequesterRevision {
                    content: content_info.clone(),
                    timestamp,
                    source: RecoverableRequesterRevisionSource::LatestStored,
                }));
            }
        }

        if let Some(content_info) = revision.requester_latest_known_content.as_ref() {
            let timestamp = self.content_info_timestamp(content_info)?;
            if self.timestamp_requires_recovery(timestamp, node_initialized_at, recovery_watermark)
            {
                return Ok(Some(RecoverableRequesterRevision {
                    content: content_info.clone(),
                    timestamp,
                    source: RecoverableRequesterRevisionSource::LatestKnown,
                }));
            }
        }

        Ok(None)
    }

    /// Reject owner-side publication until an older requester lineage has been recovered.
    fn ensure_peer_revision_does_not_require_recovery(
        &self,
        peer_onion: &str,
        revision: &bbrpc::GetContentRevisionResponse,
    ) -> Result<(), Status> {
        let Some(recoverable_revision) = self.recoverable_requester_revision(revision)? else {
            return Ok(());
        };
        let source_message = match recoverable_revision.source {
            RecoverableRequesterRevisionSource::LatestStored => {
                "peer still stores an older requester revision"
            }
            RecoverableRequesterRevisionSource::LatestKnown => {
                "peer still knows an older requester revision"
            }
        };
        Err(Status::failed_precondition(format!(
            "{source_message} from before this node was initialized; recover it before publishing to {peer_onion} (content_id={}, timestamp={}.{:09})",
            content_id_hex(&recoverable_revision.content.content_id),
            recoverable_revision.timestamp.0,
            recoverable_revision.timestamp.1,
        )))
    }

    /// Report whether one requester revision falls inside the older-lineage recovery window.
    fn requester_revision_in_recovery_window(
        &self,
        content_info: &bbrpc::ContentInfo,
    ) -> Result<Option<(i64, i64)>, Status> {
        let Some((node_initialized_at, recovery_watermark)) = self.publication_lineage_window()?
        else {
            return Ok(None);
        };
        let timestamp = self.content_info_timestamp(content_info)?;
        if self.timestamp_requires_recovery(timestamp, node_initialized_at, recovery_watermark) {
            return Ok(Some(timestamp));
        }
        Ok(None)
    }

    /// Report whether the active local revision matches one peer-advertised
    /// content id but its encrypted blob is currently missing.
    fn current_content_needs_restore_from_peer(&self, content_id: &[u8]) -> Result<bool, Status> {
        self.with_store(|store| {
            let Some(current) = store.current_content() else {
                return Ok(false);
            };
            if current.content_id != content_id {
                return Ok(false);
            }

            match store.current_blob() {
                Ok(_) => Ok(false),
                Err(StorageError::FileNotFound) => Ok(true),
                Err(error) => Err(error),
            }
        })
    }

    /// Persist the local lineage boundary once during daemon initialization.
    pub fn initialize_lineage(
        &self,
        node_initialized_at: (i64, i64),
        recovery_mode_enabled: bool,
    ) -> Result<(), Status> {
        self.with_store(|store| {
            store.initialize_lineage(node_initialized_at, recovery_mode_enabled)
        })
    }

    /// Complete recovery-mode initialization and advance the recovery watermark.
    fn complete_initialization(&self) -> Result<(), Status> {
        self.with_store(|store| store.finish_recovery_mode())
    }

    /// Report whether recovery mode blocks owner-originated publication.
    fn recovery_mode_enabled(&self) -> Result<bool, Status> {
        self.with_store(|store| Ok(store.recovery_mode_enabled()))
    }

    /// Reject one local file mutation while recovery mode is enabled.
    fn ensure_local_file_mutations_allowed(&self) -> Result<(), Status> {
        if self.recovery_mode_enabled()? {
            return Err(Status::failed_precondition(
                "local file edits are blocked while recovery mode is enabled",
            ));
        }

        Ok(())
    }

    /// Return the current owner-publication guard reason, if any.
    fn publish_blocked_reason(&self) -> Result<Option<String>, Status> {
        if self.recovery_mode_enabled()? {
            return Ok(Some(
                "recovery mode is enabled; run `bbcli init complete` before publishing".to_string(),
            ));
        }

        let oversized = self.with_store(|store| {
            Ok(store
                .current_projected_blob_len()?
                .is_some_and(|len| len > storage::MAX_SHARED_CONTENT_BLOB_BYTES))
        })?;
        if oversized {
            return Ok(Some(
                "current content exceeds the fixed 4 MiB publication limit".to_string(),
            ));
        }

        Ok(None)
    }

    /// Reject one owner-originated publish attempt when safety guards are active.
    fn ensure_owner_publication_allowed(&self) -> Result<(), Status> {
        if let Some(reason) = self.publish_blocked_reason()? {
            return Err(Status::failed_precondition(reason));
        }

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
                // Treat corrupt cached mirror bytes as absent here so proposal
                // and inventory paths can continue into the refresh logic.
                Err(StorageError::Message(_)) => Ok(0),
                Err(error) => Err(error),
            }
        })
    }

    /// Snapshot the local encrypted-store state used by the local state RPC.
    fn local_store_snapshot(&self) -> Result<Option<LocalStoreSnapshot>, Status> {
        if self.store.is_none() {
            return Ok(None);
        }

        self.with_store(|store| {
            Ok(Some(LocalStoreSnapshot {
                current_content: store.current_content().cloned(),
                tracked_peers: store.peers(),
                file_count: store.file_count(),
                total_file_bytes: store.total_file_bytes(),
                node_initialized_at: store.node_initialized_at(),
                latest_recovered_revision: store.latest_recovered_revision(),
                recovery_watermark: store.recovery_watermark(),
                recovery_mode_enabled: store.recovery_mode_enabled(),
            }))
        })
    }

    /// Snapshot per-peer local inventory fields from sidecar metadata in one store pass.
    fn local_peer_inventory_snapshot(
        &self,
    ) -> Result<BTreeMap<String, LocalPeerInventorySnapshot>, Status> {
        if self.store.is_none() {
            return Ok(BTreeMap::new());
        }

        self.with_store(|store| {
            let mut peers = BTreeMap::new();
            for peer in store.peers() {
                let peer_onion = match self.onion_from_public_key_bytes(&peer.onion_pubkey) {
                    Ok(peer_onion) => peer_onion,
                    Err(_) => continue,
                };
                let latest_known_content = peer_latest_known_content(&peer);
                let latest_cached_content = peer_latest_cached_content(&peer);
                peers.insert(
                    peer_onion,
                    LocalPeerInventorySnapshot {
                        reachability: peer.reachability,
                        pinned_by_us: peer.pinned_by_us,
                        pins_us: peer.pins_us,
                        has_storage: peer_has_storage(&peer),
                        score_seconds: peer.score_seconds,
                        score_measured_at: peer.score_measured_at,
                        stored_content_bytes: latest_cached_content
                            .as_ref()
                            .map(|content| content.content_length)
                            .unwrap_or(0),
                        latest_known_content_length: latest_known_content
                            .as_ref()
                            .map(|content| content.content_length)
                            .unwrap_or(0),
                        latest_cached_content_length: latest_cached_content
                            .as_ref()
                            .map(|content| content.content_length)
                            .unwrap_or(0),
                        stale_cache: latest_known_content
                            .as_ref()
                            .map(|content| &content.content_id)
                            != latest_cached_content
                                .as_ref()
                                .map(|content| &content.content_id),
                        storage_protection: peer_storage_protection(&peer),
                        tracked_only: peer_is_tracked_only(&peer),
                        last_live_at: peer.last_live_at,
                    },
                );
            }
            Ok(peers)
        })
    }

    /// Build the current local peer inventory without dialing any peers.
    fn peer_inventory(&self) -> Result<Vec<PeerInventoryEntry>, Status> {
        let local_peers = self.local_peer_inventory_snapshot()?;
        let recent_failures = self.recent_peer_failures.lock().unwrap().clone();

        let mut peers = Vec::new();
        for peer_onion in self.known_peers() {
            if self.is_our_onion(&peer_onion) {
                continue;
            }

            let tracked_peer = local_peers.get(&peer_onion);
            let connected = self.has_cached_peer_client(&peer_onion);
            let status = if connected {
                PeerInventoryStatus::Connected
            } else if tracked_peer
                .is_some_and(|peer| peer.reachability == storedpb::PeerReachability::Online as i32)
            {
                PeerInventoryStatus::Online
            } else {
                PeerInventoryStatus::Offline
            };
            let recent_failure = recent_failures.get(&peer_onion);

            peers.push(PeerInventoryEntry {
                onion_service_id: peer_onion,
                status,
                pinned_by_us: tracked_peer.map(|peer| peer.pinned_by_us).unwrap_or(false),
                pins_us: tracked_peer.map(|peer| peer.pins_us).unwrap_or(false),
                has_storage: tracked_peer.map(|peer| peer.has_storage).unwrap_or(false),
                score_seconds: tracked_peer
                    .map(|peer| peer.score_seconds)
                    .unwrap_or_default(),
                score_measured_at: tracked_peer
                    .map(|peer| peer.score_measured_at)
                    .unwrap_or_default(),
                stored_content_bytes: tracked_peer
                    .map(|peer| peer.stored_content_bytes)
                    .unwrap_or_default(),
                latest_known_content_length: tracked_peer
                    .map(|peer| peer.latest_known_content_length)
                    .unwrap_or_default(),
                latest_cached_content_length: tracked_peer
                    .map(|peer| peer.latest_cached_content_length)
                    .unwrap_or_default(),
                stale_cache: tracked_peer.map(|peer| peer.stale_cache).unwrap_or(false),
                storage_protection: tracked_peer
                    .map(|peer| peer.storage_protection)
                    .unwrap_or(PeerStorageProtectionClass::None),
                tracked_only: tracked_peer.map(|peer| peer.tracked_only).unwrap_or(false),
                last_live_at: tracked_peer
                    .map(|peer| peer.last_live_at)
                    .unwrap_or_default(),
                last_failure_at: recent_failure
                    .map(|failure| failure.last_failure_at)
                    .unwrap_or_default(),
                last_error_class: recent_failure
                    .map(|failure| failure.last_error_class)
                    .unwrap_or(clirpc::PeerFailureClass::Unknown as i32),
                last_error_message: recent_failure
                    .map(|failure| failure.last_error_message.clone())
                    .unwrap_or_default(),
                consecutive_failures: 0,
                next_retry_at: 0,
            });
        }

        peers.sort_by(|left, right| {
            peer_inventory_group_rank(left)
                .cmp(&peer_inventory_group_rank(right))
                .then(
                    peer_inventory_status_rank(left.status)
                        .cmp(&peer_inventory_status_rank(right.status)),
                )
                .then(right.last_live_at.cmp(&left.last_live_at))
                .then(right.score_seconds.cmp(&left.score_seconds))
                .then(left.onion_service_id.cmp(&right.onion_service_id))
        });
        Ok(peers)
    }

    /// Build the local-only state summary shown by `bbcli state`.
    pub fn local_state_summary(&self) -> Result<Option<clirpc::StateLocalSummary>, Status> {
        let Some(snapshot) = self.local_store_snapshot()? else {
            return Ok(None);
        };
        let inventory = self.peer_inventory()?;
        let mirrored_total_size_bytes =
            mirrored_total_size_bytes_from_tracked_peers(&snapshot.tracked_peers);
        let total_known = i64::try_from(inventory.len()).unwrap_or(i64::MAX);
        let connected = i64::try_from(
            inventory
                .iter()
                .filter(|peer| matches!(peer.status, PeerInventoryStatus::Connected))
                .count(),
        )
        .unwrap_or(i64::MAX);
        let mirrored_peers = i64::try_from(
            inventory
                .iter()
                .filter(|peer| peer.stored_content_bytes > 0)
                .count(),
        )
        .unwrap_or(i64::MAX);
        let mutual_storage_peers = snapshot
            .tracked_peers
            .iter()
            .filter(|peer| peer_has_storage(peer))
            .collect::<Vec<_>>();
        let mutual_storage_scores = mutual_storage_peers
            .iter()
            .map(|peer| peer.score_seconds)
            .collect::<Vec<_>>();
        let mutual_storage_peers = i64::try_from(mutual_storage_scores.len()).unwrap_or(i64::MAX);
        let current_content_id = snapshot
            .current_content
            .as_ref()
            .map(|content| content.content_id.clone());
        let storing_our_data = i64::try_from(
            snapshot
                .tracked_peers
                .iter()
                .filter(|peer| peer.requester_latest_stored_content.is_some())
                .count(),
        )
        .unwrap_or(i64::MAX);
        let storing_latest_our_data = current_content_id
            .as_ref()
            .map(|current_content_id| {
                i64::try_from(
                    snapshot
                        .tracked_peers
                        .iter()
                        .filter(|peer| {
                            peer_requester_latest_stored_content(peer)
                                .is_some_and(|content| content.content_id == *current_content_id)
                        })
                        .count(),
                )
                .unwrap_or(i64::MAX)
            })
            .unwrap_or(0);
        let min_replicas_target = self.storage_config.lock().unwrap().min_replicas.max(0);
        let predicted_fresh_replicas_now = current_content_id
            .as_ref()
            .map(|current_content_id| {
                i64::try_from(
                    snapshot
                        .tracked_peers
                        .iter()
                        .filter(|peer| {
                            peer.reachability == storedpb::PeerReachability::Online as i32
                                && peer_requester_latest_stored_content(peer).is_some_and(
                                    |content| content.content_id == *current_content_id,
                                )
                        })
                        .count(),
                )
                .unwrap_or(i64::MAX)
            })
            .unwrap_or(0);
        let publish_blocked_reason = self.publish_blocked_reason()?.unwrap_or_default();
        let predicted_replica_horizon = current_content_id
            .as_ref()
            .map(|current_content_id| {
                snapshot
                    .tracked_peers
                    .iter()
                    .filter(|peer| {
                        peer.reachability == storedpb::PeerReachability::Online as i32
                            && peer_requester_latest_stored_content(peer)
                                .is_some_and(|content| content.content_id == *current_content_id)
                    })
                    .map(|peer| {
                        if peer.pins_us {
                            None
                        } else {
                            Some(peer.score_seconds.max(0))
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let latest_recovered_revision = snapshot
            .recovery_mode_enabled
            .then(|| snapshot.latest_recovered_revision.clone())
            .flatten();
        let newer_known_recovery_hint = if snapshot.recovery_mode_enabled {
            snapshot
                .tracked_peers
                .iter()
                .filter_map(|peer| {
                    let known = peer_requester_latest_known_content(peer)?;
                    let known_content = rpc_content_info(known.clone());
                    let timestamp = self
                        .requester_revision_in_recovery_window(&known_content)
                        .ok()
                        .flatten()?;
                    let stored_matches_known = peer_requester_latest_stored_content(peer)
                        .is_some_and(|stored| stored.content_id == known.content_id);
                    (!stored_matches_known).then_some((known, timestamp))
                })
                .max_by_key(|(content, _)| {
                    self.revision_key(&content.content_id)
                        .unwrap_or((0, 0, 0, 0))
                })
        } else {
            None
        };

        Ok(Some(clirpc::StateLocalSummary {
            content: Some(clirpc::StateContentSummary {
                file_count: snapshot.file_count,
                total_size_bytes: snapshot.total_file_bytes,
                last_updated_at: snapshot.current_content.as_ref().map(|content| {
                    proto_timestamp_from_file_parts(
                        content.revision.created_at_secs,
                        content.revision.created_at_nanos,
                    )
                }),
                has_pending_update: snapshot.current_content.is_some()
                    && predicted_fresh_replicas_now < min_replicas_target,
            }),
            peers: Some(clirpc::StatePeerSummary {
                total_known,
                connected,
                storing_our_data,
                storing_latest_our_data,
                mutual_storage_peers,
                mean_mutual_storage_score_seconds: mean_score_seconds(&mutual_storage_scores),
                mirrored_peers,
                mirrored_total_size_bytes,
            }),
            durability: Some(clirpc::StateDurabilitySummary {
                predicted_fresh_replicas_now,
                predicted_min_replicas_target: min_replicas_target,
                predicted_replica_horizon: replica_horizon_points(&predicted_replica_horizon),
            }),
            recovery: Some(clirpc::StateRecoverySummary {
                recovery_mode_enabled: snapshot.recovery_mode_enabled,
                node_initialized_at: snapshot
                    .node_initialized_at
                    .map(|timestamp| proto_timestamp_from_parts(timestamp.0, timestamp.1))
                    .transpose()?,
                recovery_watermark_at: snapshot
                    .recovery_watermark
                    .map(|timestamp| proto_timestamp_from_parts(timestamp.0, timestamp.1))
                    .transpose()?,
                publish_blocked_reason,
                latest_recovered_content_id: latest_recovered_revision
                    .as_ref()
                    .map(|revision| revision.content_id.clone())
                    .unwrap_or_default(),
                latest_recovered_at: latest_recovered_revision
                    .as_ref()
                    .and_then(|revision| revision.created_at.clone()),
                newer_known_content_id: newer_known_recovery_hint
                    .as_ref()
                    .map(|(content, _)| content.content_id.clone())
                    .unwrap_or_default(),
                newer_known_at: newer_known_recovery_hint
                    .as_ref()
                    .map(|(_, timestamp)| proto_timestamp_from_parts(timestamp.0, timestamp.1))
                    .transpose()?,
            }),
        }))
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

    /// Build the local peer inventory response without dialing peers live.
    pub fn peers_response(&self) -> Result<clirpc::PeersResponse, Status> {
        Ok(clirpc::PeersResponse {
            peers: self
                .peer_inventory()?
                .into_iter()
                .map(|peer| clirpc::PeerInfo {
                    peer: Some(clirpc::Peer {
                        onion_service_id: peer.onion_service_id,
                    }),
                    status: proto_peer_status(peer.status),
                    pinned_by_us: peer.pinned_by_us,
                    pins_us: peer.pins_us,
                    has_storage: peer.has_storage,
                    score_seconds: peer.score_seconds,
                    score_measured_at: peer.score_measured_at,
                    stored_content_bytes: peer.stored_content_bytes,
                    latest_known_content_length: peer.latest_known_content_length,
                    latest_cached_content_length: peer.latest_cached_content_length,
                    stale_cache: peer.stale_cache,
                    storage_protection: proto_peer_storage_protection(peer.storage_protection),
                    tracked_only: peer.tracked_only,
                    last_live_at: peer.last_live_at,
                    last_failure_at: peer.last_failure_at,
                    last_error_class: peer.last_error_class,
                    last_error_message: peer.last_error_message,
                    consecutive_failures: peer.consecutive_failures,
                    next_retry_at: peer.next_retry_at,
                })
                .collect(),
        })
    }

    /// Build a live peer-storage snapshot for the configured peers.
    pub async fn get_peer_storage_response(
        &self,
    ) -> Result<clirpc::GetPeerStorageResponse, Status> {
        let mut storage_peers = Vec::new();

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

            // Probe the peer live so the peer-storage view reflects reachability
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
                    let _ =
                        self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned);
                    let _ = self.record_requester_revision_observation(&peer_public_key, &revision);
                    our_remaining_seconds = revision.requester_remaining_seconds;
                    our_content_synced = self.our_content_synced_with_peer(
                        revision.requester_latest_stored_content.as_ref(),
                    )?;
                } else {
                    let _ = self.note_peer_offline(&peer_onion);
                }
            } else {
                let _ = self.note_peer_offline(&peer_onion);
            }
            let (their_latest_known_content, their_latest_cached_content) =
                self.mirrored_peer_revision_state(&peer_public_key)?;

            storage_peers.push(clirpc::PeerStorageInfo {
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

        Ok(clirpc::GetPeerStorageResponse { storage_peers })
    }

    /// Build the replica-horizon report for our currently verified fresh replicas.
    fn replica_horizon(
        &self,
        storage_peers: &[clirpc::PeerStorageInfo],
        tracked_by_onion: &BTreeMap<String, storedpb::Peer>,
    ) -> Result<Vec<clirpc::ReplicaHorizonPoint>, Status> {
        let Some(current_content) = self.responder_content()? else {
            return Ok(Vec::new());
        };

        let expiry_seconds = storage_peers
            .iter()
            .filter(|contract| contract.online && contract.our_content_synced)
            .filter_map(|contract| {
                let peer_onion = contract.peer.as_ref()?.onion_service_id.clone();
                let tracked_peer = tracked_by_onion.get(&peer_onion)?;
                (tracked_peer.our_content_last_verified_content_id == current_content.content_id)
                    .then_some(if tracked_peer.pins_us {
                        None
                    } else {
                        Some(contract.our_remaining_seconds.max(0))
                    })
            })
            .collect::<Vec<_>>();

        Ok(replica_horizon_points(&expiry_seconds))
    }

    /// Build the derived storage view shown by the local CLI.
    pub async fn storage_info(&self) -> Result<clirpc::StorageInfo, Status> {
        let storage_peers = self.get_peer_storage_response().await?;
        let mut online_obligations = 0i64;
        let mut offline_obligations = 0i64;
        let mut expired_offline_obligations = 0i64;
        let tracked_peers = self.tracked_peers()?;
        let tracked_by_onion = tracked_peers
            .iter()
            .filter_map(|peer| {
                self.onion_from_public_key_bytes(&peer.onion_pubkey)
                    .ok()
                    .map(|peer_onion| (peer_onion, peer.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        let tracked_only_peers_count = i64::try_from(
            tracked_peers
                .iter()
                .filter(|peer| peer_is_tracked_only(peer))
                .count(),
        )
        .unwrap_or(i64::MAX);
        let mut contract_state_by_peer = BTreeMap::new();

        // Split mirrored-peer usage by live reachability and by whether the
        // peer has expired into best-effort storage from our perspective.
        for peer_storage in &storage_peers.storage_peers {
            let content_bytes = peer_storage.their_content_length.max(0);
            if peer_storage.online && peer_storage.our_content_synced {
                online_obligations = online_obligations.saturating_add(content_bytes);
            } else {
                offline_obligations = offline_obligations.saturating_add(content_bytes);
                if peer_storage.their_remaining_seconds < 0 {
                    expired_offline_obligations =
                        expired_offline_obligations.saturating_add(content_bytes);
                }
            }

            if let Some(peer_onion) = peer_storage
                .peer
                .as_ref()
                .map(|peer| peer.onion_service_id.as_str())
            {
                if let Ok(peer_public_key) = keys::public_key_from_onion_hostname(peer_onion) {
                    contract_state_by_peer.insert(
                        peer_public_key.as_bytes().to_vec(),
                        PeerStorageRuntimeState {
                            online: peer_storage.online,
                            our_content_synced: peer_storage.our_content_synced,
                        },
                    );
                }
            }
        }
        let storage_accounting =
            aggregate_storage_accounting(&self.mirrored_blob_usage()?, &contract_state_by_peer);

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
            pinned_peers_storage_bytes: storage_accounting.pinned_bytes,
            protected_peers_storage_bytes: storage_accounting.protected_bytes,
            disposable_peers_storage_bytes: storage_accounting.disposable_bytes,
            tracked_only_peers_count,
            offline_blocking_storage_bytes: storage_accounting.offline_blocking_bytes,
            reclaimable_peer_storage_bytes: storage_accounting.reclaimable_bytes,
            replica_horizon: self
                .replica_horizon(&storage_peers.storage_peers, &tracked_by_onion)?,
        })
    }

    /// Build the current background peer-maintenance plan.
    pub async fn background_maintenance_plan(&self) -> Result<BackgroundMaintenancePlan, Status> {
        let inventory = self.peer_inventory()?;
        let storage_peers = self.get_peer_storage_response().await?;
        let current_content = self.responder_content()?;
        let tracked_peers = self.tracked_peers()?;
        let tracked_by_onion = tracked_peers
            .into_iter()
            .filter_map(|peer| {
                self.onion_from_public_key_bytes(&peer.onion_pubkey)
                    .ok()
                    .map(|peer_onion| (peer_onion, peer))
            })
            .collect::<BTreeMap<_, _>>();
        let storage_by_onion = storage_peers
            .storage_peers
            .into_iter()
            .filter_map(|peer_storage| {
                let peer_onion = peer_storage.peer.as_ref()?.onion_service_id.clone();
                Some((peer_onion, peer_storage))
            })
            .collect::<BTreeMap<_, _>>();
        let fresh_replica_peers = storage_by_onion
            .iter()
            .filter_map(|(peer_onion, peer_storage)| {
                (peer_storage.online && peer_storage.our_content_synced)
                    .then_some(peer_onion.clone())
            })
            .collect::<BTreeSet<_>>();
        let fresh_replica_count = i64::try_from(fresh_replica_peers.len()).unwrap_or(i64::MAX);
        let min_replicas_target = self.storage_config.lock().unwrap().min_replicas.max(0);
        let missing_fresh_replicas = (min_replicas_target - fresh_replica_count).max(0);
        let missing_fresh_replicas = usize::try_from(missing_fresh_replicas).unwrap_or(usize::MAX);
        let publication_allowed = self.publish_blocked_reason()?.is_none();
        let mut action_by_onion = BTreeMap::<String, BackgroundMaintenancePeerAction>::new();
        for peer_onion in &fresh_replica_peers {
            action_by_onion.insert(
                peer_onion.clone(),
                BackgroundMaintenancePeerAction {
                    peer_onion: peer_onion.clone(),
                    propose: false,
                    check: true,
                },
            );
        }

        if publication_allowed {
            for peer in &inventory {
                let Some(peer_storage) = storage_by_onion.get(&peer.onion_service_id) else {
                    continue;
                };
                if !peer_storage.online {
                    continue;
                }
                if peer.stored_content_bytes <= 0 {
                    continue;
                }
                if peer_storage.our_content_synced && current_content.is_some() {
                    continue;
                }

                let action = action_by_onion
                    .entry(peer.onion_service_id.clone())
                    .or_insert_with(|| BackgroundMaintenancePeerAction {
                        peer_onion: peer.onion_service_id.clone(),
                        propose: false,
                        check: false,
                    });
                action.propose = true;
                action.check = true;
            }
        }

        if publication_allowed && missing_fresh_replicas > 0 {
            let now_secs = i64::try_from(self.clock.now().secs).unwrap_or(i64::MAX);
            let candidates = inventory
                .iter()
                .filter_map(|peer| {
                    let peer_storage = storage_by_onion.get(&peer.onion_service_id)?;
                    let tracked_peer = tracked_by_onion.get(&peer.onion_service_id)?;
                    if !peer_storage.online
                        || peer_storage.our_content_synced
                        || action_by_onion.contains_key(&peer.onion_service_id)
                    {
                        return None;
                    }
                    Some(PublicationCandidate {
                        peer_onion: peer.onion_service_id.clone(),
                        pinned_by_us: tracked_peer.pinned_by_us,
                        pins_us: tracked_peer.pins_us,
                        first_seen_at: optional_timestamp_parts(
                            tracked_peer.first_seen_at.as_ref(),
                        )
                        .unwrap_or((0, 0)),
                        successful_calls: tracked_peer.successful_calls,
                        failed_calls: tracked_peer.failed_calls,
                        stores_peer_data: peer.stored_content_bytes > 0,
                    })
                })
                .collect::<Vec<_>>();
            let mut rng = rand::thread_rng();
            for peer_onion in choose_publication_candidates(
                &candidates,
                missing_fresh_replicas,
                now_secs,
                &mut rng,
            ) {
                let action = action_by_onion
                    .entry(peer_onion.clone())
                    .or_insert_with(|| BackgroundMaintenancePeerAction {
                        peer_onion: peer_onion.clone(),
                        propose: false,
                        check: false,
                    });
                action.propose = true;
                action.check = true;
            }
        }

        let peer_actions = inventory
            .into_iter()
            .filter_map(|peer| action_by_onion.remove(&peer.onion_service_id))
            .filter(|action| action.propose || action.check)
            .collect();

        Ok(BackgroundMaintenancePlan {
            peer_actions,
            fresh_replica_count,
            min_replicas_target,
        })
    }

    /// Publish our current content to one peer and report the streamed
    /// progress updates for the caller.
    pub async fn publish_to_peer_updates(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::PublishToPeerUpdate>, Status> {
        self.ensure_owner_publication_allowed()?;
        self.retry_peer_operation(
            peer_onion,
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Proposal),
            || self.publish_to_peer_updates_once(peer_onion),
        )
        .await
    }

    /// Perform one proposal attempt against a peer without any outer retry
    /// loop.
    async fn publish_to_peer_updates_once(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::PublishToPeerUpdate>, Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let mut updates = vec![clirpc::PublishToPeerUpdate {
            state: clirpc::PeerStorageOperationState::ConnectingToPeer as i32,
            success: false,
            their_content_length: 0,
            their_content_downloaded_bytes: 0,
            our_content_length: 0,
            our_content_uploaded_bytes: 0,
            storage_result: clirpc::PublicationStorageResult::Unknown as i32,
        }];

        // Query the peer's live storage state before deciding what needs to
        // be synchronized in either direction.
        let policy = transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Proposal);
        let mut client = self
            .connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
            .await?;
        let mut revision = self
            .peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await?;
        self.record_requester_revision_observation(&peer_public_key, &revision)?;
        if let Some(recoverable_revision) = self.recoverable_requester_revision(&revision)? {
            info!(
                peer = %peer_onion,
                content_id = %content_id_hex(&recoverable_revision.content.content_id),
                timestamp_secs = recoverable_revision.timestamp.0,
                timestamp_nanos = recoverable_revision.timestamp.1,
                "running automatic recovery before publishing to a peer"
            );
            let recovery_update = self.run_recovery_pass().await?;
            info!(
                peer = %peer_onion,
                applied_versions = recovery_update.applied_versions,
                older_lineage_versions_found = recovery_update.older_lineage_versions_found,
                older_lineage_recoverable_versions_found = recovery_update
                    .older_lineage_recoverable_versions_found,
                "finished automatic recovery before publishing to a peer"
            );
            revision = self
                .peer_rpc_with_timeout(
                    peer_onion,
                    "get content revision",
                    policy.rpc_timeout,
                    client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                )
                .await?;
        }
        self.ensure_peer_revision_does_not_require_recovery(peer_onion, &revision)?;
        self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned)?;
        let their_content_length = self.mirrored_peer_content_length(&peer_public_key)?;
        let downloaded_their_content = 0;

        updates.push(clirpc::PublishToPeerUpdate {
            state: clirpc::PeerStorageOperationState::PublishingToPeer as i32,
            success: false,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length: 0,
            our_content_uploaded_bytes: 0,
            storage_result: clirpc::PublicationStorageResult::Unknown as i32,
        });

        // Upload our current revision only when the peer does not already hold
        // the exact same content identifier.
        let our_content = self.ensure_responder_content()?;
        let our_content_length = our_content.content_length;
        let mut uploaded_our_content = 0;
        let desired_content_id = our_content.content_id.clone();
        let mut peer_has_our_content = revision
            .requester_latest_stored_content
            .as_ref()
            .map(|content_info| content_info.content_id.clone());
        let mut retried_after_refresh = false;
        let mut publication_storage_result = clirpc::PublicationStorageResult::Unknown;
        while peer_has_our_content.as_ref() != Some(&desired_content_id) {
            let superseded_penalty =
                self.record_requester_advertisement_attempt(&peer_public_key, &our_content)?;
            if let Some(new_score) =
                self.adjust_peer_score_direct(&peer_public_key, -superseded_penalty)?
            {
                info!(
                    peer = %peer_onion,
                    superseded_pending_advertisement_penalty_seconds = superseded_penalty,
                    new_score_seconds = new_score,
                    "deducted score for one superseded undownloaded advertisement"
                );
            }
            let set_request = bbrpc::SetContentRevisionRequest {
                previous_requester_content: revision.requester_latest_known_content.clone(),
                requester_content: Some(our_content.clone()),
            };
            match self
                .peer_rpc_with_timeout(
                    peer_onion,
                    "set content revision",
                    policy.rpc_timeout,
                    client.set_content_revision(set_request),
                )
                .await
            {
                Ok(response) => {
                    publication_storage_result = proto_publication_storage_result(
                        bbrpc::SetContentRevisionStorageResult::try_from(response.storage_result)
                            .unwrap_or(bbrpc::SetContentRevisionStorageResult::Unknown),
                    );
                    if publication_storage_result
                        == clirpc::PublicationStorageResult::SidecarOnly
                    {
                        info!(
                            peer = %peer_onion,
                            our_content_length,
                            "peer accepted our sidecar update but did not cache mirrored bytes"
                        );
                    }
                    uploaded_our_content = our_content_length;
                    break;
                }
                Err(status)
                    if !retried_after_refresh
                        && matches!(
                            Self::set_content_revision_failure(&status)
                                .map(|failure| failure.reason()),
                            Some(
                                bbrpc::SetContentRevisionFailureReason::PreviousRequesterContentMismatch
                            )
                        ) =>
                {
                    info!(
                        peer = %peer_onion,
                        "peer requester revision changed during publication; refreshing before one retry"
                    );
                    revision = self
                        .peer_rpc_with_timeout(
                            peer_onion,
                            "get content revision",
                            policy.rpc_timeout,
                            client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                        )
                        .await?;
                    self.record_requester_revision_observation(&peer_public_key, &revision)?;
                    if let Some(recoverable_revision) =
                        self.recoverable_requester_revision(&revision)?
                    {
                        info!(
                            peer = %peer_onion,
                            content_id = %content_id_hex(&recoverable_revision.content.content_id),
                            timestamp_secs = recoverable_revision.timestamp.0,
                            timestamp_nanos = recoverable_revision.timestamp.1,
                            "running automatic recovery after a publication compare-and-swap mismatch"
                        );
                        let recovery_update = self.run_recovery_pass().await?;
                        info!(
                            peer = %peer_onion,
                            applied_versions = recovery_update.applied_versions,
                            older_lineage_versions_found = recovery_update
                                .older_lineage_versions_found,
                            older_lineage_recoverable_versions_found = recovery_update
                                .older_lineage_recoverable_versions_found,
                            "finished automatic recovery after a publication compare-and-swap mismatch"
                        );
                        revision = self
                            .peer_rpc_with_timeout(
                                peer_onion,
                                "get content revision",
                                policy.rpc_timeout,
                                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
                            )
                            .await?;
                    }
                    self.ensure_peer_revision_does_not_require_recovery(peer_onion, &revision)?;
                    self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned)?;
                    peer_has_our_content = revision
                        .requester_latest_stored_content
                        .as_ref()
                        .map(|content_info| content_info.content_id.clone());
                    retried_after_refresh = true;
                }
                Err(status) => return Err(status),
            }
        }
        self.maybe_exchange_peers_with_client(peer_onion, &mut client)
            .await?;

        updates.push(clirpc::PublishToPeerUpdate {
            state: clirpc::PeerStorageOperationState::SyncingContents as i32,
            success: false,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes: uploaded_our_content,
            storage_result: publication_storage_result as i32,
        });
        updates.push(clirpc::PublishToPeerUpdate {
            state: clirpc::PeerStorageOperationState::Completed as i32,
            success: true,
            their_content_length,
            their_content_downloaded_bytes: downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes: uploaded_our_content,
            storage_result: publication_storage_result as i32,
        });

        info!(
            peer = %peer_onion,
            their_content_length,
            their_content_downloaded_bytes = downloaded_their_content,
            our_content_length,
            our_content_uploaded_bytes = uploaded_our_content,
            peer_storage = %publication_storage_result.as_str_name(),
            "peer publication completed"
        );

        Ok(updates)
    }

    /// Verify one peer's stored copy of our content, update the peer score,
    /// and return the streamed
    /// progress updates that describe the check.
    pub async fn verify_peer_storage_updates(
        &self,
        peer_onion: &str,
    ) -> Result<Vec<clirpc::VerifyPeerStorageUpdate>, Status> {
        self.verify_peer_storage_updates_with_policy(
            peer_onion,
            transport::PeerRetryPolicy::for_operation(transport::PeerOperation::Check),
        )
        .await
    }

    /// Verify one peer under the provided retry and timeout policy.
    async fn verify_peer_storage_updates_with_policy(
        &self,
        peer_onion: &str,
        policy: transport::PeerRetryPolicy,
    ) -> Result<Vec<clirpc::VerifyPeerStorageUpdate>, Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let peer_was_tracked = self.is_tracked_peer(&peer_public_key)?;
        match self
            .retry_peer_operation(peer_onion, policy, || {
                self.verify_peer_storage_updates_once(peer_onion, policy)
            })
            .await
        {
            Ok(updates) => Ok(updates),
            Err(error) if transport::is_retryable_peer_status(&error) => {
                let our_content_length = self
                    .responder_content()?
                    .map(|content| content.content_length)
                    .unwrap_or(0);
                let new_score = if peer_was_tracked {
                    let _ = self.record_verified_our_content(&peer_public_key, None);
                    Some(self.update_peer_score(&peer_public_key, false)?)
                } else {
                    None
                };
                warn!(
                    peer = %peer_onion,
                    code = ?error.code(),
                    message = %error.message(),
                    new_score_seconds = new_score.unwrap_or_default(),
                    tracked = peer_was_tracked,
                    our_content_length,
                    "peer verification failed after retries"
                );
                Ok(vec![
                    clirpc::VerifyPeerStorageUpdate {
                        state: clirpc::PeerStorageOperationState::ConnectingToPeer as i32,
                        success: false,
                        our_content_length: 0,
                        our_content_section_offset: 0,
                        our_content_section_length: 0,
                    },
                    clirpc::VerifyPeerStorageUpdate {
                        state: clirpc::PeerStorageOperationState::PeerUnavailable as i32,
                        success: false,
                        our_content_length,
                        our_content_section_offset: 0,
                        our_content_section_length: 0,
                    },
                ])
            }
            Err(error) => Err(error),
        }
    }

    /// Perform one peer-storage verification attempt against a peer without
    /// any outer retry loop.
    async fn verify_peer_storage_updates_once(
        &self,
        peer_onion: &str,
        policy: transport::PeerRetryPolicy,
    ) -> Result<Vec<clirpc::VerifyPeerStorageUpdate>, Status> {
        if self.is_our_onion(peer_onion) {
            return Err(self.self_peer_error());
        }
        let peer_public_key = keys::public_key_from_onion_hostname(peer_onion)
            .map_err(|_| Status::invalid_argument("peer onion is invalid"))?;
        let peer_was_tracked = self.is_tracked_peer(&peer_public_key)?;
        let mut updates = vec![clirpc::VerifyPeerStorageUpdate {
            state: clirpc::PeerStorageOperationState::ConnectingToPeer as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        }];

        // Refresh the peer's advertised content before validating their copy of
        // our own revision.
        let mut client = if peer_was_tracked {
            self.connect_peer_client_with_timeout(peer_onion, policy.connect_timeout)
                .await?
        } else {
            self.probe_peer_client_with_timeout(peer_onion, policy.connect_timeout)
                .await?
        };
        let revision = self
            .peer_rpc_with_timeout(
                peer_onion,
                "get content revision",
                policy.rpc_timeout,
                client.get_content_revision(bbrpc::GetContentRevisionRequest {}),
            )
            .await?;
        if peer_was_tracked {
            self.record_remote_pin_claim(&peer_public_key, revision.requester_pinned)?;
            self.record_requester_revision_observation(&peer_public_key, &revision)?;
        }

        updates.push(clirpc::VerifyPeerStorageUpdate {
            state: clirpc::PeerStorageOperationState::VerifyingContent as i32,
            success: false,
            our_content_length: 0,
            our_content_section_offset: 0,
            our_content_section_length: 0,
        });

        let Some(our_content) = self.responder_content()? else {
            let new_score = if peer_was_tracked {
                self.record_verified_our_content(&peer_public_key, None)?;
                let new_score = self.update_peer_score(&peer_public_key, true)?;
                self.maybe_exchange_peers_with_client(peer_onion, &mut client)
                    .await?;
                Some(new_score)
            } else {
                None
            };
            updates.push(clirpc::VerifyPeerStorageUpdate {
                state: clirpc::PeerStorageOperationState::Completed as i32,
                success: true,
                our_content_length: 0,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            });
            debug!(
                peer = %peer_onion,
                success = true,
                new_score_seconds = new_score.unwrap_or_default(),
                tracked = peer_was_tracked,
                "peer verification completed without local content"
            );
            return Ok(updates);
        };

        if revision
            .requester_latest_stored_content
            .as_ref()
            .map(|content_info| content_info.content_id.as_slice())
            != Some(our_content.content_id.as_slice())
        {
            let new_score = if peer_was_tracked {
                self.record_verified_our_content(&peer_public_key, None)?;
                let new_score = self.update_peer_score(&peer_public_key, false)?;
                self.maybe_exchange_peers_with_client(peer_onion, &mut client)
                    .await?;
                Some(new_score)
            } else {
                None
            };
            updates.push(clirpc::VerifyPeerStorageUpdate {
                state: clirpc::PeerStorageOperationState::PeerMissingOurContent as i32,
                success: false,
                our_content_length: our_content.content_length,
                our_content_section_offset: 0,
                our_content_section_length: 0,
            });
            warn!(
                peer = %peer_onion,
                success = false,
                new_score_seconds = new_score.unwrap_or_default(),
                our_content_length = our_content.content_length,
                tracked = peer_was_tracked,
                "peer verification found our revision missing"
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
                    length: i64::try_from(section_length).unwrap_or(i64::MAX),
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
                    if raw_bytes.value
                        == local_blob[section_offset..section_offset + section_length]
            );
        let new_score = if peer_was_tracked {
            if passed {
                self.record_verified_our_content(&peer_public_key, Some(&our_content.content_id))?;
            } else {
                self.record_verified_our_content(&peer_public_key, None)?;
            }
            let new_score = self.update_peer_score(&peer_public_key, passed)?;
            self.maybe_exchange_peers_with_client(peer_onion, &mut client)
                .await?;
            Some(new_score)
        } else {
            None
        };
        updates.push(clirpc::VerifyPeerStorageUpdate {
            state: if passed {
                clirpc::PeerStorageOperationState::Completed as i32
            } else {
                clirpc::PeerStorageOperationState::InvalidContentReturned as i32
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
                new_score_seconds = new_score.unwrap_or_default(),
                our_content_length = our_content.content_length,
                section_offset,
                section_length,
                tracked = peer_was_tracked,
                "peer verification completed"
            );
        } else {
            warn!(
                peer = %peer_onion,
                success = false,
                new_score_seconds = new_score.unwrap_or_default(),
                our_content_length = our_content.content_length,
                section_offset,
                section_length,
                tracked = peer_was_tracked,
                "peer verification returned invalid content"
            );
        }

        Ok(updates)
    }

    /// Download one older-lineage recovery candidate from any peer that still serves it.
    async fn download_recovery_candidate_blob(
        &self,
        candidate: &RecoveryCandidate,
    ) -> Result<(Vec<u8>, i64, String), Status> {
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
                    let downloaded_bytes = i64::try_from(blob.len()).unwrap_or(i64::MAX);
                    return Ok((blob, downloaded_bytes, source_peer.clone()));
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

        Err(last_error.unwrap_or_else(|| {
            Status::not_found("no peer could serve the requested recovery revision")
        }))
    }

    /// Apply one recovery candidate by either restoring the missing active blob
    /// or merging one older-lineage revision into the active local file set.
    async fn apply_recovery_candidate(
        &self,
        candidate: &RecoveryCandidate,
    ) -> Result<(storage::RecoveryMergeOutcome, i64), Status> {
        let current_matches_candidate = self.with_store(|store| {
            Ok(store
                .current_content()
                .is_some_and(|current| current.content_id == candidate.content_id))
        })?;
        let current_blob_missing = if current_matches_candidate {
            self.current_content_needs_restore_from_peer(&candidate.content_id)?
        } else {
            false
        };
        let restores_missing_current_blob = current_matches_candidate && current_blob_missing;
        let (blob, downloaded_bytes, source_peer) =
            if current_matches_candidate && !current_blob_missing {
                (
                    self.with_store(|store| store.current_blob())?,
                    0,
                    String::new(),
                )
            } else {
                self.download_recovery_candidate_blob(candidate).await?
            };

        if restores_missing_current_blob {
            self.with_store(|store| store.restore_current_content_blob(&blob))?;
            info!(
                peer = %source_peer,
                content_id = %content_id_hex(&candidate.content_id),
                content_length = candidate.content_length,
                downloaded_bytes,
                "restored the missing active local content blob from a peer"
            );
            return Ok((storage::RecoveryMergeOutcome::default(), downloaded_bytes));
        }

        let recovered_files = self.with_store(|store| store.decode_revision_files(&blob))?;
        let recovered_timestamp = (
            i64::try_from(candidate.key.1).unwrap_or(i64::MAX),
            i64::from(candidate.key.2),
        );
        let merge_outcome = self.with_store(|store| {
            store.merge_recovered_revision_files(
                recovered_files,
                recovered_timestamp,
                &candidate.content_id,
            )
        })?;
        let recovered_created_at =
            proto_timestamp_from_parts(recovered_timestamp.0, recovered_timestamp.1)?;
        self.with_store(|store| {
            store.record_recovered_revision(storedpb::RecoveredRevision {
                content_id: candidate.content_id.clone(),
                created_at: Some(recovered_created_at),
            })
        })?;
        info!(
            peer = %source_peer,
            content_id = %content_id_hex(&candidate.content_id),
            content_length = candidate.content_length,
            downloaded_bytes,
            added_files = merge_outcome.added_files,
            renamed_files = merge_outcome.renamed_files,
            unchanged_files = merge_outcome.unchanged_files,
            "merged one recovered older-lineage revision into the local file set"
        );
        Ok((merge_outcome, downloaded_bytes))
    }

    /// Scan known peers, restore the missing active blob when necessary, and
    /// merge every downloadable older-lineage revision in timestamp order.
    pub async fn run_recovery_pass(&self) -> Result<RecoveryPassSummary, Status> {
        let mut known_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut older_lineage_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut recoverable_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut current_restore_candidates = BTreeMap::<Vec<u8>, RecoveryCandidate>::new();
        let mut peers_with_any_versions = 0i64;

        for peer_onion in self.known_peers() {
            if self.is_our_onion(&peer_onion) {
                continue;
            }
            let revision = match self.recovery_revision_from_peer(&peer_onion).await {
                Ok(revision) => revision,
                Err(error) => {
                    warn!(peer = %peer_onion, %error, "recovery probe from peer failed");
                    continue;
                }
            };

            let mut peer_had_versions = false;
            let mut peer_candidates = Vec::new();
            if let Some(content_info) = revision.requester_latest_known_content.clone() {
                peer_candidates.push(content_info);
            }
            if let Some(content_info) = revision.requester_latest_stored_content.clone() {
                if peer_candidates
                    .iter()
                    .all(|candidate| candidate.content_id != content_info.content_id)
                {
                    peer_candidates.push(content_info);
                }
            }

            for content_info in peer_candidates {
                let key = match self.revision_key(&content_info.content_id) {
                    Ok(key) => key,
                    Err(error) => {
                        warn!(
                            peer = %peer_onion,
                            content_id = %content_id_hex(&content_info.content_id),
                            %error,
                            "ignored one invalid recovery candidate"
                        );
                        continue;
                    }
                };
                peer_had_versions = true;
                known_candidates
                    .entry(content_info.content_id.clone())
                    .and_modify(|candidate| {
                        if !candidate.peers.contains(&peer_onion) {
                            candidate.peers.push(peer_onion.clone());
                        }
                    })
                    .or_insert_with(|| RecoveryCandidate {
                        key,
                        content_id: content_info.content_id.clone(),
                        content_length: content_info.content_length,
                        peers: vec![peer_onion.clone()],
                    });

                if self
                    .requester_revision_in_recovery_window(&content_info)?
                    .is_some()
                {
                    older_lineage_candidates
                        .entry(content_info.content_id.clone())
                        .and_modify(|candidate| {
                            if !candidate.peers.contains(&peer_onion) {
                                candidate.peers.push(peer_onion.clone());
                            }
                        })
                        .or_insert_with(|| RecoveryCandidate {
                            key,
                            content_id: content_info.content_id.clone(),
                            content_length: content_info.content_length,
                            peers: vec![peer_onion.clone()],
                        });
                }
            }

            if let Some(content_info) = revision.requester_latest_stored_content {
                let restores_missing_current_blob =
                    self.current_content_needs_restore_from_peer(&content_info.content_id)?;
                let key = self.revision_key(&content_info.content_id)?;
                let content_id = content_info.content_id.clone();
                let content_length = content_info.content_length;
                if self
                    .requester_revision_in_recovery_window(&content_info)?
                    .is_some()
                {
                    recoverable_candidates
                        .entry(content_id.clone())
                        .and_modify(|candidate| {
                            if !candidate.peers.contains(&peer_onion) {
                                candidate.peers.push(peer_onion.clone());
                            }
                        })
                        .or_insert_with(|| RecoveryCandidate {
                            key: key.clone(),
                            content_id: content_id.clone(),
                            content_length,
                            peers: vec![peer_onion.clone()],
                        });
                }
                if restores_missing_current_blob {
                    current_restore_candidates
                        .entry(content_id.clone())
                        .and_modify(|candidate| {
                            if !candidate.peers.contains(&peer_onion) {
                                candidate.peers.push(peer_onion.clone());
                            }
                        })
                        .or_insert_with(|| RecoveryCandidate {
                            key: key.clone(),
                            content_id: content_id.clone(),
                            content_length,
                            peers: vec![peer_onion.clone()],
                        });
                }
            }

            if peer_had_versions {
                peers_with_any_versions = peers_with_any_versions.saturating_add(1);
            }
        }

        let mut summary = RecoveryPassAccumulator {
            total_versions_found: i64::try_from(known_candidates.len()).unwrap_or(i64::MAX),
            peers_with_any_versions,
            older_lineage_versions_found: i64::try_from(older_lineage_candidates.len())
                .unwrap_or(i64::MAX),
            older_lineage_recoverable_versions_found: i64::try_from(recoverable_candidates.len())
                .unwrap_or(i64::MAX),
            newest_found: known_candidates
                .values()
                .max_by_key(|candidate| candidate.key)
                .cloned(),
            ..Default::default()
        };
        let newest_recoverable_key = recoverable_candidates
            .values()
            .map(|candidate| candidate.key)
            .max();
        if let Some(newest_known_only) = older_lineage_candidates
            .values()
            .filter(|candidate| Some(candidate.key) > newest_recoverable_key)
            .max_by_key(|candidate| candidate.key)
        {
            info!(
                content_id = %content_id_hex(&newest_known_only.content_id),
                timestamp_secs = newest_known_only.key.1,
                timestamp_nanos = newest_known_only.key.2,
                peer_count = newest_known_only.peers.len(),
                "recovery found a newer requester revision that peers know about but do not currently store"
            );
        }
        let mut applicable_candidates = recoverable_candidates.clone();
        for (content_id, candidate) in current_restore_candidates {
            applicable_candidates.entry(content_id).or_insert(candidate);
        }
        let mut sorted_recoverable_candidates =
            applicable_candidates.values().cloned().collect::<Vec<_>>();
        sorted_recoverable_candidates.sort_by_key(|candidate| candidate.key);

        for candidate in sorted_recoverable_candidates {
            match self.apply_recovery_candidate(&candidate).await {
                Ok((merge_outcome, downloaded_bytes)) => {
                    summary.applied_versions = summary.applied_versions.saturating_add(1);
                    summary.downloaded_bytes =
                        summary.downloaded_bytes.saturating_add(downloaded_bytes);
                    summary.added_files = summary
                        .added_files
                        .saturating_add(merge_outcome.added_files);
                    summary.renamed_files = summary
                        .renamed_files
                        .saturating_add(merge_outcome.renamed_files);
                    summary.unchanged_files = summary
                        .unchanged_files
                        .saturating_add(merge_outcome.unchanged_files);
                    summary.latest_applied = Some(candidate.clone());
                }
                Err(error) => {
                    warn!(
                        content_id = %content_id_hex(&candidate.content_id),
                        %error,
                        "skipped one recoverable revision after download or merge failure"
                    );
                }
            }
        }

        if let Some(reason) = self.publish_blocked_reason()? {
            warn!(reason = %reason, "recovery left local publication blocked");
            summary.publication_blocked_reason = Some(reason);
        }

        Ok(RecoveryPassSummary {
            total_versions_found: summary.total_versions_found,
            peers_with_any_versions: summary.peers_with_any_versions,
            older_lineage_versions_found: summary.older_lineage_versions_found,
            older_lineage_recoverable_versions_found: summary
                .older_lineage_recoverable_versions_found,
            applied_versions: summary.applied_versions,
            downloaded_bytes: summary.downloaded_bytes,
            added_files: summary.added_files,
            renamed_files: summary.renamed_files,
            unchanged_files: summary.unchanged_files,
            newest_found_content_id: summary
                .newest_found
                .as_ref()
                .map(|candidate| candidate.content_id.clone())
                .unwrap_or_default(),
            newest_found_ts: summary
                .newest_found
                .as_ref()
                .map(|candidate| i64::try_from(candidate.key.1).unwrap_or(i64::MAX))
                .unwrap_or(0),
            newest_found_ts_ns: summary
                .newest_found
                .as_ref()
                .map(|candidate| i64::from(candidate.key.2))
                .unwrap_or(0),
            latest_applied_content_id: summary
                .latest_applied
                .as_ref()
                .map(|candidate| candidate.content_id.clone())
                .unwrap_or_default(),
            latest_applied_ts: summary
                .latest_applied
                .as_ref()
                .map(|candidate| i64::try_from(candidate.key.1).unwrap_or(i64::MAX))
                .unwrap_or(0),
            latest_applied_ts_ns: summary
                .latest_applied
                .as_ref()
                .map(|candidate| i64::from(candidate.key.2))
                .unwrap_or(0),
            publication_blocked_reason: summary.publication_blocked_reason.unwrap_or_default(),
        })
    }
}

/// Read one streamed local file upload into memory.
async fn collect_set_file_upload(
    mut stream: tonic::Streaming<clirpc::SetFileChunk>,
) -> Result<PlainFile, Status> {
    let first = stream
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("file upload stream is empty"))?;
    let info = match first.chunk {
        Some(clirpc::set_file_chunk::Chunk::File(info)) => info,
        Some(clirpc::set_file_chunk::Chunk::Data(_)) => {
            return Err(Status::invalid_argument(
                "file metadata must be the first upload chunk",
            ));
        }
        None => {
            return Err(Status::invalid_argument("file upload chunk is empty"));
        }
    };
    if info.name.is_empty() {
        return Err(Status::invalid_argument("file name is required"));
    }
    if info.size_bytes < 0 {
        return Err(Status::invalid_argument("file size must be non-negative"));
    }
    let expected_len = usize::try_from(info.size_bytes)
        .map_err(|_| Status::invalid_argument("file size is too large"))?;
    let (modified_at_secs, modified_at_nanos) = timestamp_parts(info.modified_at.as_ref())?;

    let mut data = Vec::with_capacity(expected_len.min(LOCAL_CLI_FILE_CHUNK_BYTES));
    while let Some(chunk) = stream.message().await? {
        match chunk.chunk {
            Some(clirpc::set_file_chunk::Chunk::Data(bytes)) => {
                data.extend_from_slice(&bytes);
            }
            Some(clirpc::set_file_chunk::Chunk::File(_)) => {
                return Err(Status::invalid_argument(
                    "file metadata must appear only once per upload",
                ));
            }
            None => {
                return Err(Status::invalid_argument("file upload chunk is empty"));
            }
        }
    }

    if data.len() != expected_len {
        return Err(Status::invalid_argument(
            "file size does not match streamed payload",
        ));
    }

    Ok(PlainFile {
        name: info.name,
        data,
        modified_at_secs,
        modified_at_nanos,
    })
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

    /// Store one plaintext file as a unary helper.
    pub async fn set_file(
        &self,
        request: tonic::Request<clirpc::SetFileRequest>,
    ) -> Result<tonic::Response<clirpc::SetFileResponse>, tonic::Status> {
        self.node.ensure_local_file_mutations_allowed()?;
        let request = request.into_inner();
        let file = request
            .file
            .ok_or_else(|| Status::invalid_argument("file is required"))?;
        if file.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }
        let modified_at = file
            .modified_at
            .unwrap_or_else(|| proto_timestamp_from_parts(0, 0).expect("zero timestamp is valid"));
        let (modified_at_secs, modified_at_nanos) = timestamp_parts(Some(&modified_at))?;
        self.node.with_store(|store| {
            store.set_file_with_modified_at(
                &file.name,
                file.data,
                modified_at_secs,
                modified_at_nanos,
            )
        })?;
        Ok(Response::new(clirpc::SetFileResponse {}))
    }
}

#[tonic::async_trait]
impl clirpc::barter_backup_client_server::BarterBackupClient for CliService {
    /// TimerInterceptStream is the streaming response for hidden timer intercepts.
    type TimerInterceptStream = Pin<
        Box<dyn Stream<Item = Result<clirpc::TimerInterceptEvent, tonic::Status>> + Send + 'static>,
    >;

    /// GetFileStreamStream is the streamed plaintext file-download response.
    type GetFileStreamStream =
        Pin<Box<dyn Stream<Item = Result<clirpc::GetFileChunk, tonic::Status>> + Send + 'static>>;

    /// PublishToPeerStream is the streaming response for peer publication.
    type PublishToPeerStream = Pin<
        Box<dyn Stream<Item = Result<clirpc::PublishToPeerUpdate, tonic::Status>> + Send + 'static>,
    >;

    /// VerifyPeerStorageStream is the streaming response for peer verification.
    type VerifyPeerStorageStream = Pin<
        Box<
            dyn Stream<Item = Result<clirpc::VerifyPeerStorageUpdate, tonic::Status>>
                + Send
                + 'static,
        >,
    >;

    async fn state(
        &self,
        _request: tonic::Request<clirpc::StateRequest>,
    ) -> Result<tonic::Response<clirpc::StateResponse>, tonic::Status> {
        Ok(Response::new(clirpc::StateResponse {
            storage_initialized: true,
            server_onion: self.node.address().to_string(),
            uptime_seconds: self.node.uptime_seconds(),
            peer_runtime_state: clirpc::PeerRuntimeState::Unknown as i32,
            peer_runtime_error: String::new(),
            self_peer_check_state: clirpc::SelfPeerCheckState::Unknown as i32,
            self_peer_check_error: String::new(),
            local_summary: self.node.local_state_summary()?,
        }))
    }

    async fn get_test_time(
        &self,
        _request: tonic::Request<clirpc::GetTestTimeRequest>,
    ) -> Result<tonic::Response<clirpc::GetTestTimeResponse>, tonic::Status> {
        Err(Status::unimplemented(
            "test clock control is only supported by the daemon",
        ))
    }

    async fn set_test_time(
        &self,
        _request: tonic::Request<clirpc::SetTestTimeRequest>,
    ) -> Result<tonic::Response<clirpc::SetTestTimeResponse>, tonic::Status> {
        Err(Status::unimplemented(
            "test clock control is only supported by the daemon",
        ))
    }

    async fn advance_test_time(
        &self,
        _request: tonic::Request<clirpc::AdvanceTestTimeRequest>,
    ) -> Result<tonic::Response<clirpc::AdvanceTestTimeResponse>, tonic::Status> {
        Err(Status::unimplemented(
            "test clock control is only supported by the daemon",
        ))
    }

    async fn timer_intercept(
        &self,
        _request: tonic::Request<clirpc::TimerInterceptRequest>,
    ) -> Result<tonic::Response<Self::TimerInterceptStream>, tonic::Status> {
        Err(Status::unimplemented(
            "test clock control is only supported by the daemon",
        ))
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

        self.node.connect_known_peer(&peer.onion_service_id).await?;
        Ok(Response::new(clirpc::ConnectPeerResponse {}))
    }

    async fn pin_peer(
        &self,
        request: tonic::Request<clirpc::PinPeerRequest>,
    ) -> Result<tonic::Response<clirpc::PinPeerResponse>, tonic::Status> {
        let request = request.into_inner();
        let peer = request
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }

        self.node.pin_peer(&peer.onion_service_id)?;
        Ok(Response::new(clirpc::PinPeerResponse {}))
    }

    async fn unpin_peer(
        &self,
        request: tonic::Request<clirpc::UnpinPeerRequest>,
    ) -> Result<tonic::Response<clirpc::UnpinPeerResponse>, tonic::Status> {
        let request = request.into_inner();
        let peer = request
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }

        self.node.unpin_peer(&peer.onion_service_id)?;
        Ok(Response::new(clirpc::UnpinPeerResponse {}))
    }

    async fn peers(
        &self,
        _request: tonic::Request<clirpc::PeersRequest>,
    ) -> Result<tonic::Response<clirpc::PeersResponse>, tonic::Status> {
        Ok(Response::new(self.node.peers_response()?))
    }

    async fn export_built_in_peers(
        &self,
        _request: tonic::Request<clirpc::ExportBuiltInPeersRequest>,
    ) -> Result<tonic::Response<clirpc::ExportBuiltInPeersResponse>, tonic::Status> {
        Ok(Response::new(clirpc::ExportBuiltInPeersResponse {
            rust_source: self.node.export_built_in_peer_source().await?,
        }))
    }

    async fn set_file_stream(
        &self,
        request: tonic::Request<tonic::Streaming<clirpc::SetFileChunk>>,
    ) -> Result<tonic::Response<clirpc::SetFileResponse>, tonic::Status> {
        self.node.ensure_local_file_mutations_allowed()?;
        let file = collect_set_file_upload(request.into_inner()).await?;
        self.node.with_store(|store| {
            store.set_file_with_modified_at(
                &file.name,
                file.data,
                file.modified_at_secs,
                file.modified_at_nanos,
            )
        })?;
        Ok(Response::new(clirpc::SetFileResponse {}))
    }

    async fn delete_file(
        &self,
        request: tonic::Request<clirpc::DeleteFileRequest>,
    ) -> Result<tonic::Response<clirpc::DeleteFileResponse>, tonic::Status> {
        self.node.ensure_local_file_mutations_allowed()?;
        let request = request.into_inner();
        if request.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }

        self.node
            .with_store(|store| store.delete_file(&request.name))?;
        info!(file = %request.name, "deleted a local file from the active content set");
        Ok(Response::new(clirpc::DeleteFileResponse {}))
    }

    async fn get_file_stream(
        &self,
        request: tonic::Request<clirpc::GetFileRequest>,
    ) -> Result<tonic::Response<Self::GetFileStreamStream>, tonic::Status> {
        let request = request.into_inner();
        if request.name.is_empty() {
            return Err(Status::invalid_argument("file name is required"));
        }

        let file = self
            .node
            .with_store(|store| store.get_plain_file(&request.name))?;
        Ok(Response::new(Box::pin(stream::iter(get_file_chunks(file)))))
    }

    async fn list_files(
        &self,
        _request: tonic::Request<clirpc::ListFilesRequest>,
    ) -> Result<tonic::Response<clirpc::ListFilesResponse>, tonic::Status> {
        let files = self.node.with_store(|store| Ok(store.list_file_info()))?;
        Ok(Response::new(clirpc::ListFilesResponse {
            file: files.into_iter().map(rpc_file_info).collect(),
        }))
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
            resource_policy: Some(resource_policy()),
        }))
    }

    async fn get_peer_storage(
        &self,
        _request: tonic::Request<clirpc::GetPeerStorageRequest>,
    ) -> Result<tonic::Response<clirpc::GetPeerStorageResponse>, tonic::Status> {
        Ok(Response::new(self.node.get_peer_storage_response().await?))
    }

    async fn publish_to_peer(
        &self,
        request: tonic::Request<clirpc::PublishToPeerRequest>,
    ) -> Result<tonic::Response<Self::PublishToPeerStream>, tonic::Status> {
        let peer = request
            .into_inner()
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }
        let updates = self
            .node
            .publish_to_peer_updates(&peer.onion_service_id)
            .await?
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();

        Ok(Response::new(Box::pin(stream::iter(updates))))
    }

    async fn verify_peer_storage(
        &self,
        request: tonic::Request<clirpc::VerifyPeerStorageRequest>,
    ) -> Result<tonic::Response<Self::VerifyPeerStorageStream>, tonic::Status> {
        let peer = request
            .into_inner()
            .peer
            .ok_or_else(|| Status::invalid_argument("peer is required"))?;
        if peer.onion_service_id.is_empty() {
            return Err(Status::invalid_argument("peer onion is required"));
        }
        let updates = self
            .node
            .verify_peer_storage_updates(&peer.onion_service_id)
            .await?
            .into_iter()
            .map(Ok)
            .collect::<Vec<_>>();

        Ok(Response::new(Box::pin(stream::iter(updates))))
    }

    async fn init_complete(
        &self,
        _request: tonic::Request<clirpc::InitCompleteRequest>,
    ) -> Result<tonic::Response<clirpc::InitCompleteResponse>, tonic::Status> {
        self.node.complete_initialization()?;
        Ok(Response::new(clirpc::InitCompleteResponse {}))
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
        self.node
            .note_authenticated_inbound_peer_contact(&peer_identity)?;
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
        self.node
            .note_authenticated_inbound_peer_contact(&peer_identity)?;
        let request = request.into_inner();
        for peer in request.peers {
            let public_key = match ed25519_dalek::PublicKey::from_bytes(&peer.onion_pubkey) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
            if self.node.is_our_public_key(&public_key) {
                continue;
            }
            let peer_onion = keys::onion_hostname_from_public_key(&public_key);
            if let Err(error) = self
                .node
                .add_known_peer_with_origin(&peer_onion, peer_origin_code(false, false))
            {
                debug!(peer = %peer_onion, %error, "skipped discovered peer during peer exchange");
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
            self.node
                .note_authenticated_inbound_peer_contact(peer_identity)?;
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
        let requester_remaining_seconds = peer_identity
            .as_ref()
            .map(|peer_identity| self.node.peer_score_state(&peer_identity.public_key))
            .transpose()?
            .map(|(score_seconds, _)| score_seconds)
            .unwrap_or(0);
        let requester_pinned = peer_identity
            .as_ref()
            .map(|peer_identity| self.node.is_peer_pinned_by_us(&peer_identity.public_key))
            .transpose()?
            .unwrap_or(false);
        Ok(Response::new(bbrpc::GetContentRevisionResponse {
            requester_latest_stored_content: requester_content,
            requester_remaining_seconds,
            requester_latest_known_content,
            requester_pinned,
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
        self.node
            .note_authenticated_inbound_peer_contact(&peer_identity)?;
        let request = request.into_inner();
        let previous_requester_content = request.previous_requester_content;
        let requester_content = request.requester_content;
        if let Some(content_info) = previous_requester_content.as_ref() {
            validate_peer_content_info(content_info)?;
        }
        let requester_content = requester_content
            .ok_or_else(|| Status::invalid_argument("requester_content must be set"))?;
        validate_peer_content_info(&requester_content)?;
        let responder_latest_known = self
            .node
            .requester_latest_known_content(&peer_identity.public_key)?;
        if previous_requester_content != responder_latest_known {
            return Err(Node::set_content_revision_failure_status(
                bbrpc::SetContentRevisionFailureReason::PreviousRequesterContentMismatch,
                "previous_requester_content did not match the responder's latest known requester revision",
            ));
        }

        let storage_result = self
            .node
            .sync_peer_content_info(
                &peer_identity.onion_address,
                &peer_identity.public_key,
                Some(&requester_content),
            )
            .await?;

        Ok(Response::new(bbrpc::SetContentRevisionResponse {
            storage_result: match storage_result {
                SyncPeerContentResult::MirroredBytesCached => {
                    bbrpc::SetContentRevisionStorageResult::MirroredBytesCached as i32
                }
                SyncPeerContentResult::SidecarOnly => {
                    bbrpc::SetContentRevisionStorageResult::SidecarOnly as i32
                }
            },
        }))
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
            self.node
                .note_authenticated_inbound_peer_contact(peer_identity)?;
        }
        let request = request.into_inner();
        validate_peer_content_id(&request.content_id)?;
        if request.offset < 0 {
            return Err(Status::invalid_argument("offset must be non-negative"));
        }
        if request.length < 0 {
            return Err(Status::invalid_argument("length must be non-negative"));
        }
        if !request.reference_content_id.is_empty() {
            return Err(Status::invalid_argument(
                "reference_content_id is not supported",
            ));
        }

        let offset = usize::try_from(request.offset)
            .map_err(|_| Status::invalid_argument("offset is too large"))?;
        let requested_length = usize::try_from(request.length)
            .map_err(|_| Status::invalid_argument("length is too large"))?;
        let current_content_id = self.node.with_store(|store| {
            Ok(store
                .current_content_id()
                .map(|content_id| content_id.to_vec()))
        })?;
        let serves_current_content = current_content_id
            .as_ref()
            .is_some_and(|content_id| content_id.as_slice() == request.content_id.as_slice());
        let serves_requester_content = peer_identity
            .as_ref()
            .map(|peer_identity| self.node.requester_content(&peer_identity.public_key))
            .transpose()?
            .flatten()
            .is_some_and(|content_info| content_info.content_id == request.content_id);
        let allowed = serves_current_content || serves_requester_content;
        if !allowed {
            return Err(Status::not_found("content not found"));
        }

        if serves_current_content || serves_requester_content {
            if let Some(peer_identity) = peer_identity.as_ref() {
                if let Some(latency_seconds) = self.node.record_requester_advertised_download(
                    &peer_identity.public_key,
                    &request.content_id,
                )? {
                    if let Some(new_score) = self
                        .node
                        .adjust_peer_score_direct(&peer_identity.public_key, -latency_seconds)?
                    {
                        info!(
                            peer = %peer_identity.onion_address,
                            content_id = %content_id_hex(&request.content_id),
                            download_delay_seconds = latency_seconds,
                            new_score_seconds = new_score,
                            "deducted score for delayed pickup of advertised content"
                        );
                    }
                }
            }
        }

        let blob = if serves_current_content {
            self.node.with_store(|store| store.current_blob())?
        } else {
            self.node
                .with_store(|store| store.read_mirrored_blob(&request.content_id))?
        };
        if offset > blob.len() {
            return Err(Status::out_of_range("offset is past the end of the blob"));
        }
        if requested_length > transport::MAX_PEER_CONTENT_BYTES {
            return Err(Status::invalid_argument("length is too large"));
        }

        let sha256 = Sha256::digest(&blob).to_vec();
        let section_end = offset.saturating_add(requested_length).min(blob.len());
        let raw_bytes = bbrpc::RawBytes {
            value: blob[offset..section_end].to_vec(),
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
        StorageError::LocalContentTooLarge => {
            Status::resource_exhausted("current shared content exceeds the fixed 4 MiB limit")
        }
        StorageError::RecoveryRequired(message) => Status::failed_precondition(message),
        other => Status::new(Code::Internal, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
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

    /// CountingFilesystem counts peer-sidecar writes while delegating storage.
    struct CountingFilesystem {
        inner: Arc<dyn Filesystem>,
        peer_state_writes: AtomicUsize,
    }

    impl CountingFilesystem {
        /// Return the number of peer-sidecar writes observed so far.
        fn peer_state_writes(&self) -> usize {
            self.peer_state_writes.load(Ordering::SeqCst)
        }
    }

    /// ReadCountingFilesystem counts file reads while delegating storage.
    struct ReadCountingFilesystem {
        inner: Arc<dyn Filesystem>,
        reads: AtomicUsize,
    }

    impl ReadCountingFilesystem {
        /// Reset the counted read total to zero.
        fn reset_reads(&self) {
            self.reads.store(0, Ordering::SeqCst);
        }

        /// Return the number of reads observed so far.
        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl Filesystem for ReadCountingFilesystem {
        fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read(name)
        }

        fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
            self.inner.write_atomic(name, data)
        }

        fn remove(&self, name: &str) -> Result<(), StorageError> {
            self.inner.remove(name)
        }

        fn list(&self) -> Result<Vec<String>, StorageError> {
            self.inner.list()
        }
    }

    impl Filesystem for CountingFilesystem {
        fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read(name)
        }

        fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
            if name == ".peer-state.v1" {
                self.peer_state_writes.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.write_atomic(name, data)
        }

        fn remove(&self, name: &str) -> Result<(), StorageError> {
            self.inner.remove(name)
        }

        fn list(&self) -> Result<Vec<String>, StorageError> {
            self.inner.list()
        }
    }

    /// Wait until the supplied predicate becomes true.
    async fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(predicate(), "timed out waiting for condition");
    }

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

    /// BarterBackupClientCompatExt rebuilds removed unary helpers on top of streams for tests.
    #[async_trait]
    trait BarterBackupClientCompatExt {
        async fn set_file(
            &mut self,
            request: clirpc::SetFileRequest,
        ) -> Result<Response<clirpc::SetFileResponse>, Status>;

        async fn get_file(
            &mut self,
            request: clirpc::GetFileRequest,
        ) -> Result<Response<clirpc::GetFileResponse>, Status>;
    }

    #[async_trait]
    impl BarterBackupClientCompatExt for BarterBackupClientClient<tonic::transport::Channel> {
        async fn set_file(
            &mut self,
            request: clirpc::SetFileRequest,
        ) -> Result<Response<clirpc::SetFileResponse>, Status> {
            let file = request
                .file
                .ok_or_else(|| Status::invalid_argument("file is required"))?;
            let modified_at = file.modified_at.or_else(|| {
                Some(proto_timestamp_from_parts(0, 0).expect("zero timestamp is valid"))
            });
            let metadata = clirpc::FileInfo {
                name: file.name,
                size_bytes: i64::try_from(file.data.len()).unwrap_or(i64::MAX),
                modified_at,
            };
            let mut chunks = vec![clirpc::SetFileChunk {
                chunk: Some(clirpc::set_file_chunk::Chunk::File(metadata)),
            }];
            if !file.data.is_empty() {
                chunks.push(clirpc::SetFileChunk {
                    chunk: Some(clirpc::set_file_chunk::Chunk::Data(file.data)),
                });
            }
            self.set_file_stream(tokio_stream::iter(chunks)).await
        }

        async fn get_file(
            &mut self,
            request: clirpc::GetFileRequest,
        ) -> Result<Response<clirpc::GetFileResponse>, Status> {
            let mut stream = self.get_file_stream(request).await?.into_inner();
            let mut metadata: Option<clirpc::FileInfo> = None;
            let mut data = Vec::new();
            while let Some(chunk) = stream.try_next().await? {
                match chunk.chunk {
                    Some(clirpc::get_file_chunk::Chunk::File(file)) => {
                        metadata = Some(file);
                    }
                    Some(clirpc::get_file_chunk::Chunk::Data(bytes)) => {
                        data.extend_from_slice(&bytes);
                    }
                    None => return Err(Status::internal("daemon streamed an empty file chunk")),
                }
            }

            let metadata =
                metadata.ok_or_else(|| Status::internal("daemon omitted file metadata"))?;
            Ok(Response::new(clirpc::GetFileResponse {
                file: Some(clirpc::File {
                    name: metadata.name,
                    data,
                    modified_at: metadata.modified_at,
                }),
            }))
        }
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
            Ok(Response::new(bbrpc::SetContentRevisionResponse::default()))
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

        /// Apply one requester-content update using the production no-op rule
        /// for omitted content.
        fn apply_requester_content(&self, requester_content: Option<bbrpc::ContentInfo>) {
            if let Some(requester_content) = requester_content {
                *self.requester_content.lock().unwrap() = Some(requester_content);
            }
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
                requester_latest_stored_content: self.state.requester_content(),
                requester_remaining_seconds: 0,
                requester_latest_known_content: self.state.requester_content(),
                requester_pinned: false,
            }))
        }

        async fn set_content_revision(
            &self,
            request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            self.state.set_call_count.fetch_add(1, Ordering::SeqCst);
            self.state
                .apply_requester_content(request.into_inner().requester_content);

            if self.state.fail_first_set.swap(false, Ordering::SeqCst) {
                return Err(Status::unavailable("transient after apply"));
            }

            Ok(Response::new(bbrpc::SetContentRevisionResponse::default()))
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
                requester_latest_stored_content: Some(self.state.requester_content.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(self.state.requester_content.clone()),
                requester_pinned: false,
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
            if request.length < 0 {
                return Err(Status::invalid_argument("length must be non-negative"));
            }
            let offset = usize::try_from(request.offset)
                .map_err(|_| Status::invalid_argument("offset is too large"))?;
            let requested_length = usize::try_from(request.length)
                .map_err(|_| Status::invalid_argument("length is too large"))?;
            let section_end = offset
                .saturating_add(requested_length)
                .min(self.state.blob.len());
            let sampled = self
                .state
                .blob
                .get(offset..section_end)
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

    /// RetryableRevisionFailurePeerService always fails revision probes with a
    /// retryable status.
    #[derive(Clone, Default)]
    struct RetryableRevisionFailurePeerService;

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer
        for RetryableRevisionFailurePeerService
    {
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
            Err(Status::unavailable("retryable revision failure"))
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
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            Err(Status::unimplemented("download is not used in this test"))
        }
    }

    /// TimeoutDownloadPeerService advertises the right revision but keeps the
    /// sampled download hanging past the RPC timeout.
    #[derive(Clone)]
    struct TimeoutDownloadPeerService {
        /// requester_content is the local revision the peer claims to store.
        requester_content: bbrpc::ContentInfo,
        /// blob is the exact encrypted content that would eventually be served.
        blob: Vec<u8>,
    }

    impl TimeoutDownloadPeerService {
        /// Create a timeout service for one advertised requester revision.
        fn new(requester_content: bbrpc::ContentInfo, blob: Vec<u8>) -> Self {
            Self {
                requester_content,
                blob,
            }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for TimeoutDownloadPeerService {
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
                requester_latest_stored_content: Some(self.requester_content.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(self.requester_content.clone()),
                requester_pinned: false,
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
            let request = request.into_inner();
            let offset = usize::try_from(request.offset)
                .map_err(|_| Status::invalid_argument("offset is too large"))?;
            let requested_length = usize::try_from(request.length)
                .map_err(|_| Status::invalid_argument("length is too large"))?;
            let section_end = offset.saturating_add(requested_length).min(self.blob.len());
            let section = self
                .blob
                .get(offset..section_end)
                .ok_or_else(|| Status::invalid_argument("offset is too large"))?
                .to_vec();

            tokio::time::sleep(transport::PEER_RPC_TIMEOUT + Duration::from_millis(25)).await;
            Ok(Response::new(bbrpc::DownloadResponse {
                total_length: i64::try_from(self.blob.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&self.blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes { value: section },
                )),
            }))
        }
    }

    /// UnavailableHealthPeerService returns a retryable health-check failure.
    #[derive(Clone, Default)]
    struct UnavailableHealthPeerService;

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for UnavailableHealthPeerService {
        async fn health_check(
            &self,
            _request: Request<bbrpc::HealthCheckRequest>,
        ) -> std::result::Result<Response<bbrpc::HealthCheckResponse>, Status> {
            Err(Status::unavailable("peer health unavailable"))
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
            Err(Status::unimplemented(
                "get content revision is not used in this test",
            ))
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
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            Err(Status::unimplemented("download is not used in this test"))
        }
    }

    /// CountingRevisionPeerService tracks revision-probe calls and can fail a
    /// configured number of initial requests.
    #[derive(Clone)]
    struct CountingRevisionPeerService {
        /// state stores mutable counters and injected failure behavior.
        state: Arc<CountingRevisionPeerServiceState>,
    }

    /// CountingRevisionPeerServiceState tracks probe-call state for tests.
    struct CountingRevisionPeerServiceState {
        /// get_content_revision_call_count records observed revision probes.
        get_content_revision_call_count: AtomicUsize,
        /// remaining_failures counts how many initial probes should fail.
        remaining_failures: AtomicUsize,
        /// revision_response is returned once injected failures are exhausted.
        revision_response: bbrpc::GetContentRevisionResponse,
    }

    impl CountingRevisionPeerServiceState {
        /// Build one counting revision-probe state.
        fn new(
            revision_response: bbrpc::GetContentRevisionResponse,
            remaining_failures: usize,
        ) -> Self {
            Self {
                get_content_revision_call_count: AtomicUsize::new(0),
                remaining_failures: AtomicUsize::new(remaining_failures),
                revision_response,
            }
        }

        /// Report how many revision probes this service observed.
        fn get_content_revision_call_count(&self) -> usize {
            self.get_content_revision_call_count.load(Ordering::SeqCst)
        }
    }

    impl CountingRevisionPeerService {
        /// Build one counting revision-probe service.
        fn new(state: Arc<CountingRevisionPeerServiceState>) -> Self {
            Self { state }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for CountingRevisionPeerService {
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
            self.state
                .get_content_revision_call_count
                .fetch_add(1, Ordering::SeqCst);
            if self
                .state
                .remaining_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    if remaining > 0 {
                        Some(remaining - 1)
                    } else {
                        None
                    }
                })
                .is_ok()
            {
                return Err(Status::unavailable("injected transient revision failure"));
            }

            Ok(Response::new(self.state.revision_response.clone()))
        }

        async fn set_content_revision(
            &self,
            _request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            Ok(Response::new(bbrpc::SetContentRevisionResponse::default()))
        }

        async fn download(
            &self,
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            Err(Status::unimplemented("download is not used in this test"))
        }
    }

    /// PeerExchangeState tracks one peer-exchange-capable test service.
    struct PeerExchangeState {
        /// peer_exchange_call_count records how many peer exchange RPCs were observed.
        peer_exchange_call_count: AtomicUsize,
        /// revision_response is returned from GetContentRevision.
        revision_response: bbrpc::GetContentRevisionResponse,
        /// response_peers is returned from PeerExchange.
        response_peers: Vec<bbrpc::Peer>,
    }

    impl PeerExchangeState {
        /// Create state for one exchange-capable test service.
        fn new(
            revision_response: bbrpc::GetContentRevisionResponse,
            response_peers: Vec<bbrpc::Peer>,
        ) -> Self {
            Self {
                peer_exchange_call_count: AtomicUsize::new(0),
                revision_response,
                response_peers,
            }
        }

        /// Report how many peer-exchange RPCs were observed.
        fn peer_exchange_call_count(&self) -> usize {
            self.peer_exchange_call_count.load(Ordering::SeqCst)
        }
    }

    /// PeerExchangePeerService serves revision requests and peer exchange responses.
    #[derive(Clone)]
    struct PeerExchangePeerService {
        /// state stores the fixed revision response and exchange peers.
        state: Arc<PeerExchangeState>,
    }

    impl PeerExchangePeerService {
        /// Create one exchange-capable peer service from shared state.
        fn new(state: Arc<PeerExchangeState>) -> Self {
            Self { state }
        }
    }

    #[tonic::async_trait]
    impl bbrpc::barter_backup_server_server::BarterBackupServer for PeerExchangePeerService {
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
            self.state
                .peer_exchange_call_count
                .fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(bbrpc::PeerExchangeResponse {
                peers: self.state.response_peers.clone(),
            }))
        }

        async fn get_content_revision(
            &self,
            _request: Request<bbrpc::GetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::GetContentRevisionResponse>, Status> {
            Ok(Response::new(self.state.revision_response.clone()))
        }

        async fn set_content_revision(
            &self,
            _request: Request<bbrpc::SetContentRevisionRequest>,
        ) -> std::result::Result<Response<bbrpc::SetContentRevisionResponse>, Status> {
            Ok(Response::new(bbrpc::SetContentRevisionResponse::default()))
        }

        async fn download(
            &self,
            _request: Request<bbrpc::DownloadRequest>,
        ) -> std::result::Result<Response<bbrpc::DownloadResponse>, Status> {
            Err(Status::unimplemented("download is not used in this test"))
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

    /// Publish the requester's current content to the responder with the
    /// compare-and-swap field set from the responder's stored peer metadata.
    async fn publish_current_content_to_peer(
        requester_node: Arc<Node>,
        responder_node: Arc<Node>,
        connector: &netmock::MockPeerConnector,
    ) -> anyhow::Result<()> {
        if !responder_node
            .known_peers()
            .contains(&requester_node.address().to_string())
        {
            responder_node.add_known_peer(requester_node.address())?;
        }
        let _tracked = responder_node
            .connect_peer_client_with_timeout_and_tracking(
                requester_node.address(),
                Duration::from_secs(5),
                true,
            )
            .await?;
        let mut client =
            connect_p2p_client(requester_node.clone(), responder_node.clone(), connector).await?;
        let previous_requester_content =
            peer_entry(responder_node.as_ref(), requester_node.address())?
                .and_then(|peer| peer_latest_known_content(&peer))
                .map(|content| bbrpc::ContentInfo {
                    content_id: content.content_id,
                    content_length: content.content_length,
                });
        client
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content,
                requester_content: requester_node.responder_content()?,
            })
            .await?;
        Ok(())
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

    /// Return the current in-memory peer inventory entry for one onion identifier.
    fn peer_inventory_entry(
        node: &Node,
        peer_onion: &str,
    ) -> anyhow::Result<Option<PeerInventoryEntry>> {
        Ok(node
            .peer_inventory()?
            .into_iter()
            .find(|peer| peer.onion_service_id == peer_onion))
    }

    /// Return the current content info and encrypted blob from a node.
    fn current_content_snapshot(node: &Node) -> anyhow::Result<(bbrpc::ContentInfo, Vec<u8>)> {
        let content_info = node
            .responder_content()?
            .ok_or_else(|| anyhow::anyhow!("node has no current content"))?;
        let blob = node.with_store(|store| store.current_blob())?;

        Ok((content_info, blob))
    }

    /// Build a short retry policy for failure-path tests.
    fn test_check_retry_policy() -> transport::PeerRetryPolicy {
        transport::PeerRetryPolicy {
            operation: transport::PeerOperation::Check,
            connect_timeout: Duration::from_millis(50),
            rpc_timeout: Duration::from_millis(50),
            total_budget: Duration::from_millis(220),
            initial_backoff: Duration::from_millis(5),
            max_backoff: Duration::from_millis(20),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_reports_uptime_and_onion() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("password")?);
        node.mark_started();
        let (mut client, server) = spawn_cli_server(node.clone()).await?;

        let first = client.state(clirpc::StateRequest {}).await?.into_inner();
        assert_eq!(first.server_onion, node.address());

        tokio::time::sleep(Duration::from_millis(10)).await;
        let second = client.state(clirpc::StateRequest {}).await?.into_inner();
        assert!(second.uptime_seconds >= first.uptime_seconds);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_reports_recovery_metadata_and_publication_blockers() -> anyhow::Result<()>
    {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 7).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "state-recovery-owner",
            filesystem,
            clock.clone(),
        )?);

        node.initialize_lineage((100, 7), true)?;

        let summary = node
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let recovery = summary
            .recovery
            .ok_or_else(|| anyhow::anyhow!("missing recovery summary"))?;

        assert!(recovery.recovery_mode_enabled);
        assert_eq!(
            recovery.node_initialized_at,
            Some(proto_timestamp_from_parts(100, 7).unwrap())
        );
        assert_eq!(recovery.recovery_watermark_at, None);
        assert!(recovery.latest_recovered_content_id.is_empty());
        assert!(recovery.newer_known_content_id.is_empty());
        assert_eq!(
            recovery.publish_blocked_reason,
            "recovery mode is enabled; run `bbcli init complete` before publishing"
        );

        node.complete_initialization()?;

        let summary = node
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let recovery = summary
            .recovery
            .ok_or_else(|| anyhow::anyhow!("missing recovery summary"))?;

        assert!(!recovery.recovery_mode_enabled);
        assert_eq!(
            recovery.node_initialized_at,
            Some(proto_timestamp_from_parts(100, 7).unwrap())
        );
        assert_eq!(
            recovery.recovery_watermark_at,
            Some(proto_timestamp_from_parts(100, 7).unwrap())
        );
        assert!(recovery.publish_blocked_reason.is_empty());
        assert!(recovery.latest_recovered_content_id.is_empty());
        assert!(recovery.newer_known_content_id.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_reports_local_content_and_peer_summary() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let peer_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage_and_clock(
            "state-summary-owner",
            owner_filesystem,
            owner_clock.clone(),
        )?);
        let peer = Arc::new(Node::with_local_storage_and_clock(
            "state-summary-peer",
            peer_filesystem,
            peer_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        peer.set_peer_connector(connector.clone());
        owner.add_known_peer(peer.address())?;
        peer.add_known_peer(owner.address())?;
        *owner.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
            min_replicas: 1,
        };

        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"owner-data".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(peer.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "beta.txt".to_string(),
                    data: b"peer-data".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let peer_server = spawn_registered_p2p_server(peer.clone(), connector.as_ref()).await?;
        owner.publish_to_peer_updates(peer.address()).await?;
        owner.verify_peer_storage_updates(peer.address()).await?;
        owner_clock.advance(Duration::from_secs(3_600));
        owner.verify_peer_storage_updates(peer.address()).await?;

        let summary = owner
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let content = summary
            .content
            .ok_or_else(|| anyhow::anyhow!("missing local content summary"))?;
        let peers = summary
            .peers
            .ok_or_else(|| anyhow::anyhow!("missing local peer summary"))?;
        let durability = summary
            .durability
            .ok_or_else(|| anyhow::anyhow!("missing local durability summary"))?;

        assert_eq!(content.file_count, 1);
        assert_eq!(content.total_size_bytes, 10);
        assert_eq!(
            content.last_updated_at,
            Some(proto_timestamp_from_parts(100, 0).unwrap())
        );
        assert!(!content.has_pending_update);

        assert_eq!(peers.total_known, 1);
        assert_eq!(peers.connected, 1);
        assert_eq!(peers.storing_our_data, 1);
        assert_eq!(peers.storing_latest_our_data, 1);
        assert_eq!(peers.mutual_storage_peers, 1);
        assert_eq!(peers.mean_mutual_storage_score_seconds, 3_600);
        assert_eq!(peers.mirrored_peers, 0);
        assert_eq!(peers.mirrored_total_size_bytes, 0);

        assert_eq!(durability.predicted_fresh_replicas_now, 1);
        assert_eq!(durability.predicted_min_replicas_target, 1);
        assert_eq!(
            durability.predicted_replica_horizon,
            vec![clirpc::ReplicaHorizonPoint {
                remaining_fresh_replicas: 0,
                seconds_until_threshold: 3_600,
                never: false,
            }]
        );

        owner_server.abort();
        peer_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_uses_sidecar_lengths_without_reading_mirrored_blobs() -> anyhow::Result<()>
    {
        let counting = Arc::new(ReadCountingFilesystem {
            inner: Arc::new(storage::MemoryFilesystem::new()),
            reads: AtomicUsize::new(0),
        });
        let owner_filesystem: Arc<dyn Filesystem> = counting.clone();
        let owner = Arc::new(Node::with_local_storage(
            "state-sidecar-owner",
            owner_filesystem,
        )?);
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer = Arc::new(Node::with_local_storage(
            "state-sidecar-peer",
            peer_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        peer.set_peer_connector(connector.clone());
        owner.add_known_peer(peer.address())?;
        peer.add_known_peer(owner.address())?;

        CliService::new(peer.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "beta.txt".to_string(),
                    data: b"peer-data".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let peer_server = spawn_registered_p2p_server(peer.clone(), connector.as_ref()).await?;
        let mut peer_to_owner =
            connect_p2p_client(peer.clone(), owner.clone(), connector.as_ref()).await?;
        let peer_content = peer.responder_content()?.unwrap();
        peer_to_owner
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(peer_content.clone()),
            })
            .await?;

        counting.reset_reads();
        let summary = owner
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let peers = summary
            .peers
            .ok_or_else(|| anyhow::anyhow!("missing local peer summary"))?;

        assert_eq!(peers.mirrored_peers, 1);
        assert_eq!(peers.mirrored_total_size_bytes, peer_content.content_length);
        assert_eq!(counting.reads(), 0);

        owner_server.abort();
        peer_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_marks_pending_update_after_local_change() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(200, 0).unwrap()));
        let peer_clock = Arc::new(ManualClock::new(Timestamp::new(200, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage_and_clock(
            "state-pending-owner",
            owner_filesystem,
            owner_clock.clone(),
        )?);
        let peer = Arc::new(Node::with_local_storage_and_clock(
            "state-pending-peer",
            peer_filesystem,
            peer_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        peer.set_peer_connector(connector.clone());
        owner.add_known_peer(peer.address())?;
        peer.add_known_peer(owner.address())?;
        *owner.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: 0,
            min_replicas: 1,
        };

        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"owner-v1".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let peer_server = spawn_registered_p2p_server(peer.clone(), connector.as_ref()).await?;
        owner.publish_to_peer_updates(peer.address()).await?;
        owner.verify_peer_storage_updates(peer.address()).await?;
        owner_server.abort();
        peer_server.abort();

        owner_clock.advance(Duration::from_secs(1));
        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"owner-v2".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let summary = owner
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let content = summary
            .content
            .ok_or_else(|| anyhow::anyhow!("missing local content summary"))?;
        let peers = summary
            .peers
            .ok_or_else(|| anyhow::anyhow!("missing local peer summary"))?;
        let durability = summary
            .durability
            .ok_or_else(|| anyhow::anyhow!("missing local durability summary"))?;

        assert!(content.has_pending_update);
        assert_eq!(peers.storing_our_data, 1);
        assert_eq!(peers.storing_latest_our_data, 0);
        assert_eq!(durability.predicted_fresh_replicas_now, 0);
        assert!(durability.predicted_replica_horizon.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_state_reports_newer_known_recovery_hint() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(200, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage_and_clock(
            "state-recovery-hint-owner",
            owner_filesystem,
            owner_clock.clone(),
        )?);

        owner_clock.set(Timestamp::new(100, 0).unwrap());
        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "shared.txt".to_string(),
                    data: b"older".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let older = owner
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing older content"))?;

        owner_clock.set(Timestamp::new(110, 0).unwrap());
        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "shared.txt".to_string(),
                    data: b"newer".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let newer = owner
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing newer content"))?;
        let newer_revision = owner.with_store(|store| {
            let revision = store.parse_content_id(&newer.content_id)?;
            Ok(storedpb::RecoveredRevision {
                content_id: newer.content_id.clone(),
                created_at: Some(
                    proto_timestamp_from_parts(
                        i64::try_from(revision.created_at_secs).unwrap_or(i64::MAX),
                        i64::from(revision.created_at_nanos),
                    )
                    .unwrap(),
                ),
            })
        })?;

        owner_clock.set(Timestamp::new(200, 0).unwrap());
        owner.initialize_lineage((200, 0), true)?;
        owner.with_store(|store| {
            store.set_peer_requester_revision_state(
                b"peer-a",
                Some(&older.content_id),
                Some(older.content_length),
                Some(&newer.content_id),
                Some(newer.content_length),
            )?;
            store.record_recovered_revision(storedpb::RecoveredRevision {
                content_id: older.content_id.clone(),
                created_at: Some(proto_timestamp_from_parts(100, 0).unwrap()),
            })?;
            Ok(())
        })?;

        let summary = owner
            .local_state_summary()?
            .ok_or_else(|| anyhow::anyhow!("missing local state summary"))?;
        let recovery = summary
            .recovery
            .ok_or_else(|| anyhow::anyhow!("missing local recovery summary"))?;

        assert_eq!(recovery.latest_recovered_content_id, older.content_id);
        assert_eq!(
            recovery.latest_recovered_at,
            Some(proto_timestamp_from_parts(100, 0).unwrap())
        );
        assert_eq!(recovery.newer_known_content_id, newer.content_id);
        assert_eq!(recovery.newer_known_at, newer_revision.created_at);
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
                    ..Default::default()
                }),
            })
            .await?;

        let listed = client
            .list_files(clirpc::ListFilesRequest {})
            .await?
            .into_inner();
        assert_eq!(listed.file.len(), 1);
        assert_eq!(listed.file[0].name, "alpha.txt");
        assert_eq!(listed.file[0].size_bytes, 10);

        let fetched = client
            .get_file(clirpc::GetFileRequest {
                name: "alpha.txt".to_string(),
            })
            .await?
            .into_inner()
            .file
            .unwrap();
        assert_eq!(fetched.data, b"alpha-body".to_vec());

        client
            .delete_file(clirpc::DeleteFileRequest {
                name: "alpha.txt".to_string(),
            })
            .await?;

        let listed = client
            .list_files(clirpc::ListFilesRequest {})
            .await?
            .into_inner();
        assert!(listed.file.is_empty());

        client
            .set_file(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "beta.txt".to_string(),
                    data: b"beta-body".to_vec(),
                    ..Default::default()
                }),
            })
            .await?;

        let listed = client
            .list_files(clirpc::ListFilesRequest {})
            .await?
            .into_inner();
        assert_eq!(listed.file.len(), 1);
        assert_eq!(listed.file[0].name, "beta.txt");

        let storage_info = client
            .get_storage_config(clirpc::GetStorageConfigRequest {})
            .await?
            .into_inner();
        let storage_policy = storage_info.resource_policy.unwrap();
        assert_eq!(
            storage_policy.max_peer_content_bytes,
            max_peer_content_bytes_i64()
        );
        assert_eq!(
            storage_policy.max_peer_content_bytes,
            i64::try_from(storage::MAX_SHARED_CONTENT_BLOB_BYTES).unwrap_or(i64::MAX)
        );
        assert_eq!(
            storage_policy.peer_grpc_message_limit_bytes,
            i64::try_from(transport::PEER_GRPC_MESSAGE_LIMIT_BYTES).unwrap_or(i64::MAX)
        );
        assert!(!storage_policy.chunking_supported);
        let storage_config = storage_info
            .config
            .ok_or_else(|| anyhow::anyhow!("missing storage config"))?;
        assert_eq!(
            storage_config.allocated_storage_for_peers,
            DEFAULT_ALLOCATED_STORAGE_FOR_PEERS
        );
        assert_eq!(storage_config.min_replicas, DEFAULT_MIN_REPLICAS);
        let storage_info = storage_info.info.unwrap();
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
            .publish_to_peer_updates(node.address())
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

    #[test]
    fn sample_section_for_short_blob_uses_tail_from_offset() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(10, 0).unwrap()));
        let node = Node::with_local_storage_and_clock(
            "sample-short-owner",
            Arc::new(storage::MemoryFilesystem::new()),
            clock,
        )?;
        let peer_identity = Node::new("sample-short-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        let content_id = vec![0x55; CONTENT_ID_LEN];
        let blob_len = 257usize;

        let (offset, section_len) = node.sample_section(&peer_public_key, &content_id, blob_len);
        assert!(offset < blob_len);
        assert_eq!(section_len, blob_len - offset);
        Ok(())
    }

    #[test]
    fn sample_section_can_return_a_one_byte_tail() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(0, 0).unwrap()));
        let node = Node::with_local_storage_and_clock(
            "sample-tail-owner",
            Arc::new(storage::MemoryFilesystem::new()),
            clock.clone(),
        )?;
        let peer_identity = Node::new("sample-tail-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        let content_id = vec![0x77; CONTENT_ID_LEN];
        let blob_len = 32usize;

        for second in 0..1_024u64 {
            clock.set(Timestamp::new(second, 0).unwrap());
            let (offset, section_len) =
                node.sample_section(&peer_public_key, &content_id, blob_len);
            if offset == blob_len - 1 {
                assert_eq!(section_len, 1);
                return Ok(());
            }
        }

        anyhow::bail!("failed to find a one-byte tail sample offset");
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
            latest_known_content: None,
            latest_cached_content: None,
            origin,
            first_contact_direction,
            reachability: storedpb::PeerReachability::Unknown as i32,
            last_live_at: 0,
            pinned_by_us: false,
            pins_us: false,
            our_content_last_verified_content_id: Vec::new(),
            our_content_last_verified_at: 0,
            first_seen_at: Some(proto_timestamp_from_parts(0, 0).unwrap()),
            successful_calls: 0,
            failed_calls: 0,
            requester_latest_stored_content: None,
            requester_latest_known_content: None,
            requester_last_advertised_content: None,
            requester_last_advertised_at: None,
            requester_last_downloaded_advertised_content: None,
            requester_last_downloaded_advertised_at: None,
            requester_last_download_latency_seconds: 0,
        }
    }

    #[test]
    fn peer_priority_follows_product_order() {
        assert!(
            peer_priority(
                true,
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                false,
                storedpb::PeerOrigin::Manual as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
        assert!(
            peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                1,
                storedpb::FirstContactDirection::Unknown as i32,
            ) < peer_priority(
                false,
                storedpb::PeerOrigin::Manual as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
        assert!(
            peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                1,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                false,
                storedpb::PeerOrigin::BuiltIn as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            )
        );
        assert!(
            peer_priority(
                false,
                storedpb::PeerOrigin::BuiltIn as i32,
                0,
                storedpb::FirstContactDirection::Unknown as i32,
            ) > peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Outbound as i32,
            )
        );
        assert!(
            peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Outbound as i32,
            ) > peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Inbound as i32,
            )
        );
        assert!(
            peer_priority(
                false,
                storedpb::PeerOrigin::Discovered as i32,
                0,
                storedpb::FirstContactDirection::Inbound as i32,
            ) > peer_priority(
                false,
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
                outbound_candidate.pinned_by_us,
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
                equal_inbound_candidate.pinned_by_us,
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
                built_in_candidate.pinned_by_us,
                built_in_candidate.origin,
                built_in_candidate.score_seconds,
                built_in_candidate.first_contact_direction,
                1,
            ),
            PeerAdmissionPlan::Reject
        );
    }

    #[test]
    fn pinned_candidate_outranks_manual_peer_for_admission() {
        let manual_peer = test_peer(
            "priority-manual",
            storedpb::PeerOrigin::Manual as i32,
            0,
            storedpb::FirstContactDirection::Unknown as i32,
        );
        let mut pinned_candidate = test_peer(
            "priority-pinned",
            storedpb::PeerOrigin::Discovered as i32,
            -10,
            storedpb::FirstContactDirection::Inbound as i32,
        );
        pinned_candidate.pinned_by_us = true;

        assert_eq!(
            plan_peer_admission(
                std::slice::from_ref(&manual_peer),
                &pinned_candidate.onion_pubkey,
                pinned_candidate.pinned_by_us,
                pinned_candidate.origin,
                pinned_candidate.score_seconds,
                pinned_candidate.first_contact_direction,
                1,
            ),
            PeerAdmissionPlan::Admit {
                evicted_public_key: Some(manual_peer.onion_pubkey.clone()),
            }
        );
    }

    #[test]
    fn aggregate_storage_accounting_splits_deduplicated_bytes_by_class() {
        let pinned_key = vec![0x11; 32];
        let protected_key = vec![0x22; 32];
        let offline_key = vec![0x33; 32];
        let disposable_key = vec![0x44; 32];
        let usage = vec![
            MirroredBlobUsage {
                content_id: b"pinned".to_vec(),
                blob_len: 10,
                references: vec![PeerBlobReference {
                    peer_public_key: pinned_key.clone(),
                    pinned_by_us: true,
                    score_seconds: -10,
                    score_measured_at: 0,
                }],
            },
            MirroredBlobUsage {
                content_id: b"protected".to_vec(),
                blob_len: 20,
                references: vec![PeerBlobReference {
                    peer_public_key: protected_key.clone(),
                    pinned_by_us: false,
                    score_seconds: 15,
                    score_measured_at: 0,
                }],
            },
            MirroredBlobUsage {
                content_id: b"offline".to_vec(),
                blob_len: 30,
                references: vec![PeerBlobReference {
                    peer_public_key: offline_key.clone(),
                    pinned_by_us: false,
                    score_seconds: 12,
                    score_measured_at: 0,
                }],
            },
            MirroredBlobUsage {
                content_id: b"disposable".to_vec(),
                blob_len: 40,
                references: vec![PeerBlobReference {
                    peer_public_key: disposable_key.clone(),
                    pinned_by_us: false,
                    score_seconds: 0,
                    score_measured_at: 0,
                }],
            },
        ];
        let contract_states = BTreeMap::from([
            (
                pinned_key,
                PeerStorageRuntimeState {
                    online: true,
                    our_content_synced: true,
                },
            ),
            (
                protected_key,
                PeerStorageRuntimeState {
                    online: true,
                    our_content_synced: true,
                },
            ),
            (
                offline_key,
                PeerStorageRuntimeState {
                    online: false,
                    our_content_synced: false,
                },
            ),
            (
                disposable_key,
                PeerStorageRuntimeState {
                    online: false,
                    our_content_synced: false,
                },
            ),
        ]);

        let accounting = aggregate_storage_accounting(&usage, &contract_states);
        assert_eq!(accounting.pinned_bytes, 10);
        assert_eq!(accounting.protected_bytes, 50);
        assert_eq!(accounting.disposable_bytes, 40);
        assert_eq!(accounting.offline_blocking_bytes, 30);
        assert_eq!(accounting.reclaimable_bytes, 40);
    }

    #[test]
    fn replica_horizon_points_include_finite_and_never_thresholds() {
        let points = replica_horizon_points(&[Some(10), Some(25), None]);

        assert_eq!(
            points,
            vec![
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 2,
                    seconds_until_threshold: 10,
                    never: false,
                },
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 1,
                    seconds_until_threshold: 25,
                    never: false,
                },
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 0,
                    seconds_until_threshold: 0,
                    never: true,
                },
            ]
        );
    }

    #[test]
    fn replica_horizon_points_are_empty_without_replicas() {
        assert!(replica_horizon_points(&[]).is_empty());
    }

    #[test]
    fn replica_horizon_points_with_only_pinned_replicas_are_never() {
        let points = replica_horizon_points(&[None, None]);

        assert_eq!(
            points,
            vec![
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 1,
                    seconds_until_threshold: 0,
                    never: true,
                },
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 0,
                    seconds_until_threshold: 0,
                    never: true,
                },
            ]
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
    fn trim_to_capacity_preserves_pinned_peer() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("pin-trim-owner", filesystem)?;
        let capacity = 2;

        let pinned_master = test_master_priv("pin-trim-pinned");
        let pinned_peer = Node::new_for_tests_from_master(&pinned_master)?;
        let pinned_public_key = keys::public_key_from_onion_hostname(pinned_peer.address())?;
        node.track_peer_identity_with_capacity(
            &pinned_public_key,
            peer_origin_code(false, false),
            storedpb::FirstContactDirection::Inbound as i32,
            3,
        )?;
        node.pin_peer(pinned_peer.address())?;

        for index in 0..2 {
            let master = test_master_priv(&format!("pin-trim-peer-{index}"));
            let peer = Node::new_for_tests_from_master(&master)?;
            let public_key = keys::public_key_from_onion_hostname(peer.address())?;
            node.track_peer_identity_with_capacity(
                &public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
                3,
            )?;
        }

        node.trim_tracked_peers_to_capacity_with_limit(capacity)?;
        let tracked_peers = node.tracked_peers()?;
        assert_eq!(tracked_peers.len(), capacity);
        assert!(tracked_peers
            .iter()
            .any(|peer| peer.onion_pubkey == pinned_public_key.as_bytes()));
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
                ..Default::default()
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
        assert!(revision.requester_latest_stored_content.is_none());
        assert!(revision.requester_latest_known_content.is_none());
        let responder = server_node.responder_content()?.unwrap();
        assert!(!responder.content_id.is_empty());
        assert!(responder.content_length > 0);

        let download = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id.clone(),
                offset: 0,
                length: responder.content_length,
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
    async fn p2p_revision_reports_requester_score_and_pin() -> anyhow::Result<()> {
        let server_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let server_node = Arc::new(Node::with_local_storage("pin-server", server_filesystem)?);
        let client_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let client_node = Arc::new(Node::with_local_storage("pin-client", client_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());

        server_node.set_peer_connector(connector.clone());
        client_node.set_peer_connector(connector.clone());
        server_node.add_known_peer(client_node.address())?;
        let client_public_key = keys::public_key_from_onion_hostname(client_node.address())?;
        server_node.with_store(|store| {
            store.set_peer_score(client_public_key.as_bytes(), 321, 100)?;
            store.set_peer_pinned_by_us(client_public_key.as_bytes(), true)?;
            Ok(())
        })?;

        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
                .await?;

        let revision = p2p
            .get_content_revision(tonic::Request::new(bbrpc::GetContentRevisionRequest {}))
            .await?
            .into_inner();
        assert_eq!(revision.requester_remaining_seconds, 321);
        assert!(revision.requester_pinned);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_download_returns_exact_requested_range() -> anyhow::Result<()> {
        let server_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let server_node = Arc::new(Node::with_local_storage("range-server", server_filesystem)?);
        let client_node = Arc::new(Node::new("range-client")?);
        let cli = CliService::new(server_node.clone());
        let connector = Arc::new(netmock::MockPeerConnector::new());

        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: vec![0x41; 128],
                ..Default::default()
            }),
        }))
        .await?;

        let (responder, blob) = current_content_snapshot(server_node.as_ref())?;
        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
                .await?;

        let offset = 7usize;
        let length = 33usize;
        let download = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id.clone(),
                offset: i64::try_from(offset).unwrap_or(i64::MAX),
                length: i64::try_from(length).unwrap_or(i64::MAX),
                reference_content_id: Vec::new(),
            }))
            .await?
            .into_inner();
        assert_eq!(download.total_length, responder.content_length);

        let expected = &blob[offset..offset + length];
        match download.section.unwrap() {
            bbrpc::download_response::Section::RawBytes(raw_bytes) => {
                assert_eq!(raw_bytes.value, expected);
            }
            bbrpc::download_response::Section::Reference(_) => {
                panic!("download unexpectedly returned a reference section");
            }
        }

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn p2p_download_returns_short_tail_near_eof() -> anyhow::Result<()> {
        let server_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let server_node = Arc::new(Node::with_local_storage("tail-server", server_filesystem)?);
        let client_node = Arc::new(Node::new("tail-client")?);
        let cli = CliService::new(server_node.clone());
        let connector = Arc::new(netmock::MockPeerConnector::new());

        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"small-tail".to_vec(),
                ..Default::default()
            }),
        }))
        .await?;

        let (responder, blob) = current_content_snapshot(server_node.as_ref())?;
        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
                .await?;

        let offset = blob.len().saturating_sub(1);
        let download = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id.clone(),
                offset: i64::try_from(offset).unwrap_or(i64::MAX),
                length: 16 * 1024,
                reference_content_id: Vec::new(),
            }))
            .await?
            .into_inner();
        assert_eq!(download.total_length, responder.content_length);

        match download.section.unwrap() {
            bbrpc::download_response::Section::RawBytes(raw_bytes) => {
                assert_eq!(raw_bytes.value, blob[offset..].to_vec());
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
    async fn peer_inventory_uses_cached_and_persisted_reachability() -> anyhow::Result<()> {
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
        let _connected_client = requester_node
            .connect_peer_client(online_node.address())
            .await?;
        requester_node.note_peer_offline(offline_node.address())?;

        let online = peer_inventory_entry(requester_node.as_ref(), online_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing online peer entry"))?;
        let offline = peer_inventory_entry(requester_node.as_ref(), offline_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing offline peer entry"))?;

        assert_eq!(online.status, PeerInventoryStatus::Connected);
        assert!(online.last_live_at > 0);
        assert_eq!(offline.status, PeerInventoryStatus::Offline);
        assert_eq!(offline.last_live_at, 0);

        online_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_inventory_sorts_contracts_before_online_and_offline() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage(
            "peer-inventory-order",
            filesystem,
        )?);
        let contract_peer = Node::new("contract-peer")?;
        let online_peer = Node::new("online-inventory-peer")?;
        let offline_peer = Node::new("offline-inventory-peer")?;

        node.add_known_peer(contract_peer.address())?;
        node.add_known_peer(online_peer.address())?;
        node.add_known_peer(offline_peer.address())?;

        let contract_key = keys::public_key_from_onion_hostname(contract_peer.address())?;
        let online_key = keys::public_key_from_onion_hostname(online_peer.address())?;
        let offline_key = keys::public_key_from_onion_hostname(offline_peer.address())?;
        node.with_store(|store| {
            store.set_peer_score(contract_key.as_bytes(), 42, 10)?;
            store.set_peer_reachability(
                contract_key.as_bytes(),
                storedpb::PeerReachability::Online as i32,
                Some(10),
            )?;
            store.set_peer_reachability(
                online_key.as_bytes(),
                storedpb::PeerReachability::Online as i32,
                Some(20),
            )?;
            store.set_peer_reachability(
                offline_key.as_bytes(),
                storedpb::PeerReachability::Offline as i32,
                None,
            )?;
            Ok(())
        })?;

        let inventory = node.peer_inventory()?;
        assert_eq!(
            inventory
                .into_iter()
                .map(|peer| peer.onion_service_id)
                .collect::<Vec<_>>(),
            vec![
                contract_peer.address().to_string(),
                online_peer.address().to_string(),
                offline_peer.address().to_string(),
            ]
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_inventory_uses_sidecar_lengths_without_reading_mirrored_blobs(
    ) -> anyhow::Result<()> {
        let counting = Arc::new(ReadCountingFilesystem {
            inner: Arc::new(storage::MemoryFilesystem::new()),
            reads: AtomicUsize::new(0),
        });
        let local_filesystem: Arc<dyn Filesystem> = counting.clone();
        let local_node = Arc::new(Node::with_local_storage(
            "peer-inventory-sidecar-owner",
            local_filesystem,
        )?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage(
            "peer-inventory-sidecar-remote",
            remote_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());

        CliService::new(remote_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"cached blob".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        let mut remote_to_local =
            connect_p2p_client(remote_node.clone(), local_node.clone(), connector.as_ref()).await?;
        let remote_content = remote_node.responder_content()?.unwrap();
        remote_to_local
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(remote_content.clone()),
            })
            .await?;

        counting.reset_reads();
        let inventory = peer_inventory_entry(local_node.as_ref(), remote_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing inventory entry"))?;
        assert_eq!(
            inventory.stored_content_bytes,
            remote_content.content_length
        );
        assert_eq!(counting.reads(), 0);

        remote_server.abort();
        local_server.abort();
        Ok(())
    }

    #[test]
    fn pin_peer_rejects_self_and_unknown_peer() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("pin-validation-owner", filesystem)?;
        let unknown_peer = Node::new("pin-validation-unknown")?;

        let self_error = node.pin_peer(node.address()).unwrap_err();
        assert_eq!(self_error.code(), Code::FailedPrecondition);
        assert!(self_error
            .message()
            .contains("local node cannot act as its own peer"));

        let unknown_error = node.pin_peer(unknown_peer.address()).unwrap_err();
        assert_eq!(unknown_error.code(), Code::FailedPrecondition);
        assert_eq!(
            unknown_error.message(),
            "peer is not tracked; connect it first"
        );

        Ok(())
    }

    #[test]
    fn pin_and_unpin_peer_persist_in_inventory() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Node::with_local_storage("pin-persist-owner", filesystem)?;
        let peer = Node::new("pin-persist-peer")?;

        node.add_known_peer(peer.address())?;
        node.pin_peer(peer.address())?;
        let pinned = peer_inventory_entry(&node, peer.address())?
            .ok_or_else(|| anyhow::anyhow!("missing pinned peer entry"))?;
        assert!(pinned.pinned_by_us);

        node.unpin_peer(peer.address())?;
        let unpinned = peer_inventory_entry(&node, peer.address())?
            .ok_or_else(|| anyhow::anyhow!("missing unpinned peer entry"))?;
        assert!(!unpinned.pinned_by_us);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn delayed_peer_metadata_flush_coalesces_multiple_updates() -> anyhow::Result<()> {
        let base: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let counting = Arc::new(CountingFilesystem {
            inner: base.clone(),
            peer_state_writes: AtomicUsize::new(0),
        });
        let filesystem: Arc<dyn Filesystem> = counting.clone();
        let clock = Arc::new(ManualClock::new(Timestamp::new(900, 0).unwrap()));
        let mut timer_intercepts =
            clock.subscribe_timer_intercepts(TIMER_LABEL_PEER_METADATA_FLUSH_DELAY);
        let node = Node::with_local_storage_and_clock_and_flush_delay(
            "batched-peer-metadata-owner",
            filesystem,
            clock.clone(),
            Duration::from_secs(60),
        )?;
        let peer = Node::new("batched-peer-metadata-remote")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        node.add_known_peer(peer.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 10, 900))?;
        let writes_before_delayed_updates = counting.peer_state_writes();

        clock.advance(Duration::from_secs(100));
        node.note_peer_live(peer.address())?;
        assert_eq!(node.update_peer_score(&peer_public_key, true)?, 110);
        node.record_remote_pin_claim(&peer_public_key, true)?;

        let timer = timer_intercepts
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing delayed peer metadata timer"))?;
        assert_eq!(timer.duration, Duration::from_secs(60));
        assert_eq!(
            counting.peer_state_writes(),
            writes_before_delayed_updates + 1
        );

        clock.advance(Duration::from_secs(59));
        tokio::task::yield_now().await;
        assert_eq!(
            counting.peer_state_writes(),
            writes_before_delayed_updates + 1
        );

        clock.advance(Duration::from_secs(1));
        wait_until(|| counting.peer_state_writes() == writes_before_delayed_updates + 2).await;

        let reloaded = Node::with_local_storage_and_clock_and_flush_delay(
            "batched-peer-metadata-owner",
            base,
            clock,
            Duration::from_secs(60),
        )?;
        let peer = peer_inventory_entry(&reloaded, peer.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer inventory entry"))?;
        assert_eq!(peer.status, PeerInventoryStatus::Online);
        assert_eq!(peer.last_live_at, 1_000);
        assert_eq!(peer.score_seconds, 110);
        assert!(peer.pins_us);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_score_update_clamps_to_startup_observation_window() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let node = Node::with_local_storage_and_clock(
            "startup-observation-owner",
            filesystem,
            clock.clone(),
        )?;
        let peer = Node::new("startup-observation-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        node.add_known_peer(peer.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 10, 100))?;

        clock.advance(Duration::from_secs(10));
        assert_eq!(node.update_peer_score(&peer_public_key, true)?, 20);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_score_update_clamps_to_resumed_observation_window() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let clock = Arc::new(ManualClock::new(Timestamp::new(10, 0).unwrap()));
        let node = Node::with_local_storage_and_clock(
            "resumed-observation-owner",
            filesystem,
            clock.clone(),
        )?;
        let peer = Node::new("resumed-observation-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        node.add_known_peer(peer.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 10, 50))?;

        clock.advance(Duration::from_secs(100));
        node.suspend_peer_score_observation_window();
        clock.advance(Duration::from_secs(800));
        node.start_peer_score_observation_window();
        clock.advance(Duration::from_secs(15));

        assert_eq!(node.update_peer_score(&peer_public_key, true)?, 25);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_score_update_ignores_elapsed_time_while_observation_suspended(
    ) -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let node = Node::with_local_storage_and_clock(
            "suspended-observation-owner",
            filesystem,
            clock.clone(),
        )?;
        let peer = Node::new("suspended-observation-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        node.add_known_peer(peer.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 10, 50))?;

        clock.advance(Duration::from_secs(100));
        node.suspend_peer_score_observation_window();
        clock.advance(Duration::from_secs(800));

        assert_eq!(node.update_peer_score(&peer_public_key, false)?, 10);
        assert_eq!(node.peer_score_state(&peer_public_key)?.0, 10);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drop_flushes_pending_low_value_peer_metadata() -> anyhow::Result<()> {
        let base: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let counting = Arc::new(CountingFilesystem {
            inner: base.clone(),
            peer_state_writes: AtomicUsize::new(0),
        });
        let filesystem: Arc<dyn Filesystem> = counting.clone();
        let clock = Arc::new(ManualClock::new(Timestamp::new(2_000, 0).unwrap()));
        let peer = Node::new("drop-flush-remote")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        {
            let node = Node::with_local_storage_and_clock_and_flush_delay(
                "drop-flush-owner",
                filesystem,
                clock.clone(),
                Duration::from_secs(300),
            )?;
            node.add_known_peer(peer.address())?;
            let writes_before_delayed_update = counting.peer_state_writes();
            node.record_remote_pin_claim(&peer_public_key, true)?;
            assert_eq!(counting.peer_state_writes(), writes_before_delayed_update);
        }

        let reloaded = Node::with_local_storage_and_clock_and_flush_delay(
            "drop-flush-owner",
            base,
            clock,
            Duration::from_secs(300),
        )?;
        let peer = peer_inventory_entry(&reloaded, peer.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer inventory entry"))?;
        assert!(peer.pins_us);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_rollup_pass_rewrites_due_local_content() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let clock = Arc::new(ManualClock::new(Timestamp::new(10_000, 0).unwrap()));
        let node = Arc::new(
            Node::with_local_storage_and_clock_and_flush_delay_and_rollup_sampler(
                "metadata-rollup-owner",
                filesystem,
                clock.clone(),
                Duration::from_secs(60),
                Arc::new(|| Duration::from_secs(10)),
            )?,
        );
        let peer = Node::new("metadata-rollup-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        let cli = CliService::new(node.clone());
        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
                ..Default::default()
            }),
        }))
        .await?;
        let original_content_id = node
            .current_content_info()?
            .context("current content should exist after set_file")?
            .content_id;

        node.add_known_peer(peer.address())?;
        node.with_store(|store| {
            store.set_peer_score(peer_public_key.as_bytes(), 25, 9_999)?;
            Ok(())
        })?;

        assert_eq!(
            node.run_metadata_rollup_pass()?,
            MetadataRollupOutcome::NotDue
        );
        assert_eq!(
            node.current_content_info()?
                .context("current content should still exist")?
                .content_id,
            original_content_id
        );

        clock.advance(Duration::from_secs(10));
        let outcome = node.run_metadata_rollup_pass()?;
        let MetadataRollupOutcome::Rewritten { content_id } = outcome else {
            anyhow::bail!("expected a rewritten metadata rollup");
        };
        assert_ne!(content_id, original_content_id);
        assert_eq!(
            node.current_content_info()?
                .context("current content should still exist")?
                .content_id,
            content_id
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn metadata_rollup_pass_flushes_pending_low_value_peer_metadata() -> anyhow::Result<()> {
        let base: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let counting = Arc::new(CountingFilesystem {
            inner: base.clone(),
            peer_state_writes: AtomicUsize::new(0),
        });
        let filesystem: Arc<dyn Filesystem> = counting.clone();
        let clock = Arc::new(ManualClock::new(Timestamp::new(19_999, 0).unwrap()));
        let node = Arc::new(
            Node::with_local_storage_and_clock_and_flush_delay_and_rollup_sampler(
                "metadata-rollup-batched-owner",
                filesystem,
                clock.clone(),
                Duration::from_secs(300),
                Arc::new(|| Duration::from_secs(10)),
            )?,
        );
        let peer = Node::new("metadata-rollup-batched-peer")?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer.address())?;

        let cli = CliService::new(node.clone());
        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
                ..Default::default()
            }),
        }))
        .await?;
        node.add_known_peer(peer.address())?;
        node.with_store(|store| {
            store.set_peer_score(peer_public_key.as_bytes(), 10, 19_999)?;
            Ok(())
        })?;
        let writes_before_pending_update = counting.peer_state_writes();

        clock.advance(Duration::from_secs(1));
        assert_eq!(node.update_peer_score(&peer_public_key, true)?, 11);
        node.record_remote_pin_claim(&peer_public_key, true)?;
        assert_eq!(counting.peer_state_writes(), writes_before_pending_update);

        clock.advance(Duration::from_secs(10));
        let outcome = node.run_metadata_rollup_pass()?;
        assert!(matches!(outcome, MetadataRollupOutcome::Rewritten { .. }));
        assert!(
            counting.peer_state_writes() >= writes_before_pending_update + 2,
            "expected the due rollup to flush pending metadata and then persist cleared rollup state"
        );

        let reloaded = Node::with_local_storage_and_clock_and_flush_delay(
            "metadata-rollup-batched-owner",
            base,
            clock,
            Duration::from_secs(300),
        )?;
        let peer = peer_inventory_entry(&reloaded, peer.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer inventory entry"))?;
        assert_eq!(peer.score_seconds, 11);
        assert!(peer.pins_us);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_client_cache_reuses_recent_dials() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("cache-reuse-owner")?);
        let peer_identity = Node::new("cache-reuse-peer")?;
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse::default()),
        ))
        .await?;
        base_connector.register_peer(peer_identity.address(), &endpoint);

        let _first = node.connect_peer_client(peer_identity.address()).await?;
        let _second = node.connect_peer_client(peer_identity.address()).await?;

        assert_eq!(counting_connector.dial_count(), 1);
        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_client_cache_expires_after_idle_ttl() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let node = Arc::new(Node::with_local_storage_and_clock(
            "cache-expire-owner",
            Arc::new(storage::MemoryFilesystem::new()),
            clock.clone(),
        )?);
        let peer_identity = Node::new("cache-expire-peer")?;
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse::default()),
        ))
        .await?;
        base_connector.register_peer(peer_identity.address(), &endpoint);

        let _first = node.connect_peer_client(peer_identity.address()).await?;
        clock.advance(Duration::from_secs(
            u64::try_from(PEER_CLIENT_CACHE_IDLE_TTL_SECS + 1).unwrap_or(u64::MAX),
        ));
        let _second = node.connect_peer_client(peer_identity.address()).await?;

        assert_eq!(counting_connector.dial_count(), 2);
        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn retryable_peer_rpc_failure_evicts_cached_client() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("cache-evict-owner")?);
        let peer_identity = Node::new("cache-evict-peer")?;
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(UnavailableHealthPeerService).await?;
        base_connector.register_peer(peer_identity.address(), &endpoint);

        let _first = node.connect_peer_client(peer_identity.address()).await?;
        let mut cached_client = node.connect_peer_client(peer_identity.address()).await?;
        let error = node
            .peer_rpc(
                peer_identity.address(),
                "health check",
                cached_client.health_check(bbrpc::HealthCheckRequest {}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);

        let _redialed = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(counting_connector.dial_count(), 2);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clearing_peer_runtime_transport_drops_cached_clients() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("cache-clear-owner")?);
        let peer_identity = Node::new("cache-clear-peer")?;
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse::default()),
        ))
        .await?;
        base_connector.register_peer(peer_identity.address(), &endpoint);

        let _client = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(node.peer_client_cache.lock().unwrap().len(), 1);
        assert!(node.peer_connector.lock().unwrap().is_some());

        node.clear_peer_runtime_transport();

        assert!(node.peer_client_cache.lock().unwrap().is_empty());
        assert!(node.peer_connector.lock().unwrap().is_none());
        let error = node
            .connect_peer_client(peer_identity.address())
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_client_cache_stays_bounded() -> anyhow::Result<()> {
        let node = Arc::new(Node::new("cache-bound-owner")?);
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse::default()),
        ))
        .await?;

        let mut peer_onions = Vec::new();
        for index in 0..(MAX_CACHED_PEER_CLIENTS + 2) {
            let peer_identity = Node::new(&format!("cache-bound-peer-{index}"))?;
            base_connector.register_peer(peer_identity.address(), &endpoint);
            peer_onions.push(peer_identity.address().to_string());
            let _client = node.connect_peer_client(peer_identity.address()).await?;
        }

        assert_eq!(
            node.peer_client_cache.lock().unwrap().len(),
            MAX_CACHED_PEER_CLIENTS
        );

        let _redialed = node.connect_peer_client(&peer_onions[0]).await?;
        assert_eq!(counting_connector.dial_count(), MAX_CACHED_PEER_CLIENTS + 3);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_recovery_probe_runs_once_per_cached_peer_session() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "live-probe-session-owner",
            filesystem,
            clock.clone(),
        )?);
        node.initialize_lineage((100, 0), false)?;
        let peer_identity = Node::new("live-probe-session-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());

        let service_state = Arc::new(CountingRevisionPeerServiceState::new(
            bbrpc::GetContentRevisionResponse::default(),
            0,
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(CountingRevisionPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let _first = node.connect_peer_client(peer_identity.address()).await?;
        let _second = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(service_state.get_content_revision_call_count(), 1);

        clock.advance(Duration::from_secs(
            u64::try_from(PEER_CLIENT_CACHE_IDLE_TTL_SECS + 1).unwrap_or(u64::MAX),
        ));
        let _third = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(service_state.get_content_revision_call_count(), 2);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_recovery_probe_retries_after_transient_failure_in_the_same_session(
    ) -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage(
            "live-probe-retry-owner",
            filesystem,
        )?);
        node.initialize_lineage((1, 0), false)?;
        let peer_identity = Node::new("live-probe-retry-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());

        let service_state = Arc::new(CountingRevisionPeerServiceState::new(
            bbrpc::GetContentRevisionResponse::default(),
            1,
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(CountingRevisionPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let _first = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(service_state.get_content_revision_call_count(), 1);
        let _second = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(service_state.get_content_revision_call_count(), 2);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cli_connect_peer_establishes_one_live_contact() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage(
            "cli-connect-live-owner",
            filesystem,
        )?);
        node.initialize_lineage((1, 0), false)?;
        let peer_identity = Node::new("cli-connect-live-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());

        let service_state = Arc::new(CountingRevisionPeerServiceState::new(
            bbrpc::GetContentRevisionResponse::default(),
            0,
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(CountingRevisionPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let cli = CliService::new(node.clone());
        cli.connect_peer(tonic::Request::new(clirpc::ConnectPeerRequest {
            peer: Some(clirpc::Peer {
                onion_service_id: peer_identity.address().to_string(),
            }),
        }))
        .await?;

        assert_eq!(service_state.get_content_revision_call_count(), 1);
        let peer = peer_entry(node.as_ref(), peer_identity.address())?
            .context("peer was not tracked after connect")?;
        assert!(peer.last_live_at > 0);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn live_recovery_probe_penalizes_tracked_peer_on_revision_failure() -> anyhow::Result<()>
    {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "live-probe-score-owner",
            filesystem,
            clock.clone(),
        )?);
        node.initialize_lineage((1, 0), false)?;
        let peer_identity = Node::new("live-probe-score-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        node.add_known_peer(peer_identity.address())?;

        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| {
            store.set_peer_score(
                peer_public_key.as_bytes(),
                0,
                i64::try_from(clock.now().secs).unwrap_or(i64::MAX),
            )
        })?;

        let (endpoint, server) =
            spawn_plain_peer_server(RetryableRevisionFailurePeerService).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        clock.advance(Duration::from_secs(1_200));
        let _client = node.connect_peer_client(peer_identity.address()).await?;
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            -1_200
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recovery_pass_penalizes_tracked_peer_on_revision_failure() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "recovery-pass-score-owner",
            filesystem,
            clock.clone(),
        )?);
        node.initialize_lineage((1, 0), false)?;
        let peer_identity = Node::new("recovery-pass-score-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        node.add_known_peer(peer_identity.address())?;

        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| {
            store.set_peer_score(
                peer_public_key.as_bytes(),
                0,
                i64::try_from(clock.now().secs).unwrap_or(i64::MAX),
            )
        })?;

        let (endpoint, server) =
            spawn_plain_peer_server(RetryableRevisionFailurePeerService).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        clock.advance(Duration::from_secs(1_800));
        let summary = node.run_recovery_pass().await?;
        assert_eq!(summary.applied_versions, 0);
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            -1_800
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_peer_client_survives_cache_pressure() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "cache-pin-owner",
            filesystem,
            clock.clone(),
        )?);
        let base_connector = Arc::new(PlainPeerConnector::new());
        let counting_connector = Arc::new(FlakyPeerConnector::new(base_connector.clone(), 0));
        node.set_peer_connector(counting_connector.clone());

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse::default(),
            DownloadBehavior::Response(bbrpc::DownloadResponse::default()),
        ))
        .await?;

        let mut peer_onions = Vec::new();
        for index in 0..(MAX_CACHED_PEER_CLIENTS + 2) {
            let peer_identity = Node::new(&format!("cache-pin-peer-{index}"))?;
            base_connector.register_peer(peer_identity.address(), &endpoint);
            node.add_known_peer(peer_identity.address())?;
            peer_onions.push(peer_identity.address().to_string());
        }
        node.pin_peer(&peer_onions[0])?;

        for peer_onion in &peer_onions {
            let mut last_timeout = None;
            let mut connected = false;
            for _attempt in 0..3 {
                match node.connect_peer_client(peer_onion).await {
                    Ok(_client) => {
                        connected = true;
                        break;
                    }
                    Err(status) if status.code() == Code::DeadlineExceeded => {
                        last_timeout = Some(status);
                        tokio::task::yield_now().await;
                    }
                    Err(status) => return Err(status.into()),
                }
            }
            if !connected {
                return Err(last_timeout.expect("timeout status is recorded").into());
            }
            clock.advance(Duration::from_secs(1));
        }

        assert!(node.has_cached_peer_client(&peer_onions[0]));
        let cached_unpinned = peer_onions[1..]
            .iter()
            .filter(|peer_onion| node.has_cached_peer_client(peer_onion))
            .count();
        assert_eq!(cached_unpinned, MAX_CACHED_PEER_CLIENTS - 1);

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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let revision = requester_to_responder
            .get_content_revision(bbrpc::GetContentRevisionRequest {})
            .await?
            .into_inner();
        assert_eq!(
            revision.requester_latest_stored_content,
            Some(requester_content.clone())
        );

        let requester_blob = requester_node.with_store(|store| store.current_blob())?;
        let mirrored_blob = responder_node
            .with_store(|store| store.read_mirrored_blob(&requester_content.content_id))?;
        assert_eq!(mirrored_blob, requester_blob);

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_content_revision_rejects_missing_requester_content() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-clear",
            requester_filesystem,
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage(
            "responder-clear",
            responder_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());

        CliService::new(requester_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_content.clone()),
            })
            .await?;
        assert!(cached_peer_blob(
            responder_node.as_ref(),
            &requester_content.content_id
        )?);

        let error = requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: Some(requester_content.clone()),
                requester_content: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "requester_content must be set");

        let peer = peer_entry(responder_node.as_ref(), requester_node.address())?
            .context("missing tracked requester peer")?;
        assert_eq!(
            peer_latest_known_content(&peer).map(|content| content.content_id),
            Some(requester_content.content_id.clone())
        );
        assert_eq!(
            peer_latest_cached_content(&peer).map(|content| content.content_id),
            Some(requester_content.content_id.clone())
        );
        assert!(cached_peer_blob(
            responder_node.as_ref(),
            &requester_content.content_id
        )?);

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_to_peer_materializes_empty_local_content() -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage(
            "owner-no-clear",
            owner_filesystem,
        )?);
        let replacement_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::MemoryFilesystem::new());
        let replacement_node = Arc::new(Node::with_local_storage(
            "owner-no-clear",
            replacement_filesystem,
        )?);
        let peer_identity = Node::new("peer-no-clear")?;
        let connector = Arc::new(PlainPeerConnector::new());
        let service_state = Arc::new(TransientSetAckState::new());
        let (endpoint, server) =
            spawn_plain_peer_server(TransientSetAckPeerService::new(service_state.clone())).await?;
        connector.register_peer(peer_identity.address(), &endpoint);
        owner_node.set_peer_connector(connector.clone());
        replacement_node.set_peer_connector(connector.clone());
        owner_node.add_known_peer(peer_identity.address())?;
        replacement_node.add_known_peer(peer_identity.address())?;

        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let published_content = owner_node.responder_content()?.unwrap();
        let updates = owner_node
            .publish_to_peer_updates(peer_identity.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(service_state.set_call_count(), 1);
        assert_eq!(
            service_state
                .requester_content()
                .map(|content| content.content_id),
            Some(published_content.content_id.clone())
        );
        assert!(replacement_node.responder_content()?.is_none());

        let updates = replacement_node
            .publish_to_peer_updates(peer_identity.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        let replacement_content = replacement_node.responder_content()?.unwrap();
        assert_eq!(
            service_state
                .requester_content()
                .map(|content| content.content_id),
            Some(replacement_content.content_id.clone())
        );
        assert_ne!(replacement_content.content_id, published_content.content_id);
        assert_eq!(service_state.set_call_count(), 2);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn set_content_revision_rejects_previous_requester_content_mismatch() -> anyhow::Result<()>
    {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-cas-mismatch",
            requester_filesystem,
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage(
            "responder-cas-mismatch",
            responder_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());

        CliService::new(requester_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let error = requester_to_responder
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: None,
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(error.message(), "requester_content must be set");

        let peer = peer_entry(responder_node.as_ref(), requester_node.address())?
            .context("missing tracked requester peer")?;
        assert_eq!(
            peer_latest_known_content(&peer).map(|content| content.content_id),
            Some(requester_content.content_id.clone())
        );

        requester_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_to_peer_updates_auto_recovers_empty_owner_before_publication(
    ) -> anyhow::Result<()> {
        let old_owner_clock = Arc::new(ManualClock::new(Timestamp::new(90, 0).unwrap()));
        let new_owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(90, 0).unwrap()));
        let old_owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let new_owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let old_owner = Arc::new(Node::with_local_storage_and_clock(
            "lineage-owner",
            old_owner_filesystem,
            old_owner_clock,
        )?);
        let new_owner = Arc::new(Node::with_local_storage_and_clock(
            "lineage-owner",
            new_owner_filesystem,
            new_owner_clock,
        )?);
        let responder = Arc::new(Node::with_local_storage_and_clock(
            "lineage-responder",
            responder_filesystem,
            responder_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        old_owner.set_peer_connector(connector.clone());
        new_owner.set_peer_connector(connector.clone());
        responder.set_peer_connector(connector.clone());
        old_owner.add_known_peer(responder.address())?;
        new_owner.add_known_peer(responder.address())?;
        responder.add_known_peer(old_owner.address())?;

        CliService::new(old_owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let old_owner_server =
            spawn_registered_p2p_server(old_owner.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder.clone(), connector.as_ref()).await?;
        publish_current_content_to_peer(old_owner.clone(), responder.clone(), connector.as_ref())
            .await?;
        old_owner_server.abort();

        new_owner.initialize_lineage((100, 0), false)?;
        let new_owner_server =
            spawn_registered_p2p_server(new_owner.clone(), connector.as_ref()).await?;
        let updates = new_owner
            .publish_to_peer_updates(responder.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));

        let listed = new_owner.with_store(|store| Ok(store.list_file_info()))?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "alpha.txt");
        assert_eq!(
            new_owner.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        new_owner_server.abort();
        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn responder_restart_after_proposal_keeps_peer_sidecar_valid() -> anyhow::Result<()> {
        let requester_temp = tempfile::tempdir()?;
        let requester_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::OsFilesystem::new(requester_temp.path())?);
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-restart",
            requester_filesystem,
        )?);
        let responder_temp = tempfile::tempdir()?;
        let responder_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::OsFilesystem::new(responder_temp.path())?);
        let responder_node = Arc::new(Node::with_local_storage(
            "responder-restart",
            responder_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(responder_node.address())?;
        responder_node.add_known_peer(requester_node.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let requester_content = requester_node.responder_content()?.unwrap();

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;

        let updates = requester_node
            .publish_to_peer_updates(responder_node.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        let contracts = responder_node.get_peer_storage_response().await?;
        assert_eq!(contracts.storage_peers.len(), 1);

        responder_server.abort();
        drop(responder_node);

        let reloaded_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::OsFilesystem::new(responder_temp.path())?);
        let reloaded = Node::with_local_storage("responder-restart", reloaded_filesystem)?;
        let peers = reloaded.tracked_peers()?;
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peer_latest_known_content(&peers[0])
                .as_ref()
                .map(|content| content.content_length),
            Some(requester_content.content_length)
        );

        requester_server.abort();
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
                previous_requester_content: None,
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
                    ..Default::default()
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
                previous_requester_content: None,
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

        publish_current_content_to_peer(
            requester_node.clone(),
            responder_node.clone(),
            connector.as_ref(),
        )
        .await?;
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
                    previous_requester_content: None,
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
                ..Default::default()
            }),
        }))
        .await?;

        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
                .await?;
        let responder = server_node.responder_content()?.unwrap();

        let error = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id,
                offset: 0,
                length: 1,
                reference_content_id: vec![0x55; CONTENT_ID_LEN],
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn download_rejects_invalid_length() -> anyhow::Result<()> {
        let server_node = Arc::new(Node::with_local_storage(
            "download-length-server",
            Arc::new(storage::MemoryFilesystem::new()),
        )?);
        let client_node = Arc::new(Node::new("download-length-client")?);
        let cli = CliService::new(server_node.clone());
        let connector = Arc::new(netmock::MockPeerConnector::new());

        cli.set_file(tonic::Request::new(clirpc::SetFileRequest {
            file: Some(clirpc::File {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
                ..Default::default()
            }),
        }))
        .await?;

        let server = spawn_registered_p2p_server(server_node.clone(), connector.as_ref()).await?;
        let mut p2p =
            connect_p2p_client(client_node.clone(), server_node.clone(), connector.as_ref())
                .await?;
        let responder = server_node.responder_content()?.unwrap();

        let negative = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id.clone(),
                offset: 0,
                length: -1,
                reference_content_id: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(negative.code(), Code::InvalidArgument);

        let oversized = p2p
            .download(tonic::Request::new(bbrpc::DownloadRequest {
                content_id: responder.content_id,
                offset: 0,
                length: i64::try_from(transport::MAX_PEER_CONTENT_BYTES).unwrap_or(i64::MAX) + 1,
                reference_content_id: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(oversized.code(), Code::InvalidArgument);

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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let error = other_to_responder
            .download(bbrpc::DownloadRequest {
                content_id: requester_content.content_id.clone(),
                offset: 0,
                length: 1,
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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_content.clone()),
            })
            .await?;

        let revision = other_to_responder
            .get_content_revision(bbrpc::GetContentRevisionRequest {})
            .await?
            .into_inner();
        assert_eq!(revision.requester_latest_stored_content, None);
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
                    ..Default::default()
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        requester_cli
            .publish_to_peer(tonic::Request::new(clirpc::PublishToPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: responder_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;

        let contracts = requester_cli
            .get_peer_storage(tonic::Request::new(clirpc::GetPeerStorageRequest {}))
            .await?
            .into_inner()
            .storage_peers;
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
    async fn get_contracts_persists_remote_pin_claim() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "pin-claim-requester",
            requester_filesystem,
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage(
            "pin-claim-responder",
            responder_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        responder_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(responder_node.address())?;
        responder_node.add_known_peer(requester_node.address())?;

        let requester_public_key = keys::public_key_from_onion_hostname(requester_node.address())?;
        responder_node.with_store(|store| {
            store.set_peer_pinned_by_us(requester_public_key.as_bytes(), true)?;
            Ok(())
        })?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;

        let _contracts = requester_node.get_peer_storage_response().await?;
        let peer = peer_entry(requester_node.as_ref(), responder_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing peer entry"))?;
        assert!(peer.pins_us);

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
                    ..Default::default()
                }),
            }))
            .await?;
        let reserved_cli = CliService::new(reserved_node.clone());
        reserved_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"bravo-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let best_effort_server =
            spawn_registered_p2p_server(best_effort_node.clone(), connector.as_ref()).await?;
        let reserved_server =
            spawn_registered_p2p_server(reserved_node.clone(), connector.as_ref()).await?;
        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;

        publish_current_content_to_peer(
            best_effort_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let best_effort_content = best_effort_node.current_content_info()?.unwrap();
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &best_effort_content.content_id
        )?);

        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: max_peer_content_bytes_i64(),
            min_replicas: 0,
        };
        let reserved_public_key = keys::public_key_from_onion_hostname(reserved_node.address())?;
        local_node
            .with_store(|store| store.set_peer_score(reserved_public_key.as_bytes(), 10, 100))?;

        publish_current_content_to_peer(
            reserved_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
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
            None
        );

        best_effort_server.abort();
        reserved_server.abort();
        local_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_peer_can_evict_best_effort_cache_even_with_negative_score() -> anyhow::Result<()>
    {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "local-pinned-budget",
            local_filesystem,
        )?);
        let best_effort_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::MemoryFilesystem::new());
        let best_effort_node = Arc::new(Node::with_local_storage(
            "best-effort-pinned-peer",
            best_effort_filesystem,
        )?);
        let pinned_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let pinned_node = Arc::new(Node::with_local_storage("pinned-peer", pinned_filesystem)?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        best_effort_node.set_peer_connector(connector.clone());
        pinned_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(best_effort_node.address())?;
        local_node.add_known_peer(pinned_node.address())?;
        local_node.pin_peer(pinned_node.address())?;

        let best_effort_cli = CliService::new(best_effort_node.clone());
        best_effort_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let pinned_cli = CliService::new(pinned_node.clone());
        pinned_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"bravo-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let best_effort_server =
            spawn_registered_p2p_server(best_effort_node.clone(), connector.as_ref()).await?;
        let pinned_server =
            spawn_registered_p2p_server(pinned_node.clone(), connector.as_ref()).await?;
        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;

        publish_current_content_to_peer(
            best_effort_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let best_effort_content = best_effort_node.current_content_info()?.unwrap();
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &best_effort_content.content_id
        )?);

        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: max_peer_content_bytes_i64(),
            min_replicas: 0,
        };

        publish_current_content_to_peer(
            pinned_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let pinned_content = pinned_node.current_content_info()?.unwrap();
        assert!(!cached_peer_blob(
            local_node.as_ref(),
            &best_effort_content.content_id
        )?);
        assert!(cached_peer_blob(
            local_node.as_ref(),
            &pinned_content.content_id
        )?);

        best_effort_server.abort();
        pinned_server.abort();
        local_server.abort();
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
                    ..Default::default()
                }),
            }))
            .await?;

        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        let mut remote_to_local =
            connect_p2p_client(remote_node.clone(), local_node.clone(), connector.as_ref()).await?;
        let response = remote_to_local
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(remote_node.responder_content()?.unwrap()),
            })
            .await?
            .into_inner();
        assert_eq!(
            response.storage_result,
            bbrpc::SetContentRevisionStorageResult::SidecarOnly as i32
        );

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
        local_server.abort();
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
                    ..Default::default()
                }),
            }))
            .await?;

        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        publish_current_content_to_peer(
            remote_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
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
                    ..Default::default()
                }),
            }))
            .await?;
        let version_2 = remote_node.current_content_info()?.unwrap();
        assert!(version_2.content_length > version_1.content_length);

        let mut remote_to_local =
            connect_p2p_client(remote_node.clone(), local_node.clone(), connector.as_ref()).await?;
        let response = remote_to_local
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: Some(version_1.clone()),
                requester_content: Some(version_2.clone()),
            })
            .await?
            .into_inner();
        assert_eq!(
            response.storage_result,
            bbrpc::SetContentRevisionStorageResult::SidecarOnly as i32
        );
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
        local_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_peer_keeps_previous_cached_revision_when_newest_wont_fit() -> anyhow::Result<()>
    {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "local-pinned-reserved",
            local_filesystem,
        )?);
        let remote_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let remote_node = Arc::new(Node::with_local_storage(
            "remote-pinned-reserved",
            remote_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        remote_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(remote_node.address())?;
        local_node.pin_peer(remote_node.address())?;

        let remote_cli = CliService::new(remote_node.clone());
        remote_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"small".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let remote_server =
            spawn_registered_p2p_server(remote_node.clone(), connector.as_ref()).await?;
        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        publish_current_content_to_peer(
            remote_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
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

        remote_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b'x'; 1024 * 1024],
                    ..Default::default()
                }),
            }))
            .await?;
        let version_2 = remote_node.current_content_info()?.unwrap();
        assert!(version_2.content_length > version_1.content_length);

        let mut remote_to_local =
            connect_p2p_client(remote_node.clone(), local_node.clone(), connector.as_ref()).await?;
        let response = remote_to_local
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: Some(version_1.clone()),
                requester_content: Some(version_2.clone()),
            })
            .await?
            .into_inner();
        assert_eq!(
            response.storage_result,
            bbrpc::SetContentRevisionStorageResult::SidecarOnly as i32
        );
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
        local_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_inventory_and_storage_info_report_pin_accounting() -> anyhow::Result<()> {
        let local_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "local-reporting",
            local_filesystem,
        )?);
        let pinned_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let pinned_node = Arc::new(Node::with_local_storage(
            "pinned-reporting",
            pinned_filesystem,
        )?);
        let protected_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let protected_node = Arc::new(Node::with_local_storage(
            "protected-reporting",
            protected_filesystem,
        )?);
        let disposable_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let disposable_node = Arc::new(Node::with_local_storage(
            "disposable-reporting",
            disposable_filesystem,
        )?);
        let tracked_only_filesystem: Arc<dyn Filesystem> =
            Arc::new(storage::MemoryFilesystem::new());
        let tracked_only_node = Arc::new(Node::with_local_storage(
            "tracked-only-reporting",
            tracked_only_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        pinned_node.set_peer_connector(connector.clone());
        protected_node.set_peer_connector(connector.clone());
        disposable_node.set_peer_connector(connector.clone());
        tracked_only_node.set_peer_connector(connector.clone());
        for peer in [
            &pinned_node,
            &protected_node,
            &disposable_node,
            &tracked_only_node,
        ] {
            peer.add_known_peer(local_node.address())?;
        }

        for peer_onion in [
            pinned_node.address(),
            protected_node.address(),
            disposable_node.address(),
            tracked_only_node.address(),
        ] {
            local_node.add_known_peer(peer_onion)?;
        }
        local_node.pin_peer(pinned_node.address())?;

        // Start with enough room for one admission-sized peer slot plus the
        // small mirrored blobs created by this test. We tighten the budget
        // later to force the tracked-only path explicitly.
        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: max_peer_content_bytes_i64().saturating_mul(2),
            min_replicas: 0,
        };
        CliService::new(local_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "owner.txt".to_string(),
                    data: b"owner-data".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        CliService::new(pinned_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b'p'; 17],
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(protected_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b'r'; 19],
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(disposable_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b'd'; 23],
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(tracked_only_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: vec![b't'; 1_000_000],
                    ..Default::default()
                }),
            }))
            .await?;

        let local_server =
            spawn_registered_p2p_server(local_node.clone(), connector.as_ref()).await?;
        let pinned_server =
            spawn_registered_p2p_server(pinned_node.clone(), connector.as_ref()).await?;
        let protected_server =
            spawn_registered_p2p_server(protected_node.clone(), connector.as_ref()).await?;
        let disposable_server =
            spawn_registered_p2p_server(disposable_node.clone(), connector.as_ref()).await?;
        let tracked_only_server =
            spawn_registered_p2p_server(tracked_only_node.clone(), connector.as_ref()).await?;

        local_node
            .publish_to_peer_updates(pinned_node.address())
            .await?;
        publish_current_content_to_peer(
            pinned_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let pinned_length = pinned_node
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing pinned peer content"))?
            .content_length;
        local_node
            .publish_to_peer_updates(protected_node.address())
            .await?;
        publish_current_content_to_peer(
            protected_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let protected_length = protected_node
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing protected peer content"))?
            .content_length;
        local_node
            .publish_to_peer_updates(disposable_node.address())
            .await?;
        publish_current_content_to_peer(
            disposable_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let disposable_length = disposable_node
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing disposable peer content"))?
            .content_length;
        let tracked_only_length = tracked_only_node
            .current_content_info()?
            .ok_or_else(|| anyhow::anyhow!("missing tracked-only peer content"))?
            .content_length;

        let protected_public_key = keys::public_key_from_onion_hostname(protected_node.address())?;
        local_node
            .with_store(|store| store.set_peer_score(protected_public_key.as_bytes(), 90, 100))?;
        let cached_budget = pinned_length
            .saturating_add(protected_length)
            .saturating_add(disposable_length);
        assert!(tracked_only_length > cached_budget);
        *local_node.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: cached_budget,
            min_replicas: 0,
        };

        let mut tracked_only_to_local = connect_p2p_client(
            tracked_only_node.clone(),
            local_node.clone(),
            connector.as_ref(),
        )
        .await?;
        let track_only_response = tracked_only_to_local
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(tracked_only_node.responder_content()?.unwrap()),
            })
            .await?;
        assert_eq!(
            track_only_response.into_inner().storage_result,
            bbrpc::SetContentRevisionStorageResult::SidecarOnly as i32
        );

        protected_server.abort();
        local_node.evict_cached_peer_client(protected_node.address());

        let pinned_inventory = peer_inventory_entry(local_node.as_ref(), pinned_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing pinned peer inventory entry"))?;
        assert_eq!(
            pinned_inventory.storage_protection,
            PeerStorageProtectionClass::Pinned
        );
        assert_eq!(pinned_inventory.stored_content_bytes, pinned_length);
        assert!(!pinned_inventory.tracked_only);

        let protected_inventory =
            peer_inventory_entry(local_node.as_ref(), protected_node.address())?
                .ok_or_else(|| anyhow::anyhow!("missing protected peer inventory entry"))?;
        assert_eq!(
            protected_inventory.storage_protection,
            PeerStorageProtectionClass::Protected
        );
        assert_eq!(protected_inventory.stored_content_bytes, protected_length);

        let disposable_inventory =
            peer_inventory_entry(local_node.as_ref(), disposable_node.address())?
                .ok_or_else(|| anyhow::anyhow!("missing disposable peer inventory entry"))?;
        assert_eq!(
            disposable_inventory.storage_protection,
            PeerStorageProtectionClass::Disposable
        );
        assert_eq!(disposable_inventory.stored_content_bytes, disposable_length);

        let tracked_only_inventory =
            peer_inventory_entry(local_node.as_ref(), tracked_only_node.address())?
                .ok_or_else(|| anyhow::anyhow!("missing tracked-only peer inventory entry"))?;
        assert!(tracked_only_inventory.tracked_only);
        assert_eq!(
            tracked_only_inventory.storage_protection,
            PeerStorageProtectionClass::None
        );
        assert_eq!(tracked_only_inventory.stored_content_bytes, 0);

        let storage_info = local_node.storage_info().await?;
        assert_eq!(storage_info.pinned_peers_storage_bytes, pinned_length);
        assert_eq!(storage_info.protected_peers_storage_bytes, protected_length);
        assert_eq!(
            storage_info.disposable_peers_storage_bytes,
            disposable_length
        );
        assert_eq!(storage_info.tracked_only_peers_count, 1);
        assert_eq!(
            storage_info.offline_blocking_storage_bytes,
            protected_length
        );
        assert_eq!(
            storage_info.reclaimable_peer_storage_bytes,
            disposable_length
        );
        assert!(storage_info.replica_horizon.is_empty());

        local_server.abort();
        pinned_server.abort();
        disposable_server.abort();
        tracked_only_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn storage_info_reports_replica_horizon_for_verified_peers() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let peer_a_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let peer_b_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let peer_c_clock = Arc::new(ManualClock::new(Timestamp::new(1_000, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage_and_clock(
            "owner-horizon",
            owner_filesystem,
            owner_clock,
        )?);
        let peer_a_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_a = Arc::new(Node::with_local_storage_and_clock(
            "peer-a-horizon",
            peer_a_filesystem,
            peer_a_clock,
        )?);
        let peer_b_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_b = Arc::new(Node::with_local_storage_and_clock(
            "peer-b-horizon",
            peer_b_filesystem,
            peer_b_clock,
        )?);
        let peer_c_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_c = Arc::new(Node::with_local_storage_and_clock(
            "peer-c-horizon",
            peer_c_filesystem,
            peer_c_clock,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner_node.set_peer_connector(connector.clone());
        peer_a.set_peer_connector(connector.clone());
        peer_b.set_peer_connector(connector.clone());
        peer_c.set_peer_connector(connector.clone());

        for peer_onion in [peer_a.address(), peer_b.address(), peer_c.address()] {
            owner_node.add_known_peer(peer_onion)?;
        }

        let owner_public_key = keys::public_key_from_onion_hostname(owner_node.address())?;
        for peer in [&peer_a, &peer_b, &peer_c] {
            peer.add_known_peer(owner_node.address())?;
        }
        peer_c.pin_peer(owner_node.address())?;
        peer_a.with_store(|store| store.set_peer_score(owner_public_key.as_bytes(), 30, 1_000))?;
        peer_b.with_store(|store| store.set_peer_score(owner_public_key.as_bytes(), 120, 1_000))?;
        peer_c.with_store(|store| store.set_peer_score(owner_public_key.as_bytes(), 300, 1_000))?;

        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "owner.txt".to_string(),
                    data: b"owner-data".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_server =
            spawn_registered_p2p_server(owner_node.clone(), connector.as_ref()).await?;
        let peer_a_server = spawn_registered_p2p_server(peer_a.clone(), connector.as_ref()).await?;
        let peer_b_server = spawn_registered_p2p_server(peer_b.clone(), connector.as_ref()).await?;
        let peer_c_server = spawn_registered_p2p_server(peer_c.clone(), connector.as_ref()).await?;

        for peer_onion in [peer_a.address(), peer_b.address(), peer_c.address()] {
            owner_node.publish_to_peer_updates(peer_onion).await?;
            let check = owner_node.verify_peer_storage_updates(peer_onion).await?;
            assert!(check.last().is_some_and(|update| update.success));
        }

        let storage_info = owner_node.storage_info().await?;
        assert_eq!(
            storage_info.replica_horizon,
            vec![
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 2,
                    seconds_until_threshold: 30,
                    never: false,
                },
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 1,
                    seconds_until_threshold: 120,
                    never: false,
                },
                clirpc::ReplicaHorizonPoint {
                    remaining_fresh_replicas: 0,
                    seconds_until_threshold: 0,
                    never: true,
                },
            ]
        );

        owner_server.abort();
        peer_a_server.abort();
        peer_b_server.abort();
        peer_c_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_plan_counts_live_synced_replicas_without_verification(
    ) -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage(
            "maintenance-plan-owner",
            owner_filesystem,
        )?);
        let verified_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let verified_peer = Arc::new(Node::with_local_storage(
            "maintenance-plan-verified",
            verified_filesystem,
        )?);
        let synced_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let synced_unverified_peer = Arc::new(Node::with_local_storage(
            "maintenance-plan-synced",
            synced_filesystem,
        )?);
        let unsynced_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let unsynced_peer = Arc::new(Node::with_local_storage(
            "maintenance-plan-unsynced",
            unsynced_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        verified_peer.set_peer_connector(connector.clone());
        synced_unverified_peer.set_peer_connector(connector.clone());
        unsynced_peer.set_peer_connector(connector.clone());

        owner.add_known_peer(verified_peer.address())?;
        owner.add_known_peer(synced_unverified_peer.address())?;
        owner.add_known_peer(unsynced_peer.address())?;
        verified_peer.add_known_peer(owner.address())?;
        synced_unverified_peer.add_known_peer(owner.address())?;
        unsynced_peer.add_known_peer(owner.address())?;
        *owner.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
            min_replicas: 2,
        };

        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let verified_server =
            spawn_registered_p2p_server(verified_peer.clone(), connector.as_ref()).await?;
        let synced_server =
            spawn_registered_p2p_server(synced_unverified_peer.clone(), connector.as_ref()).await?;
        let unsynced_server =
            spawn_registered_p2p_server(unsynced_peer.clone(), connector.as_ref()).await?;

        owner
            .publish_to_peer_updates(verified_peer.address())
            .await?;
        owner
            .verify_peer_storage_updates(verified_peer.address())
            .await?;
        owner
            .publish_to_peer_updates(synced_unverified_peer.address())
            .await?;

        let plan = owner.background_maintenance_plan().await?;
        assert_eq!(plan.fresh_replica_count, 2);
        assert_eq!(plan.min_replicas_target, 2);

        let actions = plan
            .peer_actions
            .into_iter()
            .map(|action| (action.peer_onion.clone(), action))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            actions.get(verified_peer.address()),
            Some(&BackgroundMaintenancePeerAction {
                peer_onion: verified_peer.address().to_string(),
                propose: false,
                check: true,
            })
        );
        assert_eq!(
            actions.get(synced_unverified_peer.address()),
            Some(&BackgroundMaintenancePeerAction {
                peer_onion: synced_unverified_peer.address().to_string(),
                check: true,
                propose: false,
            })
        );
        assert!(!actions.contains_key(unsynced_peer.address()));

        unsynced_server.abort();
        synced_server.abort();
        verified_server.abort();
        owner_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_plan_skips_unsynced_peers_without_replica_target(
    ) -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage(
            "maintenance-zero-target-owner",
            owner_filesystem,
        )?);
        let fresh_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let fresh_peer = Arc::new(Node::with_local_storage(
            "maintenance-zero-target-fresh",
            fresh_filesystem,
        )?);
        let unsynced_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let unsynced_peer = Arc::new(Node::with_local_storage(
            "maintenance-zero-target-unsynced",
            unsynced_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        fresh_peer.set_peer_connector(connector.clone());
        unsynced_peer.set_peer_connector(connector.clone());
        owner.add_known_peer(fresh_peer.address())?;
        owner.add_known_peer(unsynced_peer.address())?;
        fresh_peer.add_known_peer(owner.address())?;
        unsynced_peer.add_known_peer(owner.address())?;

        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        *owner.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
            min_replicas: 0,
        };

        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let fresh_server =
            spawn_registered_p2p_server(fresh_peer.clone(), connector.as_ref()).await?;
        let unsynced_server =
            spawn_registered_p2p_server(unsynced_peer.clone(), connector.as_ref()).await?;
        owner.publish_to_peer_updates(fresh_peer.address()).await?;
        owner
            .verify_peer_storage_updates(fresh_peer.address())
            .await?;

        let plan = owner.background_maintenance_plan().await?;
        assert_eq!(plan.fresh_replica_count, 1);
        assert_eq!(plan.min_replicas_target, 0);
        assert_eq!(
            plan.peer_actions,
            vec![BackgroundMaintenancePeerAction {
                peer_onion: fresh_peer.address().to_string(),
                propose: false,
                check: true,
            }]
        );

        unsynced_server.abort();
        fresh_server.abort();
        owner_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn background_maintenance_plan_reciprocates_with_stored_peer_even_at_target(
    ) -> anyhow::Result<()> {
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner = Arc::new(Node::with_local_storage(
            "maintenance-reciprocal-owner",
            owner_filesystem,
        )?);
        let fresh_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let fresh_peer = Arc::new(Node::with_local_storage(
            "maintenance-reciprocal-fresh",
            fresh_filesystem,
        )?);
        let reciprocal_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let reciprocal_peer = Arc::new(Node::with_local_storage(
            "maintenance-reciprocal-peer",
            reciprocal_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner.set_peer_connector(connector.clone());
        fresh_peer.set_peer_connector(connector.clone());
        reciprocal_peer.set_peer_connector(connector.clone());
        owner.add_known_peer(fresh_peer.address())?;
        owner.add_known_peer(reciprocal_peer.address())?;
        fresh_peer.add_known_peer(owner.address())?;
        reciprocal_peer.add_known_peer(owner.address())?;

        CliService::new(owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "owner.txt".to_string(),
                    data: b"owner-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(reciprocal_peer.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "peer.txt".to_string(),
                    data: b"peer-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        *owner.storage_config.lock().unwrap() = clirpc::StorageConfig {
            allocated_storage_for_peers: DEFAULT_ALLOCATED_STORAGE_FOR_PEERS,
            min_replicas: 1,
        };

        let owner_server = spawn_registered_p2p_server(owner.clone(), connector.as_ref()).await?;
        let fresh_server =
            spawn_registered_p2p_server(fresh_peer.clone(), connector.as_ref()).await?;
        let reciprocal_server =
            spawn_registered_p2p_server(reciprocal_peer.clone(), connector.as_ref()).await?;
        owner.publish_to_peer_updates(fresh_peer.address()).await?;
        owner
            .verify_peer_storage_updates(fresh_peer.address())
            .await?;
        reciprocal_peer
            .publish_to_peer_updates(owner.address())
            .await?;

        let plan = owner.background_maintenance_plan().await?;
        let actions = plan
            .peer_actions
            .iter()
            .map(|action| (action.peer_onion.clone(), action.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(plan.fresh_replica_count, 1);
        assert_eq!(plan.min_replicas_target, 1);
        assert_eq!(
            actions.get(fresh_peer.address()),
            Some(&BackgroundMaintenancePeerAction {
                peer_onion: fresh_peer.address().to_string(),
                propose: false,
                check: true,
            })
        );
        assert_eq!(
            actions.get(reciprocal_peer.address()),
            Some(&BackgroundMaintenancePeerAction {
                peer_onion: reciprocal_peer.address().to_string(),
                propose: true,
                check: true,
            })
        );

        reciprocal_server.abort();
        fresh_server.abort();
        owner_server.abort();
        Ok(())
    }

    #[test]
    fn choose_publication_candidates_prioritizes_reciprocal_storage_first() {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rng = StdRng::seed_from_u64(7);
        let selected = choose_publication_candidates(
            &[
                PublicationCandidate {
                    peer_onion: "reciprocal.onion".to_string(),
                    pinned_by_us: false,
                    pins_us: false,
                    first_seen_at: (100, 0),
                    successful_calls: 0,
                    failed_calls: 0,
                    stores_peer_data: true,
                },
                PublicationCandidate {
                    peer_onion: "ordinary.onion".to_string(),
                    pinned_by_us: true,
                    pins_us: true,
                    first_seen_at: (0, 0),
                    successful_calls: 100,
                    failed_calls: 0,
                    stores_peer_data: false,
                },
            ],
            1,
            10_000,
            &mut rng,
        );

        assert_eq!(selected, vec!["reciprocal.onion".to_string()]);
    }

    #[test]
    fn choose_publication_candidates_biases_toward_pinned_older_available_peers() {
        use rand::{rngs::StdRng, SeedableRng};

        let strong = PublicationCandidate {
            peer_onion: "strong.onion".to_string(),
            pinned_by_us: true,
            pins_us: true,
            first_seen_at: (0, 0),
            successful_calls: 100,
            failed_calls: 2,
            stores_peer_data: false,
        };
        let weak = PublicationCandidate {
            peer_onion: "weak.onion".to_string(),
            pinned_by_us: false,
            pins_us: false,
            first_seen_at: (9_900, 0),
            successful_calls: 0,
            failed_calls: 8,
            stores_peer_data: false,
        };
        let mut rng = StdRng::seed_from_u64(9);
        let mut strong_wins = 0usize;
        for _ in 0..256 {
            let selected =
                choose_publication_candidates(&[strong.clone(), weak.clone()], 1, 10_000, &mut rng);
            if selected == vec!["strong.onion".to_string()] {
                strong_wins = strong_wins.saturating_add(1);
            }
        }

        assert!(
            strong_wins > 200,
            "strong peer won only {strong_wins} draws"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn advertisement_download_latency_deducts_from_peer_score_once() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "latency-score-owner",
            filesystem,
            clock.clone(),
        )?);
        let peer_identity = Node::new("latency-score-peer")?;
        node.add_known_peer(peer_identity.address())?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 100, 100))?;

        CliService::new(node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let content = node.responder_content()?.unwrap();
        assert_eq!(
            node.record_requester_advertisement_attempt(&peer_public_key, &content)?,
            0
        );

        clock.set(Timestamp::new(112, 0).unwrap());
        let latency = node
            .record_requester_advertised_download(&peer_public_key, &content.content_id)?
            .context("missing completed download latency")?;
        assert_eq!(latency, 12);
        let new_score = node
            .adjust_peer_score_direct(&peer_public_key, -latency)?
            .context("missing updated score")?;
        assert_eq!(new_score, 88);
        assert_eq!(
            node.record_requester_advertised_download(&peer_public_key, &content.content_id)?,
            None
        );
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            88
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn superseded_pending_advertisement_deducts_from_peer_score() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "superseded-score-owner",
            filesystem,
            clock.clone(),
        )?);
        let peer_identity = Node::new("superseded-score-peer")?;
        node.add_known_peer(peer_identity.address())?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 100, 100))?;

        let content_a = bbrpc::ContentInfo {
            content_id: vec![1; CONTENT_ID_LEN],
            content_length: 111,
        };
        let content_b = bbrpc::ContentInfo {
            content_id: vec![2; CONTENT_ID_LEN],
            content_length: 222,
        };
        assert_eq!(
            node.record_requester_advertisement_attempt(&peer_public_key, &content_a)?,
            0
        );
        clock.set(Timestamp::new(109, 0).unwrap());
        let penalty = node.record_requester_advertisement_attempt(&peer_public_key, &content_b)?;
        assert_eq!(penalty, 9);
        let new_score = node
            .adjust_peer_score_direct(&peer_public_key, -penalty)?
            .context("missing updated score")?;
        assert_eq!(new_score, 91);
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            91
        );
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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_node.responder_content()?.unwrap()),
            })
            .await?;

        let first_updates = requester_cli
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
    async fn check_contract_can_probe_untracked_peer_when_capacity_is_full() -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-capacity-full-probe",
            requester_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());

        for index in 0..MAX_TRACKED_PEERS {
            let master = test_master_priv(&format!("tracked-capacity-peer-{index}"));
            let peer = Node::new_for_tests_from_master(&master)?;
            let public_key = keys::public_key_from_onion_hostname(peer.address())?;
            requester_node.track_peer_identity_with_capacity(
                &public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
                MAX_TRACKED_PEERS,
            )?;
        }
        assert_eq!(requester_node.known_peers().len(), MAX_TRACKED_PEERS);

        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage(
            "responder-capacity-full-probe",
            responder_filesystem,
        )?);
        responder_node.set_peer_connector(connector.clone());
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;

        let updates = requester_node
            .verify_peer_storage_updates(responder_node.address())
            .await?;
        let responder_public_key = keys::public_key_from_onion_hostname(responder_node.address())?;

        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(requester_node.known_peers().len(), MAX_TRACKED_PEERS);
        assert!(!requester_node
            .known_peers()
            .contains(&responder_node.address().to_string()));
        assert!(!requester_node.is_tracked_peer(&responder_public_key)?);
        assert_eq!(requester_node.tracked_peers()?.len(), MAX_TRACKED_PEERS);

        responder_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_failure_does_not_track_untracked_peer_when_capacity_is_full(
    ) -> anyhow::Result<()> {
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage(
            "requester-capacity-full-offline-probe",
            requester_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());

        for index in 0..MAX_TRACKED_PEERS {
            let master = test_master_priv(&format!("tracked-offline-peer-{index}"));
            let peer = Node::new_for_tests_from_master(&master)?;
            let public_key = keys::public_key_from_onion_hostname(peer.address())?;
            requester_node.track_peer_identity_with_capacity(
                &public_key,
                peer_origin_code(false, false),
                storedpb::FirstContactDirection::Inbound as i32,
                MAX_TRACKED_PEERS,
            )?;
        }
        assert_eq!(requester_node.known_peers().len(), MAX_TRACKED_PEERS);

        let offline_peer = Node::new("untracked-offline-probe")?;
        let offline_public_key = keys::public_key_from_onion_hostname(offline_peer.address())?;
        let updates = requester_node
            .verify_peer_storage_updates_with_policy(
                offline_peer.address(),
                test_check_retry_policy(),
            )
            .await?;

        assert_eq!(updates.last().map(|update| update.success), Some(false));
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::PeerStorageOperationState::PeerUnavailable as i32)
        );
        assert_eq!(requester_node.known_peers().len(), MAX_TRACKED_PEERS);
        assert!(!requester_node
            .known_peers()
            .contains(&offline_peer.address().to_string()));
        assert!(!requester_node.is_tracked_peer(&offline_public_key)?);
        assert_eq!(requester_node.tracked_peers()?.len(), MAX_TRACKED_PEERS);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn successful_check_contract_does_not_immediately_flush_pending_peer_metadata(
    ) -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let mut timer_intercepts =
            requester_clock.subscribe_timer_intercepts(TIMER_LABEL_PEER_METADATA_FLUSH_DELAY);
        let responder_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_base: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_counting = Arc::new(CountingFilesystem {
            inner: requester_base.clone(),
            peer_state_writes: AtomicUsize::new(0),
        });
        let requester_filesystem: Arc<dyn Filesystem> = requester_counting.clone();
        let requester_node = Arc::new(Node::with_local_storage_and_clock_and_flush_delay(
            "requester-delayed-check",
            requester_filesystem,
            requester_clock.clone(),
            Duration::from_secs(60),
        )?);
        let responder_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let responder_node = Arc::new(Node::with_local_storage_and_clock(
            "responder-delayed-check",
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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_node.responder_content()?.unwrap()),
            })
            .await?;

        let first_updates = requester_cli
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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

        let first_timer = timer_intercepts
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("missing first delayed metadata timer"))?;
        let writes_before_first_flush = requester_counting.peer_state_writes();
        requester_clock.advance(first_timer.duration);
        wait_until(|| requester_counting.peer_state_writes() == writes_before_first_flush + 1)
            .await;
        let writes_after_first_flush = requester_counting.peer_state_writes();
        let peer_before_second =
            peer_inventory_entry(&requester_node, responder_node.address())?
                .ok_or_else(|| anyhow::anyhow!("missing responder peer after first check"))?;

        requester_clock.advance(Duration::from_secs(1));
        let second_updates = requester_cli
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
        let peer_after_second = peer_inventory_entry(&requester_node, responder_node.address())?
            .ok_or_else(|| anyhow::anyhow!("missing responder peer after second check"))?;
        assert_eq!(
            requester_counting.peer_state_writes(),
            writes_after_first_flush,
            "second successful check should not flush pending low-value peer metadata immediately; before={peer_before_second:?} after={peer_after_second:?}",
        );
        assert_eq!(
            peer_before_second.latest_known_content_length,
            peer_after_second.latest_known_content_length
        );
        assert_eq!(
            peer_before_second.latest_cached_content_length,
            peer_after_second.latest_cached_content_length
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
                    ..Default::default()
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
            .verify_peer_storage_updates(peer_identity.address())
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
    async fn check_contract_penalizes_retry_exhausted_transport_failures() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-check-transport-failure",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let peer_identity = Node::new("check-transport-failure-peer")?;
        let base_connector = Arc::new(netmock::MockPeerConnector::new());
        let flaky_connector = Arc::new(FlakyPeerConnector::new(base_connector, usize::MAX));
        requester_node.set_peer_connector(flaky_connector.clone());
        requester_node.add_known_peer(peer_identity.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

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
            .verify_peer_storage_updates_with_policy(
                peer_identity.address(),
                test_check_retry_policy(),
            )
            .await?;
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::PeerStorageOperationState::PeerUnavailable as i32)
        );
        assert_eq!(updates.last().map(|update| update.success), Some(false));
        assert!(flaky_connector.dial_count() >= 2);
        assert_eq!(
            peer_score_seconds(requester_node.as_ref(), peer_identity.address())?,
            -3_600
        );
        let inventory = peer_inventory_entry(requester_node.as_ref(), peer_identity.address())?
            .expect("missing peer inventory entry");
        assert_eq!(
            inventory.last_error_class,
            clirpc::PeerFailureClass::Transport as i32
        );
        assert!(inventory.last_error_message.contains("transport error"));
        assert!(inventory.last_failure_at > 0);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_penalizes_retry_exhausted_revision_failures() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-check-revision-failure",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let peer_identity = Node::new("check-revision-failure-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(peer_identity.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        requester_node.with_store(|store| {
            store.set_peer_score(
                peer_public_key.as_bytes(),
                0,
                i64::try_from(requester_clock.now().secs).unwrap_or(i64::MAX),
            )
        })?;

        let (endpoint, server) =
            spawn_plain_peer_server(RetryableRevisionFailurePeerService).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        requester_clock.advance(Duration::from_secs(1_800));
        let updates = requester_node
            .verify_peer_storage_updates_with_policy(
                peer_identity.address(),
                test_check_retry_policy(),
            )
            .await?;
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::PeerStorageOperationState::PeerUnavailable as i32)
        );
        assert_eq!(updates.last().map(|update| update.success), Some(false));
        assert_eq!(
            peer_score_seconds(requester_node.as_ref(), peer_identity.address())?,
            -1_800
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn check_contract_penalizes_retry_exhausted_download_timeouts() -> anyhow::Result<()> {
        let requester_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let requester_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let requester_node = Arc::new(Node::with_local_storage_and_clock(
            "requester-check-download-timeout",
            requester_filesystem,
            requester_clock.clone(),
        )?);
        let peer_identity = Node::new("check-download-timeout-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        requester_node.set_peer_connector(connector.clone());
        requester_node.add_known_peer(peer_identity.address())?;

        let requester_cli = CliService::new(requester_node.clone());
        requester_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let requester_content = requester_node.responder_content()?.unwrap();
        let requester_blob = requester_node.with_store(|store| store.current_blob())?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        requester_node.with_store(|store| {
            store.set_peer_score(
                peer_public_key.as_bytes(),
                0,
                i64::try_from(requester_clock.now().secs).unwrap_or(i64::MAX),
            )
        })?;

        let (endpoint, server) = spawn_plain_peer_server(TimeoutDownloadPeerService::new(
            requester_content,
            requester_blob,
        ))
        .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        requester_clock.advance(Duration::from_secs(900));
        let updates = requester_node
            .verify_peer_storage_updates_with_policy(
                peer_identity.address(),
                test_check_retry_policy(),
            )
            .await?;
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::PeerStorageOperationState::PeerUnavailable as i32)
        );
        assert_eq!(updates.last().map(|update| update.success), Some(false));
        assert_eq!(
            peer_score_seconds(requester_node.as_ref(), peer_identity.address())?,
            -900
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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(requester_node.responder_content()?.unwrap()),
            })
            .await?;

        requester_clock.advance(Duration::from_secs(3_600));
        requester_cli
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
            Some(clirpc::PeerStorageOperationState::PeerMissingOurContent as i32)
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
                    ..Default::default()
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(node.as_ref())?;
        let peer_public_key = keys::public_key_from_onion_hostname(peer_identity.address())?;
        node.with_store(|store| store.set_peer_score(peer_public_key.as_bytes(), 0, 10))?;

        // Return the right sampled bytes and hash but lie about total_length.
        let static_service = StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(content_info.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(content_info.clone()),
                requester_pinned: false,
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

        clock.advance(Duration::from_secs(90));
        let updates = node
            .verify_peer_storage_updates(peer_identity.address())
            .await?;
        assert_eq!(
            updates.last().map(|update| update.state),
            Some(clirpc::PeerStorageOperationState::InvalidContentReturned as i32)
        );
        assert_eq!(
            peer_score_seconds(node.as_ref(), peer_identity.address())?,
            -90
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_merges_peer_exchange_results_with_cooldown() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage_and_clock(
            "proposal-exchange-owner",
            filesystem,
            clock.clone(),
        )?);
        let peer_identity = Node::new("proposal-exchange-peer")?;
        let learned_peer = Node::new("proposal-exchange-learned")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        node.add_known_peer(peer_identity.address())?;

        CliService::new(node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let exchange_state = Arc::new(PeerExchangeState::new(
            bbrpc::GetContentRevisionResponse::default(),
            vec![
                bbrpc::Peer {
                    onion_pubkey: learned_peer.ed25519_keypair().public.to_bytes().to_vec(),
                },
                bbrpc::Peer {
                    onion_pubkey: peer_identity.ed25519_keypair().public.to_bytes().to_vec(),
                },
                bbrpc::Peer {
                    onion_pubkey: node.ed25519_keypair().public.to_bytes().to_vec(),
                },
                bbrpc::Peer {
                    onion_pubkey: vec![0x55; 3],
                },
            ],
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(PeerExchangePeerService::new(exchange_state.clone())).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let first = node
            .publish_to_peer_updates(peer_identity.address())
            .await?;
        assert_eq!(first.last().map(|update| update.success), Some(true));
        assert_eq!(exchange_state.peer_exchange_call_count(), 1);
        assert!(node
            .known_peers()
            .contains(&learned_peer.address().to_string()));

        let second = node
            .publish_to_peer_updates(peer_identity.address())
            .await?;
        assert_eq!(second.last().map(|update| update.success), Some(true));
        assert_eq!(exchange_state.peer_exchange_call_count(), 1);

        clock.advance(Duration::from_secs(
            u64::try_from(PEER_EXCHANGE_COOLDOWN_SECS + 1).unwrap_or(u64::MAX),
        ));
        let third = node
            .publish_to_peer_updates(peer_identity.address())
            .await?;
        assert_eq!(third.last().map(|update| update.success), Some(true));
        assert_eq!(exchange_state.peer_exchange_call_count(), 2);

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_merges_peer_exchange_results() -> anyhow::Result<()> {
        let filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let node = Arc::new(Node::with_local_storage(
            "recovery-exchange-owner",
            filesystem,
        )?);
        let peer_identity = Node::new("recovery-exchange-peer")?;
        let learned_peer = Node::new("recovery-exchange-learned")?;
        let connector = Arc::new(PlainPeerConnector::new());
        node.set_peer_connector(connector.clone());
        node.add_known_peer(peer_identity.address())?;

        let exchange_state = Arc::new(PeerExchangeState::new(
            bbrpc::GetContentRevisionResponse::default(),
            vec![bbrpc::Peer {
                onion_pubkey: learned_peer.ed25519_keypair().public.to_bytes().to_vec(),
            }],
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(PeerExchangePeerService::new(exchange_state.clone())).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let update = node.run_recovery_pass().await?;
        assert_eq!(update.applied_versions, 0);
        assert_eq!(exchange_state.peer_exchange_call_count(), 1);
        assert!(node
            .known_peers()
            .contains(&learned_peer.address().to_string()));

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn propose_contract_publishes_our_side_and_accepts_peer_publication() -> anyhow::Result<()>
    {
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
                    ..Default::default()
                }),
            }))
            .await?;
        right_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "right.txt".to_string(),
                    data: b"right-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let left_server =
            spawn_registered_p2p_server(left_node.clone(), connector.as_ref()).await?;
        let right_server =
            spawn_registered_p2p_server(right_node.clone(), connector.as_ref()).await?;
        let updates = left_cli
            .publish_to_peer(tonic::Request::new(clirpc::PublishToPeerRequest {
                peer: Some(clirpc::Peer {
                    onion_service_id: right_node.address().to_string(),
                }),
            }))
            .await?
            .into_inner()
            .try_collect::<Vec<_>>()
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        publish_current_content_to_peer(right_node.clone(), left_node.clone(), connector.as_ref())
            .await?;

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
                    ..Default::default()
                }),
            }))
            .await?;

        let left_server =
            spawn_registered_p2p_server(left_node.clone(), base_connector.as_ref()).await?;
        let right_server =
            spawn_registered_p2p_server(right_node.clone(), base_connector.as_ref()).await?;

        let updates = left_node
            .publish_to_peer_updates(right_node.address())
            .await?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));
        assert_eq!(flaky_connector.dial_count(), 4);
        let inventory = peer_inventory_entry(left_node.as_ref(), right_node.address())?
            .expect("missing peer inventory entry");
        assert_eq!(
            inventory.last_error_class,
            clirpc::PeerFailureClass::Unknown as i32
        );
        assert!(inventory.last_error_message.is_empty());
        assert_eq!(inventory.last_failure_at, 0);

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
                ..Default::default()
            }),
        }))
        .await?;

        let service_state = Arc::new(TransientSetAckState::new());
        let (endpoint, server) =
            spawn_plain_peer_server(TransientSetAckPeerService::new(service_state.clone())).await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let updates = node
            .publish_to_peer_updates(peer_identity.address())
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
        recovered_node.initialize_lineage((i64::MAX, 0), false)?;
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
                    ..Default::default()
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
                previous_requester_content: None,
                requester_content: Some(owner_node.responder_content()?.unwrap()),
            })
            .await?;

        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.applied_versions, 1);
        assert_eq!(
            update.latest_applied_content_id,
            owner_node.responder_content()?.unwrap().content_id
        );
        assert!(flaky_connector.dial_count() >= 3);
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
        recovered_node.initialize_lineage((i64::MAX, 0), false)?;
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
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_content = owner_node.responder_content()?.unwrap();
        let owner_blob = owner_node.with_store(|store| store.current_blob())?;
        let service_state = Arc::new(TransientDownloadState::new(
            owner_content.clone(),
            owner_blob,
        ));
        let (endpoint, server) =
            spawn_plain_peer_server(TransientDownloadPeerService::new(service_state.clone()))
                .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.applied_versions, 1);
        assert_eq!(update.downloaded_bytes, owner_content.content_length);
        assert_eq!(service_state.download_call_count(), 2);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn outbound_live_peer_contact_runs_automatic_recovery() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage_and_clock(
            "live-contact-recovery-owner",
            owner_filesystem,
            owner_clock,
        )?);
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_node = Arc::new(Node::with_local_storage(
            "live-contact-recovery-peer",
            peer_filesystem,
        )?);
        let recovered_clock = Arc::new(ManualClock::new(Timestamp::new(250, 0).unwrap()));
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage_and_clock(
            "live-contact-recovery-owner",
            recovered_filesystem,
            recovered_clock,
        )?);
        recovered_node.initialize_lineage((250, 0), true)?;
        recovered_node.add_known_peer(peer_node.address())?;

        let connector = Arc::new(netmock::MockPeerConnector::new());
        owner_node.set_peer_connector(connector.clone());
        peer_node.set_peer_connector(connector.clone());
        recovered_node.set_peer_connector(connector.clone());

        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let owner_server =
            spawn_registered_p2p_server(owner_node.clone(), connector.as_ref()).await?;
        let peer_server =
            spawn_registered_p2p_server(peer_node.clone(), connector.as_ref()).await?;
        let mut owner_to_peer =
            connect_p2p_client(owner_node.clone(), peer_node.clone(), connector.as_ref()).await?;
        owner_to_peer
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(owner_node.responder_content()?.unwrap()),
            })
            .await?;

        let _peer_client = recovered_node
            .connect_peer_client(peer_node.address())
            .await?;
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        owner_server.abort();
        peer_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inbound_live_peer_contact_runs_automatic_recovery() -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage_and_clock(
            "inbound-contact-recovery-owner",
            owner_filesystem,
            owner_clock,
        )?);
        let recovered_clock = Arc::new(ManualClock::new(Timestamp::new(250, 0).unwrap()));
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage_and_clock(
            "inbound-contact-recovery-owner",
            recovered_filesystem,
            recovered_clock,
        )?);
        recovered_node.initialize_lineage((250, 0), true)?;
        let peer_identity = Arc::new(Node::new("inbound-contact-recovery-peer")?);
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());

        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(owner_node.as_ref())?;
        let (peer_endpoint, peer_server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(content_info.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(content_info.clone()),
                requester_pinned: false,
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob.clone(),
                    },
                )),
            }),
        ))
        .await?;
        connector.register_peer(peer_identity.address(), &peer_endpoint);

        let (recovered_endpoint, recovered_server) =
            spawn_p2p_server(recovered_node.clone()).await?;
        let channel = netmock::connect_peer_channel(
            &recovered_endpoint,
            recovered_node.address(),
            &peer_identity.ed25519_keypair().secret,
        )
        .await?;
        let mut peer_to_recovered = BarterBackupServerClient::new(channel);
        let _response = peer_to_recovered
            .health_check(bbrpc::HealthCheckRequest {})
            .await?;

        wait_until(|| {
            recovered_node
                .with_store(|store| store.get_file("alpha.txt"))
                .map(|bytes| bytes == b"alpha-body".to_vec())
                .unwrap_or(false)
        })
        .await;

        peer_server.abort();
        recovered_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_restores_missing_current_blob_from_stored_peer_revision(
    ) -> anyhow::Result<()> {
        let local_filesystem = Arc::new(storage::MemoryFilesystem::new());
        let local_node = Arc::new(Node::with_local_storage(
            "recover-current-owner",
            local_filesystem.clone(),
        )?);
        let peer_identity = Node::new("recover-current-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        local_node.set_peer_connector(connector.clone());
        local_node.add_known_peer(peer_identity.address())?;

        CliService::new(local_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"alpha-body".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(local_node.as_ref())?;
        let blob_file_name = local_node.with_store(|store| {
            Ok(store
                .current_content()
                .map(|current| current.file_name.clone())
                .ok_or(StorageError::FileNotFound)?)
        })?;
        local_filesystem.remove(&blob_file_name)?;
        let missing_blob = local_node.with_store(|store| match store.current_blob() {
            Ok(_) => Ok(false),
            Err(StorageError::FileNotFound) => Ok(true),
            Err(error) => Err(error),
        })?;
        assert!(missing_blob);
        assert!(local_node.current_content_needs_restore_from_peer(&content_info.content_id)?);

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(content_info.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(content_info.clone()),
                requester_pinned: false,
            },
            DownloadBehavior::Response(bbrpc::DownloadResponse {
                total_length: i64::try_from(blob.len()).unwrap_or(i64::MAX),
                sha256: Sha256::digest(&blob).to_vec(),
                section: Some(bbrpc::download_response::Section::RawBytes(
                    bbrpc::RawBytes {
                        value: blob.clone(),
                    },
                )),
            }),
        ))
        .await?;
        connector.register_peer(peer_identity.address(), &endpoint);

        let update = local_node.run_recovery_pass().await?;
        assert_eq!(update.total_versions_found, 1);
        assert_eq!(update.older_lineage_versions_found, 0);
        assert_eq!(update.older_lineage_recoverable_versions_found, 0);
        assert_eq!(update.applied_versions, 1);
        assert_eq!(update.latest_applied_content_id, content_info.content_id);
        assert_eq!(
            update.downloaded_bytes,
            i64::try_from(blob.len()).unwrap_or(i64::MAX)
        );
        assert_eq!(update.added_files, 0);
        assert_eq!(update.renamed_files, 0);
        assert_eq!(update.unchanged_files, 0);
        assert_eq!(local_node.with_store(|store| store.current_blob())?, blob);
        assert_eq!(
            local_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"alpha-body".to_vec()
        );

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_uses_latest_stored_older_lineage_when_newer_known_revision_is_unavailable(
    ) -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage_and_clock(
            "fallback-owner",
            owner_filesystem,
            owner_clock.clone(),
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "fallback-owner",
            recovered_filesystem,
        )?);
        recovered_node.initialize_lineage((300, 0), false)?;
        let stale_peer_identity = Node::new("fallback-stale-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node.add_known_peer(stale_peer_identity.address())?;

        let owner_cli = CliService::new(owner_node.clone());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-1".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let version_1 = owner_node.responder_content()?.unwrap();
        let blob_1 = owner_node.with_store(|store| store.current_blob())?;

        owner_clock.set(Timestamp::new(200, 0).unwrap());
        owner_cli
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-2".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let version_2 = owner_node.responder_content()?.unwrap();
        let stale_service = StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(version_1.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(version_2.clone()),
                requester_pinned: false,
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

        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.total_versions_found, 2);
        assert_eq!(update.older_lineage_versions_found, 2);
        assert_eq!(update.older_lineage_recoverable_versions_found, 1);
        assert_eq!(update.applied_versions, 1);
        assert_eq!(update.newest_found_content_id, version_2.content_id);
        assert_eq!(update.latest_applied_content_id, version_1.content_id);

        let recovered_file = recovered_node.with_store(|store| store.get_file("alpha.txt"))?;
        assert_eq!(recovered_file, b"version-1".to_vec());

        server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_merges_divergent_branches_by_renaming_conflicting_files(
    ) -> anyhow::Result<()> {
        let branch_a_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let branch_b_clock = Arc::new(ManualClock::new(Timestamp::new(200, 0).unwrap()));
        let branch_a_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let branch_a_node = Arc::new(Node::with_local_storage_and_clock(
            "merge-owner",
            branch_a_filesystem,
            branch_a_clock,
        )?);
        let branch_b_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let branch_b_node = Arc::new(Node::with_local_storage_and_clock(
            "merge-owner",
            branch_b_filesystem,
            branch_b_clock,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "merge-owner",
            recovered_filesystem,
        )?);
        recovered_node.initialize_lineage((300, 0), false)?;
        let peer_a_identity = Node::new("merge-peer-a")?;
        let peer_b_identity = Node::new("merge-peer-b")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        recovered_node.add_known_peer(peer_a_identity.address())?;
        recovered_node.add_known_peer(peer_b_identity.address())?;

        CliService::new(branch_a_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"branch-a".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        CliService::new(branch_b_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"branch-b".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let (version_a, blob_a) = current_content_snapshot(branch_a_node.as_ref())?;
        let (version_b, blob_b) = current_content_snapshot(branch_b_node.as_ref())?;

        let (endpoint_a, server_a) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(version_a.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(version_a.clone()),
                requester_pinned: false,
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
                requester_latest_stored_content: Some(version_b.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(version_b.clone()),
                requester_pinned: false,
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

        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.applied_versions, 2);
        assert_eq!(update.added_files, 1);
        assert_eq!(update.renamed_files, 1);
        assert_eq!(update.unchanged_files, 0);
        assert_eq!(update.newest_found_content_id, version_b.content_id);
        assert_eq!(update.latest_applied_content_id, version_b.content_id);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"branch-a".to_vec()
        );
        let listed = recovered_node.with_store(|store| Ok(store.list_file_info()))?;
        assert_eq!(listed.len(), 2);
        let recovered_name = listed
            .iter()
            .find(|file| file.name != "alpha.txt")
            .map(|file| file.name.clone())
            .context("missing renamed recovered file")?;
        assert!(recovered_name.starts_with("alpha.recovered-"));
        assert!(recovered_name.ends_with(".txt"));
        assert_eq!(
            recovered_node.with_store(|store| store.get_file(&recovered_name))?,
            b"branch-b".to_vec()
        );

        server_b.abort();
        server_a.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn recover_content_skips_versions_at_or_below_the_recovery_watermark(
    ) -> anyhow::Result<()> {
        let owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let owner_node = Arc::new(Node::with_local_storage_and_clock(
            "watermark-owner",
            owner_filesystem,
            owner_clock,
        )?);
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage(
            "watermark-owner",
            recovered_filesystem,
        )?);
        recovered_node.initialize_lineage((300, 0), false)?;
        let peer_identity = Node::new("watermark-peer")?;
        let connector = Arc::new(PlainPeerConnector::new());
        recovered_node.set_peer_connector(connector.clone());
        CliService::new(owner_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"version-1".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let (version_1, blob_1) = current_content_snapshot(owner_node.as_ref())?;

        let (endpoint, server) = spawn_plain_peer_server(StaticPeerService::new(
            bbrpc::GetContentRevisionResponse {
                requester_latest_stored_content: Some(version_1.clone()),
                requester_remaining_seconds: 0,
                requester_latest_known_content: Some(version_1.clone()),
                requester_pinned: false,
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
        ))
        .await?;
        connector.register_peer(peer_identity.address(), &endpoint);
        recovered_node.add_known_peer(peer_identity.address())?;

        let initial_update = recovered_node.run_recovery_pass().await?;
        assert_eq!(initial_update.applied_versions, 1);
        assert_eq!(
            initial_update.latest_applied_content_id,
            version_1.content_id
        );
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"version-1".to_vec()
        );
        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.total_versions_found, 1);
        assert_eq!(update.older_lineage_versions_found, 0);
        assert_eq!(update.older_lineage_recoverable_versions_found, 0);
        assert_eq!(update.applied_versions, 0);
        assert!(update.latest_applied_content_id.is_empty());

        server.abort();
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
        recovered_node.initialize_lineage((i64::MAX, 0), false)?;
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
                    ..Default::default()
                }),
            }))
            .await?;
        let (content_info, blob) = current_content_snapshot(owner_node.as_ref())?;
        let revision_response = bbrpc::GetContentRevisionResponse {
            requester_latest_stored_content: Some(content_info.clone()),
            requester_remaining_seconds: 0,
            requester_latest_known_content: Some(content_info.clone()),
            requester_pinned: false,
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

        let update = recovered_node.run_recovery_pass().await?;
        assert_eq!(update.total_versions_found, 1);
        assert_eq!(update.peers_with_any_versions, 2);
        assert_eq!(update.applied_versions, 1);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"latest-body".to_vec()
        );

        bad_server.abort();
        good_server.abort();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn publish_to_peer_updates_run_automatic_recovery_before_publication(
    ) -> anyhow::Result<()> {
        let old_owner_clock = Arc::new(ManualClock::new(Timestamp::new(100, 0).unwrap()));
        let old_owner_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let old_owner = Arc::new(Node::with_local_storage_and_clock(
            "proposal-recovery-owner",
            old_owner_filesystem,
            old_owner_clock,
        )?);
        let recovered_clock = Arc::new(ManualClock::new(Timestamp::new(250, 0).unwrap()));
        let recovered_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let recovered_node = Arc::new(Node::with_local_storage_and_clock(
            "proposal-recovery-owner",
            recovered_filesystem,
            recovered_clock.clone(),
        )?);
        recovered_node.initialize_lineage((250, 0), false)?;
        let peer_filesystem: Arc<dyn Filesystem> = Arc::new(storage::MemoryFilesystem::new());
        let peer_node = Arc::new(Node::with_local_storage(
            "proposal-recovery-peer",
            peer_filesystem,
        )?);
        let connector = Arc::new(netmock::MockPeerConnector::new());
        old_owner.set_peer_connector(connector.clone());
        recovered_node.set_peer_connector(connector.clone());
        peer_node.set_peer_connector(connector.clone());

        CliService::new(old_owner.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"old-branch".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;
        let old_content = old_owner.responder_content()?.unwrap();

        recovered_clock.set(Timestamp::new(300, 0).unwrap());
        CliService::new(recovered_node.clone())
            .set_file(tonic::Request::new(clirpc::SetFileRequest {
                file: Some(clirpc::File {
                    name: "alpha.txt".to_string(),
                    data: b"local-branch".to_vec(),
                    ..Default::default()
                }),
            }))
            .await?;

        let old_owner_server =
            spawn_registered_p2p_server(old_owner.clone(), connector.as_ref()).await?;
        let peer_server =
            spawn_registered_p2p_server(peer_node.clone(), connector.as_ref()).await?;
        let mut owner_to_peer =
            connect_p2p_client(old_owner.clone(), peer_node.clone(), connector.as_ref()).await?;
        owner_to_peer
            .set_content_revision(bbrpc::SetContentRevisionRequest {
                previous_requester_content: None,
                requester_content: Some(old_content.clone()),
            })
            .await
            .context("seed peer with the old owner revision")?;
        old_owner_server.abort();
        peer_node.evict_cached_peer_client(old_owner.address());

        let recovered_server =
            spawn_registered_p2p_server(recovered_node.clone(), connector.as_ref()).await?;

        recovered_node.add_known_peer(peer_node.address())?;
        let updates = recovered_node
            .publish_to_peer_updates(peer_node.address())
            .await
            .context("publish after automatic recovery")?;
        assert_eq!(updates.last().map(|update| update.success), Some(true));

        let listed = recovered_node.with_store(|store| Ok(store.list_file_info()))?;
        assert_eq!(listed.len(), 2);
        assert_eq!(
            recovered_node.with_store(|store| store.get_file("alpha.txt"))?,
            b"local-branch".to_vec()
        );
        let recovered_name = listed
            .iter()
            .find(|file| file.name != "alpha.txt")
            .map(|file| file.name.clone())
            .context("missing recovered file after proposal")?;
        assert!(recovered_name.starts_with("alpha.recovered-"));
        assert!(recovered_name.ends_with(".txt"));
        assert_eq!(
            recovered_node.with_store(|store| store.get_file(&recovered_name))?,
            b"old-branch".to_vec()
        );

        let recovered_content = recovered_node.responder_content()?.unwrap();
        let peer = peer_entry(peer_node.as_ref(), recovered_node.address())?
            .context("peer did not record the recovered node state")?;
        assert_eq!(
            peer.latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(recovered_content.content_id)
        );

        peer_server.abort();
        recovered_server.abort();
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
                    ..Default::default()
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        requester_cli
            .publish_to_peer(tonic::Request::new(clirpc::PublishToPeerRequest {
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
                .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
                    ..Default::default()
                }),
            }))
            .await?;

        let requester_server =
            spawn_registered_p2p_server(requester_node.clone(), connector.as_ref()).await?;
        let responder_server =
            spawn_registered_p2p_server(responder_node.clone(), connector.as_ref()).await?;
        requester_cli
            .publish_to_peer(tonic::Request::new(clirpc::PublishToPeerRequest {
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
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
                    ..Default::default()
                }),
            }))
            .await?;
        requester_clock.advance(Duration::from_secs(1_800));
        let failed_updates = requester_cli
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
            .publish_to_peer(tonic::Request::new(clirpc::PublishToPeerRequest {
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
            .verify_peer_storage(tonic::Request::new(clirpc::VerifyPeerStorageRequest {
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
