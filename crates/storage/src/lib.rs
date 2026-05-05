//! Crash-safe encrypted storage for BarterBackup.
//!
//! The store keeps the active file set as an encrypted content blob, persists
//! peer metadata in a separate encrypted sidecar, and uses atomic writes so a
//! failed update cannot clobber the last valid version.

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use clock::{Clock, SystemClock};
use content::{ContentCodec, DecodedContent, PlainFile, RevisionDescriptor, RevisionSeed};
use prost::Message;
use prost_types::Timestamp as ProtoTimestamp;
use protos::storedpb;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng, RngCore};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;

const PEER_STATE_FILE: &str = ".peer-state.v1";
const PEER_STATE_NONCE_LEN: usize = 12;
const PEER_STATE_TAG_LEN: usize = 16;
const MIRRORED_BLOB_VERSION: u8 = 1;
const MIRRORED_BLOB_NONCE_LEN: usize = 12;
const MIRRORED_BLOB_TAG_LEN: usize = 16;
const METADATA_ROLLUP_MEAN_DELAY_SECS: f64 = 24.0 * 60.0 * 60.0;
/// MAX_SHARED_CONTENT_BLOB_BYTES is the fixed largest local shared blob that
/// may be accepted as the active current revision.
pub const MAX_SHARED_CONTENT_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// StorageError reports persistence, recovery, and validation failures.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The master key is too short to derive subkeys.
    #[error("master key must be at least 32 bytes, got {0}")]
    InvalidMasterKey(usize),

    /// The caller supplied an invalid file name.
    #[error("file name must not be empty")]
    InvalidFileName,

    /// The store could not find the requested file.
    #[error("file not found")]
    FileNotFound,

    /// The current on-disk state needs operator intervention.
    #[error("recovery required: {0}")]
    RecoveryRequired(String),

    /// The provided timestamp is invalid.
    #[error("invalid timestamp")]
    InvalidTimestamp,

    /// The projected shared blob would exceed the fixed local ceiling.
    #[error("current shared content exceeds the fixed 4 MiB limit")]
    LocalContentTooLarge,

    /// The content codec rejected the blob.
    #[error("content error: {0}")]
    Content(#[from] content::ContentError),

    /// The protobuf payload could not be decoded.
    #[error("protobuf error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),

    /// The protobuf payload could not be encoded.
    #[error("protobuf encode error: {0}")]
    ProtobufEncode(#[from] prost::EncodeError),

    /// An I/O error occurred in the backing filesystem.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// A general configuration or crypto setup error occurred.
    #[error("{0}")]
    Message(String),
}

/// Filesystem is the minimal atomic persistence API the store needs.
pub trait Filesystem: Send + Sync {
    /// Read the full contents of a file.
    fn read(&self, name: &str) -> Result<Vec<u8>, StorageError>;

    /// Atomically replace a file with the provided bytes.
    fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Remove a file if it exists.
    fn remove(&self, name: &str) -> Result<(), StorageError>;

    /// List the visible file names.
    fn list(&self) -> Result<Vec<String>, StorageError>;
}

/// MemoryFilesystem is an in-memory implementation used by tests.
#[derive(Debug, Default)]
pub struct MemoryFilesystem {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryFilesystem {
    /// Create an empty in-memory filesystem.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Filesystem for MemoryFilesystem {
    fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        self.files
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or(StorageError::FileNotFound)
    }

    fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        self.files
            .lock()
            .unwrap()
            .insert(name.to_string(), data.to_vec());
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), StorageError> {
        if self.files.lock().unwrap().remove(name).is_some() {
            Ok(())
        } else {
            Err(StorageError::FileNotFound)
        }
    }

    fn list(&self) -> Result<Vec<String>, StorageError> {
        let mut names = self
            .files
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }
}

/// OsFilesystem persists blobs in a directory using temp-file rename.
#[derive(Debug, Clone)]
pub struct OsFilesystem {
    root: Arc<PathBuf>,
}

impl OsFilesystem {
    /// Create an on-disk filesystem rooted at `root`.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        #[cfg(unix)]
        {
            // Create new store directories as private immediately, then repair
            // older existing ones if they were left with weaker permissions.
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(root.as_ref())?;
            fs::set_permissions(root.as_ref(), fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(root.as_ref())?;
        Ok(Self {
            root: Arc::new(root.as_ref().to_path_buf()),
        })
    }

    /// Return the root directory path.
    pub fn root(&self) -> &Path {
        self.root.as_ref().as_path()
    }
}

impl Filesystem for OsFilesystem {
    fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        match fs::read(self.root.join(name)) {
            Ok(bytes) => Ok(bytes),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(StorageError::FileNotFound),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
        // Stage the new bytes in the target directory so rename stays atomic.
        let mut temp = NamedTempFile::new_in(self.root.as_ref())?;
        io::Write::write_all(&mut temp, data)?;
        temp.as_file().sync_all()?;

        let target = self.root.join(name);
        temp.persist(&target)
            .map_err(|err| StorageError::Io(err.error))?;

        // Sync the directory entry so the rename survives power loss.
        File::open(self.root.as_ref())?.sync_all()?;
        Ok(())
    }

    fn remove(&self, name: &str) -> Result<(), StorageError> {
        match fs::remove_file(self.root.join(name)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(StorageError::FileNotFound),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    fn list(&self) -> Result<Vec<String>, StorageError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(self.root.as_ref())? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".tmp") {
                continue;
            }
            names.push(name);
        }
        names.sort();
        Ok(names)
    }
}

/// CurrentContent summarizes the active encrypted content blob.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentContent {
    /// revision is the active revision descriptor.
    pub revision: RevisionDescriptor,
    /// content_id is the active encrypted content identifier.
    pub content_id: Vec<u8>,
    /// blob_len is the serialized content blob length in bytes.
    pub blob_len: usize,
    /// file_name is the backing filesystem name for this blob.
    pub file_name: String,
}

/// StoredFileInfo is one metadata-only description of a logical user file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredFileInfo {
    /// name is the stable user-facing file identifier.
    pub name: String,
    /// size_bytes is the plaintext file length in bytes.
    pub size_bytes: i64,
    /// modified_at_secs is the Unix timestamp in whole seconds.
    pub modified_at_secs: i64,
    /// modified_at_nanos is the nanosecond component of the source file mtime.
    pub modified_at_nanos: i64,
}

/// RecoveryMergeOutcome summarizes one automatic merge of older recovered files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryMergeOutcome {
    /// added_files is the number of recovered files added under their original names.
    pub added_files: i64,
    /// renamed_files is the number of recovered files added under recovered names.
    pub renamed_files: i64,
    /// unchanged_files is the number of recovered files skipped because the
    /// active local file set already contained identical plaintext bytes.
    pub unchanged_files: i64,
}

/// MetadataRollupOutcome reports what one metadata-only rollout attempt did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataRollupOutcome {
    /// NotPending means no metadata-only rollout is currently scheduled.
    NotPending,
    /// NotDue means one metadata-only rollout is scheduled but not eligible yet.
    NotDue,
    /// ClearedWithoutCurrentContent means the pending rollout was dropped
    /// because no local content blob remained to rewrite.
    ClearedWithoutCurrentContent,
    /// ClearedSuperseded means a later real content rewrite already replaced
    /// the base revision for this pending rollout.
    ClearedSuperseded,
    /// Rewritten means the current content blob was rewritten successfully.
    Rewritten {
        /// content_id is the new local content identifier.
        content_id: Vec<u8>,
    },
}

type MetadataRollupDelaySampler = Arc<dyn Fn() -> Duration + Send + Sync>;

/// Store owns the live local file set and the encrypted content blobs on disk.
pub struct Store {
    fs: Arc<dyn Filesystem>,
    time_source: Arc<dyn Clock>,
    codec: ContentCodec,
    peer_cipher: Aes256GcmSiv,
    mirrored_blob_cipher: Aes256GcmSiv,
    mirrored_name_key: Vec<u8>,
    files: BTreeMap<String, PlainFile>,
    peers: Vec<storedpb::Peer>,
    node_initialized_at: Option<(i64, i64)>,
    latest_recovered_revision: Option<storedpb::RecoveredRevision>,
    recovery_watermark: Option<(i64, i64)>,
    recovery_mode_enabled: bool,
    current: Option<CurrentContent>,
    metadata_rollup_due_at: Option<(i64, i64)>,
    metadata_rollup_base_content_id: Vec<u8>,
    metadata_rollup_delay_sampler: MetadataRollupDelaySampler,
}

/// Return the higher-priority peer origin.
fn merge_peer_origin(current: i32, incoming: i32) -> i32 {
    current.max(incoming)
}

/// Build one persisted peer-content summary.
fn peer_content_summary(content_id: &[u8], content_length: i64) -> storedpb::PeerContent {
    storedpb::PeerContent {
        content_id: content_id.to_vec(),
        content_length,
    }
}

/// Convert one optional peer-content summary into an owned content id.
fn peer_content_id(content: Option<&storedpb::PeerContent>) -> Option<Vec<u8>> {
    content
        .filter(|content| !content.content_id.is_empty())
        .map(|content| content.content_id.clone())
}

/// Convert one active current-content record into a persisted summary.
fn current_content_summary(current: Option<&CurrentContent>) -> Option<storedpb::PeerContent> {
    current.map(|current| storedpb::PeerContent {
        content_id: current.content_id.clone(),
        content_length: i64::try_from(current.blob_len).unwrap_or(i64::MAX),
    })
}

/// Sample one exponential metadata-rollup delay with a one-day mean.
fn sample_metadata_rollup_delay() -> Duration {
    let mut rng = thread_rng();
    let draw = rng.gen_range(f64::MIN_POSITIVE..1.0);
    let delay_secs = (-draw.ln() * METADATA_ROLLUP_MEAN_DELAY_SECS).max(0.0);
    Duration::from_secs_f64(delay_secs)
}

/// Encode one `(seconds, nanos)` pair as a protobuf timestamp.
fn proto_timestamp(secs: i64, nanos: i64) -> Result<ProtoTimestamp, StorageError> {
    if !(0..1_000_000_000).contains(&nanos) {
        return Err(StorageError::InvalidTimestamp);
    }

    Ok(ProtoTimestamp {
        seconds: secs,
        nanos: i32::try_from(nanos).map_err(|_| StorageError::InvalidTimestamp)?,
    })
}

/// Encode one optional metadata timestamp using the existing zero-is-absent convention.
fn optional_proto_timestamp(secs: i64, nanos: i64) -> Result<Option<ProtoTimestamp>, StorageError> {
    if secs == 0 && nanos == 0 {
        return Ok(None);
    }
    Ok(Some(proto_timestamp(secs, nanos)?))
}

/// Decode one optional persisted protobuf timestamp into `(seconds, nanos)`.
fn optional_metadata_timestamp(
    timestamp: Option<&ProtoTimestamp>,
) -> Result<Option<(i64, i64)>, StorageError> {
    timestamp
        .map(|timestamp| {
            if !(0..1_000_000_000).contains(&timestamp.nanos) {
                return Err(StorageError::InvalidTimestamp);
            }
            Ok((timestamp.seconds, i64::from(timestamp.nanos)))
        })
        .transpose()
}

/// Return whether one peer still has a pending advertised requester revision.
fn peer_has_pending_requester_advertisement(peer: &storedpb::Peer) -> bool {
    let Some(advertised_content) = peer.requester_last_advertised_content.as_ref() else {
        return false;
    };
    let Some(advertised_at) =
        optional_metadata_timestamp(peer.requester_last_advertised_at.as_ref())
            .ok()
            .flatten()
    else {
        return false;
    };
    let downloaded_content = peer.requester_last_downloaded_advertised_content.as_ref();
    let downloaded_at =
        optional_metadata_timestamp(peer.requester_last_downloaded_advertised_at.as_ref())
            .ok()
            .flatten();

    match (downloaded_content, downloaded_at) {
        (Some(downloaded_content), Some(downloaded_at))
            if downloaded_content.content_id == advertised_content.content_id =>
        {
            downloaded_at < advertised_at
        }
        _ => true,
    }
}

/// Ensure one peer entry exists in a mutable peer vector.
fn ensure_peer_entry(
    peers: &mut Vec<storedpb::Peer>,
    onion_pubkey: &[u8],
    first_seen_at: (i64, i64),
) {
    if peers
        .iter()
        .any(|peer| peer.onion_pubkey.as_slice() == onion_pubkey)
    {
        return;
    }

    peers.push(storedpb::Peer {
        onion_pubkey: onion_pubkey.to_vec(),
        score_seconds: 0,
        score_measured_at: 0,
        latest_known_content: None,
        latest_cached_content: None,
        origin: storedpb::PeerOrigin::Discovered as i32,
        first_contact_direction: storedpb::FirstContactDirection::Unknown as i32,
        reachability: storedpb::PeerReachability::Unknown as i32,
        last_live_at: 0,
        pinned_by_us: false,
        pins_us: false,
        our_content_last_verified_content_id: Vec::new(),
        our_content_last_verified_at: 0,
        first_seen_at: Some(
            proto_timestamp(first_seen_at.0, first_seen_at.1)
                .expect("clock timestamps must be valid"),
        ),
        successful_calls: 0,
        failed_calls: 0,
        requester_latest_stored_content: None,
        requester_latest_known_content: None,
        requester_last_advertised_content: None,
        requester_last_advertised_at: None,
        requester_last_downloaded_advertised_content: None,
        requester_last_downloaded_advertised_at: None,
        requester_last_download_latency_seconds: 0,
        requester_remaining_seconds: 0,
        requester_remaining_observed_at: None,
    });
}

impl Store {
    /// Create a store backed by the system clock.
    pub fn new(fs: Arc<dyn Filesystem>, master: &[u8]) -> Result<Self, StorageError> {
        Self::new_with_time_source(fs, master, Arc::new(SystemClock))
    }

    /// Create a store with an explicit time source for deterministic tests.
    pub fn new_with_time_source(
        fs: Arc<dyn Filesystem>,
        master: &[u8],
        time_source: Arc<dyn Clock>,
    ) -> Result<Self, StorageError> {
        Self::new_with_time_source_and_rollup_sampler(
            fs,
            master,
            time_source,
            Arc::new(sample_metadata_rollup_delay),
        )
    }

    /// Create a store with an explicit time source and metadata-rollup sampler.
    pub fn new_with_time_source_and_rollup_sampler(
        fs: Arc<dyn Filesystem>,
        master: &[u8],
        time_source: Arc<dyn Clock>,
        metadata_rollup_delay_sampler: MetadataRollupDelaySampler,
    ) -> Result<Self, StorageError> {
        if master.len() < 32 {
            return Err(StorageError::InvalidMasterKey(master.len()));
        }

        // Derive all local storage keys from the same master secret.
        let revision_key = keys::derive_key(master, "bb/content/revision-id", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let metadata_key = keys::derive_key(master, "bb/content/metadata", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let file_key = keys::derive_key(master, "bb/content/file-segment", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let peer_state_key = keys::derive_key(master, "bb/storage/peer-state", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let mirrored_blob_key = keys::derive_key(master, "bb/storage/mirrored-blob", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let mirrored_name_key = keys::derive_key(master, "bb/storage/mirrored-name", 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;

        let codec = ContentCodec::new(&revision_key, &metadata_key, &file_key)?;
        let peer_cipher = Aes256GcmSiv::new_from_slice(&peer_state_key)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        let mirrored_blob_cipher = Aes256GcmSiv::new_from_slice(&mirrored_blob_key)
            .map_err(|err| StorageError::Message(err.to_string()))?;

        let mut store = Self {
            fs,
            time_source,
            codec,
            peer_cipher,
            mirrored_blob_cipher,
            mirrored_name_key,
            files: BTreeMap::new(),
            peers: Vec::new(),
            node_initialized_at: None,
            latest_recovered_revision: None,
            recovery_watermark: None,
            recovery_mode_enabled: false,
            current: None,
            metadata_rollup_due_at: None,
            metadata_rollup_base_content_id: Vec::new(),
            metadata_rollup_delay_sampler,
        };
        store.load()?;
        Ok(store)
    }

    /// Return the current content summary if one exists.
    pub fn current_content(&self) -> Option<&CurrentContent> {
        self.current.as_ref()
    }

    /// Ensure the local store has one current content revision.
    pub fn ensure_current_content(&mut self) -> Result<(), StorageError> {
        if self.current.is_some() {
            return Ok(());
        }

        self.persist_files()
    }

    /// Return the latest known content id.
    pub fn current_content_id(&self) -> Option<&[u8]> {
        self.current
            .as_ref()
            .map(|current| current.content_id.as_slice())
    }

    /// Return the current file names in sorted order.
    pub fn list_files(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }

    /// Return metadata for every logical user file in deterministic order.
    pub fn list_file_info(&self) -> Vec<StoredFileInfo> {
        self.files
            .values()
            .map(|file| StoredFileInfo {
                name: file.name.clone(),
                size_bytes: i64::try_from(file.data.len()).unwrap_or(i64::MAX),
                modified_at_secs: i64::try_from(file.modified_at_secs).unwrap_or(i64::MAX),
                modified_at_nanos: i64::from(file.modified_at_nanos),
            })
            .collect()
    }

    /// Return the stored node-initialization boundary, if one is known.
    pub fn node_initialized_at(&self) -> Option<(i64, i64)> {
        self.node_initialized_at
    }

    /// Return the newest recovered older-lineage revision that was applied locally.
    pub fn latest_recovered_revision(&self) -> Option<storedpb::RecoveredRevision> {
        self.latest_recovered_revision.clone()
    }

    /// Return the effective recovery watermark used to suppress older lineage.
    pub fn recovery_watermark(&self) -> Option<(i64, i64)> {
        self.recovery_watermark
    }

    /// Report whether recovery mode currently blocks owner-originated publication.
    pub fn recovery_mode_enabled(&self) -> bool {
        self.recovery_mode_enabled
    }

    /// Return the pending metadata-rollup deadline, if one exists.
    pub fn metadata_rollup_due_at(&self) -> Option<(i64, i64)> {
        self.metadata_rollup_due_at
    }

    /// Return the base content id for the pending metadata-rollup epoch, if any.
    pub fn metadata_rollup_base_content_id(&self) -> Option<&[u8]> {
        (!self.metadata_rollup_base_content_id.is_empty())
            .then_some(self.metadata_rollup_base_content_id.as_slice())
    }

    /// Initialize the persisted lineage state once for this store.
    pub fn initialize_lineage(
        &mut self,
        node_initialized_at: (i64, i64),
        recovery_mode_enabled: bool,
    ) -> Result<(), StorageError> {
        if !(0..1_000_000_000).contains(&node_initialized_at.1) {
            return Err(StorageError::InvalidTimestamp);
        }
        if self.node_initialized_at.is_some() {
            return Err(StorageError::Message(
                "lineage metadata is already initialized".to_string(),
            ));
        }

        self.node_initialized_at = Some(node_initialized_at);
        self.recovery_watermark = None;
        self.recovery_mode_enabled = recovery_mode_enabled;
        self.persist_peer_state()
    }

    /// Persist one newer recovered revision and advance the recovery watermark.
    pub fn record_recovered_revision(
        &mut self,
        revision: storedpb::RecoveredRevision,
    ) -> Result<(), StorageError> {
        if revision.content_id.is_empty() {
            return Err(StorageError::InvalidFileName);
        }
        let created_at = optional_metadata_timestamp(revision.created_at.as_ref())?
            .ok_or(StorageError::InvalidTimestamp)?;

        self.latest_recovered_revision = Some(revision.clone());
        self.recovery_watermark = Some(created_at);
        self.persist_peer_state()
    }

    /// Disable recovery mode and advance the watermark to the node boundary.
    pub fn finish_recovery_mode(&mut self) -> Result<(), StorageError> {
        let Some(node_initialized_at) = self.node_initialized_at else {
            return Err(StorageError::Message(
                "lineage metadata is not initialized".to_string(),
            ));
        };

        self.recovery_mode_enabled = false;
        self.recovery_watermark = Some(node_initialized_at);
        self.persist_peer_state()
    }

    /// Return whether one metadata-only rollup is currently pending.
    fn has_pending_metadata_rollup(&self) -> bool {
        self.metadata_rollup_due_at.is_some() && !self.metadata_rollup_base_content_id.is_empty()
    }

    /// Clear any pending metadata-only rollup state.
    fn clear_metadata_rollup(&mut self) {
        self.metadata_rollup_due_at = None;
        self.metadata_rollup_base_content_id.clear();
    }

    /// Schedule one metadata-only rollup if there is current content and no
    /// earlier pending rollout already exists.
    fn schedule_metadata_rollup_if_needed(&mut self) {
        let Some(current) = self.current.as_ref() else {
            return;
        };
        if self.has_pending_metadata_rollup() {
            return;
        }
        let now = self.time_source.now();
        let due_at = now.advance((self.metadata_rollup_delay_sampler)());
        self.metadata_rollup_due_at = Some((
            i64::try_from(due_at.secs).unwrap_or(i64::MAX),
            i64::from(due_at.nanos),
        ));
        self.metadata_rollup_base_content_id = current.content_id.clone();
    }

    /// Rewrite the current local content blob with newer peer metadata when
    /// one pending rollout is due.
    pub fn roll_up_peer_metadata_if_due(&mut self) -> Result<MetadataRollupOutcome, StorageError> {
        let Some(due_at) = self.metadata_rollup_due_at else {
            return Ok(MetadataRollupOutcome::NotPending);
        };
        let now = self.time_source.now();
        let now = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        if now < due_at {
            return Ok(MetadataRollupOutcome::NotDue);
        }

        let Some(current) = self.current.as_ref() else {
            self.clear_metadata_rollup();
            self.persist_peer_state()?;
            return Ok(MetadataRollupOutcome::ClearedWithoutCurrentContent);
        };
        if current.content_id != self.metadata_rollup_base_content_id {
            self.clear_metadata_rollup();
            self.persist_peer_state()?;
            return Ok(MetadataRollupOutcome::ClearedSuperseded);
        }

        self.persist_files()?;
        let content_id = self
            .current
            .as_ref()
            .map(|current| current.content_id.clone())
            .unwrap_or_default();
        self.persist_peer_state()?;
        Ok(MetadataRollupOutcome::Rewritten { content_id })
    }

    /// Persist whether recovery mode blocks owner-originated publication.
    pub fn set_recovery_mode_enabled(
        &mut self,
        recovery_mode_enabled: bool,
    ) -> Result<(), StorageError> {
        if self.recovery_mode_enabled == recovery_mode_enabled {
            return Ok(());
        }
        self.recovery_mode_enabled = recovery_mode_enabled;
        self.persist_peer_state()
    }

    /// Return the number of logical user files in the active revision.
    pub fn file_count(&self) -> i64 {
        i64::try_from(self.files.len()).unwrap_or(i64::MAX)
    }

    /// Return the total plaintext size of all logical user files.
    pub fn total_file_bytes(&self) -> i64 {
        self.files.values().fold(0i64, |total, file| {
            total.saturating_add(i64::try_from(file.data.len()).unwrap_or(i64::MAX))
        })
    }

    /// Read a plaintext file by name.
    pub fn get_file(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        Ok(self.get_plain_file(name)?.data)
    }

    /// Read one plaintext file plus its stored metadata by name.
    pub fn get_plain_file(&self, name: &str) -> Result<PlainFile, StorageError> {
        self.files
            .get(name)
            .cloned()
            .ok_or(StorageError::FileNotFound)
    }

    /// Persist or replace a plaintext file.
    pub fn set_file(&mut self, name: &str, data: Vec<u8>) -> Result<(), StorageError> {
        self.set_file_with_modified_at(name, data, 0, 0)
    }

    /// Persist or replace a plaintext file with an explicit source mtime.
    pub fn set_file_with_modified_at(
        &mut self,
        name: &str,
        data: Vec<u8>,
        modified_at_secs: u64,
        modified_at_nanos: u32,
    ) -> Result<(), StorageError> {
        if name.is_empty() {
            return Err(StorageError::InvalidFileName);
        }
        if modified_at_nanos >= 1_000_000_000 {
            return Err(StorageError::InvalidTimestamp);
        }

        let mut next_files = self.current_plain_files();
        if let Some(file) = next_files.iter_mut().find(|file| file.name == name) {
            file.data = data.clone();
            file.modified_at_secs = modified_at_secs;
            file.modified_at_nanos = modified_at_nanos;
        } else {
            next_files.push(PlainFile {
                name: name.to_string(),
                data: data.clone(),
                modified_at_secs,
                modified_at_nanos,
            });
        }
        self.enforce_shared_blob_limit_for_state(&next_files, &self.peers)?;

        let previous = self.files.insert(
            name.to_string(),
            PlainFile {
                name: name.to_string(),
                data,
                modified_at_secs,
                modified_at_nanos,
            },
        );
        match self.persist_files() {
            Ok(()) => Ok(()),
            Err(error) => {
                if let Some(previous) = previous {
                    self.files.insert(name.to_string(), previous);
                } else {
                    self.files.remove(name);
                }
                Err(error)
            }
        }
    }

    /// Delete a plaintext file.
    pub fn delete_file(&mut self, name: &str) -> Result<(), StorageError> {
        if !self.files.contains_key(name) {
            return Err(StorageError::FileNotFound);
        }

        let next_files = self
            .current_plain_files()
            .into_iter()
            .filter(|file| file.name != name)
            .collect::<Vec<_>>();
        self.enforce_shared_blob_limit_for_state(&next_files, &self.peers)?;

        let removed = self
            .files
            .remove(name)
            .expect("checked above that the file exists");
        match self.persist_files() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.files.insert(name.to_string(), removed);
                Err(error)
            }
        }
    }

    /// Return a copy of the tracked peer metadata.
    pub fn peers(&self) -> Vec<storedpb::Peer> {
        self.peers.clone()
    }

    /// Ensure a peer exists in the encrypted sidecar even before any sync.
    pub fn ensure_peer(&mut self, onion_pubkey: &[u8]) -> Result<(), StorageError> {
        self.ensure_peer_with_origin(onion_pubkey, storedpb::PeerOrigin::Discovered as i32)
    }

    /// Ensure a peer exists and record its highest-priority origin.
    pub fn ensure_peer_with_origin(
        &mut self,
        onion_pubkey: &[u8],
        origin: i32,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            if let Some(peer) = peers
                .iter()
                .find(|peer| peer.onion_pubkey.as_slice() == onion_pubkey)
            {
                let merged_origin = merge_peer_origin(peer.origin, origin);
                if merged_origin == peer.origin {
                    return Ok(false);
                }
            }

            if let Some(peer) = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey.as_slice() == onion_pubkey)
            {
                peer.origin = merge_peer_origin(peer.origin, origin);
            } else {
                peers.push(storedpb::Peer {
                    onion_pubkey: onion_pubkey.to_vec(),
                    score_seconds: 0,
                    score_measured_at: 0,
                    latest_known_content: None,
                    latest_cached_content: None,
                    origin,
                    first_contact_direction: storedpb::FirstContactDirection::Unknown as i32,
                    reachability: storedpb::PeerReachability::Unknown as i32,
                    last_live_at: 0,
                    pinned_by_us: false,
                    pins_us: false,
                    our_content_last_verified_content_id: Vec::new(),
                    our_content_last_verified_at: 0,
                    first_seen_at: Some(
                        proto_timestamp(first_seen_at.0, first_seen_at.1)
                            .expect("clock timestamps must be valid"),
                    ),
                    successful_calls: 0,
                    failed_calls: 0,
                    requester_latest_stored_content: None,
                    requester_latest_known_content: None,
                    requester_last_advertised_content: None,
                    requester_last_advertised_at: None,
                    requester_last_downloaded_advertised_content: None,
                    requester_last_downloaded_advertised_at: None,
                    requester_last_download_latency_seconds: 0,
                    requester_remaining_seconds: 0,
                    requester_remaining_observed_at: None,
                });
            }
            Ok(true)
        })
    }

    /// Upsert the latest known content id for a peer.
    pub fn set_peer_content_id(
        &mut self,
        onion_pubkey: &[u8],
        content_id: &[u8],
    ) -> Result<(), StorageError> {
        self.set_peer_content_state(
            onion_pubkey,
            Some(content_id),
            Some(0),
            Some(content_id),
            Some(0),
        )
    }

    /// Set the latest known and cached peer revisions in one update.
    pub fn set_peer_content_state(
        &mut self,
        onion_pubkey: &[u8],
        latest_known_content_id: Option<&[u8]>,
        latest_known_content_length: Option<i64>,
        latest_cached_content_id: Option<&[u8]>,
        latest_cached_content_length: Option<i64>,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }
        if latest_known_content_id.is_some_and(|content_id| content_id.is_empty()) {
            return Err(StorageError::InvalidFileName);
        }
        if latest_cached_content_id.is_some_and(|content_id| content_id.is_empty()) {
            return Err(StorageError::InvalidFileName);
        }
        if latest_known_content_id.is_some() && latest_known_content_length.is_none() {
            return Err(StorageError::InvalidFileName);
        }
        if latest_cached_content_id.is_some() && latest_cached_content_length.is_none() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_latest_known = latest_known_content_id.map(|content_id| {
                peer_content_summary(content_id, latest_known_content_length.unwrap_or(0))
            });
            let next_latest_cached = latest_cached_content_id.map(|content_id| {
                peer_content_summary(content_id, latest_cached_content_length.unwrap_or(0))
            });
            if peer.latest_known_content == next_latest_known
                && peer.latest_cached_content == next_latest_cached
            {
                return Ok(false);
            }
            peer.latest_known_content = next_latest_known;
            peer.latest_cached_content = next_latest_cached;
            Ok(true)
        })
    }

    /// Set the persisted score state for a peer.
    pub fn set_peer_score(
        &mut self,
        onion_pubkey: &[u8],
        score_seconds: i64,
        score_measured_at: i64,
    ) -> Result<(), StorageError> {
        self.set_peer_score_with_persist(onion_pubkey, score_seconds, score_measured_at, true)
            .map(|_| ())
    }

    /// Stage the persisted score state for a peer without immediately writing
    /// the encrypted peer sidecar.
    pub fn set_peer_score_pending(
        &mut self,
        onion_pubkey: &[u8],
        score_seconds: i64,
        score_measured_at: i64,
    ) -> Result<bool, StorageError> {
        self.set_peer_score_with_persist(onion_pubkey, score_seconds, score_measured_at, false)
    }

    /// Set the persisted score state for a peer with explicit write policy.
    fn set_peer_score_with_persist(
        &mut self,
        onion_pubkey: &[u8],
        score_seconds: i64,
        score_measured_at: i64,
        persist: bool,
    ) -> Result<bool, StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers_with_persist(persist, |peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            if peer.score_seconds == score_seconds && peer.score_measured_at == score_measured_at {
                return Ok(false);
            }
            peer.score_seconds = score_seconds;
            peer.score_measured_at = score_measured_at;
            Ok(true)
        })
    }

    /// Persist whether the local operator pinned this peer.
    pub fn set_peer_pinned_by_us(
        &mut self,
        onion_pubkey: &[u8],
        pinned_by_us: bool,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            if peer.pinned_by_us == pinned_by_us {
                return Ok(false);
            }
            peer.pinned_by_us = pinned_by_us;
            Ok(true)
        })
    }

    /// Persist whether this peer most recently told us that it pins us.
    pub fn set_peer_pins_us(
        &mut self,
        onion_pubkey: &[u8],
        pins_us: bool,
    ) -> Result<(), StorageError> {
        self.set_peer_pins_us_with_persist(onion_pubkey, pins_us, true)
            .map(|_| ())
    }

    /// Stage whether this peer most recently told us that it pins us without
    /// immediately writing the encrypted peer sidecar.
    pub fn set_peer_pins_us_pending(
        &mut self,
        onion_pubkey: &[u8],
        pins_us: bool,
    ) -> Result<bool, StorageError> {
        self.set_peer_pins_us_with_persist(onion_pubkey, pins_us, false)
    }

    /// Persist whether this peer most recently told us that it pins us under
    /// the requested durability policy.
    fn set_peer_pins_us_with_persist(
        &mut self,
        onion_pubkey: &[u8],
        pins_us: bool,
        persist: bool,
    ) -> Result<bool, StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers_with_persist(persist, |peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            if peer.pins_us == pins_us {
                return Ok(false);
            }
            peer.pins_us = pins_us;
            Ok(true)
        })
    }

    /// Persist which local revision this peer last returned successfully during
    /// a contract check.
    pub fn set_peer_last_verified_our_content(
        &mut self,
        onion_pubkey: &[u8],
        content_id: Option<&[u8]>,
        verified_at: Option<i64>,
    ) -> Result<(), StorageError> {
        self.set_peer_last_verified_our_content_with_persist(
            onion_pubkey,
            content_id,
            verified_at,
            true,
        )
        .map(|_| ())
    }

    /// Stage which local revision this peer most recently passed a contract
    /// check for without immediately writing the encrypted peer sidecar.
    pub fn set_peer_last_verified_our_content_pending(
        &mut self,
        onion_pubkey: &[u8],
        content_id: Option<&[u8]>,
        verified_at: Option<i64>,
    ) -> Result<bool, StorageError> {
        self.set_peer_last_verified_our_content_with_persist(
            onion_pubkey,
            content_id,
            verified_at,
            false,
        )
    }

    /// Persist which local revision this peer last returned successfully during
    /// a contract check under the requested durability policy.
    fn set_peer_last_verified_our_content_with_persist(
        &mut self,
        onion_pubkey: &[u8],
        content_id: Option<&[u8]>,
        verified_at: Option<i64>,
        persist: bool,
    ) -> Result<bool, StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }
        if content_id.is_some_and(|content_id| content_id.is_empty()) {
            return Err(StorageError::InvalidFileName);
        }
        if content_id.is_some() != verified_at.is_some() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers_with_persist(persist, |peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_content_id = content_id
                .map(|content_id| content_id.to_vec())
                .unwrap_or_default();
            let next_verified_at = verified_at.unwrap_or_default();
            if peer.our_content_last_verified_content_id == next_content_id
                && peer.our_content_last_verified_at == next_verified_at
            {
                return Ok(false);
            }
            peer.our_content_last_verified_content_id = next_content_id;
            peer.our_content_last_verified_at = next_verified_at;
            Ok(true)
        })
    }

    /// Record the latest observed transport reachability for a peer.
    pub fn set_peer_reachability(
        &mut self,
        onion_pubkey: &[u8],
        reachability: i32,
        last_live_at: Option<i64>,
    ) -> Result<(), StorageError> {
        self.set_peer_reachability_with_persist(onion_pubkey, reachability, last_live_at, true)
            .map(|_| ())
    }

    /// Stage the latest observed transport reachability for a peer without
    /// immediately writing the encrypted peer sidecar.
    pub fn set_peer_reachability_pending(
        &mut self,
        onion_pubkey: &[u8],
        reachability: i32,
        last_live_at: Option<i64>,
    ) -> Result<bool, StorageError> {
        self.set_peer_reachability_with_persist(onion_pubkey, reachability, last_live_at, false)
    }

    /// Record the latest observed transport reachability for a peer under the
    /// requested durability policy.
    fn set_peer_reachability_with_persist(
        &mut self,
        onion_pubkey: &[u8],
        reachability: i32,
        last_live_at: Option<i64>,
        persist: bool,
    ) -> Result<bool, StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers_with_persist(persist, |peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_last_live_at = last_live_at.unwrap_or(peer.last_live_at);
            if peer.reachability == reachability && peer.last_live_at == next_last_live_at {
                return Ok(false);
            }
            peer.reachability = reachability;
            peer.last_live_at = next_last_live_at;
            Ok(true)
        })
    }

    /// Record the first contact direction if it was still unknown.
    pub fn set_peer_first_contact_direction(
        &mut self,
        onion_pubkey: &[u8],
        first_contact_direction: i32,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            if peer.first_contact_direction != storedpb::FirstContactDirection::Unknown as i32 {
                return Ok(false);
            }
            peer.first_contact_direction = first_contact_direction;
            Ok(true)
        })
    }

    /// Persist the latest requester revision view we learned from this peer.
    pub fn set_peer_requester_revision_state(
        &mut self,
        onion_pubkey: &[u8],
        latest_stored_content_id: Option<&[u8]>,
        latest_stored_content_length: Option<i64>,
        latest_known_content_id: Option<&[u8]>,
        latest_known_content_length: Option<i64>,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }
        if latest_stored_content_id.is_some_and(|content_id| content_id.is_empty()) {
            return Err(StorageError::InvalidFileName);
        }
        if latest_known_content_id.is_some_and(|content_id| content_id.is_empty()) {
            return Err(StorageError::InvalidFileName);
        }
        if latest_stored_content_id.is_some() && latest_stored_content_length.is_none() {
            return Err(StorageError::InvalidFileName);
        }
        if latest_known_content_id.is_some() && latest_known_content_length.is_none() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_latest_stored = latest_stored_content_id.map(|content_id| {
                peer_content_summary(content_id, latest_stored_content_length.unwrap_or(0))
            });
            let next_latest_known = latest_known_content_id.map(|content_id| {
                peer_content_summary(content_id, latest_known_content_length.unwrap_or(0))
            });
            if peer.requester_latest_stored_content == next_latest_stored
                && peer.requester_latest_known_content == next_latest_known
            {
                return Ok(false);
            }
            peer.requester_latest_stored_content = next_latest_stored;
            peer.requester_latest_known_content = next_latest_known;
            Ok(true)
        })
    }

    /// Persist the latest requester score we observed from this peer.
    pub fn set_peer_requester_remaining_state(
        &mut self,
        onion_pubkey: &[u8],
        requester_remaining_seconds: i64,
        observed_at: (i64, i64),
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let first_seen_at = observed_at;
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_observed_at = Some(proto_timestamp(observed_at.0, observed_at.1)?);
            if peer.requester_remaining_seconds == requester_remaining_seconds
                && peer.requester_remaining_observed_at == next_observed_at
            {
                return Ok(false);
            }
            peer.requester_remaining_seconds = requester_remaining_seconds;
            peer.requester_remaining_observed_at = next_observed_at;
            Ok(true)
        })
    }

    /// Record the latest requester revision we attempted to advertise to this peer.
    ///
    /// Returns the age in seconds of one older pending advertisement that was
    /// superseded by this newer content before the peer downloaded it.
    pub fn note_peer_requester_advertisement(
        &mut self,
        onion_pubkey: &[u8],
        content_id: &[u8],
        content_length: i64,
        advertised_at: (i64, i64),
    ) -> Result<i64, StorageError> {
        if onion_pubkey.is_empty() || content_id.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let first_seen_at = advertised_at;
        let mut superseded_pending_penalty = 0i64;
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let next_advertised = Some(peer_content_summary(content_id, content_length));
            if peer.requester_last_advertised_content == next_advertised
                && peer_has_pending_requester_advertisement(peer)
            {
                return Ok(false);
            }

            if let Some(previous_advertised) = peer.requester_last_advertised_content.as_ref() {
                if previous_advertised.content_id != content_id
                    && peer_has_pending_requester_advertisement(peer)
                {
                    if let Some(previous_advertised_at) =
                        optional_metadata_timestamp(peer.requester_last_advertised_at.as_ref())?
                    {
                        superseded_pending_penalty = advertised_at
                            .0
                            .saturating_sub(previous_advertised_at.0)
                            .max(0);
                    }
                }
            }

            peer.requester_last_advertised_content = next_advertised;
            peer.requester_last_advertised_at =
                Some(proto_timestamp(advertised_at.0, advertised_at.1)?);
            Ok(true)
        })?;
        Ok(superseded_pending_penalty)
    }

    /// Record that this peer downloaded the latest advertised requester revision.
    ///
    /// Returns the observed delay in seconds when the download completed a
    /// previously pending advertisement for the same content id.
    pub fn note_peer_requester_downloaded_advertised_content(
        &mut self,
        onion_pubkey: &[u8],
        content_id: &[u8],
        downloaded_at: (i64, i64),
    ) -> Result<Option<i64>, StorageError> {
        if onion_pubkey.is_empty() || content_id.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let first_seen_at = downloaded_at;
        let mut completed_latency = None;
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            let Some(advertised_content) = peer.requester_last_advertised_content.as_ref() else {
                return Ok(false);
            };
            if advertised_content.content_id != content_id {
                return Ok(false);
            }
            let Some(advertised_at) =
                optional_metadata_timestamp(peer.requester_last_advertised_at.as_ref())?
            else {
                return Ok(false);
            };
            if !peer_has_pending_requester_advertisement(peer) {
                return Ok(false);
            }

            let latency_seconds = downloaded_at.0.saturating_sub(advertised_at.0).max(0);
            peer.requester_latest_stored_content = Some(advertised_content.clone());
            peer.requester_latest_known_content = Some(advertised_content.clone());
            peer.requester_last_downloaded_advertised_content = Some(advertised_content.clone());
            peer.requester_last_downloaded_advertised_at =
                Some(proto_timestamp(downloaded_at.0, downloaded_at.1)?);
            peer.requester_last_download_latency_seconds = latency_seconds;
            completed_latency = Some(latency_seconds);
            Ok(true)
        })?;
        Ok(completed_latency)
    }

    /// Persist one outbound peer-call outcome for availability weighting.
    pub fn record_peer_call_outcome(
        &mut self,
        onion_pubkey: &[u8],
        succeeded: bool,
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let now = self.time_source.now();
        let first_seen_at = (
            i64::try_from(now.secs).unwrap_or(i64::MAX),
            i64::from(now.nanos),
        );
        self.update_peers(|peers| {
            ensure_peer_entry(peers, onion_pubkey, first_seen_at);
            let peer = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
                .expect("peer entry must exist after ensure");
            if succeeded {
                peer.successful_calls = peer.successful_calls.saturating_add(1);
            } else {
                peer.failed_calls = peer.failed_calls.saturating_add(1);
            }
            Ok(true)
        })
    }

    /// Clear the mirrored content id for a peer while preserving score state.
    pub fn clear_peer_content_id(&mut self, onion_pubkey: &[u8]) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        self.update_peers(|peers| {
            if let Some(peer) = peers
                .iter_mut()
                .find(|peer| peer.onion_pubkey == onion_pubkey)
            {
                if peer.latest_known_content.is_none() && peer.latest_cached_content.is_none() {
                    return Ok(false);
                }
                peer.latest_known_content = None;
                peer.latest_cached_content = None;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Remove a peer entry if it exists.
    pub fn remove_peer(&mut self, onion_pubkey: &[u8]) -> Result<(), StorageError> {
        self.update_peers(|peers| {
            let before = peers.len();
            peers.retain(|peer| peer.onion_pubkey.as_slice() != onion_pubkey);
            Ok(peers.len() != before)
        })
    }

    /// Replace the persisted peer metadata set without touching current content.
    pub fn replace_peers(&mut self, peers: Vec<storedpb::Peer>) -> Result<(), StorageError> {
        let mut migrated = peers;
        let files = self.current_plain_files();
        self.enforce_shared_blob_limit_for_state(&files, &migrated)?;
        self.peers = std::mem::take(&mut migrated);
        self.schedule_metadata_rollup_if_needed();
        self.persist_peer_state()
    }

    /// Persist the current in-memory peer sidecar immediately.
    pub fn flush_peer_state(&self) -> Result<(), StorageError> {
        self.persist_peer_state()
    }

    /// Read one locally stored revision blob, whether it is current or archived.
    pub fn read_revision_blob(&self, content_id: &[u8]) -> Result<Vec<u8>, StorageError> {
        if self
            .current
            .as_ref()
            .is_some_and(|current| current.content_id.as_slice() == content_id)
        {
            self.current_blob()
        } else {
            self.read_mirrored_blob(content_id)
        }
    }

    /// Decode one locally stored revision into plaintext files.
    pub fn read_revision_files(&self, content_id: &[u8]) -> Result<Vec<PlainFile>, StorageError> {
        let blob = self.read_revision_blob(content_id)?;
        self.decode_revision_files(&blob)
    }

    /// Decode one revision blob into plaintext files without reading from disk.
    pub fn decode_revision_files(&self, blob: &[u8]) -> Result<Vec<PlainFile>, StorageError> {
        let decoded = self.codec.decode(blob)?;
        Ok(decoded.files.into_values().collect())
    }

    /// Read the raw encrypted content blob for the active revision.
    pub fn current_blob(&self) -> Result<Vec<u8>, StorageError> {
        let current = self.current.as_ref().ok_or(StorageError::FileNotFound)?;
        self.fs.read(&current.file_name)
    }

    /// Read a raw local content blob by content id.
    pub fn read_blob_by_id(&self, content_id: &[u8]) -> Result<Vec<u8>, StorageError> {
        self.fs.read(&content_file_name(content_id))
    }

    /// Parse and authenticate a content id for this store.
    pub fn parse_content_id(&self, content_id: &[u8]) -> Result<RevisionDescriptor, StorageError> {
        self.codec.parse_content_id(content_id).map_err(Into::into)
    }

    /// Read a mirrored peer blob after unwrapping the local storage envelope.
    pub fn read_mirrored_blob(&self, content_id: &[u8]) -> Result<Vec<u8>, StorageError> {
        let file_name = self.mirrored_blob_file_name(content_id)?;
        let wrapped = self.fs.read(&file_name)?;
        decrypt_mirrored_blob(&self.mirrored_blob_cipher, content_id, &wrapped)
    }

    /// Report whether a valid mirrored peer blob exists for the supplied content id.
    pub fn has_mirrored_blob(&self, content_id: &[u8]) -> Result<bool, StorageError> {
        match self.read_mirrored_blob(content_id) {
            Ok(_) => Ok(true),
            Err(StorageError::FileNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Atomically wrap and write a mirrored peer blob under a local filename.
    pub fn write_mirrored_blob(&self, content_id: &[u8], blob: &[u8]) -> Result<(), StorageError> {
        let file_name = self.mirrored_blob_file_name(content_id)?;
        let wrapped = encrypt_mirrored_blob(&self.mirrored_blob_cipher, content_id, blob);
        self.fs.write_atomic(&file_name, &wrapped)
    }

    /// Remove a mirrored peer blob if it exists.
    pub fn remove_mirrored_blob(&mut self, content_id: &[u8]) -> Result<(), StorageError> {
        let mut changed = false;
        for peer in &mut self.peers {
            if peer_content_id(peer.latest_cached_content.as_ref())
                .is_some_and(|cached_content_id| cached_content_id == content_id)
            {
                peer.latest_cached_content = None;
                changed = true;
            }
        }
        if changed {
            self.persist_peer_state()?;
        }
        let file_name = self.mirrored_blob_file_name(content_id)?;
        self.fs.remove(&file_name)
    }

    /// Restore an encrypted blob as the active local content revision.
    pub fn restore_current_content_blob(&mut self, blob: &[u8]) -> Result<(), StorageError> {
        let decoded = self.codec.decode(blob)?;
        let current_len = self.current.as_ref().map(|current| current.blob_len);
        if blob.len() > MAX_SHARED_CONTENT_BLOB_BYTES
            && !current_len.is_some_and(|current_len| {
                current_len > MAX_SHARED_CONTENT_BLOB_BYTES && blob.len() < current_len
            })
        {
            return Err(StorageError::LocalContentTooLarge);
        }
        let file_name = content_file_name(&decoded.content_id);
        self.fs.write_atomic(&file_name, blob)?;

        let previous_name = self
            .current
            .as_ref()
            .map(|current| current.file_name.clone());
        self.files = decoded.files.clone();
        self.current = Some(CurrentContent {
            revision: decoded.revision,
            content_id: decoded.content_id,
            blob_len: blob.len(),
            file_name: file_name.clone(),
        });

        if let Some(previous_name) = previous_name {
            if previous_name != file_name {
                let _ = self.fs.remove(&previous_name);
            }
        }

        self.peers = decoded.metadata.peers;
        self.persist_peer_state()
    }

    /// Remove non-local blobs that are not in the supplied valid set.
    pub fn cleanup_foreign(&self, valid_content_ids: &[Vec<u8>]) -> Result<(), StorageError> {
        let mut keep = valid_content_ids
            .iter()
            .map(|content_id| self.mirrored_blob_file_name(content_id))
            .collect::<Result<Vec<_>, _>>()?;
        keep.sort();

        for name in self.fs.list()? {
            if name == PEER_STATE_FILE {
                continue;
            }
            if self
                .current
                .as_ref()
                .is_some_and(|current| current.file_name == name)
            {
                continue;
            }
            if keep.binary_search(&name).is_ok() {
                continue;
            }
            if decode_content_file_name(&name).is_err() {
                continue;
            }
            let _ = self.fs.remove(&name);
        }
        Ok(())
    }

    /// Load the encrypted content blobs and sidecar state from disk.
    fn load(&mut self) -> Result<(), StorageError> {
        let had_peer_state = self.load_peer_state()?;
        let foreign_files = self.foreign_content_files()?;

        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        for name in self.fs.list()? {
            if name == PEER_STATE_FILE {
                continue;
            }
            if foreign_files.contains(&name) {
                continue;
            }

            let content_id = match decode_content_file_name(&name) {
                Ok(content_id) => content_id,
                Err(_) => continue,
            };
            let blob = self.fs.read(&name)?;

            match self.codec.decode(&blob) {
                Ok(decoded) if decoded.content_id == content_id => valid.push(Candidate {
                    name,
                    blob_len: blob.len(),
                    decoded,
                }),
                Ok(_) => invalid.push("content id does not match file name".to_string()),
                Err(err) => invalid.push(err.to_string()),
            }
        }

        // Accept the common crash-safe case of two valid versions and drop the older one.
        if valid.is_empty() {
            if invalid.is_empty() {
                if had_peer_state {
                    self.ensure_legacy_lineage_initialized()?;
                }
                return Ok(());
            }
            return Err(StorageError::RecoveryRequired(format!(
                "found no valid content blobs and {} invalid candidate(s)",
                invalid.len()
            )));
        }
        if valid.len() == 1 && invalid.is_empty() {
            self.adopt(valid.pop().unwrap());
            self.ensure_legacy_lineage_initialized()?;
            return Ok(());
        }
        if valid.len() == 2 && invalid.is_empty() {
            valid.sort_by(compare_candidates);
            let newest = valid.pop().unwrap();
            let older = valid.pop().unwrap();
            let _ = self.fs.remove(&older.name);
            self.adopt(newest);
            self.ensure_legacy_lineage_initialized()?;
            return Ok(());
        }

        Err(StorageError::RecoveryRequired(format!(
            "found {} valid and {} invalid content blobs",
            valid.len(),
            invalid.len()
        )))
    }

    /// Adopt a decoded content blob as the active local state.
    fn adopt(&mut self, candidate: Candidate) {
        self.files = candidate.decoded.files;
        self.current = Some(CurrentContent {
            revision: candidate.decoded.revision,
            content_id: candidate.decoded.content_id,
            blob_len: candidate.blob_len,
            file_name: candidate.name,
        });
    }

    /// Return the tracked foreign blob file names referenced by peers.
    fn foreign_content_files(&self) -> Result<BTreeSet<String>, StorageError> {
        self.peers
            .iter()
            .filter_map(|peer| peer_content_id(peer.latest_cached_content.as_ref()))
            .map(|content_id| self.mirrored_blob_file_name(&content_id))
            .collect()
    }

    /// Persist the current plaintext file set as a new encrypted revision.
    fn persist_files(&mut self) -> Result<(), StorageError> {
        let timestamp = self.time_source.now();
        if timestamp.nanos >= 1_000_000_000 {
            return Err(StorageError::InvalidTimestamp);
        }

        let had_pending_metadata_rollup = self.has_pending_metadata_rollup();
        let next_sequence = self
            .current
            .as_ref()
            .map_or(1, |current| current.revision.sequence + 1);
        let files = self.files.values().cloned().collect::<Vec<_>>();
        let encoded = self.codec.encode(
            RevisionSeed {
                sequence: next_sequence,
                created_at_secs: timestamp.secs,
                created_at_nanos: timestamp.nanos,
            },
            &files,
            &self.peers,
        )?;

        let new_name = content_file_name(&encoded.content_id);
        self.fs.write_atomic(&new_name, &encoded.bytes)?;

        let previous_name = self
            .current
            .as_ref()
            .map(|current| current.file_name.clone());
        self.current = Some(CurrentContent {
            revision: encoded.revision,
            content_id: encoded.content_id,
            blob_len: encoded.bytes.len(),
            file_name: new_name.clone(),
        });
        self.clear_metadata_rollup();

        if let Some(previous_name) = previous_name {
            if previous_name != new_name {
                let _ = self.fs.remove(&previous_name);
            }
        }

        if had_pending_metadata_rollup {
            self.persist_peer_state()?;
        }

        Ok(())
    }

    /// Reject one projected shared blob that would exceed the fixed local
    /// ceiling unless the change is reducing an already oversized state.
    fn enforce_shared_blob_limit_for_state(
        &self,
        files: &[PlainFile],
        peers: &[storedpb::Peer],
    ) -> Result<(), StorageError> {
        let projected_len = self.codec.encoded_len(files, peers)?;
        if projected_len <= MAX_SHARED_CONTENT_BLOB_BYTES {
            return Ok(());
        }
        if let Some(current_len) = self.current_projected_blob_len()? {
            if current_len > MAX_SHARED_CONTENT_BLOB_BYTES && projected_len < current_len {
                return Ok(());
            }
        }
        Err(StorageError::LocalContentTooLarge)
    }

    /// Return the current projected shared blob length from in-memory state.
    pub fn current_projected_blob_len(&self) -> Result<Option<usize>, StorageError> {
        if self.current.is_none() {
            return Ok(None);
        }
        let files = self.current_plain_files();
        Ok(Some(self.codec.encoded_len(&files, &self.peers)?))
    }

    /// Return the current plaintext file set in deterministic order.
    fn current_plain_files(&self) -> Vec<PlainFile> {
        self.files.values().cloned().collect()
    }

    /// Merge one recovered plaintext revision into the active file set.
    pub fn merge_recovered_revision_files(
        &mut self,
        recovered_files: Vec<PlainFile>,
        recovered_timestamp: (i64, i64),
        recovered_content_id: &[u8],
    ) -> Result<RecoveryMergeOutcome, StorageError> {
        let mut outcome = RecoveryMergeOutcome::default();

        for recovered_file in recovered_files {
            let existing = self.files.get(&recovered_file.name).cloned();
            match existing {
                None => {
                    self.files
                        .insert(recovered_file.name.clone(), recovered_file);
                    outcome.added_files = outcome.added_files.saturating_add(1);
                }
                Some(existing) if existing.data == recovered_file.data => {
                    outcome.unchanged_files = outcome.unchanged_files.saturating_add(1);
                }
                Some(_) => {
                    let recovered_name = self.unique_recovered_file_name(
                        &recovered_file.name,
                        recovered_timestamp,
                        recovered_content_id,
                        &recovered_file.data,
                    );
                    if self
                        .files
                        .get(&recovered_name)
                        .is_some_and(|existing| existing.data == recovered_file.data)
                    {
                        outcome.unchanged_files = outcome.unchanged_files.saturating_add(1);
                        continue;
                    }

                    let mut renamed_file = recovered_file;
                    renamed_file.name = recovered_name.clone();
                    self.files.insert(recovered_name, renamed_file);
                    outcome.renamed_files = outcome.renamed_files.saturating_add(1);
                }
            }
        }

        if outcome.added_files > 0 || outcome.renamed_files > 0 {
            self.persist_files()?;
        }

        Ok(outcome)
    }

    /// Build one unique file name for recovered content while preserving the
    /// final extension when one exists.
    fn unique_recovered_file_name(
        &self,
        original_name: &str,
        recovered_timestamp: (i64, i64),
        recovered_content_id: &[u8],
        recovered_data: &[u8],
    ) -> String {
        let recovered_stamp = format!(
            "recovered-{}-{:09}",
            recovered_timestamp.0, recovered_timestamp.1
        );
        let content_suffix =
            hex::encode(&recovered_content_id[..recovered_content_id.len().min(4)]);

        let (stem, extension) = match original_name.rsplit_once('.') {
            Some((stem, extension)) if !stem.is_empty() => {
                (stem.to_string(), format!(".{extension}"))
            }
            _ => (original_name.to_string(), String::new()),
        };
        let base_name = if extension.is_empty() {
            format!("{stem}.{recovered_stamp}")
        } else {
            format!("{stem}.{recovered_stamp}{extension}")
        };
        if self
            .files
            .get(&base_name)
            .is_none_or(|existing| existing.data == recovered_data)
        {
            return base_name;
        }

        let with_suffix = if extension.is_empty() {
            format!("{stem}.{recovered_stamp}-{content_suffix}")
        } else {
            format!("{stem}.{recovered_stamp}-{content_suffix}{extension}")
        };
        if self
            .files
            .get(&with_suffix)
            .is_none_or(|existing| existing.data == recovered_data)
        {
            return with_suffix;
        }

        let mut disambiguator = 2u32;
        loop {
            let candidate = if extension.is_empty() {
                format!("{stem}.{recovered_stamp}-{content_suffix}-{disambiguator}")
            } else {
                format!("{stem}.{recovered_stamp}-{content_suffix}-{disambiguator}{extension}")
            };
            if self
                .files
                .get(&candidate)
                .is_none_or(|existing| existing.data == recovered_data)
            {
                return candidate;
            }
            disambiguator = disambiguator.saturating_add(1);
        }
    }

    /// Apply one peer metadata mutation transactionally against the size limit.
    fn update_peers(
        &mut self,
        update: impl FnOnce(&mut Vec<storedpb::Peer>) -> Result<bool, StorageError>,
    ) -> Result<(), StorageError> {
        self.update_peers_with_persist(true, update).map(|_| ())
    }

    /// Apply one peer metadata mutation transactionally with explicit
    /// durability.
    fn update_peers_with_persist(
        &mut self,
        persist: bool,
        update: impl FnOnce(&mut Vec<storedpb::Peer>) -> Result<bool, StorageError>,
    ) -> Result<bool, StorageError> {
        let mut next_peers = self.peers.clone();
        if !update(&mut next_peers)? {
            return Ok(false);
        }
        let files = self.current_plain_files();
        self.enforce_shared_blob_limit_for_state(&files, &next_peers)?;
        self.peers = next_peers;
        self.schedule_metadata_rollup_if_needed();
        if persist {
            self.persist_peer_state()?;
        }
        Ok(true)
    }

    /// Persist the encrypted peer sidecar without touching the content blob.
    fn persist_peer_state(&self) -> Result<(), StorageError> {
        let metadata = storedpb::Metadata {
            files: Vec::new(),
            peers: self.peers.clone(),
            node_initialized_at: self
                .node_initialized_at
                .map(|timestamp| optional_proto_timestamp(timestamp.0, timestamp.1))
                .transpose()?
                .flatten(),
            latest_recovered_revision: self.latest_recovered_revision.clone(),
            recovery_watermark_at: self
                .recovery_watermark
                .map(|timestamp| optional_proto_timestamp(timestamp.0, timestamp.1))
                .transpose()?
                .flatten(),
            recovery_mode_enabled: self.recovery_mode_enabled,
            current_content: current_content_summary(self.current.as_ref()),
            metadata_rollup_due_at: self
                .metadata_rollup_due_at
                .map(|timestamp| optional_proto_timestamp(timestamp.0, timestamp.1))
                .transpose()?
                .flatten(),
            metadata_rollup_base_content_id: self.metadata_rollup_base_content_id.clone(),
        };
        let plaintext = metadata.encode_to_vec();
        let ciphertext = encrypt_sidecar(&self.peer_cipher, &plaintext);
        self.fs.write_atomic(PEER_STATE_FILE, &ciphertext)
    }

    /// Load the encrypted peer sidecar if it exists.
    fn load_peer_state(&mut self) -> Result<bool, StorageError> {
        let ciphertext = match self.fs.read(PEER_STATE_FILE) {
            Ok(ciphertext) => ciphertext,
            Err(StorageError::FileNotFound) => return Ok(false),
            Err(err) => return Err(err),
        };
        let plaintext = decrypt_sidecar(&self.peer_cipher, &ciphertext)?;
        let metadata = storedpb::Metadata::decode(plaintext.as_slice())?;
        self.peers = metadata.peers;
        self.node_initialized_at =
            optional_metadata_timestamp(metadata.node_initialized_at.as_ref())?;
        self.latest_recovered_revision = metadata.latest_recovered_revision;
        self.recovery_watermark =
            optional_metadata_timestamp(metadata.recovery_watermark_at.as_ref())?.or_else(|| {
                self.latest_recovered_revision
                    .as_ref()
                    .and_then(|revision| {
                        optional_metadata_timestamp(revision.created_at.as_ref())
                            .ok()
                            .flatten()
                    })
            });
        self.recovery_mode_enabled = metadata.recovery_mode_enabled;
        self.metadata_rollup_due_at =
            optional_metadata_timestamp(metadata.metadata_rollup_due_at.as_ref())?;
        self.metadata_rollup_base_content_id = metadata.metadata_rollup_base_content_id;
        self.current = metadata
            .current_content
            .as_ref()
            .filter(|content| !content.content_id.is_empty())
            .map(|content| {
                let revision = self.parse_content_id(&content.content_id)?;
                Ok::<CurrentContent, StorageError>(CurrentContent {
                    revision,
                    content_id: content.content_id.clone(),
                    blob_len: usize::try_from(content.content_length).unwrap_or(usize::MAX),
                    file_name: content_file_name(&content.content_id),
                })
            })
            .transpose()?;
        Ok(true)
    }

    /// Backfill lineage metadata for stores created before recovery metadata existed.
    fn ensure_legacy_lineage_initialized(&mut self) -> Result<(), StorageError> {
        if self.node_initialized_at.is_some() {
            return Ok(());
        }

        let fallback = if let Some(current) = self.current.as_ref() {
            (
                i64::try_from(current.revision.created_at_secs).unwrap_or(i64::MAX),
                i64::from(current.revision.created_at_nanos),
            )
        } else {
            let now = self.time_source.now();
            (
                i64::try_from(now.secs).unwrap_or(i64::MAX),
                i64::from(now.nanos),
            )
        };
        self.node_initialized_at = Some(fallback);
        self.recovery_watermark = None;
        Ok(())
    }

    /// Derive the opaque local filename for a mirrored peer blob.
    fn mirrored_blob_file_name(&self, content_id: &[u8]) -> Result<String, StorageError> {
        if content_id.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        let purpose = format!("bb/storage/mirrored-name/v1/{}", hex::encode(content_id));
        let name_bytes = keys::derive_key(&self.mirrored_name_key, &purpose, 32)
            .map_err(|err| StorageError::Message(err.to_string()))?;
        Ok(hex::encode(name_bytes))
    }
}

/// Candidate is a decoded on-disk content blob found during startup.
struct Candidate {
    name: String,
    blob_len: usize,
    decoded: DecodedContent,
}

/// Compare two valid candidates by revision, then by filename as a tie-breaker.
fn compare_candidates(left: &Candidate, right: &Candidate) -> std::cmp::Ordering {
    left.decoded
        .revision
        .cmp(&right.decoded.revision)
        .then(left.name.cmp(&right.name))
}

/// Convert a content id into the on-disk blob file name.
fn content_file_name(content_id: &[u8]) -> String {
    hex::encode(content_id)
}

/// Parse an on-disk content blob file name back into the content id bytes.
fn decode_content_file_name(name: &str) -> Result<Vec<u8>, StorageError> {
    hex::decode(name).map_err(|_| StorageError::Message("invalid content name".to_string()))
}

/// Build the AAD for locally wrapped mirrored peer blobs.
fn mirrored_blob_aad(content_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + content_id.len());
    aad.push(MIRRORED_BLOB_VERSION);
    aad.extend_from_slice(content_id);
    aad
}

/// Encrypt a mirrored peer blob with an inline nonce and authenticated content id.
fn encrypt_mirrored_blob(cipher: &Aes256GcmSiv, content_id: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; MIRRORED_BLOB_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = mirrored_blob_aad(content_id);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("mirrored blob encryption should not fail");

    let mut output = Vec::with_capacity(1 + MIRRORED_BLOB_NONCE_LEN + ciphertext.len());
    output.push(MIRRORED_BLOB_VERSION);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt a mirrored peer blob and validate its local wrapper metadata.
fn decrypt_mirrored_blob(
    cipher: &Aes256GcmSiv,
    content_id: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, StorageError> {
    if ciphertext.len() < 1 + MIRRORED_BLOB_NONCE_LEN + MIRRORED_BLOB_TAG_LEN {
        return Err(StorageError::RecoveryRequired(
            "mirrored peer blob is truncated".to_string(),
        ));
    }
    if ciphertext[0] != MIRRORED_BLOB_VERSION {
        return Err(StorageError::RecoveryRequired(
            "mirrored peer blob version is invalid".to_string(),
        ));
    }

    let aad = mirrored_blob_aad(content_id);
    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[1..1 + MIRRORED_BLOB_NONCE_LEN]),
            Payload {
                msg: &ciphertext[1 + MIRRORED_BLOB_NONCE_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| StorageError::RecoveryRequired("mirrored peer blob is invalid".to_string()))
}

/// Encrypt the peer sidecar with an inline random nonce.
fn encrypt_sidecar(cipher: &Aes256GcmSiv, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; PEER_STATE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: PEER_STATE_FILE.as_bytes(),
            },
        )
        .expect("sidecar encryption should not fail");

    let mut output = Vec::with_capacity(PEER_STATE_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt the peer sidecar with its inline nonce.
fn decrypt_sidecar(cipher: &Aes256GcmSiv, ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
    if ciphertext.len() < PEER_STATE_NONCE_LEN + PEER_STATE_TAG_LEN {
        return Err(StorageError::RecoveryRequired(
            "peer sidecar is truncated".to_string(),
        ));
    }

    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..PEER_STATE_NONCE_LEN]),
            Payload {
                msg: &ciphertext[PEER_STATE_NONCE_LEN..],
                aad: PEER_STATE_FILE.as_bytes(),
            },
        )
        .map_err(|_| StorageError::RecoveryRequired("peer sidecar is invalid".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FailingFilesystem injects a single write failure into an existing backend.
    struct FailingFilesystem {
        inner: Arc<dyn Filesystem>,
        fail_next_write: Mutex<bool>,
    }

    /// CountingFilesystem counts peer-sidecar writes while delegating storage.
    struct CountingFilesystem {
        inner: Arc<dyn Filesystem>,
        peer_state_writes: Mutex<u64>,
    }

    impl Filesystem for FailingFilesystem {
        fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read(name)
        }

        fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
            let mut fail_next = self.fail_next_write.lock().unwrap();
            if *fail_next {
                *fail_next = false;
                return Err(StorageError::Message("forced write failure".to_string()));
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

    impl Filesystem for CountingFilesystem {
        fn read(&self, name: &str) -> Result<Vec<u8>, StorageError> {
            self.inner.read(name)
        }

        fn write_atomic(&self, name: &str, data: &[u8]) -> Result<(), StorageError> {
            if name == PEER_STATE_FILE {
                *self.peer_state_writes.lock().unwrap() += 1;
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

    fn time_source() -> Arc<dyn Clock> {
        let clock = clock::ManualClock::new(clock::Timestamp::new(10, 1).unwrap());
        clock.set(clock::Timestamp::new(10, 1).unwrap());
        Arc::new(clock)
    }

    fn master() -> Vec<u8> {
        keys::derive_master_priv("storage-master")
    }

    fn store_with_fixed_rollup_delay(
        fs: Arc<dyn Filesystem>,
        clock: Arc<dyn Clock>,
        delay: Duration,
    ) -> Store {
        Store::new_with_time_source_and_rollup_sampler(
            fs,
            &master(),
            clock,
            Arc::new(move || delay),
        )
        .unwrap()
    }

    fn test_proto_timestamp(secs: i64, nanos: i64) -> ProtoTimestamp {
        proto_timestamp(secs, nanos).expect("test timestamps must be valid")
    }

    fn test_peer(onion_pubkey: &[u8], origin: storedpb::PeerOrigin) -> storedpb::Peer {
        storedpb::Peer {
            onion_pubkey: onion_pubkey.to_vec(),
            score_seconds: 0,
            score_measured_at: 0,
            latest_known_content: None,
            latest_cached_content: None,
            origin: origin as i32,
            first_contact_direction: storedpb::FirstContactDirection::Unknown as i32,
            reachability: storedpb::PeerReachability::Unknown as i32,
            last_live_at: 0,
            pinned_by_us: false,
            pins_us: false,
            our_content_last_verified_content_id: Vec::new(),
            our_content_last_verified_at: 0,
            first_seen_at: Some(test_proto_timestamp(0, 0)),
            successful_calls: 0,
            failed_calls: 0,
            requester_latest_stored_content: None,
            requester_latest_known_content: None,
            requester_last_advertised_content: None,
            requester_last_advertised_at: None,
            requester_last_downloaded_advertised_content: None,
            requester_last_downloaded_advertised_at: None,
            requester_last_download_latency_seconds: 0,
            requester_remaining_seconds: 0,
            requester_remaining_observed_at: None,
        }
    }

    #[test]
    fn set_get_and_persist_files() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        assert_eq!(store.get_file("alpha.txt").unwrap(), b"secret".to_vec());
        assert_eq!(store.list_files(), vec!["alpha.txt".to_string()]);

        let raw_name = store.current_content().unwrap().file_name.clone();
        let raw_blob = fs.read(&raw_name).unwrap();
        assert!(!String::from_utf8_lossy(&raw_blob).contains("secret"));

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(reloaded.get_file("alpha.txt").unwrap(), b"secret".to_vec());
    }

    #[test]
    fn set_file_metadata_round_trips_through_persistence() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store
            .set_file_with_modified_at("alpha.txt", b"secret".to_vec(), 123, 456)
            .unwrap();
        let listed = store.list_file_info();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "alpha.txt");
        assert_eq!(listed[0].size_bytes, 6);
        assert_eq!(listed[0].modified_at_secs, 123);
        assert_eq!(listed[0].modified_at_nanos, 456);

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let listed = reloaded.list_file_info();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].modified_at_secs, 123);
        assert_eq!(listed[0].modified_at_nanos, 456);
    }

    #[test]
    fn deleting_last_file_creates_empty_current_revision() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();

        store.delete_file("alpha.txt").unwrap();

        assert!(store.list_files().is_empty());
        let current = store.current_content().expect("current content");
        assert!(current.blob_len > 0);
    }

    #[test]
    fn failed_write_keeps_previous_content() {
        let base: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut initial =
            Store::new_with_time_source(base.clone(), &master(), time_source()).unwrap();
        initial.set_file("alpha.txt", b"v1".to_vec()).unwrap();

        let failing: Arc<dyn Filesystem> = Arc::new(FailingFilesystem {
            inner: base.clone(),
            fail_next_write: Mutex::new(true),
        });
        let mut store = Store::new_with_time_source(failing, &master(), time_source()).unwrap();

        assert!(store.set_file("alpha.txt", b"v2".to_vec()).is_err());

        let reloaded = Store::new_with_time_source(base, &master(), time_source()).unwrap();
        assert_eq!(reloaded.get_file("alpha.txt").unwrap(), b"v1".to_vec());
    }

    #[test]
    fn load_prefers_newer_content_and_drops_older() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"old".to_vec()).unwrap();
        let older_name = store.current_content().unwrap().file_name.clone();
        store.set_file("alpha.txt", b"new".to_vec()).unwrap();
        let newer = store.current_content().unwrap().clone();

        let reloaded = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        assert_eq!(reloaded.get_file("alpha.txt").unwrap(), b"new".to_vec());
        assert_eq!(reloaded.current_content().unwrap().revision, newer.revision);
        assert!(matches!(
            fs.read(&older_name),
            Err(StorageError::FileNotFound)
        ));
    }

    #[test]
    fn ambiguous_multiple_valid_versions_require_recovery() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("a.txt", b"a".to_vec()).unwrap();
        let first_blob = store.current_blob().unwrap();
        let first_id = store.current_content().unwrap().content_id.clone();
        store.set_file("b.txt", b"b".to_vec()).unwrap();
        let second_blob = store.current_blob().unwrap();
        let second_id = store.current_content().unwrap().content_id.clone();
        store.set_file("c.txt", b"c".to_vec()).unwrap();
        let third_blob = store.current_blob().unwrap();
        let third_id = store.current_content().unwrap().content_id.clone();

        fs.write_atomic(&content_file_name(&first_id), &first_blob)
            .unwrap();
        fs.write_atomic(&content_file_name(&second_id), &second_blob)
            .unwrap();
        fs.write_atomic(&content_file_name(&third_id), &third_blob)
            .unwrap();

        assert!(matches!(
            Store::new_with_time_source(fs, &master(), time_source()),
            Err(StorageError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn peer_sidecar_round_trips_without_rewriting_content() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let initial = store.current_content().unwrap().clone();

        store
            .set_peer_content_id(b"peer-a", b"peer-content")
            .unwrap();

        assert_eq!(store.current_content().unwrap(), &initial);
        let raw_sidecar = fs.read(PEER_STATE_FILE).unwrap();
        assert!(!String::from_utf8_lossy(&raw_sidecar).contains("peer-a"));

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(reloaded.peers().len(), 1);
        assert_eq!(reloaded.peers()[0].onion_pubkey, b"peer-a".to_vec());
    }

    #[test]
    fn unchanged_peer_content_state_is_a_noop() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let peer_key = b"peer-a";
        let content_id = b"peer-content";

        store
            .set_peer_content_state(
                peer_key,
                Some(content_id),
                Some(123),
                Some(content_id),
                Some(123),
            )
            .unwrap();
        let first_sidecar = fs.read(PEER_STATE_FILE).unwrap();

        store
            .set_peer_content_state(
                peer_key,
                Some(content_id),
                Some(123),
                Some(content_id),
                Some(123),
            )
            .unwrap();
        let second_sidecar = fs.read(PEER_STATE_FILE).unwrap();

        assert_eq!(first_sidecar, second_sidecar);
    }

    #[test]
    fn clearing_empty_peer_content_state_is_a_noop() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let peer_key = b"peer-a";

        store.ensure_peer(peer_key).unwrap();
        let first_sidecar = fs.read(PEER_STATE_FILE).unwrap();

        store.clear_peer_content_id(peer_key).unwrap();
        let second_sidecar = fs.read(PEER_STATE_FILE).unwrap();

        assert_eq!(first_sidecar, second_sidecar);
    }

    #[test]
    fn mirrored_peer_blob_round_trips_inside_local_wrapper() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let content_id = b"peer-content-id";
        let remote_blob = b"remote-ciphertext".to_vec();

        store.write_mirrored_blob(content_id, &remote_blob).unwrap();

        let file_name = store.mirrored_blob_file_name(content_id).unwrap();
        let wrapped = fs.read(&file_name).unwrap();
        assert_ne!(wrapped, remote_blob);
        assert_eq!(store.read_mirrored_blob(content_id).unwrap(), remote_blob);
    }

    #[test]
    fn mirrored_peer_blob_detects_tampering() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let content_id = b"peer-content-id";

        store
            .write_mirrored_blob(content_id, b"remote-ciphertext")
            .unwrap();

        let file_name = store.mirrored_blob_file_name(content_id).unwrap();
        let mut wrapped = fs.read(&file_name).unwrap();
        let last_index = wrapped.len() - 1;
        wrapped[last_index] ^= 0x01;
        fs.write_atomic(&file_name, &wrapped).unwrap();

        assert!(matches!(
            store.read_mirrored_blob(content_id),
            Err(StorageError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn mirrored_peer_blob_rejects_wrong_content_id() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let correct_id = b"peer-content-id";
        let wrong_id = b"other-peer-content-id";

        store
            .write_mirrored_blob(correct_id, b"remote-ciphertext")
            .unwrap();

        let wrapped = fs
            .read(&store.mirrored_blob_file_name(correct_id).unwrap())
            .unwrap();
        assert!(matches!(
            decrypt_mirrored_blob(&store.mirrored_blob_cipher, wrong_id, &wrapped),
            Err(StorageError::RecoveryRequired(_))
        ));
    }

    #[test]
    fn load_ignores_tracked_wrapped_foreign_blobs() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut local = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        local.set_file("alpha.txt", b"local".to_vec()).unwrap();
        let local_current = local.current_content().unwrap().clone();

        // Build the foreign blob on a scratch filesystem so the foreign store
        // never has to parse our local content with the wrong master key.
        let foreign_master = keys::derive_master_priv("foreign-master");
        let foreign_fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut foreign =
            Store::new_with_time_source(foreign_fs, &foreign_master, time_source()).unwrap();
        foreign.set_file("peer.txt", b"peer".to_vec()).unwrap();
        let foreign_blob = foreign.current_blob().unwrap();
        let foreign_id = foreign.current_content().unwrap().content_id.clone();

        local.set_peer_content_id(b"peer-a", &foreign_id).unwrap();
        local
            .write_mirrored_blob(&foreign_id, &foreign_blob)
            .unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(reloaded.get_file("alpha.txt").unwrap(), b"local".to_vec());
        assert_eq!(reloaded.current_content().unwrap(), &local_current);
        assert_eq!(
            reloaded.peers()[0]
                .latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(foreign_id)
        );
    }

    #[test]
    fn load_allows_only_tracked_wrapped_foreign_blobs() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut local = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        // Build the foreign blob on a scratch filesystem so the shared store
        // sees it only as an opaque mirrored peer blob.
        let foreign_master = keys::derive_master_priv("foreign-only-master");
        let foreign_fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut foreign =
            Store::new_with_time_source(foreign_fs, &foreign_master, time_source()).unwrap();
        foreign.set_file("peer.txt", b"peer".to_vec()).unwrap();
        let foreign_blob = foreign.current_blob().unwrap();
        let foreign_id = foreign.current_content().unwrap().content_id.clone();

        local.set_peer_content_id(b"peer-a", &foreign_id).unwrap();
        local
            .write_mirrored_blob(&foreign_id, &foreign_blob)
            .unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert!(reloaded.current_content().is_none());
        assert!(reloaded.list_files().is_empty());
        assert_eq!(
            reloaded.peers()[0]
                .latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(foreign_id)
        );
    }

    #[test]
    fn ensure_peer_persists_empty_peer_entry() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.ensure_peer(b"peer-a").unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(reloaded.peers().len(), 1);
        assert_eq!(reloaded.peers()[0].onion_pubkey, b"peer-a".to_vec());
        assert!(reloaded.peers()[0].latest_known_content.is_none());
        assert_eq!(
            optional_metadata_timestamp(reloaded.peers()[0].first_seen_at.as_ref()).unwrap(),
            Some((10, 1))
        );
    }

    #[test]
    fn peer_requester_revision_state_and_call_outcomes_persist() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store
            .set_peer_requester_revision_state(
                b"peer-a",
                Some(b"stored-revision"),
                Some(123),
                Some(b"known-revision"),
                Some(456),
            )
            .unwrap();
        store
            .set_peer_requester_remaining_state(b"peer-a", 789, (12, 3))
            .unwrap();
        store.record_peer_call_outcome(b"peer-a", true).unwrap();
        store.record_peer_call_outcome(b"peer-a", false).unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peer = &reloaded.peers()[0];
        assert_eq!(peer.successful_calls, 1);
        assert_eq!(peer.failed_calls, 1);
        assert_eq!(
            peer.requester_latest_stored_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"stored-revision".to_vec(), 123))
        );
        assert_eq!(
            peer.requester_latest_known_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"known-revision".to_vec(), 456))
        );
        assert_eq!(peer.requester_remaining_seconds, 789);
        assert_eq!(
            optional_metadata_timestamp(peer.requester_remaining_observed_at.as_ref()).unwrap(),
            Some((12, 3))
        );
    }

    #[test]
    fn requester_advertisement_persists_and_superseding_pending_revision_returns_penalty() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(10, 1).unwrap(),
        ));
        let mut store = Store::new_with_time_source(fs.clone(), &master(), clock.clone()).unwrap();

        let penalty = store
            .note_peer_requester_advertisement(b"peer-a", b"revision-a", 111, (10, 1))
            .unwrap();
        assert_eq!(penalty, 0);

        clock.set(clock::Timestamp::new(19, 1).unwrap());
        let penalty = store
            .note_peer_requester_advertisement(b"peer-a", b"revision-b", 222, (19, 1))
            .unwrap();
        assert_eq!(penalty, 9);

        let reloaded = Store::new_with_time_source(fs, &master(), clock).unwrap();
        let peer = &reloaded.peers()[0];
        assert_eq!(
            peer.requester_last_advertised_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"revision-b".to_vec(), 222))
        );
        assert_eq!(
            optional_metadata_timestamp(peer.requester_last_advertised_at.as_ref()).unwrap(),
            Some((19, 1))
        );
        assert_eq!(peer.requester_last_downloaded_advertised_content, None);
    }

    #[test]
    fn requester_advertised_download_completes_only_once_per_pending_revision() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(10, 1).unwrap(),
        ));
        let mut store = Store::new_with_time_source(fs.clone(), &master(), clock.clone()).unwrap();

        store
            .note_peer_requester_advertisement(b"peer-a", b"revision-a", 111, (10, 1))
            .unwrap();
        clock.set(clock::Timestamp::new(16, 1).unwrap());
        assert_eq!(
            store
                .note_peer_requester_downloaded_advertised_content(
                    b"peer-a",
                    b"revision-a",
                    (16, 1)
                )
                .unwrap(),
            Some(6)
        );
        assert_eq!(
            store
                .note_peer_requester_downloaded_advertised_content(
                    b"peer-a",
                    b"revision-a",
                    (17, 1)
                )
                .unwrap(),
            None
        );

        let reloaded = Store::new_with_time_source(fs, &master(), clock).unwrap();
        let peer = &reloaded.peers()[0];
        assert_eq!(
            peer.requester_last_downloaded_advertised_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"revision-a".to_vec(), 111))
        );
        assert_eq!(
            peer.requester_latest_stored_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"revision-a".to_vec(), 111))
        );
        assert_eq!(
            peer.requester_latest_known_content
                .as_ref()
                .map(|content| (content.content_id.clone(), content.content_length)),
            Some((b"revision-a".to_vec(), 111))
        );
        assert_eq!(
            optional_metadata_timestamp(peer.requester_last_downloaded_advertised_at.as_ref())
                .unwrap(),
            Some((16, 1))
        );
        assert_eq!(peer.requester_last_download_latency_seconds, 6);
    }

    #[test]
    fn peer_first_seen_time_is_not_reset_by_later_updates() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.ensure_peer(b"peer-a").unwrap();
        store.record_peer_call_outcome(b"peer-a", true).unwrap();
        store.set_peer_pinned_by_us(b"peer-a", true).unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peer = &reloaded.peers()[0];
        assert_eq!(
            optional_metadata_timestamp(peer.first_seen_at.as_ref()).unwrap(),
            Some((10, 1))
        );
    }

    #[test]
    fn peer_origin_upgrades_but_never_downgrades() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store
            .ensure_peer_with_origin(b"peer-a", storedpb::PeerOrigin::BuiltIn as i32)
            .unwrap();
        store
            .ensure_peer_with_origin(b"peer-a", storedpb::PeerOrigin::Manual as i32)
            .unwrap();
        store
            .ensure_peer_with_origin(b"peer-a", storedpb::PeerOrigin::Discovered as i32)
            .unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(
            reloaded.peers()[0].origin,
            storedpb::PeerOrigin::Manual as i32
        );
    }

    #[test]
    fn lineage_metadata_round_trips_and_finishes_recovery() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.initialize_lineage((100, 7), true).unwrap();
        assert_eq!(store.node_initialized_at(), Some((100, 7)));
        assert_eq!(store.recovery_watermark(), None);
        assert!(store.recovery_mode_enabled());

        store
            .record_recovered_revision(storedpb::RecoveredRevision {
                content_id: vec![0x55; content::CONTENT_ID_LEN],
                created_at: Some(test_proto_timestamp(90, 8)),
            })
            .unwrap();
        assert_eq!(store.recovery_watermark(), Some((90, 8)));
        assert_eq!(
            store.latest_recovered_revision(),
            Some(storedpb::RecoveredRevision {
                content_id: vec![0x55; content::CONTENT_ID_LEN],
                created_at: Some(test_proto_timestamp(90, 8)),
            })
        );

        let reloaded = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        assert_eq!(reloaded.node_initialized_at(), Some((100, 7)));
        assert_eq!(reloaded.recovery_watermark(), Some((90, 8)));
        assert!(reloaded.recovery_mode_enabled());

        let mut finished = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        finished.finish_recovery_mode().unwrap();
        assert_eq!(finished.recovery_watermark(), Some((100, 7)));
        assert!(!finished.recovery_mode_enabled());
    }

    #[test]
    fn legacy_store_bootstraps_lineage_without_recovery_watermark() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        store.ensure_peer(b"peer-a").unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let current = reloaded.current_content().unwrap();
        assert_eq!(
            reloaded.node_initialized_at(),
            Some((
                i64::try_from(current.revision.created_at_secs).unwrap_or(i64::MAX),
                i64::from(current.revision.created_at_nanos),
            ))
        );
        assert!(reloaded.latest_recovered_revision().is_none());
        assert_eq!(reloaded.recovery_watermark(), None);
    }

    #[test]
    fn metadata_rollup_schedules_once_per_dirty_epoch_and_persists() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(100, 7).unwrap(),
        ));
        let mut store =
            store_with_fixed_rollup_delay(fs.clone(), clock.clone(), Duration::from_secs(86_400));
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let base_content_id = store.current_content().unwrap().content_id.clone();

        store
            .set_peer_content_id(b"peer-a", b"peer-revision-a")
            .unwrap();
        let first_due = store.metadata_rollup_due_at().unwrap();
        assert_eq!(
            store.metadata_rollup_base_content_id(),
            Some(base_content_id.as_slice())
        );

        clock.set(clock::Timestamp::new(200, 9).unwrap());
        store.record_peer_call_outcome(b"peer-a", true).unwrap();
        assert_eq!(store.metadata_rollup_due_at(), Some(first_due));
        assert_eq!(
            store.metadata_rollup_base_content_id(),
            Some(base_content_id.as_slice())
        );

        let reloaded = store_with_fixed_rollup_delay(fs, clock, Duration::from_secs(86_400));
        assert_eq!(reloaded.metadata_rollup_due_at(), Some(first_due));
        assert_eq!(
            reloaded.metadata_rollup_base_content_id(),
            Some(base_content_id.as_slice())
        );
    }

    #[test]
    fn metadata_rollup_is_not_scheduled_without_current_content() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(50, 1).unwrap(),
        ));
        let mut store = store_with_fixed_rollup_delay(fs, clock, Duration::from_secs(86_400));

        store.ensure_peer(b"peer-a").unwrap();
        store.record_peer_call_outcome(b"peer-a", true).unwrap();

        assert_eq!(store.metadata_rollup_due_at(), None);
        assert_eq!(store.metadata_rollup_base_content_id(), None);
    }

    #[test]
    fn ensure_current_content_supports_metadata_only_revision() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(50, 1).unwrap(),
        ));
        let mut store = store_with_fixed_rollup_delay(fs, clock, Duration::from_secs(86_400));

        store.ensure_current_content().unwrap();

        let current = store.current_content().expect("current content");
        assert!(store.list_files().is_empty());
        assert!(current.blob_len > 0);
        assert!(store.current_projected_blob_len().unwrap().is_some());
    }

    #[test]
    fn file_rewrite_clears_pending_metadata_rollup_state() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(100, 7).unwrap(),
        ));
        let mut store =
            store_with_fixed_rollup_delay(fs.clone(), clock.clone(), Duration::from_secs(86_400));
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        store
            .set_peer_content_id(b"peer-a", b"peer-revision-a")
            .unwrap();
        assert!(store.metadata_rollup_due_at().is_some());

        clock.set(clock::Timestamp::new(101, 8).unwrap());
        store.set_file("alpha.txt", b"new-secret".to_vec()).unwrap();
        assert_eq!(store.metadata_rollup_due_at(), None);
        assert_eq!(store.metadata_rollup_base_content_id(), None);

        let reloaded = store_with_fixed_rollup_delay(fs, clock, Duration::from_secs(86_400));
        assert_eq!(reloaded.metadata_rollup_due_at(), None);
        assert_eq!(reloaded.metadata_rollup_base_content_id(), None);
    }

    #[test]
    fn due_metadata_rollup_rewrites_current_content_and_preserves_files() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(100, 0).unwrap(),
        ));
        let mut store = store_with_fixed_rollup_delay(fs, clock.clone(), Duration::from_secs(5));
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let initial_content_id = store.current_content().unwrap().content_id.clone();

        store
            .set_peer_content_id(b"peer-a", b"peer-revision-a")
            .unwrap();
        clock.set(clock::Timestamp::new(104, 0).unwrap());
        assert_eq!(
            store.roll_up_peer_metadata_if_due().unwrap(),
            MetadataRollupOutcome::NotDue
        );

        clock.set(clock::Timestamp::new(105, 0).unwrap());
        let outcome = store.roll_up_peer_metadata_if_due().unwrap();
        let MetadataRollupOutcome::Rewritten { content_id } = outcome else {
            panic!("expected a rewritten metadata rollup");
        };
        assert_ne!(content_id, initial_content_id);
        assert_eq!(store.get_file("alpha.txt").unwrap(), b"secret".to_vec());
        assert_eq!(store.metadata_rollup_due_at(), None);
        assert_eq!(store.metadata_rollup_base_content_id(), None);
    }

    #[test]
    fn stale_metadata_rollup_is_cleared_when_base_revision_changed() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let clock = Arc::new(clock::ManualClock::new(
            clock::Timestamp::new(100, 0).unwrap(),
        ));
        let mut store = store_with_fixed_rollup_delay(fs, clock.clone(), Duration::from_secs(5));
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let stale_base_content_id = store.current_content().unwrap().content_id.clone();

        store
            .set_peer_content_id(b"peer-a", b"peer-revision-a")
            .unwrap();
        clock.set(clock::Timestamp::new(101, 0).unwrap());
        store.set_file("alpha.txt", b"new-secret".to_vec()).unwrap();
        store.metadata_rollup_due_at = Some((100, 0));
        store.metadata_rollup_base_content_id = stale_base_content_id;

        assert_eq!(
            store.roll_up_peer_metadata_if_due().unwrap(),
            MetadataRollupOutcome::ClearedSuperseded
        );
        assert_eq!(store.metadata_rollup_due_at(), None);
        assert_eq!(store.metadata_rollup_base_content_id(), None);
    }

    #[test]
    fn pending_peer_metadata_requires_explicit_flush() {
        let base: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let counting = Arc::new(CountingFilesystem {
            inner: base.clone(),
            peer_state_writes: Mutex::new(0),
        });
        let fs: Arc<dyn Filesystem> = counting.clone();
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peer_key = b"pending-peer";

        store.ensure_peer(peer_key).unwrap();
        let writes_after_ensure = *counting.peer_state_writes.lock().unwrap();
        assert_eq!(writes_after_ensure, 1);

        assert!(store.set_peer_score_pending(peer_key, 42, 99).unwrap());
        assert_eq!(
            *counting.peer_state_writes.lock().unwrap(),
            writes_after_ensure
        );
        assert_eq!(store.peers()[0].score_seconds, 42);

        let reloaded = Store::new_with_time_source(base.clone(), &master(), time_source()).unwrap();
        assert_eq!(reloaded.peers()[0].score_seconds, 0);

        store.flush_peer_state().unwrap();
        assert_eq!(
            *counting.peer_state_writes.lock().unwrap(),
            writes_after_ensure + 1
        );

        let reloaded = Store::new_with_time_source(base, &master(), time_source()).unwrap();
        assert_eq!(reloaded.peers()[0].score_seconds, 42);
        assert_eq!(reloaded.peers()[0].score_measured_at, 99);
    }

    #[test]
    fn immediate_peer_sidecar_write_persists_pending_low_value_metadata() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        let peer_key = b"mixed-peer";

        store.ensure_peer(peer_key).unwrap();
        assert!(store.set_peer_score_pending(peer_key, 12, 34).unwrap());
        store.set_peer_pinned_by_us(peer_key, true).unwrap();

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(reloaded.peers()[0].score_seconds, 12);
        assert_eq!(reloaded.peers()[0].score_measured_at, 34);
        assert!(reloaded.peers()[0].pinned_by_us);
    }

    #[test]
    fn restore_current_content_blob_restores_embedded_peer_snapshot() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.ensure_peer(b"peer-b").unwrap();
        store.set_file("alpha.txt", b"version-1".to_vec()).unwrap();

        store.ensure_peer(b"peer-c").unwrap();
        store.set_file("alpha.txt", b"version-2".to_vec()).unwrap();
        let blob_with_bc = store.current_blob().unwrap();

        store.ensure_peer(b"peer-d").unwrap();
        assert_eq!(
            store
                .peers()
                .into_iter()
                .map(|peer| peer.onion_pubkey)
                .collect::<Vec<_>>(),
            vec![b"peer-b".to_vec(), b"peer-c".to_vec(), b"peer-d".to_vec()]
        );

        store.restore_current_content_blob(&blob_with_bc).unwrap();
        assert_eq!(
            store
                .peers()
                .into_iter()
                .map(|peer| peer.onion_pubkey)
                .collect::<Vec<_>>(),
            vec![b"peer-b".to_vec(), b"peer-c".to_vec()]
        );

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        assert_eq!(
            reloaded
                .peers()
                .into_iter()
                .map(|peer| peer.onion_pubkey)
                .collect::<Vec<_>>(),
            vec![b"peer-b".to_vec(), b"peer-c".to_vec()]
        );
    }

    #[test]
    fn reload_without_local_blob_keeps_current_content_summary_from_peer_state() {
        let fs = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(
            fs.clone() as Arc<dyn Filesystem>,
            &master(),
            time_source(),
        )
        .unwrap();

        store.set_file("alpha.txt", b"alpha-body".to_vec()).unwrap();
        store.flush_peer_state().unwrap();
        let current = store.current_content().unwrap().clone();
        fs.remove(&current.file_name).unwrap();

        let reloaded =
            Store::new_with_time_source(fs as Arc<dyn Filesystem>, &master(), time_source())
                .unwrap();
        let restored_current = reloaded.current_content().unwrap();
        assert_eq!(restored_current.content_id, current.content_id);
        assert_eq!(restored_current.file_name, current.file_name);
        assert!(matches!(
            reloaded.current_blob(),
            Err(StorageError::FileNotFound)
        ));
        assert!(reloaded.get_file("alpha.txt").is_err());
    }

    #[test]
    fn cleanup_foreign_leaves_current_and_valid_blobs() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let current_id = store.current_content().unwrap().content_id.clone();

        fs.write_atomic("foreign", b"data").unwrap();
        let other_id = vec![0x44; content::CONTENT_ID_LEN];
        store.write_mirrored_blob(&other_id, b"peer-blob").unwrap();

        store
            .cleanup_foreign(std::slice::from_ref(&other_id))
            .unwrap();

        assert!(fs.read("foreign").is_ok());
        assert!(fs
            .read(&store.mirrored_blob_file_name(&other_id).unwrap())
            .is_ok());
        assert!(fs.read(&content_file_name(&current_id)).is_ok());
    }

    #[test]
    fn load_rejects_legacy_raw_foreign_blobs() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut local = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        let foreign_master = keys::derive_master_priv("legacy-foreign-master");
        let foreign_fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut foreign =
            Store::new_with_time_source(foreign_fs, &foreign_master, time_source()).unwrap();
        foreign.set_file("peer.txt", b"peer".to_vec()).unwrap();
        let foreign_blob = foreign.current_blob().unwrap();
        let foreign_id = foreign.current_content().unwrap().content_id.clone();

        local.set_peer_content_id(b"peer-a", &foreign_id).unwrap();
        fs.write_atomic(&content_file_name(&foreign_id), &foreign_blob)
            .unwrap();

        assert!(matches!(
            Store::new_with_time_source(fs.clone(), &master(), time_source()),
            Err(StorageError::RecoveryRequired(_))
        ));
        assert!(fs.read(&content_file_name(&foreign_id)).is_ok());
    }

    #[test]
    fn os_filesystem_write_atomic_replaces_target() {
        let temp = tempfile::tempdir().unwrap();
        let fs = OsFilesystem::new(temp.path()).unwrap();

        fs.write_atomic("blob", b"v1").unwrap();
        fs.write_atomic("blob", b"v2").unwrap();

        assert_eq!(fs.read("blob").unwrap(), b"v2".to_vec());
        #[cfg(unix)]
        {
            let dir_mode = fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777;
            let file_mode = fs::metadata(temp.path().join("blob"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);
        }
    }

    #[test]
    fn os_filesystem_reloads_peer_sidecar_after_mirrored_state_updates() {
        let temp = tempfile::tempdir().unwrap();
        let fs: Arc<dyn Filesystem> = Arc::new(OsFilesystem::new(temp.path()).unwrap());
        let peer_key = vec![0x5a; 32];
        let content_id = b"mirrored-content-id".to_vec();
        let mirrored_blob = b"opaque-peer-ciphertext".to_vec();

        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store
            .set_peer_content_state(
                &peer_key,
                Some(&content_id),
                Some(i64::try_from(mirrored_blob.len()).unwrap()),
                Some(&content_id),
                Some(i64::try_from(mirrored_blob.len()).unwrap()),
            )
            .unwrap();
        store
            .set_peer_reachability(
                &peer_key,
                storedpb::PeerReachability::Online as i32,
                Some(123),
            )
            .unwrap();
        store.set_peer_score(&peer_key, 456, 789).unwrap();
        store
            .write_mirrored_blob(&content_id, &mirrored_blob)
            .unwrap();
        drop(store);

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peer = &reloaded.peers()[0];
        assert_eq!(peer.onion_pubkey, peer_key);
        assert_eq!(peer.score_seconds, 456);
        assert_eq!(peer.score_measured_at, 789);
        assert_eq!(
            peer.latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(content_id.clone())
        );
        assert_eq!(
            peer.latest_cached_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(content_id.clone())
        );
        assert_eq!(
            reloaded.read_mirrored_blob(&content_id).unwrap(),
            mirrored_blob
        );
    }

    #[test]
    fn remove_mirrored_blob_clears_cached_peer_reference() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let peer_key = vec![0x7b; 32];
        let content_id = b"cached-content-id".to_vec();
        let mirrored_blob = b"opaque-peer-ciphertext".to_vec();

        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        store
            .set_peer_content_state(
                &peer_key,
                Some(&content_id),
                Some(i64::try_from(mirrored_blob.len()).unwrap()),
                Some(&content_id),
                Some(i64::try_from(mirrored_blob.len()).unwrap()),
            )
            .unwrap();
        store
            .write_mirrored_blob(&content_id, &mirrored_blob)
            .unwrap();
        store.remove_mirrored_blob(&content_id).unwrap();

        let peer = &store.peers()[0];
        assert_eq!(
            peer.latest_known_content
                .as_ref()
                .map(|content| content.content_id.clone()),
            Some(content_id.clone())
        );
        assert!(peer.latest_cached_content.is_none());
        assert!(matches!(
            store.read_mirrored_blob(&content_id),
            Err(StorageError::FileNotFound)
        ));
    }

    #[test]
    fn peer_pin_and_verification_metadata_round_trip() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let peer_key = vec![0x33; 32];
        let content_id = b"verified-local-content-id".to_vec();
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();

        store.set_peer_pinned_by_us(&peer_key, true).unwrap();
        store.set_peer_pins_us(&peer_key, true).unwrap();
        store
            .set_peer_last_verified_our_content(&peer_key, Some(&content_id), Some(456))
            .unwrap();
        drop(store);

        let reloaded = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peer = &reloaded.peers()[0];
        assert!(peer.pinned_by_us);
        assert!(peer.pins_us);
        assert_eq!(peer.our_content_last_verified_content_id, content_id);
        assert_eq!(peer.our_content_last_verified_at, 456);
    }

    fn max_payload_len_for_peer_count(peer_count: usize) -> usize {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let peers = (0..peer_count)
            .map(|index| {
                test_peer(
                    format!("peer-{index:08}").as_bytes(),
                    storedpb::PeerOrigin::Manual,
                )
            })
            .collect::<Vec<_>>();

        let mut low = 1usize;
        let mut high = MAX_SHARED_CONTENT_BLOB_BYTES;
        while low < high {
            let mid = low + (high - low).div_ceil(2);
            let files = vec![PlainFile {
                name: "payload.bin".to_string(),
                data: vec![0u8; mid],
                modified_at_secs: 0,
                modified_at_nanos: 0,
            }];
            let encoded_len = store.codec.encoded_len(&files, &peers).unwrap();
            if encoded_len <= MAX_SHARED_CONTENT_BLOB_BYTES {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        low
    }

    #[test]
    fn set_file_rejects_resulting_shared_blob_over_limit() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let max_len = max_payload_len_for_peer_count(0);

        store.set_file("payload.bin", vec![0u8; max_len]).unwrap();
        let current = store.current_content().unwrap().clone();
        assert_eq!(store.get_file("payload.bin").unwrap().len(), max_len);

        assert!(matches!(
            store.set_file("payload.bin", vec![0u8; max_len + 1]),
            Err(StorageError::LocalContentTooLarge)
        ));
        assert_eq!(store.get_file("payload.bin").unwrap().len(), max_len);
        assert_eq!(store.current_content().unwrap(), &current);
    }

    #[test]
    fn metadata_update_rejects_resulting_shared_blob_over_limit() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        let max_len = max_payload_len_for_peer_count(1);

        store.set_file("payload.bin", vec![0u8; max_len]).unwrap();
        store.ensure_peer(b"peer-0").unwrap();
        assert_eq!(store.peers().len(), 1);

        assert!(matches!(
            store.ensure_peer(b"peer-1"),
            Err(StorageError::LocalContentTooLarge)
        ));
        assert_eq!(store.peers().len(), 1);
    }

    #[test]
    fn oversized_metadata_state_still_allows_get_and_size_reducing_delete() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();

        store.set_file("alpha.txt", vec![0u8; 512 * 1024]).unwrap();
        store.set_file("beta.txt", vec![0u8; 512 * 1024]).unwrap();
        let before = store
            .current_projected_blob_len()
            .unwrap()
            .expect("current blob length");
        let files = store.current_plain_files();
        let make_peers = |count: usize| {
            (0..count)
                .map(|index| {
                    test_peer(
                        format!("peer-{index:08}").as_bytes(),
                        storedpb::PeerOrigin::Discovered,
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut high = 1usize;
        while store.codec.encoded_len(&files, &make_peers(high)).unwrap()
            <= MAX_SHARED_CONTENT_BLOB_BYTES
        {
            high *= 2;
        }
        let mut low = 1usize;
        while low < high {
            let mid = low + (high - low) / 2;
            if store.codec.encoded_len(&files, &make_peers(mid)).unwrap()
                <= MAX_SHARED_CONTENT_BLOB_BYTES
            {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        let oversized_peers = make_peers(high);
        let projected = store.codec.encoded_len(&files, &oversized_peers).unwrap();
        store.peers = oversized_peers;
        assert!(projected > before);

        assert!(
            store.current_projected_blob_len().unwrap().unwrap() > MAX_SHARED_CONTENT_BLOB_BYTES
        );
        assert_eq!(store.get_file("alpha.txt").unwrap().len(), 512 * 1024);
        store.delete_file("beta.txt").unwrap();
        assert_eq!(store.list_files(), vec!["alpha.txt".to_string()]);
    }
}
