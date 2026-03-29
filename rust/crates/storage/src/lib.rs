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
use protos::storedpb;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;
use thiserror::Error;

const PEER_STATE_FILE: &str = ".peer-state.v1";
const PEER_STATE_NONCE_LEN: usize = 12;
const PEER_STATE_TAG_LEN: usize = 16;

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

    /// The last remaining file cannot be deleted.
    #[error("cannot delete the last remaining file")]
    CannotDeleteLastFile,

    /// The current on-disk state needs operator intervention.
    #[error("recovery required: {0}")]
    RecoveryRequired(String),

    /// The provided timestamp is invalid.
    #[error("invalid timestamp")]
    InvalidTimestamp,

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

/// Store owns the live local file set and the encrypted content blobs on disk.
pub struct Store {
    fs: Arc<dyn Filesystem>,
    time_source: Arc<dyn Clock>,
    codec: ContentCodec,
    peer_cipher: Aes256GcmSiv,
    files: BTreeMap<String, Vec<u8>>,
    peers: Vec<storedpb::Peer>,
    current: Option<CurrentContent>,
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

        let codec = ContentCodec::new(&revision_key, &metadata_key, &file_key)?;
        let peer_cipher = Aes256GcmSiv::new_from_slice(&peer_state_key)
            .map_err(|err| StorageError::Message(err.to_string()))?;

        let mut store = Self {
            fs,
            time_source,
            codec,
            peer_cipher,
            files: BTreeMap::new(),
            peers: Vec::new(),
            current: None,
        };
        store.load()?;
        Ok(store)
    }

    /// Return the current content summary if one exists.
    pub fn current_content(&self) -> Option<&CurrentContent> {
        self.current.as_ref()
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

    /// Read a plaintext file by name.
    pub fn get_file(&self, name: &str) -> Result<Vec<u8>, StorageError> {
        self.files
            .get(name)
            .cloned()
            .ok_or(StorageError::FileNotFound)
    }

    /// Persist or replace a plaintext file.
    pub fn set_file(&mut self, name: &str, data: Vec<u8>) -> Result<(), StorageError> {
        if name.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        self.files.insert(name.to_string(), data);
        self.persist_files()
    }

    /// Delete a plaintext file while preserving at least one file.
    pub fn delete_file(&mut self, name: &str) -> Result<(), StorageError> {
        if !self.files.contains_key(name) {
            return Err(StorageError::FileNotFound);
        }
        if self.files.len() == 1 {
            return Err(StorageError::CannotDeleteLastFile);
        }

        self.files.remove(name);
        self.persist_files()
    }

    /// Return a copy of the tracked peer metadata.
    pub fn peers(&self) -> Vec<storedpb::Peer> {
        self.peers.clone()
    }

    /// Upsert the latest known content id for a peer.
    pub fn set_peer_content_id(
        &mut self,
        onion_pubkey: &[u8],
        content_id: &[u8],
    ) -> Result<(), StorageError> {
        if onion_pubkey.is_empty() || content_id.is_empty() {
            return Err(StorageError::InvalidFileName);
        }

        if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|peer| peer.onion_pubkey == onion_pubkey)
        {
            peer.content_id = content_id.to_vec();
        } else {
            self.peers.push(storedpb::Peer {
                onion_pubkey: onion_pubkey.to_vec(),
                score_seconds: 0,
                score_measured_at: 0,
                content_id: content_id.to_vec(),
            });
        }

        self.persist_peer_state()
    }

    /// Remove a peer entry if it exists.
    pub fn remove_peer(&mut self, onion_pubkey: &[u8]) -> Result<(), StorageError> {
        let before = self.peers.len();
        self.peers
            .retain(|peer| peer.onion_pubkey.as_slice() != onion_pubkey);
        if self.peers.len() != before {
            self.persist_peer_state()?;
        }
        Ok(())
    }

    /// Read the raw encrypted content blob for the active revision.
    pub fn current_blob(&self) -> Result<Vec<u8>, StorageError> {
        let current = self.current.as_ref().ok_or(StorageError::FileNotFound)?;
        self.fs.read(&current.file_name)
    }

    /// Read any stored content blob by content id.
    pub fn read_blob_by_id(&self, content_id: &[u8]) -> Result<Vec<u8>, StorageError> {
        self.fs.read(&content_file_name(content_id))
    }

    /// Atomically write an arbitrary content blob under its content id.
    pub fn write_content_blob(&self, content_id: &[u8], blob: &[u8]) -> Result<(), StorageError> {
        self.fs.write_atomic(&content_file_name(content_id), blob)
    }

    /// Remove a stored content blob if it exists.
    pub fn remove_content_blob(&self, content_id: &[u8]) -> Result<(), StorageError> {
        self.fs.remove(&content_file_name(content_id))
    }

    /// Remove non-local blobs that are not in the supplied valid set.
    pub fn cleanup_foreign(&self, valid_content_ids: &[Vec<u8>]) -> Result<(), StorageError> {
        let mut keep = valid_content_ids
            .iter()
            .map(|content_id| content_file_name(content_id))
            .collect::<Vec<_>>();
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
        self.load_peer_state()?;

        let mut valid = Vec::new();
        let mut invalid = Vec::new();
        for name in self.fs.list()? {
            if name == PEER_STATE_FILE {
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
                return Ok(());
            }
            return Err(StorageError::RecoveryRequired(format!(
                "found no valid content blobs and {} invalid candidate(s)",
                invalid.len()
            )));
        }
        if valid.len() == 1 && invalid.is_empty() {
            self.adopt(valid.pop().unwrap());
            return Ok(());
        }
        if valid.len() == 2 && invalid.is_empty() {
            valid.sort_by(|left, right| compare_candidates(left, right));
            let newest = valid.pop().unwrap();
            let older = valid.pop().unwrap();
            let _ = self.fs.remove(&older.name);
            self.adopt(newest);
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

    /// Persist the current plaintext file set as a new encrypted revision.
    fn persist_files(&mut self) -> Result<(), StorageError> {
        let timestamp = self.time_source.now();
        if timestamp.nanos >= 1_000_000_000 {
            return Err(StorageError::InvalidTimestamp);
        }

        let next_sequence = self
            .current
            .as_ref()
            .map_or(1, |current| current.revision.sequence + 1);
        let files = self
            .files
            .iter()
            .map(|(name, data)| PlainFile {
                name: name.clone(),
                data: data.clone(),
            })
            .collect::<Vec<_>>();
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

        if let Some(previous_name) = previous_name {
            if previous_name != new_name {
                let _ = self.fs.remove(&previous_name);
            }
        }

        Ok(())
    }

    /// Persist the encrypted peer sidecar without touching the content blob.
    fn persist_peer_state(&self) -> Result<(), StorageError> {
        let metadata = storedpb::Metadata {
            files: Vec::new(),
            peers: self.peers.clone(),
        };
        let plaintext = metadata.encode_to_vec();
        let ciphertext = encrypt_sidecar(&self.peer_cipher, &plaintext);
        self.fs.write_atomic(PEER_STATE_FILE, &ciphertext)
    }

    /// Load the encrypted peer sidecar if it exists.
    fn load_peer_state(&mut self) -> Result<(), StorageError> {
        let ciphertext = match self.fs.read(PEER_STATE_FILE) {
            Ok(ciphertext) => ciphertext,
            Err(StorageError::FileNotFound) => return Ok(()),
            Err(err) => return Err(err),
        };
        let plaintext = decrypt_sidecar(&self.peer_cipher, &ciphertext)?;
        let metadata = storedpb::Metadata::decode(plaintext.as_slice())?;
        self.peers = metadata.peers;
        Ok(())
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

    fn time_source() -> Arc<dyn Clock> {
        let clock = clock::ManualClock::new(clock::Timestamp::new(10, 1).unwrap());
        clock.set(clock::Timestamp::new(10, 1).unwrap());
        Arc::new(clock)
    }

    fn master() -> Vec<u8> {
        keys::derive_master_priv("storage-master")
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
    fn deleting_last_file_is_rejected() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs, &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();

        assert!(matches!(
            store.delete_file("alpha.txt"),
            Err(StorageError::CannotDeleteLastFile)
        ));
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
    fn cleanup_foreign_leaves_current_and_valid_blobs() {
        let fs: Arc<dyn Filesystem> = Arc::new(MemoryFilesystem::new());
        let mut store = Store::new_with_time_source(fs.clone(), &master(), time_source()).unwrap();
        store.set_file("alpha.txt", b"secret".to_vec()).unwrap();
        let current_id = store.current_content().unwrap().content_id.clone();

        fs.write_atomic("foreign", b"data").unwrap();
        let other_id = vec![0x44; content::CONTENT_ID_LEN];
        fs.write_atomic(&content_file_name(&other_id), b"peer-blob")
            .unwrap();

        store
            .cleanup_foreign(std::slice::from_ref(&other_id))
            .unwrap();

        assert!(fs.read("foreign").is_ok());
        assert!(fs.read(&content_file_name(&other_id)).is_ok());
        assert!(fs.read(&content_file_name(&current_id)).is_ok());
    }

    #[test]
    fn os_filesystem_write_atomic_replaces_target() {
        let temp = tempfile::tempdir().unwrap();
        let fs = OsFilesystem::new(temp.path()).unwrap();

        fs.write_atomic("blob", b"v1").unwrap();
        fs.write_atomic("blob", b"v2").unwrap();

        assert_eq!(fs.read("blob").unwrap(), b"v2".to_vec());
    }
}
