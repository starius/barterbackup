//! Encrypted content blob encoding for BarterBackup.
//!
//! The codec gives the project a versioned, comparable revision descriptor and
//! an authenticated content container that never stores plaintext filenames or
//! file bytes on disk.

use aes_gcm_siv::aead::{Aead, Payload};
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use prost::Message;
use protos::storedpb;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use thiserror::Error;

/// Header bytes that identify an encoded content blob.
pub const HEADER_MAGIC: &[u8; 4] = b"BBUC";

/// File format version for the outer content blob.
pub const BLOB_VERSION: u8 = 1;

/// File format version for the encrypted revision descriptor.
pub const REVISION_VERSION: u8 = 1;

/// Size of the content-id plaintext before authentication.
pub const REVISION_PLAINTEXT_LEN: usize = 1 + 8 + 8 + 4 + 4;

/// AES-GCM-SIV nonce length.
pub const NONCE_LEN: usize = 12;

/// AES-GCM-SIV tag length.
pub const TAG_LEN: usize = 16;

/// Total serialized content-id length.
pub const CONTENT_ID_LEN: usize = REVISION_PLAINTEXT_LEN + TAG_LEN;

/// Blob alignment used to reduce size leakage.
pub const CONTENT_ALIGNMENT: usize = 32 * 1024;

const CONTENT_ID_NONCE: [u8; NONCE_LEN] = *b"bb-cid-v001!";

/// ContentError reports validation, encoding, or decoding failures.
#[derive(Debug, Error)]
pub enum ContentError {
    /// The provided key material has the wrong length.
    #[error("content key {label} must be 32 bytes, got {actual}")]
    InvalidKeyLength {
        /// label identifies the failing key slot.
        label: &'static str,
        /// actual is the observed byte length.
        actual: usize,
    },

    /// The revision fields are invalid.
    #[error("invalid revision: {0}")]
    InvalidRevision(&'static str),

    /// The caller attempted to encode an empty file set.
    #[error("at least one file is required")]
    EmptyFileSet,

    /// Duplicate file names are not allowed.
    #[error("duplicate file name {0:?}")]
    DuplicateFileName(String),

    /// The blob header is invalid.
    #[error("invalid blob header")]
    InvalidHeader,

    /// The blob version is unsupported.
    #[error("unsupported blob version {0}")]
    UnsupportedBlobVersion(u8),

    /// The revision descriptor version is unsupported.
    #[error("unsupported revision version {0}")]
    UnsupportedRevisionVersion(u8),

    /// The encoded blob is truncated or otherwise inconsistent.
    #[error("truncated or inconsistent content blob")]
    Truncated,

    /// The metadata length is invalid for the current platform.
    #[error("metadata ciphertext length is invalid")]
    InvalidMetadataLength,

    /// The file ordering in metadata is invalid.
    #[error("metadata file ordering is invalid")]
    InvalidFileOrdering,

    /// One stored file metadata field is invalid.
    #[error("invalid file metadata: {0}")]
    InvalidFileMetadata(&'static str),

    /// The file hash did not match the decrypted body.
    #[error("file hash mismatch for {0:?}")]
    FileHashMismatch(String),

    /// Cryptographic authentication failed.
    #[error("content authentication failed")]
    Crypto,

    /// Prost encoding or decoding failed.
    #[error("protobuf error: {0}")]
    Protobuf(#[from] prost::DecodeError),
}

/// RevisionSeed provides caller-controlled ordering data for a new revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevisionSeed {
    /// sequence is the monotonic revision number for this seed.
    pub sequence: u64,
    /// created_at_secs is the Unix timestamp in whole seconds.
    pub created_at_secs: u64,
    /// created_at_nanos is the nanosecond component of the timestamp.
    pub created_at_nanos: u32,
}

/// RevisionDescriptor is the authenticated, comparable revision descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevisionDescriptor {
    /// sequence is the monotonic revision number for this seed.
    pub sequence: u64,
    /// created_at_secs is the Unix timestamp in whole seconds.
    pub created_at_secs: u64,
    /// created_at_nanos is the nanosecond component of the timestamp.
    pub created_at_nanos: u32,
    /// metadata_ciphertext_len is the serialized metadata segment length.
    pub metadata_ciphertext_len: u32,
}

impl Ord for RevisionDescriptor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sequence
            .cmp(&other.sequence)
            .then(self.created_at_secs.cmp(&other.created_at_secs))
            .then(self.created_at_nanos.cmp(&other.created_at_nanos))
            .then(
                self.metadata_ciphertext_len
                    .cmp(&other.metadata_ciphertext_len),
            )
    }
}

impl PartialOrd for RevisionDescriptor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// PlainFile is a decrypted user file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainFile {
    /// name is the stable user-facing file identifier.
    pub name: String,
    /// data is the plaintext file body.
    pub data: Vec<u8>,
    /// modified_at_secs is the Unix timestamp in whole seconds.
    pub modified_at_secs: u64,
    /// modified_at_nanos is the nanosecond component of the source file mtime.
    pub modified_at_nanos: u32,
}

/// EncodedContent is the result of sealing a content revision.
#[derive(Clone, Debug, PartialEq)]
pub struct EncodedContent {
    /// revision is the authenticated descriptor for this blob.
    pub revision: RevisionDescriptor,
    /// content_id is the encrypted revision descriptor sent to peers.
    pub content_id: Vec<u8>,
    /// metadata is the decrypted metadata used to encode the blob.
    pub metadata: storedpb::Metadata,
    /// bytes is the complete encrypted content blob.
    pub bytes: Vec<u8>,
}

/// DecodedContent is the result of opening a content blob.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedContent {
    /// revision is the authenticated descriptor for this blob.
    pub revision: RevisionDescriptor,
    /// content_id is the encrypted revision descriptor found in the blob.
    pub content_id: Vec<u8>,
    /// metadata is the authenticated metadata message.
    pub metadata: storedpb::Metadata,
    /// files maps file names to plaintext bodies and metadata.
    pub files: BTreeMap<String, PlainFile>,
}

/// ContentCodec owns the subkeys used to encode and decode content blobs.
#[derive(Clone)]
pub struct ContentCodec {
    revision_cipher: Aes256GcmSiv,
    metadata_cipher: Aes256GcmSiv,
    file_cipher: Aes256GcmSiv,
}

impl ContentCodec {
    /// Build a codec from raw 32-byte subkeys.
    pub fn new(
        revision_key: &[u8],
        metadata_key: &[u8],
        file_key: &[u8],
    ) -> Result<Self, ContentError> {
        let revision_cipher = build_cipher("revision", revision_key)?;
        let metadata_cipher = build_cipher("metadata", metadata_key)?;
        let file_cipher = build_cipher("file", file_key)?;

        Ok(Self {
            revision_cipher,
            metadata_cipher,
            file_cipher,
        })
    }

    /// Encode a new revision from plaintext files and known peers.
    pub fn encode(
        &self,
        seed: RevisionSeed,
        files: &[PlainFile],
        peers: &[storedpb::Peer],
    ) -> Result<EncodedContent, ContentError> {
        // Normalize the file set before deriving metadata or offsets.
        let ordered_files = normalize_files(files)?;
        let metadata = build_metadata(&ordered_files, peers);
        let metadata_plain = metadata.encode_to_vec();
        let revision = build_revision_descriptor(seed, metadata_plain.len())?;
        let content_id = self.make_content_id(revision)?;

        // Seal metadata first so its serialized length matches the revision.
        let metadata_aad = revision.serialize();
        let metadata_ciphertext =
            encrypt_random(&self.metadata_cipher, &metadata_aad, &metadata_plain);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(BLOB_VERSION);
        bytes.extend_from_slice(&content_id);
        bytes.extend_from_slice(&metadata_ciphertext);

        // Seal each file independently so tampering is localized and easy to
        // validate while keeping every file fully authenticated.
        for file in &ordered_files {
            let file_aad = build_file_aad(revision, &file.name, file.data.len() as u64);
            let file_ciphertext = encrypt_random(&self.file_cipher, &file_aad, &file.data);
            bytes.extend_from_slice(&file_ciphertext);
        }

        // Fill the remainder of the aligned blob with random cover bytes.
        let padding_len = aligned_padding(bytes.len(), CONTENT_ALIGNMENT);
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            OsRng.fill_bytes(&mut padding);
            bytes.extend_from_slice(&padding);
        }

        Ok(EncodedContent {
            revision,
            content_id,
            metadata,
            bytes,
        })
    }

    /// Return the encoded blob length for one revision without allocating or
    /// producing ciphertext bytes.
    pub fn encoded_len(
        &self,
        files: &[PlainFile],
        peers: &[storedpb::Peer],
    ) -> Result<usize, ContentError> {
        let ordered_files = normalize_files(files)?;
        let metadata = build_metadata(&ordered_files, peers);
        let metadata_plain = metadata.encode_to_vec();
        let metadata_ciphertext_len = encrypted_segment_len(metadata_plain.len());

        let mut total_len = HEADER_MAGIC.len() + 1 + CONTENT_ID_LEN + metadata_ciphertext_len;
        for file in &ordered_files {
            total_len = total_len
                .checked_add(encrypted_segment_len(file.data.len()))
                .ok_or(ContentError::InvalidMetadataLength)?;
        }
        total_len = total_len
            .checked_add(aligned_padding(total_len, CONTENT_ALIGNMENT))
            .ok_or(ContentError::InvalidMetadataLength)?;

        Ok(total_len)
    }

    /// Decode an encrypted content blob into plaintext files and metadata.
    pub fn decode(&self, encoded: &[u8]) -> Result<DecodedContent, ContentError> {
        // Parse and authenticate the outer header before touching inner data.
        let mut offset = 0usize;
        if encoded.len() < HEADER_MAGIC.len() + 1 + CONTENT_ID_LEN {
            return Err(ContentError::Truncated);
        }
        if &encoded[..HEADER_MAGIC.len()] != HEADER_MAGIC {
            return Err(ContentError::InvalidHeader);
        }
        offset += HEADER_MAGIC.len();

        let version = encoded[offset];
        offset += 1;
        if version != BLOB_VERSION {
            return Err(ContentError::UnsupportedBlobVersion(version));
        }

        let content_id = encoded[offset..offset + CONTENT_ID_LEN].to_vec();
        offset += CONTENT_ID_LEN;
        let revision = self.parse_content_id(&content_id)?;

        let metadata_len = usize::try_from(revision.metadata_ciphertext_len)
            .map_err(|_| ContentError::InvalidMetadataLength)?;
        if encoded.len() < offset + metadata_len {
            return Err(ContentError::Truncated);
        }

        let metadata_plain = decrypt_random(
            &self.metadata_cipher,
            &revision.serialize(),
            &encoded[offset..offset + metadata_len],
        )?;
        offset += metadata_len;

        let metadata = storedpb::Metadata::decode(metadata_plain.as_slice())?;
        validate_file_headers(metadata.files.as_slice())?;

        // Decrypt and validate each file in the exact order described by metadata.
        let mut files = BTreeMap::new();
        for file_header in metadata.files.iter() {
            let plaintext_len =
                usize::try_from(file_header.file_length).map_err(|_| ContentError::Truncated)?;
            let ciphertext_len = encrypted_segment_len(plaintext_len);
            if encoded.len() < offset + ciphertext_len {
                return Err(ContentError::Truncated);
            }

            let file_aad = build_file_aad(
                revision,
                &file_header.name,
                u64::try_from(plaintext_len).map_err(|_| ContentError::Truncated)?,
            );
            let plaintext = decrypt_random(
                &self.file_cipher,
                &file_aad,
                &encoded[offset..offset + ciphertext_len],
            )?;
            offset += ciphertext_len;

            verify_file_hash(&file_header.name, &file_header.file_sha256, &plaintext)?;
            let file = PlainFile {
                name: file_header.name.clone(),
                data: plaintext,
                modified_at_secs: u64::try_from(file_header.modified_at).map_err(|_| {
                    ContentError::InvalidFileMetadata("modified_at is out of range")
                })?,
                modified_at_nanos: u32::try_from(file_header.modified_at_ns).map_err(|_| {
                    ContentError::InvalidFileMetadata("modified_at_ns is out of range")
                })?,
            };
            if files.insert(file_header.name.clone(), file).is_some() {
                return Err(ContentError::DuplicateFileName(file_header.name.clone()));
            }
        }

        // Keep the padding opaque, but require the full blob alignment.
        if !encoded.len().is_multiple_of(CONTENT_ALIGNMENT) {
            return Err(ContentError::Truncated);
        }

        Ok(DecodedContent {
            revision,
            content_id,
            metadata,
            files,
        })
    }

    /// Parse and authenticate a content identifier.
    pub fn parse_content_id(&self, content_id: &[u8]) -> Result<RevisionDescriptor, ContentError> {
        if content_id.len() != CONTENT_ID_LEN {
            return Err(ContentError::Truncated);
        }

        let plaintext = self
            .revision_cipher
            .decrypt(
                Nonce::from_slice(&CONTENT_ID_NONCE),
                Payload {
                    msg: content_id,
                    aad: &[],
                },
            )
            .map_err(|_| ContentError::Crypto)?;

        RevisionDescriptor::deserialize(&plaintext)
    }

    /// Seal a revision descriptor into a deterministic content identifier.
    pub fn make_content_id(&self, revision: RevisionDescriptor) -> Result<Vec<u8>, ContentError> {
        self.revision_cipher
            .encrypt(
                Nonce::from_slice(&CONTENT_ID_NONCE),
                Payload {
                    msg: &revision.serialize(),
                    aad: &[],
                },
            )
            .map_err(|_| ContentError::Crypto)
    }
}

impl RevisionDescriptor {
    /// Serialize the descriptor into its fixed-width binary form.
    pub fn serialize(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REVISION_PLAINTEXT_LEN);
        bytes.push(REVISION_VERSION);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.created_at_secs.to_be_bytes());
        bytes.extend_from_slice(&self.created_at_nanos.to_be_bytes());
        bytes.extend_from_slice(&self.metadata_ciphertext_len.to_be_bytes());
        bytes
    }

    /// Deserialize a fixed-width binary revision descriptor.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ContentError> {
        if bytes.len() != REVISION_PLAINTEXT_LEN {
            return Err(ContentError::Truncated);
        }
        if bytes[0] != REVISION_VERSION {
            return Err(ContentError::UnsupportedRevisionVersion(bytes[0]));
        }

        let sequence = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
        let created_at_secs = u64::from_be_bytes(bytes[9..17].try_into().unwrap());
        let created_at_nanos = u32::from_be_bytes(bytes[17..21].try_into().unwrap());
        let metadata_ciphertext_len = u32::from_be_bytes(bytes[21..25].try_into().unwrap());

        if created_at_nanos >= 1_000_000_000 {
            return Err(ContentError::InvalidRevision(
                "created_at_nanos must be below one second",
            ));
        }
        if metadata_ciphertext_len as usize <= NONCE_LEN + TAG_LEN {
            return Err(ContentError::InvalidRevision(
                "metadata ciphertext is too short",
            ));
        }

        Ok(Self {
            sequence,
            created_at_secs,
            created_at_nanos,
            metadata_ciphertext_len,
        })
    }
}

/// Compute the ciphertext segment length for a plaintext payload.
pub fn encrypted_segment_len(plaintext_len: usize) -> usize {
    NONCE_LEN + plaintext_len + TAG_LEN
}

/// Compute the required padding to align a blob.
pub fn aligned_padding(current_len: usize, alignment: usize) -> usize {
    let remainder = current_len % alignment;
    if remainder == 0 {
        0
    } else {
        alignment - remainder
    }
}

/// Build a validated revision descriptor once the metadata length is known.
fn build_revision_descriptor(
    seed: RevisionSeed,
    metadata_plain_len: usize,
) -> Result<RevisionDescriptor, ContentError> {
    if seed.created_at_nanos >= 1_000_000_000 {
        return Err(ContentError::InvalidRevision(
            "created_at_nanos must be below one second",
        ));
    }

    let metadata_ciphertext_len = encrypted_segment_len(metadata_plain_len);
    let metadata_ciphertext_len =
        u32::try_from(metadata_ciphertext_len).map_err(|_| ContentError::InvalidMetadataLength)?;

    Ok(RevisionDescriptor {
        sequence: seed.sequence,
        created_at_secs: seed.created_at_secs,
        created_at_nanos: seed.created_at_nanos,
        metadata_ciphertext_len,
    })
}

/// Build protobuf metadata from the normalized file set and peer list.
fn build_metadata(files: &[PlainFile], peers: &[storedpb::Peer]) -> storedpb::Metadata {
    let file_headers = files
        .iter()
        .map(|file| storedpb::FileHeader {
            name: file.name.clone(),
            file_length: i64::try_from(file.data.len()).unwrap(),
            file_sha256: Sha256::digest(&file.data).to_vec(),
            modified_at: i64::try_from(file.modified_at_secs).unwrap_or(i64::MAX),
            modified_at_ns: i64::from(file.modified_at_nanos),
        })
        .collect();

    storedpb::Metadata {
        files: file_headers,
        peers: peers.to_vec(),
        node_initialized_at: 0,
        node_initialized_at_ns: 0,
        latest_recovered_revision: None,
        recovery_watermark_at: 0,
        recovery_watermark_at_ns: 0,
        recovery_mode_enabled: false,
        current_content: None,
        metadata_rollup_due_at: 0,
        metadata_rollup_due_at_ns: 0,
        metadata_rollup_base_content_id: Vec::new(),
    }
}

/// Normalize the plaintext file set into a deterministic order.
fn normalize_files(files: &[PlainFile]) -> Result<Vec<PlainFile>, ContentError> {
    if files.is_empty() {
        return Err(ContentError::EmptyFileSet);
    }

    let mut normalized = files.to_vec();
    normalized.sort_by(|left, right| left.name.cmp(&right.name));

    for window in normalized.windows(2) {
        if window[0].name == window[1].name {
            return Err(ContentError::DuplicateFileName(window[0].name.clone()));
        }
    }

    Ok(normalized)
}

/// Validate that metadata file headers are strictly ordered and unique.
fn validate_file_headers(file_headers: &[storedpb::FileHeader]) -> Result<(), ContentError> {
    if file_headers.is_empty() {
        return Err(ContentError::EmptyFileSet);
    }

    for window in file_headers.windows(2) {
        if window[0].name >= window[1].name {
            return Err(ContentError::InvalidFileOrdering);
        }
    }

    for file in file_headers {
        if file.modified_at < 0 {
            return Err(ContentError::InvalidFileMetadata(
                "modified_at must not be negative",
            ));
        }
        if !(0..1_000_000_000).contains(&file.modified_at_ns) {
            return Err(ContentError::InvalidFileMetadata(
                "modified_at_ns must be below one second",
            ));
        }
    }

    Ok(())
}

/// Derive authenticated data for an encrypted file segment.
fn build_file_aad(revision: RevisionDescriptor, file_name: &str, file_len: u64) -> Vec<u8> {
    let mut aad = revision.serialize();
    aad.extend_from_slice(&file_len.to_be_bytes());
    aad.extend_from_slice(file_name.as_bytes());
    aad
}

/// Encrypt a payload with a random nonce stored inline.
fn encrypt_random(cipher: &Aes256GcmSiv, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM-SIV encryption should not fail with valid inputs");

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt a payload with an inline nonce prefix.
fn decrypt_random(
    cipher: &Aes256GcmSiv,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ContentError> {
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(ContentError::Truncated);
    }

    cipher
        .decrypt(
            Nonce::from_slice(&ciphertext[..NONCE_LEN]),
            Payload {
                msg: &ciphertext[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| ContentError::Crypto)
}

/// Verify the plaintext hash against the metadata hash.
fn verify_file_hash(
    file_name: &str,
    expected_hash: &[u8],
    plaintext: &[u8],
) -> Result<(), ContentError> {
    let actual_hash = Sha256::digest(plaintext);
    if actual_hash.as_slice() != expected_hash {
        return Err(ContentError::FileHashMismatch(file_name.to_string()));
    }
    Ok(())
}

/// Construct an AES-GCM-SIV cipher from a validated 32-byte key.
fn build_cipher(label: &'static str, key: &[u8]) -> Result<Aes256GcmSiv, ContentError> {
    if key.len() != 32 {
        return Err(ContentError::InvalidKeyLength {
            label,
            actual: key.len(),
        });
    }

    Ok(Aes256GcmSiv::new_from_slice(key).expect("32-byte key length is validated"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    const REVISION_KEY: [u8; 32] = [0x11; 32];
    const METADATA_KEY: [u8; 32] = [0x22; 32];
    const FILE_KEY: [u8; 32] = [0x33; 32];

    fn codec() -> ContentCodec {
        ContentCodec::new(&REVISION_KEY, &METADATA_KEY, &FILE_KEY).unwrap()
    }

    fn sample_seed(sequence: u64) -> RevisionSeed {
        RevisionSeed {
            sequence,
            created_at_secs: 1_717_171_717,
            created_at_nanos: 123_456_789,
        }
    }

    fn sample_files() -> Vec<PlainFile> {
        vec![
            PlainFile {
                name: "alpha.txt".to_string(),
                data: b"alpha-body".to_vec(),
                modified_at_secs: 1_700_000_001,
                modified_at_nanos: 11,
            },
            PlainFile {
                name: "beta.txt".to_string(),
                data: b"beta-body".to_vec(),
                modified_at_secs: 1_700_000_002,
                modified_at_nanos: 22,
            },
        ]
    }

    /// Build a random but portable test file name.
    fn arb_file_name() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9._-]{0,7}".prop_map(|name| name.to_string())
    }

    /// Build a deterministic file set with unique names.
    fn arb_file_set() -> impl Strategy<Value = Vec<PlainFile>> {
        proptest::collection::btree_map(
            arb_file_name(),
            proptest::collection::vec(any::<u8>(), 0..96),
            1..5,
        )
        .prop_map(|files| {
            files
                .into_iter()
                .map(|(name, data)| PlainFile {
                    name,
                    data,
                    modified_at_secs: 0,
                    modified_at_nanos: 0,
                })
                .collect()
        })
    }

    /// Return the parsed prefix of an encoded blob that is fully authenticated.
    fn authenticated_prefix_len(encoded: &EncodedContent) -> usize {
        let file_ciphertext_len = encoded
            .metadata
            .files
            .iter()
            .map(|file| encrypted_segment_len(file.file_length as usize))
            .sum::<usize>();

        HEADER_MAGIC.len()
            + 1
            + CONTENT_ID_LEN
            + encoded.revision.metadata_ciphertext_len as usize
            + file_ciphertext_len
    }

    #[test]
    fn content_id_round_trips_and_orders_by_sequence() {
        let codec = codec();
        let lower = build_revision_descriptor(sample_seed(1), 10).unwrap();
        let higher = build_revision_descriptor(sample_seed(2), 10).unwrap();

        let lower_id = codec.make_content_id(lower).unwrap();
        let higher_id = codec.make_content_id(higher).unwrap();

        assert_eq!(codec.parse_content_id(&lower_id).unwrap(), lower);
        assert_eq!(codec.parse_content_id(&higher_id).unwrap(), higher);
        assert!(higher > lower);
        assert_ne!(lower_id, higher_id);
    }

    #[test]
    fn encode_decode_round_trip_preserves_files_and_metadata() {
        let codec = codec();
        let peers = vec![storedpb::Peer {
            onion_pubkey: b"peer".to_vec(),
            score_seconds: 9,
            score_measured_at: 77,
            content_id: b"cid".to_vec(),
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
        }];
        let encoded = codec
            .encode(sample_seed(7), &sample_files(), &peers)
            .unwrap();
        let decoded = codec.decode(&encoded.bytes).unwrap();

        assert_eq!(decoded.revision, encoded.revision);
        assert_eq!(decoded.content_id, encoded.content_id);
        assert_eq!(decoded.metadata, encoded.metadata);
        assert_eq!(
            decoded.files.get("alpha.txt").unwrap().data,
            b"alpha-body".to_vec(),
        );
        assert_eq!(
            decoded.files.get("beta.txt").unwrap().data,
            b"beta-body".to_vec(),
        );
        assert_eq!(
            decoded.files.get("alpha.txt").unwrap().modified_at_secs,
            1_700_000_001
        );
        assert_eq!(decoded.files.get("beta.txt").unwrap().modified_at_nanos, 22);
        assert_eq!(encoded.bytes.len() % CONTENT_ALIGNMENT, 0);
    }

    #[test]
    fn identical_plaintexts_produce_distinct_ciphertexts() {
        let codec = codec();
        let files = vec![
            PlainFile {
                name: "one".to_string(),
                data: vec![0x55; 64],
                modified_at_secs: 0,
                modified_at_nanos: 0,
            },
            PlainFile {
                name: "two".to_string(),
                data: vec![0x55; 64],
                modified_at_secs: 0,
                modified_at_nanos: 0,
            },
        ];
        let first = codec.encode(sample_seed(9), &files, &[]).unwrap();
        let second = codec.encode(sample_seed(9), &files, &[]).unwrap();

        assert_ne!(first.bytes, second.bytes);
        assert_eq!(first.revision, second.revision);
        assert_eq!(first.content_id, second.content_id);
    }

    #[test]
    fn encoded_len_matches_encoded_blob_length() {
        let codec = codec();
        let files = sample_files();
        let encoded = codec.encode(sample_seed(11), &files, &[]).unwrap();

        assert_eq!(codec.encoded_len(&files, &[]).unwrap(), encoded.bytes.len());
    }

    #[test]
    fn tampering_with_file_ciphertext_is_detected() {
        let codec = codec();
        let mut encoded = codec.encode(sample_seed(5), &sample_files(), &[]).unwrap();
        let mut offset = HEADER_MAGIC.len() + 1 + CONTENT_ID_LEN;
        offset += usize::try_from(encoded.revision.metadata_ciphertext_len).unwrap();
        offset += NONCE_LEN;
        encoded.bytes[offset] ^= 0x01;

        assert!(matches!(
            codec.decode(&encoded.bytes),
            Err(ContentError::Truncated)
                | Err(ContentError::Crypto)
                | Err(ContentError::FileHashMismatch(_))
        ));
    }

    #[test]
    fn duplicate_file_names_are_rejected() {
        let codec = codec();
        let files = vec![
            PlainFile {
                name: "dup".to_string(),
                data: b"a".to_vec(),
                modified_at_secs: 0,
                modified_at_nanos: 0,
            },
            PlainFile {
                name: "dup".to_string(),
                data: b"b".to_vec(),
                modified_at_secs: 0,
                modified_at_nanos: 0,
            },
        ];

        assert!(matches!(
            codec.encode(sample_seed(1), &files, &[]),
            Err(ContentError::DuplicateFileName(name)) if name == "dup"
        ));
    }

    #[test]
    fn invalid_revision_nanos_are_rejected() {
        let codec = codec();
        let seed = RevisionSeed {
            sequence: 1,
            created_at_secs: 0,
            created_at_nanos: 1_000_000_000,
        };

        assert!(matches!(
            codec.encode(seed, &sample_files(), &[]),
            Err(ContentError::InvalidRevision(_))
        ));
    }

    proptest! {
        #[test]
        fn property_round_trip_preserves_random_files(
            files in arb_file_set(),
            sequence in 1u64..10_000,
            created_at_secs in 0u64..2_000_000_000,
            created_at_nanos in 0u32..1_000_000_000,
        ) {
            let codec = codec();
            let encoded = codec
                .encode(
                    RevisionSeed {
                        sequence,
                        created_at_secs,
                        created_at_nanos,
                    },
                    &files,
                    &[],
                )
                .unwrap();
            let decoded = codec.decode(&encoded.bytes).unwrap();
            let expected_files = files
                .iter()
                .map(|file| (file.name.clone(), file.clone()))
                .collect::<BTreeMap<_, _>>();

            prop_assert_eq!(decoded.files, expected_files);
            prop_assert_eq!(decoded.content_id, encoded.content_id);
            prop_assert_eq!(decoded.revision, encoded.revision);
        }
    }

    proptest! {
        #[test]
        fn property_tampering_authenticated_bytes_is_detected(
            files in arb_file_set(),
            flip_seed in any::<usize>(),
            flip_mask in 1u8..=0x80,
        ) {
            let codec = codec();
            let encoded = codec
                .encode(sample_seed(42), &files, &[])
                .unwrap();
            let prefix_len = authenticated_prefix_len(&encoded);
            let flip_index = flip_seed % prefix_len;
            let mut tampered = encoded.bytes.clone();
            tampered[flip_index] ^= flip_mask;

            let decoded = codec.decode(&tampered);
            prop_assert!(decoded.is_err(), "tampering inside the authenticated prefix must fail");
        }
    }
}
