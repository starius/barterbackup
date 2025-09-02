# barterbackup

Mutual backup system: you store my data, I store yours.

**Overview**
- BarterBackup is a daemon + CLI that lets peers mutually back up data over
  Tor onion services. Each node stores an encrypted blob for its peers in
  exchange for peers storing its own encrypted blob.
- The system negotiates storage “contracts”, verifies availability with spot
  checks, and can recover content from multiple replicas.

**Terminology**
- File: A user‑provided input sent by the client. There can be many files.
- Content: A single finalized encrypted blob derived from the current set of
  files. This is the unit that is stored locally and backed up to peers.

**Architecture**
- clirpc (CLI ↔ daemon): Local gRPC API used by the CLI.
- bbrpc (daemon ↔ peer): Public gRPC API exposed via the node’s onion site.
- storedpb (on‑disk): Metadata and revision information persisted locally.

**Key APIs**
- clirpc service
  - Unlock: Provide the main password (derives the master secret key).
  - ConnectPeer, ConnectedPeers: Manage peer connectivity by onion ID.
  - SetFile, GetFile, ListFiles: Manage the file set that forms current
    content. ListFiles returns only names.
  - SetStorageConfig, GetStorageConfig: Control how much peer data to store
    and the minimum replica count; daemon reports capacity and obligations.
  - GetContracts: View current storage contracts with peers.
  - ProposeContract, CheckContract, RecoverContent: Long‑running/streaming
    operations to form, verify, and recover content from peers.
  - SetAeadKeyForPeer: Configure symmetric key for encrypted chat with a
    specific peer.
  - Chat: Bidirectional stream for messages and file offers.

- bbrpc service
  - PeerExchange: Share peer onion identities for discovery.
  - GetContentRevision, SetContentRevision: Sync which content revision is
    stored on each side and propose updates/deletions.
  - Download: Retrieve sections of content, optionally using reference
    sections for efficient deltas. Response includes a SHA-256 hash.
  - EncryptedDownload: AEAD‑wrapped variant used inside encrypted chats.
  - Chat, EncryptedChat: Send chat actions (init, message, file, stop).
    Tag numbers are msg = 3, file = 4, stop = 5.

- storedpb messages
  - ContentRevision: Marks a concrete version produced by SetFile; its AEAD
    becomes the content_id used in bbrpc. Keys derived from it encrypt
    Metadata (AEAD) and content (AES‑CTR).
  - Metadata: Tracks the most recent revision, content_length, content_sha256,
    and per‑peer records.
  - Peer: Stores onion_pubkey, optional aead_key for chat, and scoring fields
    used to evaluate peers over time.

**Security Model**
- Unlock derives a master secret from the main password. Keys from this secret
  encrypt content and metadata and identify the node’s onion service.
- Content is encrypted; Metadata is AEAD‑encrypted; content payload uses
  AES‑CTR. Chats and encrypted downloads can be AEAD‑protected using a per‑peer
  symmetric key configured out‑of‑band via SetAeadKeyForPeer.
- All inter‑node communication happens over Tor onion services.

**Developer Notes**
- RPC code generation (reproducible):
  - Tools are installed inside Docker, not on your host.
  - Generate stubs: `make rpc`.
  - Generated `.pb.go` files are committed to the repo.
  - protoc comes from Debian (bookworm). Go plugins are pinned by Go 1.23
    `tool` directives in `go.mod`, and installed during the Docker image
    build via `go install`.
  - If you change proto files, re-run `make rpc` and commit changes.
  - Go package options are set in each `.proto` via `option go_package`.
- Proto style rules:
  - Comments are English sentences: start with a capital letter and end with
    punctuation.
  - Field comments must start with the field name (for example, "name is …",
    "encrypted_chat_request is …").
  - Wrap comments at about 80 characters (tabs count as 8 spaces).

**Status and TODOs**
- Client API uses SetFile/GetFile/ListFiles for file management.
- Some streaming RPCs in clirpc reference message types that still need
  concrete schemas (ProposeContract*, CheckContract*, RecoverContent*,
  ChatAction/ChatEvent).
- bbrpc ChatRequest tag numbers corrected (msg = 3, file = 4, stop = 5).
- Next steps:
  - Implement contract lifecycle and background verification.
  - Enforce storage allocation and replica policies.
  - Implement recovery orchestration and progress reporting.
  - Flesh out missing clirpc messages and wire daemon/CLI flow.

**Quick Usage Flow (Conceptual)**
- Start the daemon (exposes local clirpc and onion bbrpc).
- Use the CLI to:
  - Unlock with the main password.
  - Connect to peers by onion ID.
  - Add files with SetFile; inspect with ListFiles/GetFile.
  - Optionally set a per‑peer AEAD key for encrypted chat/transfers.
  - Propose/verify contracts; recovery runs automatically in the background.
