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

- bbrpc service
  - PeerExchange: Share peer onion identities for discovery.
  - GetContentRevision, SetContentRevision: Sync which content revision is
    stored on each side and propose updates/deletions.
  - Download: Retrieve sections of content, optionally using reference
    sections for efficient deltas. Response includes a SHA-256 hash.
  - EncryptedDownload: AEAD‑wrapped variant using an out‑of‑band password.

- storedpb messages
  - ContentRevision: Marks a concrete version produced by SetFile; its AEAD
    becomes the content_id used in bbrpc. Keys derived from it encrypt
    Metadata (AEAD) and content (AES‑CTR).
  - Metadata: Tracks the most recent revision, content_length, content_sha256,
    and per‑peer records.
  - Peer: Stores onion_pubkey and scoring fields used to evaluate peers over
    time.

**Security Model**
- Unlock derives a master secret from the main password. Keys from this secret
  encrypt content and metadata and identify the node’s onion service.
- Content is encrypted; Metadata is AEAD‑encrypted; content payload uses
  AES‑CTR. Encrypted downloads can be AEAD‑protected using a shared password
  configured out‑of‑band.
- All inter‑node communication happens over Tor onion services.

**Developer Notes**
- RPC code generation (reproducible):
  - Tools come from the Nix dev shell (`flake.nix`); no host installs needed.
  - Generate stubs: `make rpc` (runs via `nix develop --command ...`).
  - Generated `.pb.go` files are committed to the repo.
  - Tools are pinned by `flake.lock`. If you change proto files, re-run
    `make rpc` and commit changes.
  - Go package options are set in each `.proto` via `option go_package`.
- Proto style rules:
  - Comments are English sentences: start with a capital letter and end with
    punctuation.
  - Field comments must start with the field name (for example, "name is …",
    "encrypted_download_request is …").
  - Wrap comments at about 80 characters (tabs count as 8 spaces).

**Status and TODOs**
- Client API uses SetFile/GetFile/ListFiles for file management.
- clirpc message types for contract management and recovery are defined;
  implementations may still evolve.
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
  - Propose/verify contracts; recovery runs automatically in the background.
