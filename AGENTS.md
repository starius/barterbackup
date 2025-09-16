BarterBackup – Agent Notes

Scope

- This file guides agents working in this repository.
- It documents terminology, API decisions, style rules, and open issues.

Repo layout

- clirpc: Local CLI ↔ daemon gRPC proto and generated stubs.
- bbrpc: Public daemon ↔ peer gRPC proto and generated stubs.
- storedpb: On‑disk metadata proto and generated stubs.
- internal/keys: Key derivation utilities (memory‑hard master key, HKDF, Ed25519 from master).
- internal/torserver: Tor‑backed gRPC server using bine and PQ‑hybrid TLS.
- cmd/bbdaemon: Minimal daemon wiring that starts the Tor‑backed gRPC server.
- scripts: Helper scripts (e.g., RPC code generation).
- Makefile, Dockerfile.rpc: Reproducible RPC generation with Docker.

Terminology

- File: A user‑provided input. The client can submit one or more files.
- Content: A single finalized encrypted blob derived from the current set of
  files. This is what gets backed up to peers.

Client API (clirpc)

- RPCs use file‑centric operations:
  - SetFile(SetFileRequest) returns (SetFileResponse).
  - GetFile(GetFileRequest) returns (GetFileResponse).
  - ListFiles(ListFilesRequest) returns (ListFilesResponse) and returns only
    names.
- Messages:
  - File { string name; bytes data; }.
  - ListFilesResponse returns `repeated string name`.
- Older SetContent/SetFiles and GetContent/GetFiles were replaced by the above
  to clarify “file” vs “content”.
- Chat: Bidirectional stream is defined via `ChatAction` and `ChatEvent`.

Stored metadata (storedpb)

- ContentRevision refers to versions produced by SetFile. Fields include
  `created_at`, `created_at_ns`, and `metadata_aead_length` (size of the
  AEAD‑encrypted Metadata blob).
- Metadata tracks the most recent revision and lists of `files` and `peers`.
  Per‑file info is in `FileHeader { name, file_length, file_sha256 }`.
- Content‑level sizing in peer RPCs uses `content_length` (see bbrpc
  `ContentInfo`). Content SHA‑256 appears in transfer responses such as
  `DownloadResponse.sha256` and `ChatFile.sha256`.

Server API (bbrpc)

- Peer discovery, content revision sync, downloads, and chat remain as in the
  proto for now.
- ChatRequest oneof tags are fixed: msg = 3, file = 4, stop = 5.

Proto style rules

- Comments are English sentences: start with a capital letter and end with a
  period (or appropriate punctuation).
- Wrap lines at about 80 characters. If tabs are used, consider them as 8
  spaces for wrapping. Prefer spaces in comments.
- Field comments must start with the field name followed by a sentence, e.g.,
  "encrypted_chat_request is AEAD(ChatRequest)." and "name is ...".
- Always separate fields in messages with a single empty line for readability.

Next steps for contributors

- Regenerate Go stubs after .proto changes.
- Update daemon and CLI implementations to the new SetFile/GetFile/ListFiles
  API.
- Message schemas for ProposeContract*, CheckContract*, RecoverContent*, and
  ChatAction/ChatEvent are defined; wire up and refine implementations.
- No action needed for ChatRequest tags; they are already fixed.

RPC generation

- Use Docker for reproducible proto builds; do not install protoc or plugins
  on the host.
- Generate stubs: `make rpc`.
- protoc comes from Debian bookworm. Go plugins are pinned by Go 1.24 `tool`
  directives in `go.mod` and installed in the Docker image via `go install`.
- Subsequent runs only execute protoc; tools are preinstalled in the image.
- Commit generated `.pb.go` files.

Go code style

- Imports are grouped into exactly two blocks: standard library, then everything else (including this repo).
- Insert a single empty line before any `return` that follows other code at the same indentation level (not immediately after `{`).
- No trailing whitespace or tabs on otherwise empty lines.
- Run `go fmt ./...` to normalize formatting.

Keys and crypto (internal/keys)

- DeriveMasterPriv(seed string) → []byte: Derives master private material from a user‑provided password/seed string using Argon2id with a deterministic salt.
- DeriveKey(masterPriv, purpose, n) → []byte: HKDF‑SHA256 with domain separation label `purpose`.
- DeriveEd25519FromMaster(masterPriv, "tor/onion/v3") → ed25519 keypair for the onion service.

Tor gRPC server (internal/torserver)

- Uses bine to start Tor and publish a v3 onion service with the Ed25519 key derived from the master key.
- Exposes `Start(ctx, Config, impl)` which returns a server handle with `OnionID()` and `GRPC()` accessors.
- TLS: Enforces TLS 1.3 with ONLY `X25519MLKEM768` in `CurvePreferences` (no fallback). Go 1.24+ provides this hybrid KEX.
- Uses a self‑signed Ed25519 certificate for the TLS handshake; the onion layer provides origin authentication.

Daemon entry (cmd/bbdaemon)

- Reads the node password from `BB_PASSWORD`, derives the master key via `keys.DeriveMasterPriv`, and starts the Tor‑backed gRPC server on onion port 80.
- The bbrpc implementation is currently a minimal stub; wire real handlers as they are implemented.

Examples

- The `examples/` directory contains reference snippets (bine usage, key derivation). Do not modify them; the production implementations now live under `internal/` as described above and may replace the need for the examples.
