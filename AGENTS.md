BarterBackup – Agent Notes

Scope

- This file guides agents working in this repository.
- It documents terminology, API decisions, style rules, and open issues.

 Repo layout

- clirpc: Local CLI ↔ daemon gRPC proto and generated stubs.
- bbrpc: Public daemon ↔ peer gRPC proto and generated stubs.
- storedpb: On‑disk metadata proto and generated stubs.
- internal/keys: Key derivation utilities (memory‑hard master key, HKDF, Ed25519 from master).
- internal/network: P2P networking abstraction + implementations (Tor + in‑memory mock).
- internal/node: Node orchestration (single BarterBackup instance using Network).
- internal/torserver: Tor‑backed gRPC server using bine and PQ‑hybrid TLS. [legacy; superseded by internal/network]
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
  RPC method name is `CliChat` (renamed from `Chat`) to avoid a name
  collision with the bbrpc `Chat` method when both services are implemented on
  `Node`.
- Health check: RPC method name is `LocalHealthCheck` (renamed from
  `HealthCheck`) to avoid a collision with bbrpc `HealthCheck` on `Node`.
  Local health check returns `server_onion` and `uptime_seconds`.

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
- HealthCheck returns basic liveness and addresses:
  - Request: `HealthCheckRequest {}` (empty).
  - Response: `HealthCheckResponse { string client_onion; string server_onion; }`.
  - Server populates `server_onion` from its own address and `client_onion`
    by inferring the caller’s Ed25519 pubkey from the TLS context and
    computing the Tor v3 onion hostname via bine/torutil.
  - If the client certificate/public key cannot be determined, the server
    returns `Unauthenticated`.

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
- Run `make fmt` to normalize formatting (protos via `clang-format`, Go via
  `go fmt`).
- Run `make unit` to execute unit tests.
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

Development workflow

- Implement both bbrpc and clirpc services as methods on `internal/node.Node`.
  To avoid Go method name collisions (no overloading), clirpc RPCs that collide
  with bbrpc are renamed as follows:
  - `HealthCheck` → `LocalHealthCheck`.
  - `Chat` → `CliChat`.
- Keep server and client RPC handlers in separate files under
  `internal/node/` for clarity:
  - bbrpc server methods: `internal/node/bbrpc_server.go`.
  - clirpc server methods: `internal/node/clirpc_server.go` (create as you
    implement clirpc service methods).
- Register both services in `Node.Start`.
- For now, tests may call clirpc methods directly on `Node`  without going
  through gRPC. Peer-to-peer dials use the internal `dialPeer` method. The
  internal peer connection helper is named `getPeerConn` (renamed from
  `getConn`) to avoid confusion with any future CLI connectivity.
- After proto edits:
  - Run `make rpc`.
  - Run `make fmt`.
  - Run `make unit`.

Go code style

- Imports are grouped into exactly two blocks: standard library, then everything else (including this repo).
- Insert a single empty line before any `return` that follows other code at the same indentation level (not immediately after `{`).
- No trailing whitespace or tabs on otherwise empty lines.
- Run `go fmt ./...` to normalize formatting.
- Don't inline short functions into a single line.
- Don't inline short structs definitions and literals into a single line. Each field on a separate line.
  - Applies to trivial getters/setters and constructors. Avoid one‑line anonymous funcs; expand to multi‑line blocks.
- Expand goroutines/closures to multi-line bodies for readability.

gRPC limits

- To mitigate DoS from oversized messages, both server and client set 16 KiB limits:
  - Server: `grpc.NewServer(..., grpc.MaxRecvMsgSize(16*1024), grpc.MaxSendMsgSize(16*1024))`.
  - Client: `grpc.DialContext(..., grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16*1024), grpc.MaxCallSendMsgSize(16*1024)))`.
- If fields of a structs are commented, insert an empty line before a commented field.

Testing

- Prefer table-driven tests with subtests and `t.Parallel()` at test and subtest levels when appropriate.
- Use `github.com/stretchr/testify/require` for assertions; avoid ad-hoc logging.
- Do not capture loop variables (no `tc := tc`); recent Go range semantics make this unnecessary.
- Put every field in table structs on its own line for readability.
- For deterministic cryptographic outputs, store expected values as hex strings.
  - If unknown initially, leave empty, run tests to see the actual hex in the failure message, and paste into the table.

Build and install

- Install daemon: `make install` (sets `CGO_ENABLED=0` and runs `go install ./cmd/bbdaemon`).

Proto updates

- bbrpc includes `HealthCheck(HealthCheckRequest) returns (HealthCheckResponse)` for simple liveness checks.

Keys and crypto (internal/keys)

- DeriveMasterPriv(seed string) → []byte: Derives master private material from a user‑provided password/seed string using Argon2id with a deterministic salt.
- DeriveKey(masterPriv, purpose, n) → []byte: HKDF‑SHA256 with domain separation label `purpose`.
- DeriveEd25519FromMaster(masterPriv, "tor/onion/v3") → ed25519 keypair for the onion service.

 Tor gRPC server (internal/torserver)

- Uses bine to start Tor and publish a v3 onion service with the Ed25519 key derived from the master key.
- Exposes `Start(ctx, Config, impl)` which returns a server handle with `OnionID()` and `GRPC()` accessors.
- TLS: Enforces TLS 1.3 with ONLY `X25519MLKEM768` in `CurvePreferences` (no fallback). Go 1.24+ provides this hybrid KEX.
- Uses a self‑signed Ed25519 certificate for the TLS handshake; the onion layer provides origin authentication.

Node + Network

- Node (internal/node)
  - Represents a single BarterBackup instance (bbrpc now; clirpc in future).
  - Derives identity from password via `keys.DeriveMasterPriv` and HKDF → Ed25519.
  - Computes onion address from the Ed25519 public key (bine/torutil v3 ID) and exposes it via `Address()`.
  - API: `New(seed string, net Network)`, `Start(ctx)`, `Stop()`, `Address()`, `DialPeer(ctx, addr)`.
  - Registers bbrpc server via the provided `Network` registrar.
  - HealthCheck implementation returns `client_onion` and `server_onion` as described above.
  - Maintains a connection pool of gRPC `ClientConn` keyed by onion address, with idle eviction:
    - Reuses connections for repeated calls to the same peer.
    - Evicts and closes connections not used for 5 minutes (checked every minute).

- Network (interface + impls)
  - Interface: `internal/node/network.go` (TLS 1.3 with ONLY `X25519MLKEM768`).
  - Implementations:
    - TorNetwork at `internal/nettor/tor.go`.
    - MockNetwork at `internal/netmock/mock.go`.
  - Methods:
    - `Register(ctx, addr, priv, srv *grpc.Server) (unregister, err)` — `addr` is the onion hostname (e.g., "xxx.onion"). Node constructs the gRPC server (with TLS) and passes it; Network opens transport and serves it.
    - `Dial(ctx, addr) (net.Conn, error)` — Network opens a raw connection to `addr`. Node provides `grpc.WithContextDialer` and TLS.
  - Constructors and lifecycle:
    - `nettor.NewTorNetwork()` and `netmock.NewMockNetwork()` return instances.
    - Both types implement `Close() error` (currently no-op) for future resource management.

- TorNetwork (internal/nettor/tor.go)
  - Real transport using bine/Tor v3 onion service from the node’s Ed25519 key.
  - Starts Tor with a temporary data directory (permissions `0700`) and cleans it on unregister.
  - Stores the Tor instance on Register and reuses it for Dial (no per‑dial Tor).
  - Dial requires a `.onion` hostname (port optional; `:80` added if missing). TLS verification is handled in Node (client side).

- MockNetwork (internal/netmock/mock.go)
  - Fully in‑memory with `grpc/test/bufconn`; no TCP usage (compatible with synctest).
  - Provides a raw `net.Conn` from the bufconn listener; Node builds gRPC/TLS on top.
  - Constructor: `netmock.NewMockNetwork()`. Implements `Close() error`.
  - Useful for unit/integration tests (see `internal/node/node_mock_test.go`).

gRPC limits

- To mitigate DoS from oversized messages, both server and client set 16 KiB limits:
  - Server: `grpc.NewServer(..., grpc.MaxRecvMsgSize(16*1024), grpc.MaxSendMsgSize(16*1024))`.
  - Client: `grpc.DialContext(..., grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16*1024), grpc.MaxCallSendMsgSize(16*1024)))`.
  - Centralized as `grpcMaxMsg` in `internal/node/node.go` with rationale in godoc.

Daemon (cmd/bbdaemon)

- Uses `Node` with `TorNetwork`; reads `BB_PASSWORD`, starts node, logs address, waits for signal.

Daemon entry (cmd/bbdaemon)

- Reads the node password from `BB_PASSWORD`, derives the master key via `keys.DeriveMasterPriv`, and starts the Tor‑backed gRPC server on onion port 80.
- The bbrpc implementation is currently a minimal stub; wire real handlers as they are implemented.

Examples

- The `examples/` directory contains reference snippets (bine usage, key derivation). Do not modify them; the production implementations now live under `internal/` as described above and may replace the need for the examples.
