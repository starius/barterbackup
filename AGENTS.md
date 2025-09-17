BarterBackup – Agent Notes

Scope

- This file guides agents working in this repository.
- It documents terminology, API decisions, style rules, and open issues.

 Repo layout

- clirpc: Local CLI ↔ daemon gRPC proto and generated stubs.
- bbrpc: Public daemon ↔ peer gRPC proto and generated stubs.
- storedpb: On‑disk metadata proto and generated stubs.
- internal/keys: Key derivation utilities (memory‑hard master key, HKDF, Ed25519 from master).
- internal/bbnode: Node orchestration (single BarterBackup instance using Network).
- internal/nettor: Tor transport (bine) implementation of the Network interface.
- internal/netmock: In‑memory transport for tests.
- cmd/bbd: Daemon entry and app.
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

- Implement both bbrpc and clirpc services as methods on `internal/bbnode.Node`.
  - To avoid Go method name collisions, clirpc RPCs that would collide with bbrpc are renamed: `LocalHealthCheck`, `CliChat`.
- Keep server handlers in separate files (`internal/bbnode/bbrpc_server.go`, `internal/bbnode/clirpc_server.go`).
- Register both services in `Node.Start`.
- Peer-to-peer dials use the internal `dialPeer` method.
- After proto edits: `make rpc`, `make fmt`, `make unit`.

Go code style

- Imports are grouped into exactly two blocks: standard library, then everything else.
- Avoid redundant import aliasing (don’t alias a package to its own name) except in generated code.
- Insert a single empty line before any `return` that follows other code at the same indentation level (not immediately after `{`).
- No trailing whitespace or tabs on otherwise empty lines.
- Run `go fmt ./...` to normalize formatting.
- Don't inline short functions into a single line.
- Don't inline short structs definitions and literals into a single line. Each field on a separate line.
  - Applies to trivial getters/setters and constructors. Avoid one‑line anonymous funcs; expand to multi‑line blocks.
- Expand goroutines/closures to multi-line bodies for readability.

gRPC limits

- P2P only: To mitigate DoS from oversized messages in peer-to-peer traffic, both P2P server and client use a 16 KiB limit.
  - Server: `grpc.NewServer(..., grpc.MaxRecvMsgSize(16*1024), grpc.MaxSendMsgSize(16*1024))`.
  - Client: `grpc.DialContext(..., grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16*1024), grpc.MaxCallSendMsgSize(16*1024)))`.
- Centralized as public constant `GRPCMaxMsgSize` in `bbrpc/consts.go`.
- Local CLI ↔ daemon gRPC does not apply these limits.
- If fields of a structs are commented, insert an empty line before a commented field.

Testing

- Prefer table-driven tests with subtests and `t.Parallel()` at test and subtest levels when appropriate.
- Use `github.com/stretchr/testify/require` for assertions; avoid ad-hoc logging.
- Do not capture loop variables (no `tc := tc`); recent Go range semantics make this unnecessary.
- Put every field in table structs on its own line for readability.
- For deterministic cryptographic outputs, store expected values as hex strings.
  - If unknown initially, leave empty, run tests to see the actual hex in the failure message, and paste into the table.

- gRPC/TLS tests: prefer `bufconn` and resilient assertions.
  - Use `google.golang.org/grpc/test/bufconn` to avoid real networking.
  - Wrap negative-path gRPC dials with small timeouts and
    `grpc.WithReturnConnectionError()` to fail fast (optional).
  - When creating mismatch scenarios, it can be enough to reuse a test body
    and only swap one half of a keypair (e.g., mismatch server pub vs. priv,
    or use a different client private key) to guarantee failure.
  - Use `testing/synctest.Test(t, func(t *testing.T){...})` for time-based
    control and to avoid long real sleeps; keep timeouts small (hundreds of
    milliseconds) so negatives do not stall for seconds.

Build and install

- Install daemon and CLI: `make install` (installs `./cmd/bbd` and `./cmd/bbcli`).

Proto updates

- bbrpc includes `HealthCheck(HealthCheckRequest) returns (HealthCheckResponse)` for simple liveness checks.

Keys and crypto (internal/keys)

- DeriveMasterPriv(seed string) → []byte: Derives master private material from a user‑provided password/seed string using Argon2id with a deterministic salt.
- DeriveKey(masterPriv, purpose, n) → []byte: HKDF‑SHA256 with domain separation label `purpose`.
- DeriveEd25519FromMaster(masterPriv, "tor/onion/v3") → ed25519 keypair for the onion service.

 Tor transport (internal/nettor)

- Uses bine to start Tor and publish a v3 onion service with the Ed25519 key derived from the master key.
- bbnode layer enforces TLS 1.3 with ONLY `X25519MLKEM768`.

Node + Network

- Node (internal/bbnode)
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

CLI and Daemon Apps

- Daemon app (`cmd/bbd/bbdapp`):
  - Public API: `type Config`, `Parse(opts...)`, `Run(ctx, cfg)`.
  - Parse options: `WithOSArgs()` or `WithArgs([]string)`; uses go-flags (flags.Default).
  - Data layout: `DataDir/cli-keys` (ephemeral, recreated on start), `DataDir/tor` (persistent for Tor).
  - Unlock flow: serves only local clirpc on start; `Unlock` RPC starts Tor + bbnode with the provided password and logs node onion.
  - Local clirpc security: TLS 1.3 + `X25519MLKEM768`, long‑lived (10y) self‑signed certs (server + client), server pins client cert, client pins `server.pub`.
  - Locking: `cli-keys/.lock` via `github.com/starius/flock`; keys and dir removed on shutdown.
- CLI app (`cmd/bbcli/bbcliapp`):
  - Public API: `Run(ctx, opts...)`; uses go-flags (flags.Default) with Parser.CommandHandler.
  - CommandHandler opens the connection after parsing common flags and before Execute; client is stored privately in runtime.
  - Subcommands live in `cmd_<name>.go`:
    - `healthcheck`: prints server onion and human‑readable uptime.
    - `unlock`: secure password entry or `--password-file`, then clirpc `Unlock`.
  - Defaults: `BBCLI_CLI_KEYS_DIR` points to `~/.barterbackup/cli-keys`.
- Mains are minimal and use `signal.NotifyContext` for cancellation.

Logging

- bbd logs all significant/long‑running steps with timestamps: data dir setup, cli‑keys creation/removal, local gRPC bind/serve, unlock/start of node, shutdown, and any gRPC Serve errors.
- Tor layer logs whether the Tor data dir is created or reused and logs onion service startup.

Environment prefixes

- Daemon env prefix: `BBD_` (e.g., `BBD_DATA_DIR`, `BBD_CLI_ADDR`).
- CLI env prefix: `BBCLI_` (e.g., `BBCLI_DAEMON_ADDR`, `BBCLI_CLI_KEYS_DIR`).

Examples

- The `examples/` directory contains reference snippets (bine usage, key derivation). Do not modify them; the production implementations now live under `internal/` as described above and may replace the need for the examples.
