# BarterBackup

BarterBackup is a Rust mutual-backup system built around a daemon (`bbd`) and
a CLI (`bbcli`). It also includes a Go Docker integration harness for
end-to-end testing against `clirpc`, with a fast Chutney-backed lane and a
separate public-Tor smoke lane.

Each node keeps one encrypted content blob derived from the user's file set,
stores encrypted blobs for peers, and recovers the newest revision from peers
when local state is lost. Peer traffic runs over Tor onion services with
mutual TLS and enforced post-quantum hybrid key exchange.

Each mirrored peer blob also has an encrypted peer sidecar. A sidecar is a
small local metadata record that says which peer and content revision the
cached blob belongs to without exposing plaintext user data.

## Features

- locked-start daemon with local admin RPC (`clirpc`)
- peer-to-peer RPC (`bbrpc`) over Arti onion services
- TLS 1.3 with `X25519MLKEM768` enforced for peer and local RPC traffic
- deterministic node identity derived from the main seed/password
- encrypted local storage and encrypted mirrored peer storage
- atomic content writes with rename-based replacement
- multi-node tests, manual clocks, and adversarial transport/parser coverage

## Repository layout

- `cmd/bbd`: daemon binary
- `cmd/bbcli`: CLI binary
- `crates/*`: Rust libraries
- `bbrpc`, `clirpc`, `storedpb`: protobuf definitions
- `integration/docker`: Go Docker integration harness
- `flake.nix`: Nix development shell
- `Makefile`: convenience targets for build/test/fmt/clippy/install

## Development environment

The simplest way to get a working toolchain is:

```bash
nix develop
```

The Nix shell provides a recent Rust toolchain plus common development tools.
Any `make` target can be run inside it directly, for example:

```bash
nix develop --command make test
nix develop --command make build-static
nix develop --command make build-static-bbd
nix develop --command make rpc
nix develop --command bash -lc 'cd integration/docker && go test ./...'
nix develop --command make integration-test-docker-tor-smoke
```

Without Nix, use a current stable Rust toolchain. Protobuf compilation uses a
vendored `protoc`, so a host `protoc` installation is not required.

## Build

```bash
cargo build --workspace
```

Build release binaries:

```bash
cargo build --release -p bbd -p bbcli
```

Install the binaries into Cargo's install root:

```bash
make install
```

Build distributable variants:

```bash
nix build .
make build-static
make build-static-bbd
make build-static-linux-amd64
make build-static-linux-arm64
make build-windows
make sanitize-address
make rpc
make cli-docs
make integration-test-docker-tor-smoke
make docker-dev-env-build
make docker-dev-env ARGS='--name lab up --nodes 3'
```

`nix build .` produces a packaged install tree under `result/` with the
musl-linked `bbd` and `bbcli` binaries plus the generated man pages and shell
completions. `make build-static` produces musl-linked Linux binaries for the
current Linux host architecture. `make build-static-linux-amd64` and
`make build-static-linux-arm64` always build release musl-linked Linux
binaries for those targets and are intended to work from any supported
`nix develop` host by using the cross toolchains from the dev shell.
`make build-windows` uses `cargo-xwin` to produce `x86_64-pc-windows-msvc`
binaries and requests static CRT linkage; Windows system DLLs still remain
dynamic as usual, and the first run downloads the Microsoft SDK pieces that
`cargo-xwin` needs. `make sanitize-address` is a Linux-only nightly target
that rebuilds the workspace with AddressSanitizer instrumentation. `make rpc`
generates the Go `clirpc` stubs under `integration/docker/gen/clirpc`.
`make cli-docs` regenerates checked-in shell completions, man pages, and
Markdown CLI manuals under `completions/`, `docs/man/`, and `docs/cli/`.
The generated Markdown manuals are:

- [docs/cli/bbd.md](/home/user/barterbackup/rust2/docs/cli/bbd.md)
- [docs/cli/bbcli.md](/home/user/barterbackup/rust2/docs/cli/bbcli.md)

## Test

Run the full workspace test suite:

```bash
cargo test --workspace
```

Useful focused runs:

```bash
cargo test -p bbd
cargo test -p bbcli
cargo test -p node
cargo test -p tlsutil
cargo test -p content
```

Other helpers:

```bash
make fmt
make clippy
```

Docker integration:

```bash
make rpc
make build-static-bbd
cd integration/docker && go test ./...
make integration-test-docker-tor-smoke
```

Private Chutney lane:

- regenerates the Go `clirpc` stubs
- builds the static `bbd` binary for the current Linux host with
  `make build-static-bbd`
- runs the fast Go Docker suite under `integration/docker`

Run one specific integration test:

```bash
make rpc
make build-static-bbd
cd integration/docker && go test -run '^TestDockerMaintenanceRefillsReplicaTargetFromKnownPeer$' -v -count=1
```

It runs `bbd` inside Docker containers against a private Chutney Tor network.
That lane also includes logical-clock scenarios driven through hidden local
test-clock RPCs.

`make integration-test-docker-tor-smoke`:

- builds the same static `bbd` binary
- regenerates the Go `clirpc` stubs
- runs one basic public-Tor recovery smoke test in Docker

`make docker-dev-env-build`:

- builds static `bbd` and `bbcli` binaries for the current Linux host
- regenerates the Go `clirpc` stubs
- keeps the host-side `bbcli` binary available for the persistent manual lab

The Docker integration harness requires:

- a Linux host
- the dev-shell tools from `nix develop`
- a working Docker daemon

For the detailed Docker workflow, runtime layout, artifact handling, timeout
debugging, harness-specific knobs, and the persistent manual Docker
environment, see
[integration/docker/README.md](/home/user/barterbackup/rust2/integration/docker/README.md).

## Configuration

Daemon:

- `BBD_LOCAL_ADDR`: local `clirpc` listen address, default `127.0.0.1:9911`
- `BBD_DATA_DIR`: daemon state directory, default `~/.barterbackup`
- `RUST_LOG`: standard tracing filter, default `info`

CLI:

- `BBCLI_LOCAL_ADDR`: daemon address, default `https://127.0.0.1:9911`
- `BBCLI_DATA_DIR`: daemon data directory used to locate `<data-dir>/cli-keys`,
  default `~/.barterbackup`
- `BBCLI_CLI_KEYS_DIR`: directory containing `server.pub` and `client.key`
- `bbcli --local-addr` also accepts a bare `host:port` value and will assume
  `https://`, so the same address string can be reused for `bbd` and `bbcli`

To see debug logs from the daemon, start it with `RUST_LOG=debug`, for example:

```bash
RUST_LOG=debug bbd
```

You can also scope this to specific crates, for example:

```bash
RUST_LOG=bbd=debug,node=debug bbd
```

Important current behavior:

- the daemon generates local admin mTLS keys under `<data-dir>/cli-keys`
- those keys are regenerated on each daemon start and are valid only for that
  daemon session
- graceful daemon shutdown removes `<data-dir>/cli-keys` because those session
  keys are no longer valid after exit
- `<data-dir>/tor` keeps Arti's public network cache state, including
  directory information such as microdescriptors and related sqlite state
- the hidden-service identity key is not written to disk; `bbd` re-derives it
  from the main seed on every unlock and inserts it into Arti's ephemeral
  keystore for that process only
- because the hidden-service key is ephemeral but Arti otherwise persists some
  per-service replay and introduction-point state, startup prunes only the
  hidden-service-specific `state/hs_ipt*.json` and
  `hss_iptreplay/replay_barterbackup` paths while keeping the public Tor cache
- `bbcli --data-dir <dir>` automatically uses `<dir>/cli-keys`
- `BBCLI_CLI_KEYS_DIR` overrides that path when you need to point at copied
  session keys explicitly
- if `bbd` runs over SSH, you can copy that session `cli-keys` directory to
  your local machine and run `bbcli` locally against the forwarded daemon
  address with `BBCLI_CLI_KEYS_DIR` pointing at the copied keys
- on operating systems that support owner-only modes, `BBD_DATA_DIR`,
  `<data-dir>/cli-keys`, and the files written under them are tightened to
  owner-only permissions

The daemon also takes an exclusive lock on `<data-dir>/.lock`, so two `bbd`
instances cannot use the same state directory concurrently.

## Quick start

Install or otherwise place `bbd` and `bbcli` on your `PATH`, then start the
daemon:

```bash
bbd
```

Unlock it with the main seed/password. Interactive usage will prompt and mask
input; non-interactive usage can stream the password through stdin. The unlock
path trims trailing whitespace-like characters from stdin so simple `echo`
examples are safe. The first start also needs an explicit `init` to bind the
data directory to the main password:

```bash
echo 'correct horse battery staple' | bbcli init --password-stdin
echo 'correct horse battery staple' | bbcli unlock --password-stdin
```

One main password corresponds to one node identity and one onion service.
Do not run multiple live nodes with the same password at the same time. A
second node may use that password only when the first node is no longer
available and you are bringing up a replacement for recovery or takeover.

For a replacement node that is recovering older replicas before it publishes
again, initialize it in recovery mode:

```bash
echo 'correct horse battery staple' | bbcli init --recovery-mode --password-stdin
echo 'correct horse battery staple' | bbcli unlock --password-stdin
```

If you use a custom data directory:

```bash
bbd --data-dir /tmp/barterbackup
echo 'correct horse battery staple' | \
  bbcli --data-dir /tmp/barterbackup init --password-stdin
echo 'correct horse battery staple' | \
  bbcli --data-dir /tmp/barterbackup unlock --password-stdin
```

If Tor access needs a custom Arti client configuration, point the daemon at
one Arti client TOML file with `--arti-config`. This is the path for bridges,
pluggable transports such as `obfs4` or `snowflake`, and other advanced Arti
client settings:

```bash
bbd --data-dir /tmp/barterbackup --arti-config /path/to/arti.toml
```

The daemon passes that file through directly to embedded Arti using Arti's
native client config format. If the file omits `storage.state_dir`, `bbd`
injects its usual `<data-dir>/tor` state path before bootstrap. If the file
already sets `storage.state_dir`, `bbd` uses that path as-is.

`bbcli init` checks the main password locally before it sends the seed to the
daemon. It prints the estimated `zxcvbn` score, `guesses_log10`, and any
available feedback, then rejects weak passwords unless you explicitly pass
`--allow-weak-password`. The intended baseline is a password-manager secret or
at least `7+` truly random Diceware-style words; non-English words are fine
too if they are chosen randomly rather than composed by hand.

Add a peer:

```bash
bbcli peer connect <peer-onion-id>
```

Manage files:

```bash
bbcli file set alpha.txt ./alpha.txt
bbcli file list
bbcli file get alpha.txt ./alpha.out
bbcli file get alpha.txt > alpha.out
bbcli file delete alpha.txt
```

Plaintext file I/O happens on the CLI side:

- `bbcli file set <name> <path>` reads the plaintext file from the machine
  where `bbcli` runs, then sends the bytes over local `clirpc`
- `bbcli file get <name> <path>` writes the plaintext file on the machine
  where `bbcli` runs
- omitting the output path on `bbcli file get` prints the file to stdout when
  stdout is piped or when the file is valid UTF-8 text
- binary output is refused on a terminal unless you pass an output path or
  explicitly pipe stdout to another program

Inspect peers, storage, and recovery:

```bash
bbcli peer list
bbcli peer pin <peer-onion-id>
bbcli peer unpin <peer-onion-id>
bbcli peer publish <peer-onion-id>
bbcli peer verify <peer-onion-id>
bbcli config get
bbcli config get --resource-policy
bbcli init complete
bbcli stop
```

Bootstrap peers:

- the binary carries a compiled built-in peer list from
  [`crates/node/src/builtin_peers.rs`](crates/node/src/builtin_peers.rs)
- that list is intentionally empty in the repository by default
- operators can regenerate a new source file from a live node with the hidden
  `bbcli peer export-built-in` command
- the export merges the already built-in peers with currently connected live
  peers, deduplicates them, and prints the full Rust source file so it can be
  dropped back into the tree directly

For example:

```bash
bbcli peer export-built-in > crates/node/src/builtin_peers.rs
```

Recovery workflow:

- `bbcli peer list` reports the current local peer inventory without dialing peers
  live, including pin state, storage protection class, tracked-only state,
  cached bytes, mirrored-peer staleness, and recent failure/backoff context
  when a peer is timing out or unavailable
- every known peer always has one persisted sidecar record; only some peers
  also have mirrored bytes cached locally
- `bbcli peer pin` marks a friend or otherwise trusted peer as operator-pinned;
  pinned peers are never evicted from mirrored storage accounting and stay at
  the top of outbound connection-priority decisions
- `bbcli peer unpin` removes that local operator override without changing the
  peer's current mirrored content directly
- `bbcli peer publish` runs one manual owner-to-peer publication pass
- `bbcli peer verify` checks one peer's current copy of our latest local
  revision and updates that peer's local durability score
- `bbcli config get` reports the current writable storage config plus derived
  storage information, including pinned/protected/disposable byte totals,
  tracked-only peer count, offline-blocking bytes, reclaimable bytes, and the
  current fresh-replica horizon for our own content
- `bbd` maintains the configured `min_replicas` target in the background; when
  fresh online replicas drop below that target, it actively searches for more
  peers to store our current revision on
- candidate search is peer-centric and weighted:
  - peers whose data we already store locally are tried first
  - peers pinned by us or pinning us get strong weight boosts
  - older first-seen peers get a moderate boost
  - peers with better observed live success history get a moderate boost
  - all eligible peers still keep some chance because selection remains
    weighted-random rather than fixed-order
- a peer may accept our sidecar update but decline to cache mirrored bytes when
  its peer-storage budget is full; that is not a protocol failure, but such a
  peer does not count as one of the current fresh replicas
- `bbcli config get --resource-policy` reports the current fixed peer-content
  ceiling, peer transport message limit, retry timing policy, and related
  runtime resource bounds
- replacement nodes should start with `bbcli init --recovery-mode`; while
  recovery mode is enabled, owner-originated publication stays disabled and
  local file mutation commands such as `bbcli file set` and `bbcli file delete`
  are rejected
- correct local wall-clock time matters when a node is initialized, because the
  recovery boundary compares authenticated revision timestamps against the
  node's local initialization time
- older-lineage recovery now runs automatically after new live peer contact
  and during background maintenance; it scans known peers, looks at both the
  newest revision a peer knows about and the newest revision it can still
  serve, and merges every downloadable older-lineage revision whose
  authenticated timestamp is older than the current node generation but newer
  than the last applied recovery watermark
- if the freshest known older-lineage revision is unavailable everywhere,
  recovery still uses an older stored revision when that is the newest replica
  any peer can actually serve
- while recovery mode remains enabled, `bbcli state` keeps showing both the
  newest older-lineage revision already merged locally and any newer recoverable
  requester revision that peers still know about but do not currently store
- recovery is additive and conservative:
  - a new file name is added directly
  - identical file contents are skipped
  - different contents under the same file name create a second file with a
    `.recovered-...` timestamp suffix before the final extension
- automatic recovery preserves older data but does not replay historical
  deletions from older lineages
- if recovery grows the local file set past the publishable content limit, the
  recovered files stay available locally and `bbcli state` reports a
  `publish_blocked_reason`; at that point the operator must delete enough files
  locally before publication can resume
- once you have recovered everything you still want from older replicas, run
  `bbcli init complete`
- `bbcli init complete` disables recovery mode, advances the effective
  recovery watermark to the current node-generation boundary, and allows
  publication again; after that point, older unseen lineages are ignored
  automatically

## Security model

- the main seed/password is stretched with Argon2id
- subkeys are derived with HKDF-SHA256
- node identity is a deterministic Ed25519 keypair
- peer transport uses Arti onion services plus mutual TLS
- TLS is restricted to TLS 1.3 with `X25519MLKEM768`
- user data is stored only in encrypted content blobs
- peer metadata and mirrored-peer revision state are stored only in encrypted
  peer sidecars
- daemon-private paths are tightened to owner-only permissions when the host
  OS provides that notion

## Notes

- `bbd` starts locked and only serves local admin RPC until `Unlock`
- `bbcli init` must be run once per new data directory before the first unlock
- `bbcli unlock` waits for the daemon to become ready instead of failing on
  early startup races
- `bbcli unlock` returns once the local encrypted store is open; the public
  Tor-facing peer runtime may still be starting in the background, and
  `bbcli state` reports that readiness explicitly
- `bbcli` waits briefly for `bbd` to create the session `cli-keys` instead of
  creating that directory on its own
- protobufs are compiled at build time; there are no checked-in generated Rust
  stubs to refresh manually
