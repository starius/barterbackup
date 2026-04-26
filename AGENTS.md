BarterBackup – Agent Notes

Scope

- This file guides agents working in this repository.
- The product implementation is Rust.
- `integration/docker` contains a Go Docker integration harness with a fast
  private-Chutney lane and a separate public-Tor smoke lane.

Repository layout

- `cmd/bbd`: daemon binary.
- `cmd/bbcli`: CLI binary.
- `crates/protos`: protobuf/gRPC bindings compiled at build time.
- `crates/keys`: seed derivation and onion identity helpers.
- `crates/tlsutil`: local and peer TLS helpers.
- `crates/content`: encrypted content blob format.
- `crates/storage`: encrypted local and mirrored-peer storage.
- `crates/clock`: system and manual clocks.
- `crates/transport`: peer dial abstraction.
- `crates/netmock`: TLS-backed mock peer transport for tests.
- `crates/nettor`: Arti-backed peer transport.
- `crates/node`: node orchestration and both RPC services.
- `bbrpc`, `clirpc`, `storedpb`: `.proto` definitions.
- `integration/docker`: Go integration tests that drive `clirpc` directly.

Terminology

- File: a user-provided file managed through `SetFile`, `GetFile`, and
  `ListFiles`.
- Content: one finalized encrypted blob derived from the current set of files.

Build and test

- Prefer `nix develop` for a ready-to-use toolchain.
- On clean machines, prefer the flake/dev-shell path to provide repository
  dependencies before installing ad-hoc system packages by hand.
- Any repository `make` target can be run as
  `nix develop --command make <target>`.
- The flake is expected to carry the developer-facing tools needed for Rust,
  Go, protobuf, Arti, Tor, and the Docker/Chutney integration harness,
  including Docker client and daemon binaries when integration tests depend on
  them.
- Docker integration tests still require a working Docker daemon outside the
  shell; the flake can provide client or daemon binaries, but it does not by
  itself start or supervise Docker for you.
- When preparing commits, run `make fmt` regularly so formatter output stays
  grouped with the code changes that caused it rather than leaking into later
  unrelated commits.
- Keep test-only CLI flags and options hidden from help output so normal users
  do not discover and invoke them accidentally.
- Main commands:
  - `cargo build --workspace`
  - `cargo test --workspace`
  - `cargo fmt --all`
  - `cargo clippy --workspace --all-targets`
- Convenience wrappers:
  - `make build`
  - `make test`
  - `make fmt`
  - `make clippy`
  - `make install`
  - `make rpc`
  - `make integration-test-docker`
  - `make integration-test-docker-tor-smoke`
  - `make build-static`
  - `make build-static-linux-amd64`
  - `make build-static-linux-arm64`
  - `make build-windows`
  - `make sanitize-address`

Proto generation

- Rust protobuf code is generated at build time by `crates/protos/build.rs`.
- The build uses `protoc-bin-vendored`; do not add a host `protoc` dependency
  just to build the project.
- After editing `.proto` files, rebuild or retest the workspace. There are no
  checked-in generated Rust stubs to commit.
- `make rpc` generates Go `clirpc` stubs for `integration/docker`. Those
  generated files live under `integration/docker/gen` and are not checked in.

Transport and security

- `bbd` serves local `clirpc` over mutual TLS with pinned Ed25519 keys.
- Peer traffic runs over Arti onion services plus mutual TLS.
- TLS policy is TLS 1.3 only with `X25519MLKEM768` enforced.
- Node identity is the deterministic Ed25519 key derived from the main seed.
- `<data-dir>/tor` keeps Arti's public network cache state, while the hidden
  service identity key is inserted into Arti's ephemeral keystore at unlock
  time and is not persisted to disk.
- Startup prunes only the hidden-service-specific replay and introduction-point
  state under `<data-dir>/tor` so restart warnings do not conflict with that
  ephemeral-key model.
- Local content and mirrored peer content must remain encrypted at rest.
- A peer sidecar is the encrypted local metadata record stored alongside one
  mirrored peer blob.
- The daemon locks the data directory with `<data-dir>/.lock`.
- On operating systems that support owner-only modes, the data directory,
  `cli-keys`, and the private files under them are tightened accordingly.

Current operational details

- The daemon starts locked and must be unlocked through `bbcli unlock`.
- Local admin mTLS material lives in `<data-dir>/cli-keys`.
- Those local admin keys are currently regenerated on each daemon start.
- `bbcli --data-dir <dir>` uses the matching `<dir>/cli-keys` directory by
  default, while `BBCLI_CLI_KEYS_DIR` remains available when the session keys
  are copied elsewhere.

Code style

- Keep names explicit and descriptive.
- Every public type/function/method should have a doc comment.
- Add short comments before non-trivial blocks inside functions.
- Prefer straightforward control flow over clever compactness.
- Keep comments and docs as English sentences with normal punctuation.

Testing

- Prefer deterministic tests.
- Use `clock::ManualClock` for long-horizon behavior.
- Use `netmock` for multi-node transport tests that do not need real Tor.
- Cover malformed peer responses and recovery edge cases, not just happy paths.
- Docker integration tests use the Go harness under `integration/docker`.
  The fast lane uses a private Chutney network, and the public-Tor smoke lane
  runs separately behind `make integration-test-docker-tor-smoke`. The harness
  keeps runtime state outside the repo under `/tmp/barterbackup-integration`
  unless `BB_DOCKER_TEST_WORKDIR` overrides it.

Open product gaps

- fresh-node bootstrap still needs a product decision when only the seed is
  available and no peer addresses survive locally;
- divergent recovery branches still need operator-facing UX and RPC support;
- external Tor / pluggable transport support is still undecided.
