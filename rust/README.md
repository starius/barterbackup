BarterBackup (Rust)

This Rust workspace is the active implementation of BarterBackup.
The Go tree remains in the repository as a behavioral reference, but the Rust
code now provides the working daemon, CLI, encrypted storage, peer transport,
and multi-node test coverage.

Current state

- `bbd` starts a local mTLS-protected `clirpc` daemon, stays locked until
  `Unlock`, verifies a fingerprint for existing data directories, then starts
  the deterministic onion-backed peer runtime and background maintenance loop.
- `bbcli` manages files, peers, storage settings, contracts, and recovery over
  local `clirpc`.
- `node` implements both `clirpc` and `bbrpc` behavior, peer synchronization,
  contract proposal/checking, scoring, and recovery helpers.
- `storage` persists encrypted revisions and mirrored peer blobs with atomic
  rename-based writes.
- `netmock` provides TLS-backed multi-node tests without Tor.
- `nettor` runs the real Arti transport with deterministic hidden-service
  identity derived from the node seed.
- `clock` provides deterministic wall-clock control for long-horizon node tests.

Security model

- Master secret: Argon2id from the user seed/password.
- Derived keys: HKDF-SHA256 with domain-separated labels.
- Node identity: deterministic Ed25519 keypair -> Tor v3 onion hostname.
- Peer transport: Tor onion services plus mutual TLS 1.3 with
  `X25519MLKEM768` enforced through `rustls-post-quantum`.
- Local CLI transport: separate pinned mutual TLS credentials.
- At-rest data: encrypted content blobs and encrypted metadata only. User file
  bodies are never written to disk in plaintext by the storage layer.

Workspace map

- `crates/protos`: gRPC/protobuf types and services.
- `crates/keys`: seed derivation, HKDF labels, onion hostname conversion.
- `crates/clitls`: local and peer TLS configuration and certificate helpers.
- `crates/content`: encrypted content blob format.
- `crates/storage`: encrypted local and mirrored-peer storage.
- `crates/clock`: system and manual clocks for deterministic tests.
- `crates/transport`: peer dial abstraction.
- `crates/netmock`: TLS-backed mock peer transport.
- `crates/nettor`: Arti-backed Tor peer transport.
- `crates/node`: node state, RPC services, recovery, contracts, scoring.
- `cmd/bbd`: daemon binary.
- `cmd/bbcli`: CLI binary.

Build and test

From `rust/`:

- Build everything: `cargo build --workspace`
- Test everything: `cargo test --workspace`
- Focused packages:
  - `cargo test -p node`
  - `cargo test -p bbd`
  - `cargo test -p bbcli`
  - `cargo test -p nettor`

Remote builder workflow

Heavy builds should run on `barterbackup-dev` through the helper scripts in the
repo root.

- Sync and run one Rust command remotely:
  - `./scripts/remote-rust cargo test -p node`
- Run the main Rust test suite remotely:
  - `./scripts/remote-test`
- Run nextest remotely:
  - `./scripts/remote-nextest`

`remote-rust` automatically drops the throwaway remote `rust/target`
directory when the builder is low on disk space before syncing sources.

Nix

The top-level `flake.nix` provides a Rust dev shell with a recent toolchain and
common tooling.

- Enter the Rust shell locally:
  - `nix develop .#rust`
- Useful tools in the shell include:
  - `cargo-nextest`
  - `cargo-deny`
  - `cargo-audit`
  - `cargo-fuzz`
  - `protobuf`
  - `clang`

End-to-end shape

A usable workflow today is:

1. Start `bbd`.
2. Use `bbcli unlock <seed-or-password>`.
3. Use `bbcli set-file`, `get-file`, `list-files`, and `connect-peer`.
4. Let the daemon background loop propose contracts, refresh mirrored content,
   run checks, and drive recovery.
5. Use `bbcli get-contracts`, `check-contract`, `propose-contract`, and
   `recover-content` to inspect or force the same workflows manually.

Notes

- The Rust workspace intentionally favors battle-tested primitives and explicit
  documentation over a line-for-line Go port.
- The `arti-experiment` repository remains useful only as historical evidence
  that deterministic Arti hidden-service keys were possible. The production
  transport in this workspace is built against current Arti crates.
