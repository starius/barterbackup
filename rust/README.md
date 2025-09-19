BarterBackup (Rust) — Overview

This is a commented Rust scaffold of the BarterBackup project.
It mirrors the Go layout and decisions described in AGENTS.md, but uses idiomatic Rust libraries:

- gRPC: tonic + prost
- Protobuf codegen: tonic-build (Docker is optional; local `protoc` is acceptable for a PoC)
- Tor transport (embedded): arti (in-process Tor). The Tor network integration is stubbed and documented; hooking gRPC streams into arti rendezvous streams is planned.
- Keys and crypto: argon2, hkdf, ed25519-dalek, sha2

Status

- Protos: Compiled to Rust types and services (bbrpc, clirpc, storedpb).
- Keys: DeriveMasterPriv, DeriveKey, DeriveEd25519FromMaster ported and tested with the same vectors as Go.
- Node: Skeleton node with addresses derived from Ed25519 -> v3 onion, LocalHealthCheck implemented. bbrpc HealthCheck is stubbed with a clear TODO for client certificate extraction.
- Network: Mock and Tor transports are scaffolded. MockNetwork will grow to use TLS+TCP with tonic. TorNetwork includes a design and pointers to arti-experiment, but is not wired to gRPC yet.
- CLI/Daemon: Minimal clap-based stubs, with notes on wiring later.

Why not fully wire arti → gRPC in this first pass?

Arti exposes incoming rendezvous streams (AsyncRead/AsyncWrite), while tonic usually serves via a socket listener. Tonic does support `serve_with_incoming`, so it’s feasible to adapt arti streams into tonic’s incoming stream. Doing so cleanly requires a small adapter layer and TLS setup with rustls. That’s the next logical step once we agree on the shape here.

Crate map (mirrors Go structure)

- crates/protos: Compiled protobuf stubs and service traits (bbrpc, clirpc, storedpb).
- crates/keys: Key derivation utilities.
- crates/node: Node orchestration combining protos + network + keys.
- crates/netmock: In-memory/local testing transport (to be fleshed out using TCP + rustls).
- crates/nettor: Tor transport (arti-based, planned adapter).
- cmd/bbd: Daemon entry (stub).
- cmd/bbcli: CLI entry (stub).

Build

- From `rust/`: `cargo build`.
  - Protos are generated at build time using a vendored `protoc` (no system install needed).
- Tests: `cargo test -p keys -p node`

Static binaries (self-contained)

- Preferred: build against musl for static linking.
  - Install toolchain: `rustup target add x86_64-unknown-linux-musl` and `apt-get install musl-tools` (or your distro’s equivalent).
  - Build: `cargo build --release --target x86_64-unknown-linux-musl -p bbd -p bbcli`.
  - Resulting files: `target/x86_64-unknown-linux-musl/release/bbd` and `.../bbcli`.
  - Verify static: `file target/x86_64-unknown-linux-musl/release/bbd` should include “statically linked”.
  - Linker note: we default to `x86_64-unknown-linux-musl-gcc` in `.cargo/config.toml` (works on Nix and many distros). If you only have `musl-gcc`, override with `CC_x86_64_unknown_linux_musl=musl-gcc cargo build ...`.
- Containerized (no rustup needed): use a musl cross image that already includes the target.
  - Example: `docker run --rm -v "$PWD":/work -w /work messense/rust-musl-cross:x86_64-musl cargo build --release --target x86_64-unknown-linux-musl -p bbd -p bbcli`.
  - Artifacts will appear under your local `target/x86_64-unknown-linux-musl/release/`.

Nix users

- You need a toolchain that includes the musl target’s std. Two options:
  - rustup: `nix shell nixpkgs#rustup nixpkgs#pkgsCross.musl64.stdenv.cc -c bash -lc 'rustup toolchain install stable && rustup target add x86_64-unknown-linux-musl && cd rust && cargo build --release --target x86_64-unknown-linux-musl -p bbd -p bbcli'`
  - Oxalica overlay: use a shell with `rust-bin.stable.latest.default.override { targets = [ "x86_64-unknown-linux-musl" ]; }` and `pkgsCross.musl64.stdenv.cc`, then `cargo build --release --target x86_64-unknown-linux-musl -p bbd -p bbcli`.


Notes

- TLS 1.3 + X25519MLKEM768 exact enforcement is not yet available in rustls; we enforce TLS 1.3 and X25519 and mark hybrid PQ as a TODO.
- For onion v3 address derivation, we use the `torut` crate, which implements the v3 address encoding.
