BarterBackup (Rust) — Overview

This is a commented Rust scaffold of the BarterBackup project.
It mirrors the Go layout and decisions described in AGENTS.md, but uses idiomatic Rust libraries:

- gRPC: tonic + prost
- Protobuf codegen: tonic-prost-build with vendored `protoc` (no host install needed)
- Tor transport (embedded): arti (in-process Tor). The Tor network integration is stubbed and documented; hooking gRPC streams into arti rendezvous streams is planned.
- Keys and crypto: argon2, hkdf, ed25519-dalek, sha2

 Status

- Protos: Compiled to Rust types and services (bbrpc, clirpc, storedpb) via vendored `protoc`.
- Keys: DeriveMasterPriv, DeriveKey, DeriveEd25519FromMaster ported and tested with the same vectors as Go.
- Node: Skeleton node with addresses derived from Ed25519 -> v3 onion, LocalHealthCheck implemented. bbrpc HealthCheck is stubbed with a clear TODO for client certificate extraction.
- Network: Mock and Tor transports are scaffolded. MockNetwork will grow to use TLS+TCP with tonic. TorNetwork includes a design and pointers to arti-experiment, but is not wired to gRPC yet.
- CLI/Daemon: Minimal stubs. TLS wiring moving to `clitls`.
- TLS (clitls): mutual TLS with SPKI pinning and PQ-hybrid enforcement (X25519+ML‑KEM‑768) using rustls + rustls-post-quantum.

Why not fully wire arti → gRPC in this first pass?

Arti exposes incoming rendezvous streams (AsyncRead/AsyncWrite), while tonic usually serves via a socket listener. Tonic does support `serve_with_incoming`, so it’s feasible to adapt arti streams into tonic’s incoming stream. Doing so cleanly requires a small adapter layer and TLS setup with rustls. That’s the next logical step once we agree on the shape here.

Crate map (mirrors Go structure)

- crates/protos: Compiled protobuf stubs and service traits (bbrpc, clirpc, storedpb).
- crates/keys: Key derivation utilities.
- crates/node: Node orchestration combining protos + network + keys.
- crates/clitls: Mutual TLS helpers and key file I/O compatible with Go (`server.pub`, `client.key`).
- crates/netmock: In-memory/local testing transport (to be fleshed out using TCP + rustls).
- crates/nettor: Tor transport (arti-based, planned adapter).
- cmd/bbd: Daemon entry (stub).
- cmd/bbcli: CLI entry (stub).

Build

- From `rust/`: `cargo build`.
  - Protos are generated at build time using vendored `protoc` (no host install).
- Make targets:
  - `make build` — builds only `bbd` and `bbcli` (release). Injects `PATH=/home/user/nix/result-apps/bin` for Nix shells.
  - `make unit` — runs tests for `keys`, `clitls`, `node` with `--all-features` (enables optional PQ tests when requested).
- Tests (manual):
  - Core: `cargo test -p keys -p clitls -p node`
  - PQ fallback: `cargo test -p clitls --features pq_tls_tests`

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

- TLS: enforced TLS 1.3 with PQ-hybrid `X25519MLKEM768` using `rustls-post-quantum`. Connections that do not offer this kx group fail the handshake (see clitls tests).
- Tonic: workspace uses tonic 0.14.2 and prost 0.14.1 consistently.
- clitls files: `server.pub` is a PEM-encoded SPKI (Ed25519). `client.key` is a PEM-encoded PKCS#8 v1 Ed25519 private key. `clitls::write_keys/read_keys` are compatible with the Go formats.
- For onion v3 address derivation, use `torut`/arti pieces; full wiring to be completed in `crates/nettor`.
