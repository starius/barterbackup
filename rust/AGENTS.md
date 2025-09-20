BarterBackup (Rust) — Agent Notes

Scope

- This file guides agents working under `rust/` only. The root `AGENTS.md` continues to govern the Go code.
- Documents workspace layout, build/test steps, TLS design (mTLS + SPKI pinning), post-quantum (PQ) hybrid enforcement, and open tasks.

Workspace layout

- crates/protos: Protobuf stubs and tonic services for `bbrpc`, `clirpc`, `storedpb`.
  - Uses `protoc-bin-vendored` to avoid host `protoc`.
  - Tonic toolchain aligned to 0.14.2 (prost 0.14.1).
- crates/keys: Key derivation (Argon2id master, HKDF, Ed25519 from master).
- crates/node: Node orchestration; implements tonic servers for clirpc and bbrpc.
- crates/clitls: Mutual TLS helper library for CLI ↔ daemon.
- crates/netmock: Mock or local transport placeholder (future TCP+TLS wiring).
- crates/nettor: Tor transport (arti-based, planned adapter layer).
- cmd/bbd, cmd/bbcli: Daemon and CLI entry points (TLS wiring in progress).

Build and tests

- Make targets (from `rust/`):
  - `make build`: builds only `bbd` and `bbcli` in release mode.
  - `make unit`: runs unit tests for `keys`, `clitls`, `node` with PATH set to `/home/user/nix/result-apps/bin` (helps Nix workflows).
- Protos: compiled during `cargo build` using vendored protoc; no host protoc is required.
- Static builds: supported via musl. See `.cargo/config.toml` for `x86_64-unknown-linux-musl` linker/ar settings.
  - Example: `cargo build --release --target x86_64-unknown-linux-musl -p bbd -p bbcli`.

gRPC + TLS (mutual, pinned, PQ-hybrid)

- Library: `rustls 0.23.32` + `rustls-post-quantum 0.2.3`.
- TLS policy: TLS 1.3 only; kx groups forced to `[X25519MLKEM768]`.
- Mutual auth:
  - Server: requires a client certificate and pins the client’s Ed25519 SPKI.
  - Client: pins the server’s SPKI.
- Key/cert material and file formats (compatible with Go):
  - `server.pub`: PEM-encoded SubjectPublicKeyInfo (Ed25519) of server.
  - `client.key`: PEM-encoded PKCS#8 (v1) Ed25519 private key of client.
- clitls API (crate `clitls`):
  - `generate_ed25519() -> (PublicKey, SecretKey)`
  - `write_keys(dir, &server_pub, &client_priv)` / `read_keys(dir) -> (server_pub, client_priv)`
  - `build_server_tls(expected_client_pub, server_priv) -> rustls::ServerConfig`
  - `build_client_tls(server_pub, client_priv) -> rustls::ClientConfig`
- Tests:
  - `configs_build_and_keys_roundtrip`: verifies TLS configs and key file roundtrip.
  - PQ fallback tests (feature `pq_tls_tests`):
    - PQ server vs X25519-only client fails.
    - PQ client vs X25519-only server fails.
    - PQ client vs PQ server succeeds.

tonic 0.14 migration

- Entire workspace uses tonic 0.14.2 and prost 0.14.1. Avoid mixed tonic versions.
- `crates/node` server traits updated to tonic 0.14 signatures.
- When wiring TLS for servers/clients:
  - Servers: `Server::builder().tls_config(ServerTlsConfig::new().rustls_server_config(Arc::new(cfg))?)`.
  - Clients: `Endpoint::from_shared(url)?.tls_config(ClientTlsConfig::new().rustls_client_config(Arc::new(cfg))?)`.

Tor integration (arti)

- Goal: in-process Tor via `arti` to mirror Go’s `bine` approach.
- Plan: adapt arti rendezvous streams into `tonic::transport::Server::serve_with_incoming` and use rustls for TLS on top.
- Status: scaffolding present; wiring pending finalization of clitls in bbd/bbcli.

Conventions and notes

- Do not depend on host `protoc`; use vendored `protoc` via `protoc-bin-vendored` in `crates/protos/build.rs`.
- Keep TLS 1.3 + PQ-hybrid enforcement strict. Connections MUST fail if the peer does not support `X25519MLKEM768`.
- SPKI pinning must verify Ed25519 OID (1.3.101.112) and exact key bytes.
- Keep changes minimal and aligned with the Go architecture.

Open tasks / next steps

- Wire TLS into `cmd/bbd` and `cmd/bbcli` using `clitls` (replace h2c in tests where applicable).
- Enable and run PQ fallback tests in CI (remove or keep `pq_tls_tests` feature flag, but ensure negatives run).
- Complete arti integration and adapter for serving/dialing over Tor streams.
- Update `rust/README.md` to reflect PQ-hybrid enforcement via `rustls-post-quantum` and the tonic 0.14.2 upgrade.

