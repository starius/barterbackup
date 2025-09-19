BarterBackup (Rust) — Notes and TODOs

Summary

- This is a scaffolded Rust port mirroring the Go layout. It focuses on clarity and comments so we can evaluate a Rust direction.
- gRPC: tonic + prost. Protos compiled from the existing files in bbrpc/, clirpc/, storedpb/.
- Keys and crypto: Argon2id + HKDF + Ed25519 (ed25519-dalek), matching Go outputs.
- Tor transport: arti (in-process Tor). Adapter to tonic incoming streams is sketched.

Open TODOs

- P2P TLS and client-onion inference
  - Implement rustls mutual TLS for P2P (mock network) and extract the client certificate in tonic server context to compute client_onion in bbrpc::HealthCheck (matches Go).
  - Enforce TLS 1.3 and X25519. PQ hybrid X25519MLKEM768 is not exposed in rustls yet — track for future.

- Mock network (netmock)
  - Provide helpers to spin up tonic servers over TCP + rustls with client auth.
  - Provide client builders that pin server public key and load client key.
  - Port Go tests: HealthCheck with two nodes, client_onion/server_onion assertions.

- Tor transport (nettor)
  - Use arti to launch onion service with Ed25519 derived from master key (purpose "tor/onion/v3").
  - Wrap arti rendezvous streams into a tonic-compatible Incoming stream (serve_with_incoming) with rustls on top.
  - Add onion self-dial for testing (optional) or rely on mock network tests.

- Local CLI gRPC
  - Replace h2c with rustls and key pinning analogous to Go clitls. Keep self-signed, long-lived certs.
  - Add env var prefixes: BBD_/BBCLI_, flags parity with Go.

- Protos/codegen
  - Current build.rs relies on local protoc. If needed, pre-generate and commit prost code to avoid protoc dependency.

- Structure parity
  - Keep services implemented on a single Node, split files if helpful (mirroring internal/bbnode/* in Go) while staying idiomatic Rust.

Design notes

- Onion address derivation uses torut v3 to compute the .onion from the Ed25519 public key, mirroring bine/torutil in Go.
- keys::derive_master_priv/derive_key/derive_ed25519_from_master produce identical bytes to Go (tests included).

