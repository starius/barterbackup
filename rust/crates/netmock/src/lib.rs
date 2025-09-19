//! Mock network transport for tests.
//!
//! This crate is a placeholder for a future in-memory transport. For now, we
//! recommend using a local `TcpListener` with tonic’s `serve_with_incoming` for tests.
//!
//! Design sketch (aligned with Go tests):
//! - Bind a TCP port on localhost per node.
//! - Use rustls for TLS 1.3 with X25519 (PQ hybrid TODO).
//! - Enable client authentication to read peer certs in bbrpc `HealthCheck`.
//! - Provide helpers for creating a client Channel pinned to a server’s public key.

// Intentionally empty for the initial scaffold.

