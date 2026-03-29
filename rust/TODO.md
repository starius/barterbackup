BarterBackup (Rust) - Remaining work

The large implementation/test gaps from the initial Rust bring-up are closed.
What remains now is mostly product completion and operational hardening.

Still open

- Bootstrap a fresh node from only the seed plus minimal operator input.
  Today a restarted node can recover from persisted peer metadata, but a
  completely fresh machine still needs at least one reachable peer address to
  begin recovery.
- Surface divergent sibling timelines during recovery. Recovery currently picks
  the newest revision by decrypted timestamp, but the daemon and CLI still need
  RPCs and UX to show older conflicting branches and let the operator inspect
  or switch them.
- Decide how external Tor and pluggable transports fit into the final product.
  The current implementation uses in-process Arti. Supporting users whose ISPs
  block Tor still needs a product decision and implementation path.
- Flesh out storage accounting and contract policy beyond the current scoring
  and sync model. Storage quotas, expiration policy, and operator-facing
  visibility are still basic.
- Add deeper long-running fuzz and soak coverage. Property tests and multi-node
  scenarios now cover the main parser and maintenance paths, but the project
  still lacks dedicated `cargo-fuzz` targets and longer chaos-style network
  campaigns.

Guardrails

- Keep the Rust implementation authoritative and use the Go tree only as a
  semantic reference.
- Prefer current dependency releases for Arti, tonic, rustls, and crypto.
- Do not weaken onion hostname validation or the enforced `X25519MLKEM768`
  policy without an explicit design decision.
- Do not add plaintext storage shortcuts even for tests.
