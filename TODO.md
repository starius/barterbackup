BarterBackup (Rust) - Open work

These are the product and hardening items that are still unresolved.

- Bootstrap a fresh node from only the seed plus minimal operator input.
  Today a restarted node can recover from persisted peer metadata, but a
  completely fresh machine still needs at least one reachable peer address to
  begin recovery. We still need a product decision on whether bootstrap should
  come from manually supplied peer onion IDs, a separately persisted contact
  list, or a dedicated discovery mechanism.
- Decide the local `clirpc` mTLS key lifecycle. The daemon currently generates
  fresh local admin TLS keys on every start. We still need a product decision
  on whether to keep that behavior or persist and reuse the local admin keys,
  and if we persist them, whether the client key lives on the host or stays on
  the operator machine.
- Rewrap mirrored peer blobs before storing them on local disk. The current
  store encrypts peer metadata in the sidecar, but it writes downloaded peer
  content blobs to disk as raw remote-provided bytes after hash verification.
  We should authenticate and encrypt those mirrored blobs again under locally
  derived storage keys before writing them, so untrusted peers never control
  literal on-disk bytes outside our own AEAD-wrapped format.
- Surface divergent sibling timelines during recovery. Recovery currently picks
  the newest revision by decrypted timestamp, but the daemon and CLI still need
  RPCs and UX to show conflicting branches, warn about later-discovered
  revisions from sibling timelines, and let the operator inspect or switch
  them.
- Decide how external Tor and pluggable transports fit into the final product.
  The current implementation uses in-process Arti. Supporting users whose ISPs
  block Tor still needs a product decision and implementation path, including
  whether to support external Tor, pluggable transports, or operator-managed
  hidden-service keys.
- Finish production hardening around observability, resource bounds, and
  hostile-input handling. The daemon still needs a clearer operator-facing
  story for structured logs and per-peer summaries, plus explicit limits and
  policies for connection counts, task cancellation, chunk or metadata sizes,
  repeated partial downloads, and other malicious or malformed peer behavior.
- Flesh out storage accounting and contract policy beyond the current scoring
  and sync model. Storage quotas, expiration policy, and operator-facing
  visibility are still basic.
- Add deeper long-running fuzz and soak coverage. Property tests and multi-node
  scenarios now cover the main parser and maintenance paths, but the project
  still lacks dedicated `cargo-fuzz` targets and longer chaos-style network
  campaigns.
