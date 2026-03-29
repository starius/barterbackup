BarterBackup (Rust) - Remaining work

Current focus

- Keep the Rust implementation authoritative and maintain the Go tree only as a
  semantic reference.
- Prefer current dependency releases for Arti, tonic, rustls, and crypto.
- Keep running heavy builds on `barterbackup-dev` through the remote scripts.

Remaining gaps

- Add a full end-to-end daemon/CLI integration test that runs `bbd`, uses the
  generated local CLI keys, and drives `bbcli` over the real local mTLS path.
- Extend the daemon maintenance tests beyond the mock transport happy path to
  cover recovery after local wipe, peer corruption, and repeated offline/online
  transitions.
- Add more adversarial tests around malformed peer responses, especially for
  background maintenance and recovery loops.
- Expand fuzzing coverage for encrypted content parsing and metadata decoding.
- Revisit whether the daemon background scheduler itself should use a fully
  synthetic async clock instead of real tokio time. The core score logic and
  long-horizon node scenarios already use the manual clock, but the daemon loop
  still uses real timer ticks.

Guardrails

- Do not weaken the onion hostname validation added to peer management.
- Do not relax the enforced `X25519MLKEM768` peer TLS policy without an
  explicit design decision.
- Do not add plaintext local storage shortcuts for testing.
