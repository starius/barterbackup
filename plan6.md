Plan 6 - Init, fast unlock, UX, and Tor-state hardening

This plan covers the `/tmp/bb-next.txt` items that are actionable without more
product input. It assumes the current ephemeral local admin key model stays in
place and keeps the existing peer-transport design based on Arti and `rustls`.

Items deferred to `TODO.md`

- Final CLI command grouping needs review before implementation.
- The configurable local-content size limit needs a decided config surface and
  default policy before `bbcli set-file` can enforce it.

Execution scope

1. Add explicit storage initialization and make unlock depend on it.
   Deliverables:
   - Add `bbcli init` to initialize a data directory before the first unlock.
   - Persist an explicit initialized marker so the daemon can distinguish:
     - missing/uninitialized storage;
     - initialized storage with the wrong password;
     - initialized storage with the correct password.
   - Make `bbcli unlock` fail clearly if init has not happened yet.
   - Keep the initialization path idempotent and safe on an already initialized
     directory.
   Validation:
   - daemon and CLI tests for first-time init, repeated init, unlock before
     init, and wrong-password handling after init.

2. Make unlock return quickly after password validation.
   Deliverables:
   - Split unlock into two phases:
     - synchronous validation of the main password and local encrypted store;
     - asynchronous startup of the peer-facing Tor runtime.
   - Return success from `Unlock` as soon as the password is verified and the
     daemon has entered the unlocked state.
   - Keep the daemon usable for local RPCs while the peer runtime finishes
     bootstrapping in the background.
   - Report peer-runtime readiness through health/status instead of making the
     unlock RPC wait for onion publication.
   Design notes:
   - The daemon must still reject a wrong password immediately.
   - Background peer-runtime failures must be visible and must not leave the
     daemon in an ambiguous partially unlocked state.
   Validation:
   - tests that unlock returns before Tor bootstrap completes;
   - tests that local file RPCs work immediately after unlock;
   - tests that wrong-password unlock still fails immediately.

3. Improve CLI UX for local file handling and common failures.
   Deliverables:
   - Teach `bbcli get-file` that omitting the output path means:
     - print to stdout when stdout is not a terminal, or when the content is
       valid UTF-8;
     - otherwise fail with a clear message suggesting `| cat` or `| less`.
   - Keep `bbcli set-file` reading the local plaintext path on the client and
     `bbcli get-file` writing the local plaintext path on the client.
   - Document that responsibility clearly in `README.md`.
   - Translate common daemon and transport failures into user-facing CLI
     messages, including:
     - daemon not running;
     - daemon still locked;
     - unlock already in progress;
     - invalid unlock password;
     - uninitialized data directory.
   Validation:
   - CLI unit tests for stdout-vs-file behavior and binary/TTY refusal;
   - CLI integration tests for the mapped friendly error cases.

4. Harden and document Tor state behavior.
   Deliverables:
   - Document the current Tor state layout under `<data-dir>/tor`, including
     what is cached there and what is intentionally not persisted.
   - Confirm in code and tests that the node identity private key used for the
     onion address is not written to disk.
   - Investigate and fix the Arti restart warnings about missing previous hidden
     service keys, while keeping the node identity derived from the seed rather
     than loading it from disk.
   - Keep or improve persistence of public Tor state such as microdescriptors
     and other network caches under the Tor state directory.
   Validation:
   - targeted tests around Tor state directory setup and persistence behavior;
   - a restart scenario on the real builder showing the warning is gone or
     reduced to an understood benign case with code comments explaining why.

5. Add self-health monitoring over Tor and expose it through healthcheck.
   Deliverables:
   - Make the unlocked node periodically connect to its own onion service over
     Tor and run the peer health RPC through the real peer transport path.
   - Extend local health output so `bbcli healthcheck` shows whether the public
     peer-facing onion service is currently reachable through that self-check.
   - Keep the self-check lightweight and bounded so it cannot stall shutdown or
     flood the network.
   Validation:
   - daemon tests for pre-unlock, post-unlock, and unhealthy-self states;
   - focused real-Tor validation on the builder if practical.

6. Prove peer-data privacy more explicitly.
   Deliverables:
   - Add tests that a third peer cannot learn another peer's mirrored content
     or mirrored sidecar state through the peer RPC surface.
   - Tighten any remaining peer RPCs if they leak more than the requester's own
     data.
   Validation:
   - explicit multi-peer privacy regression tests covering both content and
     metadata.

Suggested commit structure

1. Add explicit init state and `bbcli init`.
2. Make unlock fast and move peer runtime startup to the background.
3. Improve `bbcli get-file` stdout behavior and friendly error reporting.
4. Document local file-path ownership and Tor state behavior.
5. Fix Arti restart warnings while preserving derived onion identity.
6. Add self-Tor health checks and expose them through healthcheck.
7. Add third-peer privacy regression tests and any needed RPC hardening.
