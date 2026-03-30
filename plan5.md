Plan 5 - Implement the decided product behavior

This plan turns the latest product decisions into concrete implementation work.
It covers only the items that are now decided enough to build. Deferred items
such as external Tor and pluggable transports stay out of scope.

Scope decisions locked in

1. Fresh-node bootstrap will use a hardcoded built-in peer list.
   - Add source code for a built-in list now, with the list initially empty.
   - Add a hidden `bbcli` command that prints a complete Rust source file for
     that list by merging:
     - the already built-in peer list;
     - currently known working peers that are online and connected.
   - The export must deduplicate entries and print the whole file so it can be
     saved directly as a new checked-in version.

2. Local `clirpc` mTLS keys stay ephemeral per daemon session.
   - The daemon keeps generating fresh local admin keys on start.
   - Graceful shutdown must remove the session keys because they are no longer
     valid.
   - Documentation must explain the SSH workflow: copy the session `cli-keys`
     to the operator machine and run `bbcli` locally against the forwarded
     daemon address if desired.

3. Divergence handling becomes explicit and blocking.
   - When a divergent revision is discovered, download it immediately and store
     it separately.
   - Block normal file-manipulation CLI commands until the conflict is
     resolved.
   - Keep the non-selected version forever as an archived revision.
   - Record when the operator resolved the conflict.

4. Storage accounting policy is fixed.
   - Default peer-storage budget becomes 1 GiB.
   - Peers with score `> 0` are reserved tier.
   - Peers with score `<= 0` are best-effort tier and are evicted first.
   - Track and report both latest-known and latest-cached peer revisions.
   - If a reserved-tier peer cannot store its newest known revision locally, it
     must still retain its latest cached revision.
   - Recovery must choose the freshest available revision across all peers, not
     merely the freshest known revision.

5. Connection admission policy is fixed.
   - Cap the number of peer connections at 1024.
   - Record the first-seen relationship for a peer: we connected first or the
     peer connected first.
   - Priority order from highest to lowest:
     - manually added;
     - reserved tier;
     - in the hardcoded built-in list;
     - we connected first;
     - the peer connected first.
   - If a peer fits multiple categories, use the highest priority only.
   - When the cap is hit, evict the lowest-priority peers first.

6. Rename `clitls` to `tlsutil`.
   - The crate already serves both local admin TLS and peer TLS, so the old
     name is misleading.

Out of scope for this plan

- External Tor and pluggable transports remain deferred.
- The remaining build-system follow-ups in `TODO.md` stay separate unless they
  naturally fall out of this work.

Implementation order

1. Rename the TLS utility crate and clean up its role boundaries.
   Deliverables:
   - Rename `crates/clitls` to `crates/tlsutil`.
   - Update all Cargo manifests, imports, comments, and README references.
   - Make module-level docs state clearly that the crate contains shared TLS
     helpers for both local admin RPC and peer-to-peer RPC.
   Why first:
   - This touches many files. Doing it early avoids repeated churn in later
     commits.
   Validation:
   - `cargo test -p tlsutil`
   - `cargo test --workspace`

2. Fix the local admin key lifecycle UX without changing the ephemeral model.
   Deliverables:
   - Add a graceful daemon stop path:
     - new `clirpc` `Stop` RPC;
     - new `bbcli stop` command;
     - `bbd` Ctrl+C handler triggers the same graceful shutdown path.
   - Ensure graceful shutdown removes the session `cli-keys`.
   - Split read-only and write paths for local admin keys:
     - read-only commands must not create `~/.barterbackup/cli-keys`;
     - if keys are missing, wait briefly for `bbd` to create them and print a
       clear message such as `waiting for bbd to create cli keys in ...`;
     - if the keys still do not appear, return a clear error that names the
       expected files instead of `tighten server.pub`.
   - Document the ephemeral-key model and the SSH workflow in `README.md`.
   Design notes:
   - `bbcli healthcheck` and other commands that only need to connect should
     use a read-only helper that never creates directories.
   - Only daemon startup and explicit key-generation paths should create
     `cli-keys`.
   Validation:
   - unit tests for read-only key lookup and timeout messaging;
   - daemon integration tests for `bbcli stop`, graceful Ctrl+C shutdown, and
     key cleanup;
   - remote `cargo test -p bbd -p bbcli`.

3. Add built-in bootstrap peers and the hidden export command.
   Deliverables:
   - Add a dedicated source file for the built-in peer list, initially empty.
   - Load these peers at startup as a distinct peer-origin class.
   - Add a hidden `bbcli` command that prints the full Rust source file for the
     built-in list.
   - The export command must:
     - include the current built-in list;
     - add online connected peers not already present;
     - deduplicate and sort deterministically.
   Design notes:
   - Keep the generated file format intentionally simple so copying it back
     into the repository is trivial.
   Validation:
   - unit tests for merge, deduplication, sorting, and hidden-command output;
   - integration test that a node seeds peers from the built-in list.

4. Introduce the richer peer-state model needed for storage and connection
   policy.
   Deliverables:
   - Extend persisted peer metadata to track:
     - peer origin class: manual, built-in, discovered;
     - first-contact direction;
     - current score and reserved-tier status;
     - latest-known revision;
     - latest-cached revision;
     - per-revision metadata needed for reporting and recovery, including
       timestamp, size, and any known file-count summary.
   - Migrate load/store code and tests to the new model.
   Why before the next phases:
   - Both storage policy and connection eviction depend on this state.
   Validation:
   - persistence round-trip tests;
   - backward-compatibility tests for existing on-disk state where practical;
   - property tests for peer-state merge/update invariants.

5. Implement the storage accounting and recovery policy.
   Deliverables:
   - Raise the default peer-storage budget to 1 GiB.
   - Add reserved-tier and best-effort cache accounting.
   - Ensure reserved-tier peers retain their latest cached revision even when
     the newest known revision cannot be cached locally.
   - Distinguish latest-known from latest-cached in APIs, internal reports, and
     persisted sidecars.
   - Change recovery selection to:
     - examine all peers;
     - choose the freshest available cached revision across all peers;
     - if the globally freshest known revision is unavailable everywhere, tell
       the user that recovery fell back to an older available revision and
       include timestamps and sizes where known.
   Design notes:
   - A peer with stale cached data should not poison recovery if another peer
     has a fresher cached revision.
   Validation:
   - unit tests for quota pressure and eviction;
   - multi-peer recovery tests covering:
     - newest-known unavailable on one peer but available on another;
     - newest-known unavailable everywhere, falling back to newest available;
     - reserved-tier retention under quota pressure;
     - best-effort eviction under quota pressure;
     - restart persistence of latest-known/latest-cached state.

6. Implement divergence download, storage, blocking, and resolution.
   Deliverables:
   - Detect sibling revisions during sync/recovery.
   - Download divergent revisions immediately and store them separately.
   - Persist conflict metadata with:
     - revision id;
     - timestamp;
     - origin type and peer identity where relevant;
     - size;
     - file count;
     - resolution status;
     - archive timestamp for the non-selected branch.
   - Block normal file commands while unresolved conflicts exist.
   - Add CLI/RPC surface for:
     - listing conflicts;
     - checking out each conflicting revision;
     - resolving a conflict by choosing the revision to keep active;
     - checking out archived revisions later.
   - Make `bbd` log a warning with concrete commands to inspect and resolve the
     conflict.
   - Make file-related `bbcli` commands fail with a conflict error that prints
     the available revision details.
   Design notes:
   - Keep archived revisions forever, distinct from the current active head.
   - Other non-file commands such as `unlock`, `stop`, `connect-peer`, and
     health/status commands must continue to work.
   Validation:
   - unit tests for conflict detection and persistence;
   - integration tests for command blocking and resolution;
   - multi-node tests where divergence is introduced intentionally and both
     branches remain accessible after resolution.

7. Implement connection admission and eclipse resistance.
   Deliverables:
   - Enforce a 1024-peer connection cap.
   - Compute effective peer priority from the fixed order:
     - manual;
     - reserved tier;
     - built-in;
     - we connected first;
     - they connected first.
   - Apply the same persisted peer metadata to admission decisions.
   - Reject or evict lower-priority peers first when the cap is exceeded.
   - Ensure a wave of inbound low-priority peers cannot crowd out manual,
     reserved-tier, or built-in peers.
   Design notes:
   - Connection admission and peer eviction should be deterministic and
     inspectable in logs and tests.
   Validation:
   - deep unit tests for every priority combination;
   - tests for tie handling and replacement order;
   - explicit eclipse-style scenario where many inbound peers try to outnumber
     good peers.

8. Refresh the user-facing documentation after the behavioral work lands.
   Deliverables:
   - Update `README.md` for:
     - built-in bootstrap peers;
     - hidden peer-list export workflow;
     - ephemeral local admin keys and SSH advice;
     - `bbcli stop`;
     - conflict behavior and resolution workflow;
     - latest-known vs latest-cached recovery wording.
   - Keep comments and docstrings aligned with the renamed `tlsutil` crate and
     the actual command surface.

Suggested commit structure

1. Rename `clitls` to `tlsutil`.
2. Add `Stop` RPC, `bbcli stop`, and graceful daemon shutdown.
3. Separate read-only local key lookup from key creation and fix the waiting
   behavior for `bbcli`.
4. Add built-in bootstrap peers and the hidden export command.
5. Expand persisted peer metadata for origin, direction, and cached-vs-known
   revision tracking.
6. Raise peer-storage budget to 1 GiB and implement reserved vs best-effort
   accounting.
7. Adjust recovery to select the freshest available cached revision and report
   fallback clearly.
8. Implement divergence persistence, blocking, checkout, resolution, and
   archive handling.
9. Enforce the 1024-peer cap with priority-based eviction and eclipse tests.
10. Refresh README and remaining comments.

Remote execution plan

- Do all heavy work on `barterbackup-dev`:
  - full `cargo test --workspace`;
  - `make clippy`;
  - live Tor scenarios;
  - any long-running multi-node tests.
- Use `barterbackup-arm64` for confirmation after behavior stabilizes:
  - `cargo test --workspace`;
  - `make clippy`;
  - targeted daemon and node tests if failures appear.
- Keep local runs lightweight:
  - grep, file edits, and very small focused checks only when needed to debug a
    machine-specific issue.

Exit criteria

- Built-in peer list flow exists and can emit a ready-to-commit source file.
- `bbcli healthcheck` no longer creates `cli-keys` when the daemon is absent.
- Graceful shutdown via Ctrl+C and `bbcli stop` removes session admin keys.
- Divergence is downloaded, persisted, visible, blocking, resolvable, and
  archived.
- Storage accounting distinguishes latest-known from latest-cached and recovery
  handles stale peers correctly.
- The 1024-peer cap and priority-based admission behavior are fully covered by
  tests, including eclipse-style scenarios.
- The TLS helper crate, comments, and docs are no longer misleading.
