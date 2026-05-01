# Automatic Peer-Triggered Recovery and Recovery-CLI Retirement

## Goal

Finish the recovery redesign so that:

- a recovery-mode node does not require `bbcli recovery run` to discover and
  merge older lineage;
- one live peer connection is enough to trigger the same safe remote-state
  analysis already used after `SetContentRevision` compare-and-swap mismatch;
- repeated live traffic does not re-run the same recovery probe endlessly for
  the same peer connection;
- the `bbcli recovery` command group can be removed entirely;
- the operator-facing command that exits recovery mode stays under the `init`
  namespace because recovery mode is entered via `bbcli init --recovery-mode`.

## Requested behavior

### 1. Trigger recovery analysis on new live peer connections

When a peer connection becomes live in either direction:

- run `GetContentRevision` once against that peer;
- analyze the response exactly like the current publication CAS-mismatch path:
  - inspect `requester_latest_known_content`;
  - inspect `requester_latest_stored_content`;
  - if the stored revision falls inside the recoverable older-lineage window,
    download and merge it;
  - if a newer known revision exists but cannot be served by that peer, keep it
    only as a hint and continue relying on other peers for an actual download.

This should happen for:

- outbound connections we establish to a peer;
- inbound connections from a peer to us.

### 2. Avoid repeating the same analysis on every routine contact

Remember in memory, per peer, that this connection-triggered analysis has
already run for the current live session.

Required scope:

- do not persist this marker across daemon restart;
- clear it when the live connection is lost and a new connection later forms;
- keep it separate from the existing publication CAS path, which may still need
  to run additional recovery if a peer changes its requester revision after the
  initial connection analysis.

Practical rule:

- "once per live session per peer" is enough.

## CLI surface changes

### 3. Remove `bbcli recovery run`

Once automatic peer-triggered recovery is in place:

- remove `RecoverContent` from `clirpc`;
- remove `bbcli recovery run` from the CLI;
- remove README/docs/completions/man references to manual recovery runs.

The product model becomes:

- `bbcli init --recovery-mode` starts a replacement node in safe non-publishing
  mode;
- recovery happens automatically as peers become connected;
- operator action is only needed to allow publication again after they are
  satisfied that recovery has completed.

### 4. Retire the `bbcli recovery` command group

The whole `bbcli recovery` section should go away.

Recommended replacement:

- reshape `bbcli init` into a command group and add:
  - `bbcli init complete`

Meaning:

- this disables recovery mode;
- advances the effective recovery watermark to the node-generation boundary;
- allows publication again from the recovered node.

Why this name is better:

- it stays attached to the lifecycle that began with
  `bbcli init --recovery-mode`;
- it reads naturally as completing initialization of the replacement node;
- it avoids keeping a long-term `recovery` namespace when recovery is meant to
  be automatic.

Alternative names considered:

- `bbcli recovery finish`
  - accurate but no longer desirable because the whole `recovery` group should
    be retired;
- `bbcli publish resume`
  - workable, but weaker because it disconnects the action from the recovery
    initialization flow.

Recommendation:

- use `bbcli init complete`;
- reshape `bbcli init` from a leaf command into a command group so the recovery
  lifecycle stays under the same namespace;
- do not keep `bbcli recovery finish` except possibly as a short-lived hidden
  compatibility alias during the change if the user wants that; otherwise
  remove it outright since the product is not released yet.

## Implementation plan

### A. Factor one reusable remote-state analysis path

Extract the logic currently used after publication CAS mismatch into one helper
that can be used from:

- the current CAS-mismatch path;
- outbound newly-live peer connection handling;
- inbound newly-live peer connection handling.

That helper should:

- fetch `GetContentRevision` if the caller does not already have it;
- decide whether recovery is needed;
- run `recover_content_update()` only when the peer response exposes a
  recoverable stored older-lineage revision;
- log the trigger source clearly at `INFO`, for example:
  - automatic recovery after peer became live;
  - automatic recovery after publication CAS mismatch.

### B. Add in-memory per-peer session gating

Add one in-memory marker to peer runtime state, for example:

- `recovery_probe_completed_for_live_session`

Required behavior:

- set it after one successful connection-triggered analysis attempt,
  regardless of whether recovery found anything to merge;
- clear it when the live session ends;
- do not let it suppress the publication CAS-mismatch path.

Important nuance:

- if the first `GetContentRevision` attempt fails due to transient transport
  error before any actual analysis happens, do not mark the session complete;
- only mark complete after one real revision analysis finished.

### C. Hook both live-connection directions

Find the current code paths where a peer becomes live and attach the reusable
analysis helper there.

This must cover:

- outbound connection establishment;
- inbound live peer identification.

Design constraint:

- do not create a reconnect storm or nested repeated analysis loops;
- keep the probe best-effort and bounded by the existing retry/timeouts used for
  peer RPCs.

### D. Replace the CLI/RPC naming

Protocol and CLI changes:

- remove `RecoverContent` request/stream RPC from `clirpc`;
- remove `RecoveryCommand::Run`;
- remove `RecoveryCommand` entirely;
- reshape `InitCommand` into a command group so it supports both:
  - the existing initialization operation;
  - `bbcli init complete`;
- rename `FinishRecovery` RPC to init-oriented wording, preferably:
  - `InitComplete`.

Recommended corresponding RPC names:

- `InitCompleteRequest`
- `InitCompleteResponse`

Server behavior remains the same:

- disable recovery mode;
- advance watermark to the generation boundary;
- allow publication again.

## Impact

### Product impact

Positive:

- recovery-mode nodes become self-driving once they connect to surviving peers;
- the operator no longer needs to remember to run a manual recovery pass;
- naming becomes more accurate: automatic recovery plus explicit completion of
  the replacement-node initialization flow.

Behavioral change:

- recovery happens sooner and on peer contact, not only on explicit CLI action
  or publication attempts;
- the `init` CLI surface becomes a command group rather than a single leaf
  command.

Potential risk:

- if the hook is attached too broadly, repeated live flaps could cause too many
  recovery probes;
- the per-live-session marker is the main control against that.

### Code impact

Likely touch points:

- `cmd/bbcli/src/lib.rs`
- `cmd/bbd/src/app.rs`
- `crates/node/src/lib.rs`
- `clirpc/barter_backup_client.proto`
- generated docs/completions/man output
- integration harness helpers that call recovery/finish commands

## Test plan

### Unit tests

Add or extend deterministic node tests for:

1. outbound live connection triggers exactly one recovery analysis for that
   live session.
2. inbound live connection triggers exactly one recovery analysis for that live
   session.
3. repeated successful operations on the same live session do not re-run the
   connection-triggered analysis.
4. disconnect then reconnect clears the in-memory marker and allows one new
   analysis.
5. transient pre-analysis probe failure does not set the marker.
6. connection-triggered analysis recovers from `requester_latest_stored_content`
   using the same window rules as the CAS-mismatch path.
7. connection-triggered analysis does not incorrectly advance state when only
   `requester_latest_known_content` is newer but not downloadable.
8. publication CAS mismatch still triggers recovery even if the session marker
   was already set.
9. `InitComplete` disables recovery mode and advances watermark exactly as the
   old finish path did.
10. removed `RecoverContent` surface no longer appears in CLI parsing/help.
11. `bbcli init complete` help/output replaces the old recovery-finish surface.

### Integration tests with `netmock`

Add focused multi-node scenarios for:

1. recovery-mode replacement node connects to one surviving replica peer and
   recovers automatically without any manual recovery command.
2. broker peer becomes live first, reveals a better peer later, and the
   recovered node still succeeds once that better peer becomes connected.
3. same-password replacement node cannot wipe stored data merely by connecting;
   it must recover first and remain publication-blocked until initialization is
   completed explicitly.
4. one live session performs only one automatic probe despite multiple follow-up
   RPCs on that session.
5. reconnecting the same peer causes exactly one fresh automatic probe.

### Docker integration tests

Cover the main operator scenarios:

1. replacement node in recovery mode automatically recovers after `peer connect`
   without `bbcli recovery run`.
2. `A -> B -> C` discovery still works with no manual recovery command.
3. a newly connected same-password recovery node does not clear existing remote
   replicas.
4. `bbcli init complete` reenables publication and suppresses further
   older-lineage recovery exactly like today's finish semantics.
5. docs/manual-env tests use the new command name and no longer rely on
   `bbcli recovery run`.

## Documentation updates required

Update README and generated docs to explain:

- recovery is automatic on live peer contact;
- `bbcli recovery run` no longer exists;
- recovery mode pauses owner publication while the node gathers older lineage;
- `bbcli init complete` is the explicit operator step that ends that
  initialization-time recovery phase and allows publication again.

## Recommended commit split

1. **Automatic recovery on peer-live events**
   - factor reusable recovery-analysis helper;
   - hook outbound and inbound live-session events;
   - add in-memory per-session gating;
   - add focused unit and integration coverage.

2. **Retire manual recovery run and rename finish semantics**
   - remove `RecoverContent` RPC and CLI command;
   - replace `bbcli recovery finish` with `bbcli init complete`;
   - reshape the `init` CLI surface as needed;
   - update tests, README, generated docs, man page, and completions.

## Assessment

This is a good cleanup.

Why it is strong:

- it finishes the product direction already implied by the safe-recovery
  redesign;
- it removes an easy-to-forget manual step;
- it makes the operator-visible command name describe the real lifecycle
  transition.

Main thing to watch:

- the "run once per live session" marker must be attached to real live-session
  lifecycle, not just to peer identity globally. Otherwise reconnects could
  either spam recovery or permanently suppress needed future probes.
