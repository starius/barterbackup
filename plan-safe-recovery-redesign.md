# Safe Recovery and Remote-State Redesign

## Goal

Redesign peer revision synchronization and recovery so that:

- a freshly launched same-password node cannot silently clear or overwrite
  older remote replicas;
- passive peer-state advertisements do not mutate local mirrored state;
- recovery is automatic and data-preserving;
- manual conflict resolution RPCs and CLI commands are removed;
- recovery remains safe even when the recovered file set grows too large to
  publish immediately.

## Problems to solve

The current design has two unsafe properties:

1. `GetContentRevisionResponse.responder_content` is only an advertisement at
   the protocol level, but several callers immediately treat it as
   authoritative current state and pass it into `sync_peer_content_info(...)`.
   This lets a passive `GetContentRevision` response update or clear local
   mirrored peer state.
2. `SetContentRevisionRequest.requester_content = None` is an explicit clear,
   and a same-password replacement node can currently reach that path before it
   has analyzed older remote state. That is how stored data can be lost even
   without eviction pressure.

This redesign removes the first behavior and hardens the second with an
explicit compare-and-swap contract.

## Proposed design

### 1. Remove passive responder-side revision propagation

- Remove `GetContentRevisionResponse.responder_content` from
  `bbrpc/barter_backup_server.proto`.
- Remove all code that reacts to `responder_content` during:
  - contract listing;
  - contract proposal;
  - contract checking;
  - any background maintenance.
- `GetContentRevision` becomes a read-only description of what the responder
  knows about the requester's content, not a backchannel for pushing the
  responder's own latest content.

Impact:

- passive reads stop changing local mirrored-peer state;
- mirrored peer content can change only through explicit owner-originated
  actions or explicit incoming `SetContentRevision` calls from peers.

### 2. Make the data owner the only party that pushes requester revisions

The owner of the data must initiate `SetContentRevision` in three cases:

- after the local content changes;
- after a peer connects or reconnects;
- periodically while the node is allowed to publish.

Additional trigger:

- after unlock, if the node is not in recovery mode and already has local
  content, enqueue the same proposal logic instead of waiting for the next
  periodic tick.

This keeps ownership explicit: the storing side no longer infers requested
state from passive peer reads.

### 3. Add compare-and-swap semantics to `SetContentRevision`

Rename fields to remove ambiguity:

- rename `GetContentRevisionResponse.requester_content` to
  `requester_latest_stored_content`
- keep `GetContentRevisionResponse.requester_latest_known_content`

This separates:

- "latest requester revision this peer can actually serve now"
- from "latest requester revision this peer knows exists"

Add a new field to `SetContentRevisionRequest`:

- `previous_requester_content`

Semantics:

- it is the revision the requester believes the responder currently considers
  to be the latest known requester revision for this identity;
- `nil` is valid only when the requester believes the responder has never seen
  any requester revision for this identity.

Responder behavior:

- validate `requester_content` as today;
- reject the request with `failed_precondition` plus a machine-readable error
  reason if `previous_requester_content` does not match the responder's current
  `requester_latest_known_content`;
- only after that match succeeds, update the responder's stored requester
  revision state.

Important clarification:

- the compare must be against the responder's latest known requester revision,
  not merely the currently cached/stored requester revision.
- This is the critical safeguard when the responder knows about a fresher
  requester revision but has already dropped the blob.

This means the caller must usually use:

- `GetContentRevisionResponse.requester_latest_known_content`

as the value for the next `previous_requester_content`.

If `requester_latest_known_content` is absent, then the caller may use `nil`.

Client behavior on compare failure:

1. call `GetContentRevision`;
2. inspect `requester_latest_stored_content`;
3. if that stored revision falls into the allowed automatic-recovery window,
   download and merge it;
4. regardless of whether recovery was triggered, remember that the next
   `SetContentRevision` for this peer must send:
   - `previous_requester_content =
     GetContentRevisionResponse.requester_latest_known_content`

This ensures the client never blindly overwrites unknown remote lineage and
always advances from the peer's latest known requester state.

### 4. Persist lineage metadata on the owner node

Persist new local metadata:

- `node_initialized_at`
  - recorded once when `bbcli init` succeeds;
- `latest_recovered_revision`
  - `nil` if no remote recovery has been applied yet;
  - otherwise stores at least:
    - recovered `content_id`;
    - authenticated revision timestamp;
    - optional parsed revision key fields if convenient.
- `recovery_mode_enabled`
  - set by `bbcli init --recovery-mode`;
  - can be toggled later by explicit CLI commands.

Timestamp source:

- use the authenticated revision metadata already derivable from the content
  ID / revision key, not any peer-supplied free-form timestamp.
- authenticate peer-provided sidecars and revision metadata before using them
  for any recovery or publication decision.
- `node_initialized_at` is local node metadata; revision timestamps come from
  authenticated content metadata.

### 5. Enforce generation boundaries before overwriting remote state

Before an owner node publishes a new requester revision to one peer:

1. inspect the peer's current `GetContentRevision` result;
2. compare the peer's latest known requester revision timestamp against:
   - `node_initialized_at`;
   - `latest_recovered_revision`, if set.

Rules:

- if the peer's latest known requester revision is newer than or equal to
  `node_initialized_at`, it belongs to this node generation and may be
  overwritten by normal publishing;
- if it is older than `node_initialized_at`, it belongs to a pre-recovery
  lineage and must trigger automatic recovery before overwrite is allowed;
- if `latest_recovered_revision` is set, only trigger another recovery when a
  newly discovered recoverable revision is fresher than
  `latest_recovered_revision` but still older than `node_initialized_at`.

The owner node must never blindly retry `SetContentRevision` after a compare
failure. It must first analyze the remote previous state.

### 6. Replace manual conflict resolution with automatic recovery and merge

Remove the separate conflict workflow:

- remove active conflict persistence as a user-facing blocking concept;
- remove conflict list / checkout / resolve CLI commands and RPCs;
- recovery becomes automatic and additive.

Automatic recovery algorithm:

1. Query all known peers with `GetContentRevision`.
2. For each peer, inspect both:
   - `requester_latest_known_content`;
   - `requester_latest_stored_content`.
3. Prefer any revision that is actually downloadable now
   (`requester_latest_stored_content`) and satisfies the time-window rules.
4. Use `requester_latest_known_content` only as a hint that a newer lineage
   exists and should continue to be searched for elsewhere.
5. Download one recoverable candidate, decode files, and merge them into the
   local file set automatically.

Merge rules:

- if a recovered file name is new locally, add it;
- if the file name exists locally and the plaintext content matches exactly,
  skip it;
- if the file name exists locally and the plaintext content differs:
  - create another file name by inserting a recovered timestamp suffix before
    the final extension;
  - preserve the original extension;
  - if a name collision still happens, append a random suffix after the
    recovered timestamp.

Recommended filename rule:

- `name.ext` -> `name.recovered-YYYYMMDDTHHMMSSZ.ext`
- `archive.tar.gz` -> `archive.tar.recovered-YYYYMMDDTHHMMSSZ.gz`
- `README` -> `README.recovered-YYYYMMDDTHHMMSSZ`

After a successful merge:

- update `latest_recovered_revision` to the recovered revision that was
  actually applied;
- log the recovery at `INFO`;
- continue scanning in future passes for any newer recoverable revision still
  older than `node_initialized_at`.

This is intentionally conservative:

- it preserves data by merging and renaming rather than deleting or choosing
  one branch over another;
- intentional deletions from old lineages are not replayed automatically.

### 7. Use both latest-known and latest-stored requester revisions

When analyzing one peer's `GetContentRevision`:

- `requester_latest_known_content` answers:
  - "What is the newest requester revision this peer knows exists?"
- `requester_latest_stored_content` answers:
  - "What requester revision can this peer actually serve right now?"

Decision rule:

- if `requester_latest_stored_content` is useful for automatic recovery under
  the time-window rules, use it even when `requester_latest_known_content` is
  fresher;
- keep looking at other peers for the newer known version;
- never advance `latest_recovered_revision` beyond a revision that was not
  actually downloaded and merged.

### 8. Add explicit recovery mode to block outgoing publication

Add `bbcli init --recovery-mode`.

While recovery mode is enabled:

- block all owner-originated `SetContentRevision` attempts from the client side;
- block background proposal / publishing loops from the client side;
- block local file mutations such as `bbcli file set` and `bbcli file delete`;
- allow inbound peer `SetContentRevision` handling as today.

Add explicit CLI operations:

- one command to disable recovery mode when the operator decides recovery is
  complete.

This is needed to prevent a node from remaining permanently recovery-eligible
because some peer continues advertising an old lineage.

When recovery mode is disabled:

- automatically advance the effective recovery watermark to the node's current
  generation boundary;
- the CLI must state clearly that older unseen lineage will no longer be
  recovered after this point.

### 9. Recovery must not be blocked by post-merge oversize

If automatic recovery merges files and the resulting local file set exceeds the
maximum content size:

- do not roll back the recovery;
- do not block local access to the recovered files;
- block further owner-originated publishing / `SetContentRevision` until the
  operator removes enough files locally;
- log the oversize publish-blocked condition at `WARN`;
- expose the blocked reason in local state / CLI output.

This is intentionally different from manual `file set` rejection, because
recovery is data-preserving first and publishing second.

## Protocol and surface changes

### `bbrpc`

- remove `GetContentRevisionResponse.responder_content`;
- add `SetContentRevisionRequest.previous_requester_content`;
- keep `SetContentRevisionRequest.requester_content`;
- rename `GetContentRevisionResponse.requester_content` to
  `requester_latest_stored_content`;
- keep `requester_latest_known_content`.

### `clirpc` and CLI

Remove:

- conflict listing RPCs and CLI commands;
- checkout-conflict RPCs and CLI commands;
- resolve-conflict RPCs and CLI commands.

Add:

- recovery-mode status in local state output;
- CLI command(s) to:
  - disable recovery mode.

Adjust:

- `bbcli recovery run` becomes an automatic merge/report operation rather than
  a precursor to manual conflict resolution.

### Local storage

Persist:

- `node_initialized_at`;
- `latest_recovered_revision`;
- `recovery_mode_enabled`.

Remove or retire:

- user-facing active conflict / archived conflict machinery once replacement
  recovery coverage is complete.

## Recommended commit split

1. **Protocol and metadata groundwork**
   - add persisted generation/recovery metadata;
   - extend `SetContentRevisionRequest`;
   - remove `responder_content` from the peer protocol;
   - update proto consumers and test stubs.
2. **Owner-driven publication only**
   - remove passive `responder_content` handling;
   - route publish triggers through owner-initiated proposal logic only.
3. **CAS protection for requester revisions**
   - enforce `previous_requester_content` against latest-known requester state;
   - add machine-readable rejection paths;
   - block blind overwrite retries.
4. **Automatic recovery and merge engine**
   - implement candidate selection from `requester_latest_known_content` and
     `requester_latest_stored_content`;
   - implement merge and rename rules;
   - persist recovery watermark updates.
5. **Recovery mode and publish blocking**
   - add `--recovery-mode`;
   - block outgoing publication while enabled;
   - add oversize-after-recovery blocking and reporting.
6. **Conflict UX removal and docs**
   - remove obsolete conflict RPCs, CLI commands, tests, and README sections;
   - replace with automatic-recovery documentation and operational guidance.

## Test plan

### Unit tests

Add deterministic unit coverage for each rule and edge case:

- `SetContentRevision` compare-and-swap:
  - first call with both sides `nil`;
  - match against stored latest-known requester revision;
  - reject stale `previous_requester_content`;
  - reject `nil` when responder already knows a requester revision;
  - accept overwrite only when `previous_requester_content` equals the
    responder's latest-known requester revision, even if the blob is no longer
    cached.
  - machine-readable mismatch reason is returned and stable.
- removal of passive `responder_content` side effects:
  - `GetContentRevision` alone does not mutate mirrored peer state;
  - contract listing/checking/probing no longer change mirrored peer blobs via
    passive reads.
- generation-boundary logic:
  - previous revision older than `node_initialized_at` triggers recovery;
  - previous revision equal to or newer than `node_initialized_at` does not;
  - `latest_recovered_revision` gates repeated recovery.
- candidate selection:
  - use stored `requester_latest_stored_content` when useful even if
    `requester_latest_known_content` is fresher;
  - do not advance the recovery watermark past an unavailable latest-known
    version.
- merge rules:
  - new file add;
  - identical-content skip;
  - rename-on-different-content;
  - extension preservation;
  - no-extension names;
  - multi-dot names;
  - dotfiles;
  - timestamp-suffix collision fallback.
- recovery mode:
  - outgoing proposal blocked;
  - local file mutation blocked;
  - inbound peer storage updates still accepted;
  - disabling recovery mode re-enables publishing and advances the effective
    watermark as designed.
- oversize-after-recovery:
  - merge still succeeds;
  - publish path is blocked afterwards with a clear reason.
- watermark management:
  - marking current generation suppresses future recovery of older revisions;
  - persisted metadata survives restart.

### Integration tests with `netmock`

Add targeted multi-node scenarios:

- **real bug regression**:
  - same-password replacement node starts empty;
  - one peer still stores older content;
  - replacement node cannot clear or overwrite that peer before recovery.
- **CAS rejection then recovery**:
  - peer knows an older requester revision;
  - owner attempts publish with stale `previous_requester_content`;
  - request is rejected;
  - owner fetches remote state, analyzes
    `requester_latest_stored_content`, recovers if appropriate, merges, and
    retries safely using `requester_latest_known_content` as the next
    `previous_requester_content`.
- **latest-known newer than latest-stored**:
  - one peer advertises a newer latest-known revision but stores only an older
    revision;
  - older stored revision is still recovered if it falls in the allowed window.
- **automatic merge without conflicts API**:
  - divergent revisions from multiple peers are merged additively and renamed
    deterministically instead of blocking on manual resolution.
- **recovery mode safety**:
  - no outgoing `SetContentRevision` while recovery mode is enabled;
  - after explicit recovery-mode exit, publishing resumes.
- **oversize preserved but unpublished**:
  - automatic recovery grows the local set beyond the upload ceiling;
  - recovered files remain accessible;
  - publish attempts fail with the expected blocked reason.

### Docker integration tests

Cover the main operational and dangerous scenarios:

- recovery replacement node on real daemon processes cannot wipe old remote
  replicas;
- two-peer and three-peer recovery on the public-transport-like stack;
- `A -> B -> C` discovery still works under the new recovery rules;
- peer with only stale-but-useful stored content still contributes recovery;
- repeated restarts preserve `node_initialized_at`, recovery watermark, and
  recovery mode;
- oversize-after-recovery warning is visible in logs / CLI state.

## README updates required

The README must be rewritten for recovery:

- remove manual conflict-resolution guidance;
- explain recovery mode and when to use it;
- explain that replacement recovery nodes must start in recovery mode;
- explain that correct local clock time at node initialization is important for
  recovery generation boundaries to work correctly;
- explain that recovery now merges old revisions conservatively and may create
  renamed files instead of discarding differences;
- explain explicitly that automatic recovery preserves older files but does not
  replay historical deletions from older lineages;
- explain the publish-blocked state when recovered data becomes too large;
- explain the compare-and-swap algorithm and the meaning of:
  - latest known requester revision;
  - latest stored requester revision;
  - recovery watermark advancement when recovery mode is exited;
- explain the generation boundary:
  - one password == one node identity;
  - replacement nodes recover older lineages before publishing;
  - the operator must explicitly finish recovery mode before the node starts
    publishing again.

## Feedback on the proposal

### What is strong

- It directly addresses the real destructive flaw by removing passive
  responder-driven updates.
- The compare-and-swap requirement is the right guardrail. Without it, any
  recovery safety story is incomplete.
- Automatic additive merge is more robust than the current manual conflict
  resolution for backup use cases. It biases toward not losing user data.
- Recovery mode is a good operational safeguard even if the protocol changes
  are already correct.

### Weak points and missing decisions

1. **The compare target must be latest-known, not merely latest-stored.**
   This is now the explicit rule. The field rename to
   `requester_latest_stored_content` is good and should remove the confusion
   that existed with the old `requester_content` name.

2. **Timestamp semantics need to be explicit.**
   The plan depends on "older than init time" and "newer than latest
   recovered". That is valid only if the timestamp comes from authenticated
   revision metadata, not a free-form peer claim. The current revision key can
   already parse authenticated `created_at` from the content ID; the redesign
   should use that.

3. **Clock skew is still a product tradeoff.**
   `node_initialized_at` is local wall-clock time, while recovered revision
   timestamps were created on earlier machines. If clocks were badly wrong, the
   generation split can misclassify a lineage. The plan should document that it
   relies on roughly sane clocks and still favors recovery over overwrite when
   unsure.

4. **Automatic merge intentionally does not replay deletions.**
   That is probably the right choice for backups, but it must be explicit.
   Otherwise operators may expect recovery of "state" while the algorithm is
   really recovering "data preservation".

5. **Recovery mode and local edits.**
   This is resolved in the stricter direction: local file edits should be
   blocked while recovery mode is enabled.

6. **The retry path should have a machine-readable failure reason.**
   The caller can always re-run `GetContentRevision`, but it is better if the
   `SetContentRevision` rejection clearly distinguishes:
   - stale `previous_requester_content`;
   - invalid `requester_content`;
   - storage-limit problems;
   - peer transport failures.

7. **Watermark behavior after “finish recovery” must be explicit.**
   Advancing the recovery watermark automatically when recovery mode is exited
   is fine, but both the CLI and the README must explain that this chooses to
   ignore any older unseen lineage from that point onward.

Overall assessment:

- the plan is good;
- the protocol direction is correct;
- the biggest thing to tighten before implementation is the precise semantics
  of `previous_requester_content` versus `requester_latest_known_content`.
