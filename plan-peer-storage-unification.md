# Peer/Storage Unification and Replica Search Plan

## Goal

Retire the separate notion of a "storage contract" and treat storage as one
dimension of peer state.

After this change:

- every known peer has one persisted sidecar/peer record;
- only some peers also have mirrored bytes stored locally;
- background maintenance decides whether enough currently online peers hold our
  freshest replica;
- when online fresh replicas fall below `config.min_replicas`, the node enters
  an active search mode and tries to publish to additional peers;
- recovery keeps track of newer `requester_latest_known_content` hints even
  when the downloadable stored revision is older.

## Requested behavior

### 1. Remove the conceptual split between peer and storage contract

Replace the current model of:

- known peer metadata; and
- separate "working storage contract" state

with one peer-centric model:

- each known peer always has one persisted sidecar/metadata record;
- that record may or may not also point to locally cached mirrored content;
- local storage of the peer's bytes becomes an attribute of the peer record,
  not a different logical entity.

Practical consequence:

- user-facing CLI/state should stop presenting "contract" as a first-class
  object distinct from peer state;
- internal scoring/selection may still use publication/storage-related fields,
  but they should live on peer state.

### 2. Track how many online peers currently hold our freshest replica

`bbd` should have background maintenance that:

- checks whether connected/live peers currently have our freshest content;
- keeps a local count of online peers with fresh replicas;
- compares that count against `config.min_replicas`;
- when the count is below the target, enters active search mode for new
  storage candidates.

This can share machinery with the existing "does this peer have our data?"
checks.

Important distinction:

- the target is not just "known peers that historically stored something";
- it is "currently online peers that have the freshest replica".

### 3. Active search mode chooses candidate peers probabilistically

When more fresh online replicas are needed, choose candidate peers using a
weighted random choice.

Factors:

- strongest hard preference:
  - if we already store that peer's data unilaterally, prefer it first;
- local pin:
  - peers pinned by us should get a strong weight boost;
- remote pin:
  - peers that pin us should get a strong weight boost;
- peer age:
  - record first-seen time and prefer older peers;
- availability:
  - track successful and failed calls over time and prefer peers with higher
    observed uptime/success ratio.

Selection rule:

- local unilateral-storage relationship may remain an imperative first pass;
- all other factors should be weights, not absolute filters;
- selection should stay random enough that every eligible peer has some chance,
  but strongly biased by the weighted score;
- coefficients for each factor should be explicit constants/configurable
  internals, not hidden magic.

### 4. Persist more peer metadata from normal protocol traffic

To support the new model, store for every known peer:

- first-seen time;
- whether we pin the peer;
- whether the peer pins us;
- rolling success/failure stats for calls;
- latest `GetContentRevisionResponse`-derived requester state we learned:
  - latest requester stored content;
  - latest requester known content.

This implies:

- `pins_us` should be retained from `GetContentRevisionResponse`;
- we should persist enough of the latest response to make later selection and
  recovery decisions without requiring immediate re-contact.

### 5. Handle `SetContentRevision` from peers even when we cannot store bytes

When another node calls `SetContentRevision` for its content:

- always store the sidecar/metadata for that peer if the peer is known or can
  be admitted as known;
- if there is room for a full `4 MiB` blob under `config.peers_storage`
  according to:
  - `used + 4 MiB <= config.peers_storage`
  then also download and cache the mirrored bytes;
- otherwise, do not download the bytes, but do not fail the RPC either.

The response should tell the caller that:

- sidecar was accepted;
- mirrored bytes were not cached because local peer-storage budget was full.

This needs a new field in `SetContentRevisionResponse`.

### 6. Use latest-known requester info during recovery

Recovery should not rely only on the latest stored downloadable revision.

If a peer tells us:

- `requester_latest_stored_content = older downloadable revision`
- `requester_latest_known_content = newer non-downloadable revision`

then recovery should:

- record that a newer lineage exists;
- know that the downloaded/stored version is not the freshest one;
- log this fact clearly;
- expose both pieces of information in `bbcli state`.

This should stay visible until recovery is manually completed with
`bbcli init complete`.

After `bbcli init complete`:

- these pending-recovery hints should no longer be presented as actionable.

## Recommended design

### A. Move to a single peer-sidecar model

Refactor persisted state so peer records are authoritative and contain:

- reachability/liveness info;
- pin state;
- first-seen time;
- publication/storage scoring inputs;
- mirrored-bytes presence/size if cached locally;
- latest requester stored/known content metadata learned from the peer.

This does not require deleting all internal helper abstractions immediately,
but the persisted model and user-facing language should become peer-centric.

### B. Define one "fresh online replicas" maintenance loop

Background maintenance should compute:

- freshest local content ID;
- connected peers that advertise/store that same freshest revision;
- count of peers that are currently online and fresh.

If count `< min_replicas`:

- search for additional candidates;
- attempt `SetContentRevision` publication to them;
- update local peer state based on the response.

This loop should be bounded and incremental so it does not spam the network.

### C. Add explicit weighted candidate selection

Implement a dedicated peer-selection helper with:

- clearly named factors;
- explicit coefficients;
- weighted-random choice;
- deterministic test seams using `ManualClock` and injectable RNG.

Recommended order:

1. build eligible peer set;
2. if any peer already has unilateral reciprocal storage value, optionally
   narrow to that subset first;
3. compute weighted score for each remaining peer;
4. sample randomly by weight.

### D. Extend `SetContentRevisionResponse`

Add a machine-readable field describing storage outcome, for example:

- mirrored bytes cached;
- sidecar accepted but bytes not cached due to local storage budget.

This is not an RPC failure.

That lets the publisher:

- know publication metadata succeeded;
- know actual mirrored bytes were not retained by this peer.

### E. Extend recovery-side status and state

Persist and report:

- latest recovered downloadable revision timestamp/info;
- latest known requester revision info that is newer than the downloadable one;
- whether recovery still knows of fresher unseen lineage.

Surface this in `bbcli state` while recovery mode remains active.

## Impact

### Product impact

Positive:

- the model becomes easier to explain: peers always exist, storage bytes are
  just one attribute of peer state;
- replica maintenance targets the thing we actually care about:
  fresh online replicas;
- low-storage peers can still preserve useful lineage metadata even when they
  cannot mirror bytes;
- recovery becomes better informed about unseen fresher lineage.

Behavior change:

- "contract" language should disappear from the product surface;
- some peers will keep only sidecars with no mirrored bytes;
- publication success becomes more nuanced than pure success/failure.

Risk:

- unifying the model touches selection, publication, state display, recovery,
  and storage accounting at once;
- weighted selection can become unstable if coefficients are not tested well;
- sidecar-only peers must not be accidentally treated as full replicas.

### Code impact

Likely touch points:

- `crates/storage/src/lib.rs`
- `storedpb/stored.proto`
- `crates/node/src/lib.rs`
- `bbrpc/barter_backup_server.proto`
- `cmd/bbcli/src/lib.rs`
- `clirpc/barter_backup_client.proto`
- `README.md`
- generated CLI docs/completions/man if command/state output changes
- Docker harness/integration tests

## Open questions and weak points

### 1. "Online peer has our data" needs a precise definition

We need one exact criterion:

- peer is currently live; and
- peer's latest requester stored content matches our freshest local content.

It must not count:

- merely known peers;
- peers with only `latest_known` metadata;
- peers with stale cached revisions.

### 2. Sidecar-only acceptance may affect publisher assumptions

If a peer accepts sidecar but not bytes:

- should the publisher count it as a replica candidate immediately?
- likely no, because it does not yet hold mirrored bytes.

So the response field must be reflected in local accounting, or the replica
count will become overoptimistic.

### 3. Availability scoring must not be too noisy

"Succeeded/failed calls" is directionally right, but the exact window matters.

We should avoid:

- lifetime ratios that never forgive old outages;
- tiny windows that oscillate too much.

A rolling or exponentially-decayed score is likely better than raw totals.

### 4. First-seen time is valuable but sybil-sensitive

Preferring older peers is useful operationally, but it is not trustworthy as a
security signal. It should remain just one moderate weight, not a strong
authoritative factor.

### 5. Contract retirement must be reflected carefully in UX

There may still be internal tests and CLI/state text that assume "contract" is
the main storage object. The plan should explicitly remove or rename that
surface instead of silently leaving stale terminology behind.

## README work

README should be updated to explain:

- peer metadata vs mirrored bytes;
- that every known peer may have a stored sidecar even if we do not mirror its
  content;
- that replica maintenance targets fresh online replicas;
- that publication to a peer may succeed only for metadata if the peer is out
  of peer-storage budget;
- that recovery can report "newer known than stored" lineage until
  `bbcli init complete`.

## Test plan

### Unit tests

Add deterministic tests for:

1. peer records persist sidecar-only state without mirrored bytes.
2. `SetContentRevision` accepts sidecar but declines byte caching when
   `used + 4 MiB > peers_storage`.
3. the new response field distinguishes:
   - sidecar+bytes stored;
   - sidecar stored, bytes skipped.
4. fresh-online-replica counting includes only:
   - live peers;
   - peers with freshest stored requester content.
5. stale peers or sidecar-only peers are not counted as fresh replicas.
6. weighted candidate selection:
   - favors unilateral-storage peers;
   - boosts locally pinned peers;
   - boosts peers that pin us;
   - boosts older peers;
   - boosts higher-availability peers;
   - still allows lower-weight peers to be selected sometimes with deterministic
     seeded RNG tests.
7. first-seen time is recorded on first admission and not reset later.
8. success/failure availability stats update on peer RPC outcomes.
9. recovery records newer `latest_known` lineage even when only older stored
   bytes are downloadable.
10. `bbcli state` local summary includes:
    - fresh online replica count;
    - sidecar-only vs mirrored peer accounting if surfaced;
    - newer-known-than-stored recovery hint while recovery mode is active.
11. `bbcli init complete` clears/suppresses pending recovery hints.

### Netmock / multi-node tests

Add multi-node tests for:

1. falling below `min_replicas` causes automatic candidate search.
2. candidate publication chooses a peer by weighted policy, not fixed ordering.
3. a sidecar-only accepted peer is not counted as a fresh replica.
4. once storage budget becomes available, the node can later mirror bytes for a
   peer whose sidecar already exists.
5. remote pin information learned from `GetContentRevision` affects later
   candidate selection.
6. recovery sees:
   - older stored revision;
   - newer known revision;
   and records the "fresher exists elsewhere" condition.

### Docker integration tests

Cover main product scenarios:

1. node below `min_replicas` finds another peer and republishes automatically.
2. candidate selection prefers pinned/older/higher-uptime peers over weaker
   peers over repeated seeded runs.
3. peer with no remaining peer-storage budget accepts sidecar but not bytes,
   and publisher reports this clearly.
4. recovery-mode replacement node shows in `bbcli state` that:
   - an older stored revision was recovered;
   - a newer known requester revision still exists somewhere else.
5. after `bbcli init complete`, the recovery-specific hint disappears.

## Suggested commit split

1. **Unify persisted peer storage metadata**
   - move sidecar/storage fields onto peer-centric state
   - extend stored protobufs and storage helpers
   - add unit tests for sidecar-only peers

2. **Extend peer protocol for sidecar-only acceptance**
   - add `SetContentRevisionResponse` storage-result field
   - update publisher and responder logic
   - add unit/netmock tests for sidecar accepted but bytes skipped

3. **Track fresh online replicas and weighted candidate selection**
   - add first-seen, pins-us persistence, availability stats
   - add weighted search helper and background maintenance integration
   - add deterministic selection tests

4. **Expose newer-known-than-stored recovery state**
   - persist latest known requester lineage hints
   - surface them in recovery logic and `bbcli state`
   - update README and integration coverage

5. **Retire storage-contract terminology from user-facing output**
   - rename/remove stale CLI/state/docs language
   - regenerate docs/completions/man if needed

## Recommendation

This is a good direction.

The strongest parts:

- it removes an awkward conceptual split that has already become leaky;
- it aligns replica maintenance with online freshness instead of static
  "contract existence";
- it uses cheap sidecar retention to preserve more knowledge for recovery.

The main thing not to miss is accounting discipline:

- sidecar-only peers must never be mistaken for real replicas;
- latest-known hints must never be mistaken for downloadable stored content;
- weighted peer choice must stay testable and not turn into opaque heuristics.

If those boundaries are enforced clearly in state and tests, the redesign is
coherent and worth doing.
