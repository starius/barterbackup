# Plan: Finish Remaining Operator-Facing Hardening

## Goal

Close the `TODO.md` item:

- finish the remaining operator-facing hardening around observability and
  resource controls.

This plan assumes the recently completed work is already in place:

- structured peer-maintenance logs
- peer I/O bounds for the current single-blob protocol
- shared retry/timeout handling
- clearer `bbcli peer list` summaries
- dedicated Docker integration coverage for the main peer scenarios

So the remaining gap is not "add logging from scratch". The remaining gap is:

1. decide which resource ceilings are part of the public product surface;
2. expose them clearly to operators;
3. enforce them consistently;
4. document and test the chosen policy.

## Current State

### Already present

- Hard peer-content ceiling enforced in the transport/node path:
  - `transport::MAX_PEER_CONTENT_BYTES = 4 MiB`
  - peer gRPC message cap derived from it
- Peer retry/connect/RPC timeout policy exists and is centralized.
- `bbcli peer list` already shows:
  - status
  - score
  - cached/known lengths
  - stored bytes
  - staleness
  - last live timestamp
- `bbcli config get` already reports current storage config plus derived storage
  information.
- Recovery / check / proposal paths already log peer failures with more context
  than before.

### Still unresolved

- The product still does not define which remaining ceilings are intentionally
  operator-visible and stable.
- The main unresolved policy question is whether we keep the current single-blob
  design with an explicit size ceiling, or introduce chunking now.
- The daemon does not yet expose one coherent operator-facing "resource policy"
  view. Operators can infer pieces from code and partial CLI output, but not from
  one authoritative surface.
- Current `bbcli peer list` summaries are clearer than before, but they still do not surface
  enough recent-failure context to explain *why* a peer is offline/unavailable
  without looking at logs.

## Recommendation

Do **not** implement chunking in this item.

Instead, finish the operator-facing hardening by formalizing the current
single-blob design and exposing its limits clearly.

Reason:

- chunking is a protocol/storage design change, not just hardening;
- the system already has a bounded and tested single-blob model;
- the separate `TODO` item about local content size policy already exists;
- this item should make the current model explicit and operable before the
  project takes on a new transfer/storage architecture.

So the recommended result of this plan is:

- keep the current single-blob peer model for now;
- make its limits explicit, queryable, and documented;
- add only the operator-facing controls that are truly needed;
- leave chunking as a separate future project if the product later needs larger
  peer content than the current model allows.

## Scope

### In scope

- define the public resource-ceiling policy for peer operations;
- expose those ceilings through `clirpc` and `bbcli`;
- improve peer/status observability enough that operators can diagnose normal
  failures without reading daemon logs first;
- add enforcement tests and Docker integration tests for the exposed policy;
- document the supported operational model.

### Out of scope

- changing the local-content size-limit policy item from `TODO.md`;
- protocol chunking / streaming redesign;
- external Tor / pluggable transports;
- deferred batching of low-value metadata writes.

## Proposed Work

## Phase 1: Freeze The Product Policy

Create one short internal design decision and then implement against it.

Decision points to settle:

1. Peer mirrored-content ceiling
- Recommended: keep the current 4 MiB ceiling for now.
- Make it an explicit public product limit, not just an internal constant.

2. Peer transfer model
- Recommended: keep single-blob transfer for now.
- Explicitly defer chunking.

3. Operator-configurable vs fixed limits
- Recommended split:
  - fixed for now:
    - peer mirrored-content ceiling
    - peer gRPC message ceiling derived from it
    - tracked-peer metadata cap
    - peer-client cache size
  - operator-configurable now:
    - retry/connect/RPC timeout policy only if we decide operators really need
      it in normal usage
- If timeout tuning is not meant to be user-facing yet, expose it read-only
  first and keep writes internal.

4. Failure semantics
- oversize peer content should remain a hard reject;
- CLI output should say clearly whether a failure is due to:
  - configured storage budget
  - protocol content ceiling
  - timeout / transport unavailability.

Deliverable:
- a committed code-level policy, not just docs.

## Phase 2: Add A Coherent Resource-Policy Surface

Add one authoritative local RPC view for operator-facing limits.

Recommended shape:

- extend `GetStorageConfigResponse` with a nested read-only limits section, or
- add a separate `GetRuntimePolicy` / `GetResourcePolicy` RPC.

Preferred direction:
- separate read-only `GetResourcePolicy` response, because storage budget and
  transport/runtime ceilings are related but not the same object.

It should report at least:

- `max_peer_content_bytes`
- `peer_grpc_message_limit_bytes`
- `peer_connect_timeout_ms`
- `peer_rpc_timeout_ms`
- `peer_operation_budget_ms`
- `max_tracked_peers`
- `max_cached_peer_clients`
- whether chunking is supported
  - for now: `false`

Why this matters:
- operators need one place to understand the daemon's actual limits;
- integration tests can assert product policy directly instead of inferring it.

## Phase 3: Improve Peer-Level Operator Observability

Extend `PeerInfo` / `bbcli peer list` inventory with recent operational context.

Recommended additions:

- `last_failure_at`
- `last_error_class`
  - e.g. `offline`, `timeout`, `transport`, `oversize`, `storage_budget`
- `consecutive_failures`
- `next_retry_at` or `retry_backoff_seconds`
- possibly `last_successful_check_at`

Recommended CLI behavior:

- `bbcli peer list` should keep the default concise one-line summary;
- add an optional detailed mode or a second command if needed later;
- default summary should at least include the last error class when a peer is
  offline or backoff-delayed.

Why this matters:
- today a user can see `offline`, but not enough about whether the node is
  backing off, timing out, or rejecting a peer on resource policy grounds.

## Phase 4: Make Resource Rejections Human And Consistent

Audit every operator-visible resource failure and normalize the wording.

Cases to cover:

- peer content exceeds protocol ceiling;
- peer content exceeds current storage budget / maximum acceptable peer content;
- peer request exceeds download-range bounds;
- retry budget exhausted / timeout conditions;
- local admin requests that imply an impossible peer-storage outcome.

Desired result:
- CLI errors and streamed status updates should distinguish:
  - protocol ceiling
  - current budget
  - temporary timeout/unavailability
- avoid vague `resource exhausted` text without context.

This is especially important for:

- `propose-contract`
- `check-contract`
- `recover-content`
- peer inventory / contract listing surfaces

## Phase 5: Decide Whether Timeouts Become Public Config

This is the main optional branch in the plan.

Recommended approach:

### Step 5A: expose read-only timeout policy first

Expose the current retry/connect/RPC timing policy through the new resource
policy surface.

### Step 5B: only add writable timeout config if there is a strong operator need

If we decide to make it writable, add:

- validated config fields for connect timeout / RPC timeout / operation budget
- strict bounds and sane defaults
- CLI updates under `bbcli config get` and `bbcli config set`

Reason for caution:
- writable timeout knobs increase support burden;
- they should not be exposed unless the project is ready to own those settings
  as stable public behavior.

So the default plan is:
- read-only in this item;
- writable only if required after review.

## Phase 6: Tests

### Unit tests

Add focused unit coverage for:

1. resource policy reporting
- values match the live daemon/node policy;
- chunking support is reported as disabled.

2. validation and formatting
- human-readable error classification for oversize / budget / timeout cases;
- `bbcli peer list` formatting with new failure context.

3. enforcement
- oversize peer content still hard-rejects;
- budget-constrained peer content reports budget-specific failure;
- timeout-exhausted operations keep their intended error class.

### Daemon / local RPC tests

Add `bbd`/`bbcli` integration-style tests for:

- `bbcli config get` or new policy command reporting the right limits;
- `bbcli peer list` output showing offline/failure context consistently;
- human wording for the main operator-visible resource failures.

### Docker integration tests

Add or extend scenarios for:

1. oversize peer content policy
- peer attempts to advertise/store content above the supported ceiling;
- operator-visible failure must state that the content exceeds the peer-content
  limit.

2. storage-budget-specific rejection
- peer content fits protocol ceiling but exceeds current storage budget;
- failure must be distinguishable from protocol oversize.

3. peer summary observability
- after a forced timeout/offline path, `bbcli peer list` / direct `clirpc` peer view
  must show the new failure/backoff fields.

These tests should stay in the fast Chutney lane.

## Phase 7: Documentation

Update:

- `README.md`
- operator-facing CLI docs if split later
- relevant proto comments / public doc comments

Document clearly:

- current mirrored-peer content size limit;
- that peer transfer is still single-blob, not chunked;
- which limits are fixed vs configurable;
- how to inspect the daemon's current resource policy;
- how to interpret peer offline/backoff/failure states.

## Suggested Commit Breakdown

1. `Define public resource policy surface`
- add read-only RPC/proto reporting for runtime/resource limits
- tests for reported values

2. `Expose peer failure context`
- extend peer inventory state and CLI output
- unit tests and local RPC tests

3. `Clarify operator resource failures`
- normalize user-visible error classes/messages
- tests for oversize / budget / timeout wording

4. `Add resource-policy integration coverage`
- Docker tests for oversize, budget rejection, and peer observability

5. `Document resource policy`
- README / comments / any CLI docs

If timeout policy becomes writable, insert one extra dedicated commit:

- `Add validated timeout policy config`

## Acceptance Criteria

This item is done when all of the following are true:

1. An operator can query the daemon and see the supported resource ceilings
   directly, without reading code.
2. An operator can distinguish protocol-size rejection from storage-budget
   rejection from timeout/offline failure.
3. Peer inventory surfaces enough recent failure context to explain why a peer is
   currently offline or delayed.
4. The chosen policy about chunking is explicit:
   - either supported and tested, or
   - explicitly unsupported and surfaced as such.
5. Unit tests and Docker integration tests cover the operator-visible resource
   policy.
6. The `TODO.md` item can be removed without leaving hidden design decisions in
   code comments only.

## Recommended Final Decision

Unless review strongly objects, the implementation should take this concrete
position:

- keep the current single-blob peer protocol;
- keep the 4 MiB mirrored-peer content ceiling for now;
- expose that ceiling and related runtime limits explicitly;
- improve peer failure observability;
- defer protocol chunking to a future separate project.

That is the smallest coherent way to finish this `TODO` item without smuggling a
major protocol redesign into a hardening task.
