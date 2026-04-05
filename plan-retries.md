# Retry And Reliability Plan

## Goal

Make peer maintenance and recovery resilient to normal onion-service instability.
One failed Tor rendezvous or one bad circuit must not cost a full maintenance
interval, and the daemon must recover from a degraded local peer runtime
without operator intervention.

This plan is intentionally limited to reliability work. It does not change the
product model, storage policy, or the bbrpc surface unless a narrowly scoped
API addition becomes necessary.

## Current Failure Mode

Today the daemon retries failed peer work only by waiting for the next
maintenance pass. The default maintenance interval is 60 seconds, so one
transient dial failure produces one warning and then a full-minute gap before
the next attempt.

The critical current behavior is:

- `run_maintenance_pass()` does one recovery attempt, then one proposal attempt
  and one check attempt per peer.
- `connect_peer_client()` gives each dial one 10 second timeout.
- `peer_rpc()` gives each RPC one 20 second timeout.
- There is no production retry loop inside proposal, check, or recovery.
- There is no automatic restart of the local Arti/onion runtime when the
  self-check stays unhealthy.

That is exactly consistent with the field log pattern where proposal failures
repeat once per minute for long periods.

## bbrpc Retry Safety Audit

The peer retry design must assume at-least-once delivery at the RPC layer.
That means the same request can be repeated after an ambiguous failure where the
remote side may already have applied it.

The current bbrpc methods are safe enough for transport retries if retried
carefully:

### `HealthCheck`

Safe to retry. It is read-only and returns only caller/server identity.

### `PeerExchange`

Safe to retry. Repeating the same peer list only re-upserts tracked peers.
Current peer tracking is deduplicating, not append-only.

### `GetContentRevision`

Safe to retry. It is read-only.

### `Download`

Safe to retry. It is read-only. Repeating the same download only repeats the
same verified blob read on the remote side and the same verified blob transfer
on the local side.

### `SetContentRevision`

Safe to retry under the current storage model, but it is the only method that
needs explicit care.

Why it is still safe:

- the request is an upsert of the requester's desired revision, not an append;
- the server validates the same `content_id` and `content_length` every time;
- `sync_peer_content_info()` updates peer state by replacement, not by creating
  duplicate metadata records;
- repeated writes of the same mirrored blob overwrite the same content-id based
  blob path atomically;
- a repeated clear request remains a clear request.

The real risk is wasted work, not corruption. An ambiguous failure after the
remote side accepted `SetContentRevision` can cause the caller to repeat the
same proposal and the responder to re-download or re-check the same blob.

The retry design should therefore:

- always begin a fresh proposal/check cycle with `GetContentRevision`;
- avoid replaying `SetContentRevision` blindly without first refreshing live
  peer state;
- treat duplicate `SetContentRevision` as acceptable but expensive.

Conclusion: automatic retries are acceptable for the existing bbrpc methods.
They must be implemented as reconnect-and-reissue logic with state refresh, not
as raw opaque transport replay.

## Work Plan

### 1. Introduce a production retry policy module

Add a small retry policy shared by maintenance, manual CLI contract commands,
and recovery.

The policy should define:

- which statuses are retryable;
- per-attempt connect timeout;
- per-attempt RPC timeout;
- per-operation total budget;
- exponential backoff with jitter;
- logging shape for attempt count and remaining budget.

The current tests-only retry classification in `cmd/bbd/src/app.rs` should move
into production code and become the single source of truth.

Commit shape:

- add retry policy types and helpers;
- unit test status classification and backoff schedule;
- no behavior change yet.

### 2. Split retryable failures from terminal failures

Normalize peer errors so the caller can distinguish:

- retryable dial failures;
- retryable RPC transport failures;
- retryable deadlines;
- terminal peer rejections such as invalid argument, not found, or
  failed-precondition;
- local shutdown cancellation.

Today `peer_rpc()` wraps most peer errors into `Unavailable`, which hides useful
structure. Tighten that mapping so retry policy decisions are based on code and
context, not string parsing alone.

Commit shape:

- refine peer error mapping;
- add tests for timeout, transport, and terminal failure classification.

### 3. Add reconnect-and-retry to proposal

Wrap `propose_contract_updates()` in an operation budget with multiple attempts.

Rules:

- each attempt must reconnect from scratch;
- each attempt must start with `GetContentRevision`;
- `SetContentRevision` may be repeated if the refreshed revision still shows
  the peer missing our content;
- retry only retryable failures;
- preserve current final semantics and progress-update stream shape.

This is the highest-value change because it directly addresses the field logs.

Commit shape:

- implement retry loop for proposal only;
- add deterministic tests with connectors that fail the first N attempts and
  then succeed;
- add tests for ambiguous `SetContentRevision` failure followed by success.

### 4. Add reconnect-and-retry to check

Wrap `check_contract_updates()` in the same retry policy.

Rules:

- reconnect on every attempt;
- refresh peer revision on every attempt;
- if the peer has no local content obligation for us, only score once for the
  final successful conclusion;
- do not score multiple times because of retries;
- repeated sample downloads are acceptable.

Commit shape:

- implement retry loop for check;
- add tests proving score changes happen once per completed check, not once per
  retry attempt.

### 5. Add reconnect-and-retry to recovery

Wrap peer revision queries and blob downloads in retry logic during recovery.

Rules:

- retries must happen inside one recovery call, not only on the next
  maintenance pass;
- candidate selection still happens across all peers first;
- when downloading a candidate, try multiple peers and multiple attempts per
  peer within the operation budget;
- keep current fallback semantics for latest-known versus latest-cached.

Commit shape:

- implement retry loop for recovery probes and downloads;
- add deterministic tests for flaky peers and partial peer availability.

### 6. Reuse one live peer session within one attempt

Do not reconnect between `GetContentRevision` and `SetContentRevision` or
between `GetContentRevision` and the check download inside the same attempt.

The retry unit is:

- connect once;
- run the sequence for that operation;
- on failure, discard the session and start a fresh attempt.

This keeps the logic simple while still reducing circuit churn and repeated TLS
handshakes.

Commit shape:

- factor a per-attempt peer session helper;
- reuse it in proposal and check;
- add tests proving one attempt does not redial unnecessarily.

### 7. Add peer-local failure state and backoff

Track in memory per peer:

- consecutive retryable failures;
- last success time;
- last failure time;
- next eligible background maintenance attempt;
- last failure class.

Use this state only for background maintenance. Manual CLI actions should still
run immediately.

Background policy:

- first failure retries quickly within the same maintenance operation budget;
- repeated failure grows backoff with jitter;
- success clears the failure streak;
- the daemon should avoid logging the same peer failure at a fixed one-minute
  cadence forever.

Commit shape:

- add peer retry state;
- wire it into background maintenance scheduling;
- add manual-clock tests for backoff timing and reset on success.

### 8. Add self-healing for the local peer runtime

The existing self-check should become a repair trigger, not just a status flag.

Required behavior:

- if self-check fails for N consecutive intervals or for a configured duration,
  restart the peer runtime;
- if the peer runtime task exits unexpectedly, restart it;
- restart must recreate the Arti client and republish the onion service;
- avoid restart storms with bounded restart backoff.

This is necessary because onion-service runtime degradation is one plausible
root cause when both inbound and outbound peer traffic stay broken.

Commit shape:

- add runtime supervisor state;
- use the existing self-check loop as the health signal;
- add deterministic tests with a connector/runtime stub that stays unhealthy
  until restart.

### 9. Add bounded concurrency to background maintenance

Background maintenance is serial today. One slow or flaky peer can consume too
much of the pass.

Change this to a small bounded concurrency model:

- one recovery task;
- peer proposal/check tasks with a modest concurrency cap;
- each task obeys its own retry budget and shutdown token.

This increases resilience without letting the node fan out uncontrollably.

Commit shape:

- add concurrent maintenance execution with cancellation safety;
- add tests ensuring shutdown still cancels hanging peer work cleanly.

### 10. Improve reliability-focused observability

Logs and local admin views should expose enough state to debug reliability
problems without reading code.

Add at minimum:

- attempt number and retry budget exhaustion;
- consecutive failure count;
- last successful peer contact;
- last failure class;
- whether the local self-peer check is healthy when logging peer failures.

Prefer state-transition logging over identical fixed-interval warnings.

Commit shape:

- structured log improvements;
- extend local admin reporting if needed;
- add tests for log-triggering state changes where practical.

### 11. Real-Tor soak validation on `barterbackup-dev`

After deterministic tests pass, run a real-Tor soak scenario on the remote
builder:

- two live Arti-backed nodes;
- repeated proposals and checks;
- injected peer restarts;
- temporary unavailability windows;
- confirm fast recovery without waiting for whole maintenance intervals.

This should stay as an ignored integration test plus a documented manual command
sequence.

## Testing Strategy

Most of the new coverage should stay deterministic and local to the codebase:

- `netmock` connectors that fail N times before succeeding;
- hanging connectors to verify timeout and shutdown;
- manual clock for backoff timing;
- score/accounting assertions to prove retries do not duplicate side effects;
- recovery tests with several peers advertising the same content.

Only the final soak validation needs real Arti/Tor.

Heavy runs should be done on `ssh barterbackup-dev`, not on the local machine.

## Order Of Execution

The safest implementation order is:

1. retry policy module;
2. error classification cleanup;
3. proposal retries;
4. check retries;
5. recovery retries;
6. per-attempt session reuse;
7. background peer backoff state;
8. peer runtime self-healing;
9. concurrent maintenance;
10. observability pass;
11. real-Tor soak validation.

That order keeps each commit independently reviewable and lets the highest-value
reliability fixes land first.
