# Plan: Cancel Interrupted Local `bbcli` RPCs in `bbd`

## Problem

If a local `bbcli` command is interrupted after the request has reached `bbd`,
`bbd` can still finish the RPC-side work and only later notice the broken local
TLS connection. The operator then sees a late log like:

```text
ERROR bbd::app: failed local CLI TLS handshake error=tls handshake eof
```

That is the wrong failure mode for a cancelled local admin request. The daemon
should notice the disconnect promptly, cancel the in-flight local RPC work, and
avoid finishing side effects that the client no longer cares about.

## Current shape

Relevant code paths today:

- Local CLI TLS is terminated before tonic in `run_with_peer_runtime_until()` in
  `cmd/bbd/src/app.rs`.
- The local gRPC service is `DaemonRpcService`, which forwards almost every
  request straight into `DaemonService` and then into `node::CliService`.
- The daemon already uses `CancellationToken` for daemon shutdown and
  background-maintenance lifetimes.
- There is no request-scoped cancellation token threaded through local RPC
  handlers.

As a result, daemon shutdown is cancellable, but an interrupted local client
command is not.

## Goal

For local CLI RPCs only:

- detect client disconnect / cancellation promptly,
- stop the server-side task for that request,
- propagate cancellation into lower layers that may be doing network or storage
  work,
- return `Status::cancelled` or equivalent internal early-stop behavior instead
  of completing the whole request,
- avoid noisy operator-facing error logs for expected client-side interruption.

## Non-goals

- Do not change peer RPC semantics.
- Do not redesign daemon-global shutdown.
- Do not make background maintenance cancellable by local client disconnect.
- Do not silently swallow genuine TLS or transport failures that happen before a
  request starts.

## Design

### 1. Introduce request-scoped cancellation for local RPCs

Add a small request context for local CLI handlers, conceptually:

- a `CancellationToken`,
- helpers to check / await cancellation,
- conversion to `Status::cancelled("local CLI request cancelled")`.

`DaemonRpcService` should become the place that creates one request token per
incoming RPC and passes it into the actual implementation.

The important distinction is:

- daemon shutdown token: process/service lifetime,
- local RPC token: one client request lifetime.

These should remain separate and composable.

### 2. Detect disconnect from the local gRPC request lifecycle

Before changing lower layers, confirm the most reliable signal tonic/hyper gives
us for an aborted local request.

Preferred direction:

- use a request/response future that is cancelled or notified when the client
  disconnects,
- attach that signal to the request token,
- avoid polling raw sockets manually if tonic already exposes a usable signal.

Fallback if tonic does not expose it cleanly:

- wrap each local RPC handler in a spawned task,
- monitor the connection/request future externally,
- cancel/abort the task when the request is dropped by the transport.

The implementation should be based on the actual local tonic behavior rather
than guesswork. The first change in this slice should therefore include a small
repro test that proves the chosen signal fires on interrupted `bbcli` calls.

### 3. Add cancellable handler wrappers in `DaemonRpcService`

Instead of forwarding methods directly like:

- `self.daemon.connect_peer(request).await`

wrap local handlers with a helper like:

- `run_local_rpc(request, |ctx, request| async move { ... })`

That helper should:

- create the request token,
- start a cancellation watcher tied to client disconnect,
- run the actual handler future under `tokio::select!`,
- return early with `Status::cancelled` if the client goes away first,
- ensure any spawned watcher task is cleaned up.

Start with the long-running / side-effecting local RPCs first:

- `connect_peer`
- `set_file_stream`
- `delete_file`
- `publish_to_peer`
- `verify_peer_storage`
- any other unary local RPCs that can block on network or heavy store work

Read-only fast RPCs can either use the same wrapper for uniformity or be left
for a second pass if the helper adds too much boilerplate.

### 4. Thread cancellation into `node::CliService` and lower operations

Returning early from the outer tonic handler is not enough if the actual work is
already happening in nested futures. The request token has to reach the slow
operations.

Add cancellable variants or optional context parameters where needed, so the
following can stop promptly:

- local upload parsing in `set_file_stream`,
- peer dials / live-contact calls in `connect_peer`,
- publish/verify loops,
- any retry / wait loops,
- long-running storage or transport calls that are awaited directly.

Preferred style:

- cancellable helper wrappers around existing futures,
- `tokio::select!` on `token.cancelled()` and the real operation,
- preserve existing behavior when no request token is supplied.

Avoid invasive signature churn where a small number of wrappers can isolate the
change.

### 5. Ensure partial work stops at safe boundaries

For each cancellable operation, define the safe cancellation boundary.

Examples:

- `set_file_stream`
  - if cancelled before final persistence, do not commit the new file/content
    revision,
  - if persistence already committed, return success semantics only if the
    operation is truly complete.
- `connect_peer`
  - if cancelled before tracking/persisting the peer, leave no partial state,
  - if tracking already happened, cancellation should stop follow-up live
    contact work.
- `publish_to_peer` / `verify_peer_storage`
  - cancellation should stop waiting/retrying and avoid extra network work,
  - do not corrupt score or peer state with half-finished bookkeeping.

The implementation should prefer coarse safe checkpoints over attempting to make
already-committed side effects reversible.

### 6. Reduce noisy logging for expected client interruption

Once request cancellation is wired correctly, expected local client aborts should
not look like daemon failures.

Adjust logging so that:

- real TLS handshake failures before a request exists remain `ERROR` or `WARN`,
- request-side local disconnects after a request has started are logged at most
  as `DEBUG` or `INFO`, or not at all if tonic cancellation is enough,
- `Status::cancelled` paths do not emit scary operator-facing messages.

The exact log site may remain outside `failed local CLI TLS handshake`; the key
behavioral goal is to stop treating normal interrupted `bbcli` commands as a
server-side failure worth an operator alarm.

## Testing plan

### Unit / daemon tests

Add focused tests in `cmd/bbd/src/app.rs` that prove:

1. A long-running local RPC is cancelled when the client side is dropped.
2. The server-side work does not run to completion after cancellation.
3. No unexpected persistent side effects remain after cancellation.
4. The daemon stays healthy and accepts a subsequent local RPC normally.

Good candidates:

- an artificially delayed `connect_peer` path,
- an upload stream where the client disconnects mid-request,
- a publish/verify request cancelled while waiting on a mocked peer.

These tests should use deterministic mocks/manual clocks where possible.

### Integration-style local RPC test

Add one test that exercises the real local gRPC path over the daemon’s local TLS
server rather than only direct service calls. The purpose is to prove that the
chosen disconnect signal matches actual `bbcli` interruption semantics.

### Regression log test

If practical, add a test around the relevant log path or error mapping so an
interrupted local RPC no longer surfaces as a generic daemon failure.

## Commit split

### Commit 1: local RPC cancellation framework

- request-scoped cancellation token/context
- local handler wrapper in `DaemonRpcService`
- one focused long-running RPC wired through it
- tests proving disconnect-triggered cancellation works

### Commit 2: propagate cancellation through local side-effecting RPCs

- `connect_peer`, `set_file_stream`, `delete_file`, publish/verify paths
- safe cancellation checkpoints
- tests for no-completion-after-disconnect behavior

### Commit 3: log cleanup and remaining polish

- adjust expected interruption logging
- add any final integration-style regression coverage

## Validation

Before each commit:

- `make fmt`
- build the touched crate(s)
- targeted `bbd` tests for the cancellation path

After the final commit:

- broader `bbd` test lane
- any relevant `bbcli` tests if client-side interruption handling needs small
  CLI adjustments

## Risks

- tonic may not expose an easy per-request disconnect signal, forcing a lower-
  level wrapper around request execution.
- Cancelling too aggressively can leave bookkeeping in an inconsistent state if
  safe boundaries are not chosen carefully.
- Some storage mutations are intentionally atomic only at the final commit step;
  tests must prove cancellation does not commit partial revisions.

## Success criteria

- interrupting a long-running `bbcli` command stops server-side work promptly,
- the daemon does not finish the whole RPC after client disappearance,
- expected interruptions are reported as cancellation, not scary daemon errors,
- normal completed local CLI RPCs behave exactly as before.
