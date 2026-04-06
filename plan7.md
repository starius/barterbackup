# Plan 7: Proof Checks, Peer Exchange, and Peer Session Reuse

## Goal

Improve peer synchronization and proof checking in three concrete ways:

1. make proof checks transfer only the challenged piece, not the whole suffix;
2. activate `PeerExchange` in normal peer workflows;
3. reuse recent peer connections through an in-memory cache instead of
   redialing for every logical operation.

This plan also changes failed-check scoring so an unreachable or non-serving
peer is penalized after the check retry budget is exhausted.

## Current State

- Peer traffic is on-demand. The node dials peers when needed and does not keep
  a standing connection pool.
- One logical proposal/check/recovery attempt already reuses a single live
  client within that attempt.
- `PeerExchange` exists on the server side, but normal client-side flows do not
  call it.
- Contract checks currently choose a 16 KiB sample conceptually, but the
  protocol requests `Download(content_id, offset)` and the responder returns
  the entire blob suffix from that offset to EOF.
- Check retries exist, but if retries are exhausted because the peer is
  unreachable or the sampled download never completes, the check returns an
  error instead of deducting score once for that failed check period.

## Design Decisions

### 1. Proof checks should request an explicit range

The protocol should request exactly the challenged range:

- add `length` to `bbrpc.DownloadRequest`;
- keep `offset`;
- keep `total_length` and full-blob `sha256` in the response;
- return exactly `min(length, blob_len - offset)` raw bytes.

There is no need for a Merkle proof because the checking node already has the
whole encrypted blob locally and can compare the returned piece directly.

### 2. Sample selection should allow short tail pieces

The sample chooser should select an offset anywhere inside the blob, not only
inside the range where a full 16 KiB sample fits.

That means:

- target piece size is 16 KiB;
- actual piece size is `min(16 KiB, blob_len - offset)`;
- for blobs shorter than 16 KiB, the whole blob is the challenged piece;
- for offsets near the end, the challenged piece is shorter than 16 KiB.

This matches the desired edge-case behavior and must be covered by tests.

### 3. Failed checks after retries should deduct score once

If a check cannot complete after the retry budget because the peer is offline,
times out, or otherwise fails to serve the sampled piece, that is a failed
contract check and must deduct score once for that elapsed period.

Important rule:

- retries remain internal to one logical check;
- score changes happen once per logical check, never once per retry attempt.

### 4. `PeerExchange` should be activated on normal successful contact

The implementation should begin using `PeerExchange` during successful live
peer interactions.

The reply should continue to include all known peers, not only currently
connected ones. Discovery is about reachability candidates, not only active
sessions. Dead-peer cleanup is a separate policy question and is out of scope
for this plan.

To avoid excess chatter, peer exchange should be rate-limited per peer in
memory. A successful exchange should not run on every maintenance minute.

### 5. Use an idle connection cache, not permanent live connections

The better model here is not “always stay connected to peers”.

The implementation should add a bounded in-memory cache of reusable peer
channels/sessions:

- keyed by peer onion;
- reused across logical operations when still healthy;
- evicted on transport/RPC failure that suggests the session is stale;
- evicted after an idle TTL;
- bounded by an LRU-style entry cap;
- never persisted to disk.

This keeps Tor/onion behavior pragmatic:

- we avoid needless repeated dials for frequent peers;
- we still reconnect cleanly when cached sessions go stale;
- correctness does not depend on a permanent connection staying alive.

## Work Plan

### Commit 1: Add ranged download support

Update the peer download protocol and implementation:

- add `length` to `bbrpc.DownloadRequest`;
- update protobuf comments to document exact-range semantics;
- update the responder to validate `offset` and `length`;
- return only the requested raw range;
- preserve `total_length` and whole-blob `sha256`;
- reject invalid ranges cleanly.

Tests:

- whole blob shorter than 16 KiB returns the whole blob;
- request near EOF returns a short tail piece;
- request exactly aligned to the end of a one-byte tail works;
- negative or oversized ranges are rejected;
- current full-content downloads used elsewhere still work when requesting the
  remaining blob length explicitly.

### Commit 2: Change check sampling to explicit piece checks

Update the checker to use the new range request:

- choose any offset within the blob;
- compute `section_length = min(16 KiB, blob_len - offset)`;
- request exactly that range;
- compare returned bytes against the local encrypted blob slice;
- keep validating the reported `total_length` and whole-blob `sha256`.

Tests:

- deterministic sample offset/length for small blobs;
- deterministic sample offset/length for offsets near the end;
- sampled check succeeds when the returned short tail matches;
- sampled check fails when the peer lies about total length, hash, or bytes.

### Commit 3: Penalize failed checks after retry exhaustion

Refine `check_contract_updates()` error handling:

- if retries eventually succeed, update score once based on the final result;
- if retries are exhausted before the sampled piece is obtained or validated,
  deduct score once;
- include a clear final update/state for “check failed because the peer did
  not serve the sample”.

This should apply to:

- failed revision probes;
- failed sampled downloads;
- timeouts;
- transport unavailability.

Tests:

- transient sampled-download failure followed by success does not double-score;
- repeated transport failure deducts score once;
- repeated timeout deducts score once;
- repeated revision-probe failure deducts score once.

### Commit 4: Implement client-side `PeerExchange`

Add a normal caller path for `PeerExchange`:

- implement a helper that sends our known peers and merges the reply;
- reuse the already-open peer client/session when available;
- call it after successful live contact, not on blind failures;
- rate-limit exchanges per peer with an in-memory cooldown.

Likely integration points:

- successful proposal attempts;
- successful checks;
- successful recovery probe/download paths where a live session already exists.

Tests:

- successful exchange merges newly learned peers;
- duplicates are ignored cleanly;
- invalid peer records from a responder are skipped;
- rate limiting suppresses immediate repeated exchange calls.

### Commit 5: Add a bounded idle connection cache

Introduce a peer session/channel cache in the node layer:

- cache healthy peer channels keyed by onion;
- return a cached channel when present and still inside idle TTL;
- on retryable channel/RPC failure, drop that cached entry and redial;
- bound the cache by a small LRU-style cap;
- expose no persistence and no product config yet.

This cache should be shared by:

- `connected_peers_response()`;
- `get_contracts_response()`;
- proposals;
- checks;
- recovery probes/downloads;
- peer exchange.

Tests:

- repeated operations to the same peer reuse the cached dial path;
- expired idle entry forces a redial;
- retryable failure evicts the cached entry and reconnects;
- cache stays bounded under many peers.

### Commit 6: Final validation

Run the relevant package suites after the above changes and keep them clean:

- `cargo test -p node`
- `cargo clippy -p node --tests -- -D warnings`
- `cargo test -p bbd`
- `cargo clippy -p bbd --tests -- -D warnings`

Then rerun the ignored live-Tor recovery test to make sure the new range
downloads, peer exchange, and cached sessions do not break real transport.

## Testing Requirements

Every behavioral change above must have unit or deterministic integration
coverage.

Minimum required coverage:

- range download semantics;
- short-blob and near-EOF sample lengths;
- check scoring on retry exhaustion;
- no duplicate score updates across retries;
- peer exchange merge/dedup/rate-limit behavior;
- connection cache reuse, expiry, and eviction;
- daemon-level regression coverage for maintenance still functioning with the
  new node-side behaviors.

## Non-Goals

- no Merkle proof design in this plan;
- no pluggable transport changes;
- no dead-peer pruning policy;
- no new persistent peer-session state on disk.
