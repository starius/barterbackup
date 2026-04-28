# Recovery, Replication, and Init Password Policy

## 1. Recovery via a peer learned during peer exchange

### Current state

This is only partially covered today.

What already exists:
- Docker coverage for peer gossip inventory propagation in `TestDockerPeerExchangeGossip`.
- Node unit coverage for recovery-time peer exchange in `recover_content_merges_peer_exchange_results`.

What is still missing:
- No end-to-end test proves that a recovering node can start with only peer `B`,
  learn peer `C` from `B`, and then recover its content from `C` when `B`
  does not store the content itself.

### Implementation plan

1. Add one Docker integration test for the full second-hop recovery path.
2. Scenario:
   - `A` and `recovered` share the same seed.
   - `C` stores a replica of `A`'s content.
   - `B` does not store that content.
   - `recovered` initially knows only `B`.
   - `B` knows `C`, so peer exchange can reveal `C`.
3. Drive recovery with `RecoverContentUntilRecovered`.
4. Assert:
   - the recovered node learns `C` into its peer inventory;
   - the recovered node restores the expected file contents;
   - recovery succeeds even though the first contacted peer did not have the
     data.
5. Keep the existing unit test. It still usefully covers the lighter-weight
   merge behavior, while the new Docker test covers the real cross-node flow.

## 2. Background storage contracts and replica refill

### Current state

The daemon already performs background maintenance on its own.

What already exists:
- `bbd` runs a maintenance loop that wakes on a timer and after local
  mutations.
- Each pass performs recovery first, then runs background contract propose/check
  work across known peers.
- Existing daemon tests already show automatic syncing without a user-issued
  `bbcli contract propose`.

What is still missing:
- `min_replicas` is not currently used as an enforcement target.
- The current loop sweeps known peers opportunistically, but it does not decide
  "we are below the requested replica count, so refill now until the target is
  satisfied".

### Implementation plan

1. Define the counted replica set for the current content revision.
   - Count only peers whose contract view says our current content is synced.
   - Reuse the same freshness notion already used for `fresh_replicas_now` and
     `replica_horizon`.
2. Add one helper in the node/daemon layer that computes the current replica
   deficit against `min_replicas`.
3. Extend background maintenance so that when a deficit exists, it prioritizes
   candidate peers that are known but not currently counted as fresh replicas.
4. Keep manual contract commands unchanged. They remain an explicit operator
   tool, but they stop being the only way to restore the target after peer
   degradation.
5. Add deterministic tests:
   - unit tests for deficit calculation and candidate selection;
   - daemon tests showing background maintenance refills a deficit when another
     known peer is available;
   - Docker integration coverage where one replica goes offline and a different
     known peer is filled automatically.
6. Keep the limitation explicit: if the node has no additional known peers, it
   still cannot conjure new replicas out of nowhere. Discovery and refill are
   separate concerns.

## 3. `bbcli init` password-quality check

### Current state

This is not implemented today.

What already exists:
- `bbcli init` checks only that the password is present and, for terminal
  entry, that the confirmation matches.
- The daemon and RPC surface do not enforce any password-strength policy.

### Implementation plan

1. Add a CLI-side password-strength dependency in `cmd/bbcli`.
   - Recommended crate: `zxcvbn`.
   - Verified current docs.rs entry: `zxcvbn` is the standard Rust port of the
     Dropbox password-strength estimator.
2. Add a new `bbcli init --allow-weak-password` override flag.
   - Limit it to `init` only.
   - Do not change `unlock`.
3. After password collection and confirmation, run the strength check before the
   init RPC.
4. Reject weak passwords by default with a hard estimator threshold.
   - Hard gate: `guesses_log10 >= 25.0`.
   - Do not use the coarse `score` bucket as the pass/fail rule.
   - Return a clear error that mentions `--allow-weak-password`.
5. Print the estimator result in both the success and failure paths.
   - Include `score`.
   - Include `guesses_log10`.
   - Include `zxcvbn` feedback text when it is available.
6. Keep this entirely CLI-side.
   - No `bbd` changes.
   - No `bbrpc` or `clirpc` changes.
7. Add tests in `cmd/bbcli` for:
   - weak password rejection;
   - strong password acceptance;
   - override acceptance for a weak password;
   - success and failure output including `score`, `guesses_log10`, and
     feedback;
   - continued preflight behavior, so daemon-state checks still happen before
     we ask for terminal input.
8. Update the README and CLI docs as part of the same change.
   - Document the hard `guesses_log10 >= 25.0` floor.
   - Document `--allow-weak-password`.
   - Give concrete operator guidance:
     - prefer `7+` truly random Diceware-style words;
     - words from the operator's own language are fine if they are chosen
       randomly rather than written as a familiar phrase;
     - surface `zxcvbn`'s own warning/suggestion feedback instead of inventing
       custom heuristics.
