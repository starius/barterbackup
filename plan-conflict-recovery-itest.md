# Conflict Recovery Follow-Up Plan

## Current reading of the code

### Conflict trigger semantics

The current recovery conflict detector operates on content revisions, not on
peer-side metadata.

Relevant points:

- Divergence is computed from `RecoveryCandidate` revision keys and content ids
  in `recovery_candidates_diverge(...)`.
- Recovery candidates come from peer-advertised `requester_content` /
  `requester_latest_known_content` and from the local `current_content` only.
- Local peer metadata such as scores, reachability, and contracts lives in the
  encrypted peer-state sidecar and does not change `current_content`.
- File edits (`SetFile`, `DeleteFile`) create a new content blob and therefore a
  new content revision. Metadata-only changes do not.

So the intended rule already appears to be true in the current design:

- a conflict is about divergent file-state revisions;
- metadata-only local changes should not create a conflict by themselves.

However, this specific rule is not strong enough in tests yet. We need explicit
coverage for it.

## Goal

Finish conflict handling to the standard you described:

1. prove that metadata-only local changes do not create editing conflicts;
2. add end-to-end integration tests for the real multi-node conflict scenario;
3. if unit coverage disproves the current reading, fix the implementation;
4. keep the work split into atomic commits.

## Phase 1: Unit-level proof of the metadata-only rule

### Test to add

Add a focused node-level test with this shape:

1. owner revision `v1` exists on peer `B`;
2. recovered node restores `v1` from `B`;
3. recovered node performs only metadata-only changes locally, for example:
   - connect a new peer;
   - update peer score/reachability through normal flows if a deterministic path
     exists;
4. prove that the metadata-only change actually happened before the newer
   file-state is discovered:
   - prefer checking observable peer metadata through `clirpc` / node state;
   - if needed, also assert on targeted logs;
   - do not let this test pass if the supposed metadata-only mutation was a
     no-op;
5. another peer `C` later advertises a fresher file-state revision `v2`;
6. recovery should move to `v2` automatically;
7. no active conflict should be recorded;
8. normal file commands should remain unblocked;
9. prove that the metadata-only local state was effectively rolled back or
   superseded as expected by the auto-resolution path:
   - verify the final observable metadata state through `clirpc` or stored node
     state;
   - confirm there is no lingering conflict marker;
   - confirm the final file-state is `v2`.

### Why this goes first

This is the narrowest proof of requirement `1`.
If it fails, we fix the recovery/conflict logic before writing the heavier
integration suite.

### Expected likely outcome

I expect this test to pass with the current code, because only `current_content`
feeds divergence and metadata-only changes do not mutate it.

## Phase 2: If needed, implement the conflict trigger fix

Only do this if Phase 1 disproves the current reading.

### Intended fix direction

Ensure divergence detection only considers file-state revisions:

- local sidecar-only mutations must never be treated as a revision;
- only `current_content` and peer-advertised content revisions participate in
  `recovery_candidates_diverge(...)`;
- do not let local operator or peer bookkeeping create synthetic conflict state.

### Tests required with the fix

- metadata-only local updates do not create conflicts;
- real local file edits still do create conflicts against a divergent remote
  branch;
- active conflict registration still persists the expected conflicting file-state
  revisions only.

## Phase 3: Add the Docker/Chutney conflict integration suite

Add a real integration test group in `integration/docker/` using the current Go
harness and direct `clirpc` calls.

### Shared base scenario

Build one helper flow that creates the topology:

1. start `A` and `B`;
2. `A` uploads file-state `v1` to `B`;
3. verify with `B`'s `clirpc` that `B` knows/stores `v1`;
4. stop `B`;
5. start `C`;
6. `A` changes files to `v2`;
7. `A` uploads `v2` to `C`;
8. verify with `C`'s `clirpc` that `C` knows/stores `v2`;
9. stop `C`;
10. destroy `A`;
11. restart `B`;
12. recreate `A` fresh and recover from `B`, so `A` gets outdated `v1`.

From there, split into subtests.

### Subtest 1: keep remote `C` version

1. after recovery from `B`, `A` edits files locally to create branch `v1a`;
2. restart `C` so `A` can discover branch `v2`;
3. `A` must detect a conflict;
4. normal file-edit commands must be blocked;
5. `list-conflicts` must show both unresolved revisions;
6. `checkout-revision` for both revisions must produce the expected file trees
   in temporary directories;
7. resolve the conflict in favor of `C`'s revision;
8. the local active files must now match `C`'s branch;
9. the non-selected local branch must remain archived and still be checkoutable;
10. normal file editing must be unblocked again;
11. subsequent new edits must replicate successfully to both `B` and `C`.

### Subtest 2: keep local `A` version

Same setup, but resolve in favor of `A`'s post-recovery local edit branch.

Assertions:

- local active files match the local branch;
- `C`'s branch is archived and checkoutable;
- normal edits resume;
- subsequent new edits replicate to both `B` and `C`.

### Subtest 3: metadata-only local changes auto-resolve

1. after recovery from `B`, do not edit files on `A`;
2. perform only metadata-only changes locally, for example:
   - connect another peer;
   - trigger contract/probe bookkeeping if needed;
3. verify via `clirpc` or logs that the metadata-only change really took effect;
4. restart `C` with fresher file-state `v2`;
5. `A` should update to `v2` automatically;
6. no conflict should be recorded;
7. normal file commands should remain usable;
8. verify via `clirpc` that the final metadata view matches the expected
   auto-resolved state rather than preserving the superseded local-only
   metadata branch.

## Phase 4: Add lower-level assertions around archived conflict state

The node test already covers the main archived checkout path, but add explicit
coverage for the integration path too:

- `list-conflicts` marks archived entries as `unresolved=false`;
- `resolved_at` is populated;
- archived revisions remain checkoutable after subsequent successful edits and
  uploads.

## Phase 5: Validation matrix

### Unit / node tests

Required targeted runs:

- the new metadata-only no-conflict test;
- existing divergent conflict test;
- recovery latest/fallback tests;
- storage conflict persistence tests.

### Integration tests

Required runs:

- conflict keep-remote subtest;
- conflict keep-local subtest;
- metadata-only auto-resolve subtest.

These should run on the remote builder only.

## Commit plan

1. add unit test for metadata-only local updates not creating conflict;
2. if needed, fix conflict trigger semantics;
3. add shared Docker/Chutney conflict harness helpers;
4. add integration subtest for keeping remote version;
5. add integration subtest for keeping local version;
6. add integration subtest for metadata-only auto-resolve;
7. update docs/TODO only if the new coverage resolves any tracked open item.

## Expected answer to your question `1`

Based on the current code, it looks like the system already treats conflicts as
file-state divergence, not as peer-side metadata drift.

But this must be proven with an explicit unit test before we rely on it.
