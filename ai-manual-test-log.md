# AI Manual Test Log

Date: 2026-04-15
Repo: `/home/user/barterbackup/rust2`
Hosts:
- `barterbackup-dev1`
- `barterbackup-dev2`

Scope:
- remote-only build and manual validation
- no local Rust builds
- focus on daemon startup, CLI usability, contract sync, restart, and recovery

## Environment preparation

- Verified SSH access to both hosts.
- Installed on both hosts:
  - `curl`
  - `xz-utils`
  - `ca-certificates`
  - `git`
  - `rsync`
  - `build-essential`
  - `pkg-config`
  - `clang`
  - `protobuf-compiler`
- Installed Nix in daemon mode on both hosts.
- Synced the repo to `/root/barterbackup-rust2/` on both hosts with `rsync`.

## Build and baseline

- `nix develop --command make build` passed on both hosts after fixing one
  dev-shell issue:
  - the shell had exported `CC`, `CXX`, and `AR` for the static-musl toolchain
    unconditionally
  - that broke normal host builds on the second host
  - fix: unset `CC`, `CXX`, and `AR` in the dev shell
- `make test` on both hosts hit one existing failing daemon test:
  - `app::tests::manual_maintenance_tick_refreshes_restarted_peer`
  - failure:
    - `timed out waiting for mirrored peer content after manual tick`
- targeted follow-up showed:
  - the failure is a test-harness race, not a confirmed live product failure
  - direct proposal after peer restart works
  - the existing test shuts the peer down while the previous manual
    maintenance pass can still be in flight

## Early CLI and operator checks

Verified on earlier fresh runs during this session:

- `bbcli state` before `bbd` exists:
  - printed:
    - `waiting for bbd to create cli keys in directory ...`
  - then failed with:
    - `bbd is not running yet or has not created its session cli keys; start \`bbd\` and retry`
- `bbcli unlock` before `bbcli init`:
  - failed with:
    - `daemon storage is not initialized; run \`bbcli init\` first`
- `bbcli connect-peer <our-onion>`:
  - failed with:
    - `the local node cannot be connected as its own peer`
- `bbcli init` on an already initialized directory:
  - failed before asking for a password
  - message:
    - `daemon storage is already initialized; run \`bbcli unlock\` instead`

These messages are good enough to point the user to the next action.

## Live two-host Tor scenario

### Local addresses

- The default local address `127.0.0.1:9911` was already occupied on both
  hosts.
- For this run I started:
  - host 1 daemon with `--local-addr 127.0.0.1:19911`
  - host 2 daemon with `--local-addr 127.0.0.1:19912`

This exercised the synchronized `--local-addr` option naming on both `bbd`
and `bbcli`.

### Fresh nodes

- Owner node data dir: `/root/bb-a`
- Peer node data dir: `/root/bb-b`

Observed onions:

- owner:
  - `mze2qa6dlxrgbp2zsoivuil6yfg422hrer2eacfhook3m25ejuvon2id.onion`
- peer:
  - `xlynz3c4fwqn6b3ilod2bbw6ui6bje45sjjbvlkxr5zosyhiey2e5lad.onion`

### Payload

Created on the owner host:

- `/root/manual-payloads/source-snapshot.tar`
- `/root/manual-payloads/random-1m.bin`

Original hashes:

- `96d0e4162b41cb29f1d330f5b83ca11113a71440dd20859d95ffe6036cc9b27d  /root/manual-payloads/source-snapshot.tar`
- `984c92905a6ffcfd02c8eb53be47e8a91ced8f890ddd23e3ec3920cb2d155c60  /root/manual-payloads/random-1m.bin`

Uploaded on the owner with:

- `bbcli set-file source-snapshot.tar ...`
- `bbcli set-file random-1m.bin ...`

`bbcli list-files` on the owner returned:

- `random-1m.bin`
- `source-snapshot.tar`

### First contract attempt

Connected peers both ways with `bbcli connect-peer`.

First owner-side proposal:

- command:
  - `bbcli propose-contract xlynz3c4...lad.onion`
- result:
  - failed
- error:
  - `set content revision from xlynz3c4...lad.onion: connect peer timed out`

Interpretation:

- the owner reached the peer far enough to ask for the peer revision
- then the peer attempted the reverse dial needed by `SetContentRevision`
- that reverse dial timed out

This is a live reliability issue, not a shell/orchestration issue.

### Second contract attempt

Retried the same proposal once more after both services had been up a bit
longer.

Second owner-side proposal:

- succeeded
- streamed states ended with:
  - `state=8 success=true`

Peer-side status after the successful retry:

- `bbcli peers` showed:
  - one `with_contract` entry for the owner
  - `status=connected`
  - `stored_content_bytes=1867776`
  - `latest_known_content_length=1867776`
  - `latest_cached_content_length=1867776`
  - `stale_cache=false`
- `bbcli get-contracts` showed:
  - `online=true`
  - `synced=true`
  - `their_content_length=1867776`
  - matching latest-known and latest-cached content ids
  - positive `their_remaining_seconds`

So the peer did successfully store the owner data after the retry.

## Restart behavior

### Graceful peer stop

Executed on the peer:

- `bbcli stop`

Verified after the stop:

- `<data-dir>/cli-keys` had been removed

This part behaved correctly.

### Peer restart

Restarted the peer daemon locked on the same data dir.

Observed locked state before unlock:

- `storage_initialized: true`
- `server_onion:` empty
- `peer_runtime_state: unknown`
- `self_peer_check_state: unknown`

That is the expected locked state.

### Unlock failure after restart

Restart unlock on the peer failed reproducibly:

- command:
  - `printf '%s\n' 'beta-demo-seed-2026' | bbcli unlock --password-stdin`
- error:
  - `recovery required: peer sidecar is invalid`

This is a real product bug.

Notes:

- fingerprint verification had already passed, otherwise unlock would have
  failed earlier with an invalid-password error
- the failure happens while reopening the local encrypted store
- it reproduces on repeated unlock attempts against the restarted daemon

Because of this bug, I could not complete the final recovery part of the live
cross-host scenario in this run.

## Additional live observations

- On the peer host, `peer_runtime_state: ready` appeared before
  `self_peer_check_state: healthy`.
- The self-check remained unhealthy for roughly one minute with:
  - `connect peer timed out`
- It eventually recovered without manual intervention.

This is not fatal by itself, but it is relevant to operator expectations and
first-contact reliability.

## Follow-up debugging performed after the live failure

The restart failure did not reproduce in narrower deterministic tests:

- storage-level regression on a real on-disk filesystem:
  - pass
- node-level restart after successful proposal:
  - pass
- daemon-level restart after proposal plus `get-contracts` using mock transport:
  - pass

That means the current evidence points to a live Tor-backed sequence that is
not yet covered by a deterministic regression.

## Confirmed issues from this manual run

1. The first live `propose-contract` can fail even after both nodes have
   reported that the peer runtime is up.
2. After a successful live contract and graceful stop, restarting the peer can
   leave the local encrypted store unlockable with:
   - `recovery required: peer sidecar is invalid`
3. The current deterministic test suite does not yet reproduce issue `2`.

## Confirmed fixes and validated improvements during this work

- the dev shell now supports normal host builds on both machines by unsetting
  `CC`, `CXX`, and `AR`
- stale peer-runtime transport state is now dropped before runtime replacement
  in the daemon supervisor
- added targeted regressions for:
  - clearing cached peer runtime clients
  - storage sidecar reload on disk
  - node restart after proposal
  - daemon restart after contract inspection with mock transport

## Follow-up validation after self-check restart fix

Date: 2026-04-17

The earlier live failures were rerun after changing the daemon supervisor so
pre-healthy self-check transport timeouts no longer trigger a full peer
runtime restart. A deterministic daemon regression now covers that policy:

- `app::tests::prehealthy_timeout_self_checks_do_not_restart_peer_runtime`

Focused daemon validation also passed:

- `app::tests::peer_runtime_restarts_after_repeated_self_check_failures`
- `app::tests::restart_after_contract_view_keeps_unlockable_peer_state`

Fresh two-host run:

- owner host:
  - data dir: `/root/live-a`
  - local addr: `127.0.0.1:21911`
  - onion:
    - `bcrf5m54fmoosgtdt4hsmwurbmu4lh5jrklqheamtffp7rcnumetijyd.onion`
- peer host:
  - data dir: `/root/live-b`
  - local addr: `127.0.0.1:21912`
  - onion:
    - `u5o52rzwnpa5ug4j7zlol7sjzfjw5ow5lmnzapvctb3j2rlmdoo3mmad.onion`

Observed runtime behavior before data sync:

- both nodes reached `peer_runtime_state: ready`
- self-check later became unhealthy with normal Tor transport errors
- unlike the failing run, the peer runtime stayed `ready`
- no self-check-driven Arti restart churn happened before contract work

Peer sidecar checkpoints on the peer host using `/root/store-inspect`:

1. after `connect-peer`, before any mirrored content:
   - sidecar opened successfully
2. after mirrored content was stored and after `bbcli get-contracts`:
   - sidecar opened successfully
3. after graceful `bbcli stop` on the peer:
   - `cli-keys` was removed
   - sidecar still opened successfully while the daemon was stopped
4. after starting a new `bbd` on the same peer data dir and unlocking:
   - unlock succeeded
   - sidecar still opened successfully

The earlier live error:

- `recovery required: peer sidecar is invalid`

did not reproduce after the self-check restart fix.

Full recovery scenario:

1. owner uploaded two payloads:
   - `/root/manual-payloads/random-1m.bin`
   - `/root/manual-payloads/source-snapshot.tar`
2. owner connected to peer and proposed the contract
3. peer stored mirrored content successfully
4. owner was stopped
5. a fresh owner daemon was started in `/root/live-a-recover` on
   `127.0.0.1:23911`
6. fresh owner was initialized and unlocked with the same seed
7. before reconnecting to the peer:
   - `list-files` was empty
   - `recover-content` reported:
     - `recovered=false`
     - `peers_with_latest=0`
8. after reconnecting to the peer:
   - `recover-content` reported:
     - `most_recent_length=1867776`
     - `peers_with_latest=1`
     - `recoverable_length=1867776`
     - `downloaded_bytes=1867776`
     - `recovered=true`
9. recovered files were downloaded and hashed:
   - recovered `random-1m.bin` hash matched the original
   - recovered `source-snapshot.tar` hash matched the original

Recovered file hashes:

- `d21a336e2455de7b76dd8e37610225cf338b93eadedd0081520da711f6385c64`
  `random-1m.bin`
- `01c7828d1e2e4f07310fbec59dc32960b283970fcf9e87e713c365df47f8f29e`
  `source-snapshot.tar`

Conclusion from the follow-up run:

- the earlier live first-contact/restart instability was tied to aggressive
  self-check-driven peer runtime restarts before the node had ever observed a
  healthy self-check
- once that restart policy was fixed, the previously failing peer stop/restart
  and full cross-host recovery scenario succeeded end to end

## End state of this run

- Remote builds succeeded on both hosts.
- Live owner upload and peer backup succeeded after one retry.
- Graceful stop cleaned up the ephemeral CLI keys as intended.
- Full end-to-end live recovery was blocked by the restart unlock failure on
  the peer node.
