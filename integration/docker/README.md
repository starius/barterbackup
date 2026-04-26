# Docker Integration Harness

This directory contains the Go end-to-end integration harness for
BarterBackup.

It runs real `bbd` daemons in Docker containers and talks to their local
`clirpc` endpoints directly. Peer traffic goes through a private Chutney Tor
network in the fast lane, and there is also a separate public-Tor smoke lane.
Together they exercise Arti, onion services, gRPC, TLS, and recovery.

## Run

From the repository root:

```bash
nix develop --command make integration-test-docker
nix develop --command make integration-test-docker-tor-smoke
```

`make integration-test-docker`:

- builds static Linux binaries for `bbd` and `bbcli`
- regenerates the Go `clirpc` stubs with `make rpc`
- runs `go test ./...` in this module against the private Chutney network

`make integration-test-docker-tor-smoke`:

- builds the same static binaries
- regenerates the Go `clirpc` stubs
- runs `TestDockerRealTorRecoverySmoke` against public Tor

If Docker is not already running on the machine, start `dockerd` from the dev
shell in a separate terminal:

```bash
nix develop --command sh -lc '
  mkdir -p /tmp/barterbackup-dockerd
  dockerd \
    --host unix:///tmp/barterbackup-docker.sock \
    --data-root /tmp/barterbackup-dockerd/data \
    --exec-root /tmp/barterbackup-dockerd/exec \
    --pidfile /tmp/barterbackup-dockerd/dockerd.pid
'
```

Then point the test shell at that socket:

```bash
export DOCKER_HOST=unix:///tmp/barterbackup-docker.sock
nix develop --command make integration-test-docker
```

## Runtime Layout

The harness keeps its runtime state outside the repository. By default it uses:

```text
/tmp/barterbackup-integration
```

You can override that with:

```bash
BB_DOCKER_TEST_WORKDIR=/path/to/workdir
```

Each test scenario gets its own temporary directory under that work root. The
layout looks like this:

```text
<workdir>/testdockerbackupandrecoveryoverchutney-1234567890/
  logs/
    owner.log
    peer.log
    recovered.log
  owner/
  peer/
  recovered/
```

The `logs/` directory contains `docker logs` output for each test node.

## Keeping Artifacts

By default, successful scenarios are deleted at the end of the test.
Failed scenarios are kept.

To keep artifacts even on success, set:

```bash
BB_KEEP_INTEGRATION_ARTIFACTS=1
```

Example:

```bash
nix develop --command env \
  BB_KEEP_INTEGRATION_ARTIFACTS=1 \
  make integration-test-docker
```

## Timeouts And Debugging

The Go integration package uses the normal `go test` timeout. The default is
10 minutes, which is often too short when you are debugging a slow or stuck
scenario.

If you see:

```text
panic: test timed out after 10m0s
```

rerun with a larger timeout and a fixed work directory:

```bash
nix develop --command bash -lc '
  export BB_DOCKER_TEST_WORKDIR=/tmp/barterbackup-integration-debug
  export BB_KEEP_INTEGRATION_ARTIFACTS=1
  cd integration/docker
  go test -v -timeout 30m ./...
'
```

Important detail:

- if the test fails normally, the harness cleanup runs and writes per-node logs
  into `<workdir>/<scenario>/logs/`
- if the whole `go test` process is terminated by the package timeout panic,
  cleanup may not finish, so those copied log files might be missing

In that timeout case, inspect the live containers directly:

```bash
docker ps -a --format '{{.Names}}' | grep '^bb-'
docker logs <container-name>
```

The harness names containers like:

```text
bb-<scenario-name>-<node-name>
```

so it is easy to match them to the timed-out test.

## Useful Knobs

- `BB_DOCKER_TEST_WORKDIR`: where scenario directories and Chutney state live
- `BB_KEEP_INTEGRATION_ARTIFACTS=1`: keep scenario directories even on success
- `BB_DOCKER_TEST_PARALLEL=<n>`: limit how many scenarios run in parallel
- `BB_DOCKER_TEST_TIMEOUT=<duration>`: per-operation harness timeout used
  inside the Go tests, separate from the outer `go test -timeout`
- `BB_DOCKER_REAL_TOR=1`: enable the public-Tor smoke test when running the
  Go package directly
