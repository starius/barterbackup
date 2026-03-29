# Open Questions (Round 2)

1. Fresh-node bootstrap

The current Rust code can recover after restart when the data directory still
contains persisted peer metadata. A completely fresh machine started with only
the same seed still needs at least one reachable peer address before recovery
can begin.

We need a product decision for that bootstrap step. Plausible directions are:

- require the operator to provide one or more peer onion IDs manually;
- derive or persist a small bootstrap contact list outside the encrypted data
  directory;
- add a separate discovery mechanism.

This does not block the current implementation, but it does block the literal
"download the binary, run it with the same seed, and recover" story unless the
operator also has some bootstrap peer information.

2. Local `clirpc` mTLS key lifecycle

The current Rust daemon generates fresh local admin TLS keys on every start.
That avoids any dependency on the main seed/password, but it also means the
local CLI credentials are not stable across restarts.

An alternative worth considering is to persist and reuse the local admin keys
across daemon restarts while still keeping them independent from the main
seed/password. That would improve automation and operator experience, but it
needs a product decision about where the long-lived admin client key should
live.

The main directions are:

- persist both the local admin server key and client key on the host;
- persist only the server key on the host and keep the client key local to the
  operator machine.

This is not decided yet.
