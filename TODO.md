BarterBackup (Rust) - Open work

These items are grouped by practical product priority.

## Should do soon

- Add deferred batching for low-value peer metadata writes such as
  reachability updates and liveness-score changes. Those fields are useful,
  but they should not force an encrypted metadata rewrite on every small
  update when a short configurable flush delay would preserve SSD life and
  battery.

## Polish later

- Investigate switching the container and integration-test runtime back to
  `scratch` by resolving the current `fs-mistrust` passwd/group dependency.
  Private-network Tor tests currently need a fuller base image even though the
  binaries themselves are static.
