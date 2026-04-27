BarterBackup (Rust) - Open work

These items are grouped by practical product priority.

## Polish later

- Investigate switching the container and integration-test runtime back to
  `scratch` by resolving the current `fs-mistrust` passwd/group dependency.
  Private-network Tor tests currently need a fuller base image even though the
  binaries themselves are static.
