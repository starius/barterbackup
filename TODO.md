BarterBackup (Rust) - Open work

These items are grouped by practical product priority.

## Must do before real users

- Decide where the configurable local-content size limit belongs and what the
  default policy should be. `bbcli file set` should reject changes that exceed
  that limit once the content-size config is added.
- Finish the remaining operator-facing hardening around observability and
  resource controls. Structured peer logs, peer I/O bounds, timeout handling,
  dedicated fuzz targets, and clearer CLI peer summaries are now in place, but
  the daemon still needs a final decision on any future chunking or other
  operator-facing resource ceilings beyond the current peer cap.
- Extend storage accounting beyond the fixed 1 GiB peer budget and current
  score-tier policy. Expiration policy, historical visibility, and richer
  operator reporting for mirrored peer storage are still basic.

## Should do soon

- Decide how external Tor and pluggable transports fit into the final product.
  The current implementation uses in-process Arti. Supporting users whose ISPs
  block Tor still needs a product decision and implementation path, including
  whether to support external Tor, pluggable transports, or operator-managed
  hidden-service keys.
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
