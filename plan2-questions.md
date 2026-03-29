# Open Questions

These are the main design questions that came up while implementing the Rust
rewrite. They do not block the current local encrypted storage and CLI work,
but they do affect the next transport/recovery phases.

1. Should the daemon default to a locked startup model, with `Unlock` creating
   the live node and opening the encrypted store, or should we keep an
   alternate direct-start path for automation and tests?

2. Should encrypted content blob filenames remain hex-encoded for portability,
   or do you want the implementation to move to raw-byte filenames under a
   wrapped filesystem once the full on-disk layout is finalized?

3. For peer identity, do you want the long-term contract and peer metadata to
   key strictly by onion public key, strictly by TLS certificate identity, or
   by a checked relation between both?

4. For the final P2P transport, do you want us to freeze on the first rustls /
   Arti combination that can enforce the desired PQ-hybrid group policy, or do
   you want a fallback compatibility mode if the stack support stays uneven?

5. The scoring model still needs a precise spec. Is the intended penalty on a
   failed check a fixed decrement, a decrement equal to elapsed time since the
   last successful check, or something harsher once a peer repeatedly fails?

6. Recovery still needs a policy for ambiguous top revisions from different
   peers with the same sequence number but different ciphertext. The current
   content design gives deterministic ordering, but we still need a product
   rule for what to trust if peers disagree.
