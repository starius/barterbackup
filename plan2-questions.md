# Open Questions

These are the main design questions that came up while implementing the Rust
rewrite. They do not block the current local encrypted storage and CLI work,
but they do affect the next transport/recovery phases.

1. Should the daemon default to a locked startup model, with `Unlock` creating
   the live node and opening the encrypted store, or should we keep an
   alternate direct-start path for automation and tests?

A:

  - Start bbd in foreground under systemd or tmux.
  - bbd acquires the data-dir lock immediately.
  - bbd exposes only local admin RPC while locked.
  - A separate short-lived command unlocks it:
      - bbcli unlock --password-stdin
  - SSH session ends; daemon keeps running.

Note that bbcli must not show the passord being typed. It must mask input, when
dealing with a real terminal, as `***`.

Note 2. If `bbcli unlock` is called too eatly (before bbd is ready to accept it),
bbcli must wait for bbd to be ready. E.g. if the RPC port is not listened yet
or it returns some status indicating that it is still not ready.

2. Should encrypted content blob filenames remain hex-encoded for portability,
   or do you want the implementation to move to raw-byte filenames under a
   wrapped filesystem once the full on-disk layout is finalized?

I want physical filenames (and file sizes) not to depend on the stored files.
E.g. all the files should be stored in a single encrypted file. So this question
is not really relevant. The physical file name should be something portable,
not depending on its content.

3. For peer identity, do you want the long-term contract and peer metadata to
   key strictly by onion public key, strictly by TLS certificate identity, or
   by a checked relation between both?

I want the same ed25519 key to identify both. Let's use raw ed25519 pubkey bytes
for internal representation and onion ID (without .onion) as string representation
(e.g. when presenting to user in CLI or in the log). We can have a single type
in Rust, having methods to automate this, I guess. Like .String() in Go.

4. For the final P2P transport, do you want us to freeze on the first rustls /
   Arti combination that can enforce the desired PQ-hybrid group policy, or do
   you want a fallback compatibility mode if the stack support stays uneven?

IIUC, PQ key exchange is already implemented, and arti and rustls are already used.
Close the testing gaps. We need some way to test `bbd<->bbd` workings without
a real arti, so they work fast. Test PQ enforcement. Try to inject networking
errors in a test, breaking PQ part of key exchange (manipulate a bit in PQ key),
make sure it breaks.

Additionally:
  - Server TLS accepts any Ed25519 client cert.
  - The app then interprets the cert as node identity.
  - That is coherent with onion-derived identity, but it should be documented as an explicit design decision.

Document that `CLI<->bbd` also uses PQ-hybrid TLS in the current Rust code, but
it is still a local admin interface and should not be exposed directly over an
untrusted network. E.g. use SSH and keep the CLI traffic inside it, or run the
CLI directly on the same machine as bbd.


5. The scoring model still needs a precise spec. Is the intended penalty on a
   failed check a fixed decrement, a decrement equal to elapsed time since the
   last successful check, or something harsher once a peer repeatedly fails?

Let's use a decrement equal to elapsed time. So the same value (time since the
pevious check) is either added or deduced depending on the outcome.

6. Recovery still needs a policy for ambiguous top revisions from different
   peers with the same sequence number but different ciphertext. The current
   content design gives deterministic ordering, but we still need a product
   rule for what to trust if peers disagree.

We should use a timestamp for each revision and it should be seen from the rev ID
after decryption (not in the encrypted form). Just use the latest version.

We should also consider what to do if a later revision is discovered later.
We need to identify such revisions (older than the recovered and not coming from
this node, i.e. potentially missed during initial recovery). We need to log them
in bbd and maybe show a warning in BBCLI when they exist to resolve them. Need some
additional clirpc to do it. Maybe we need to have something like Git branches?
So we could see that there is a revision from a sibling timeline and decide what
to do with it. Anyway, the user must be informed about this, including in CLI,
and be able to switch there or checkout that state somewhere to look at it and
decide which "branch" stays.

7. Ideally if you do not focus too much on the remote server in commits and docs.
   This is an artifact of our local development. It is not of interest for Git
   history or other devs. Keep using the remote server, though.

8. Some people's ISP block Tor and they need to use Tor pluggable transports. How
   they could use bbd? Can arti use the transports already? Can we support
   external Tor as an option? Can we run the external Tor ourselves, passing
   transports? Another option: if someone already has an external Tor, give him
   hidden service's private key and config and instructions to use it with bbd.
   This needs discussion.
