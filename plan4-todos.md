Plan 4 follow-up

1. The ignored `live_tor_recovery_round_trip` test is in place, but I did not
observe a full successful end-to-end completion on `barterbackup-dev`.

The run progressed past Arti bootstrap once the remote workspace ownership was
fixed, opened live Tor network connections, and then remained in the initial
A->B contract proposal phase until the expanded manual-test timeout budget was
exhausted. The recreated-node recovery phase was never reached in that public
Tor run.

This now looks like an environment and timing problem around cold public-Tor
hidden-service publication or rendezvous on the throwaway builder, not a local
configuration bug in the Rust code. It needs a longer-lived public-Tor soak
run, a builder with prewarmed Tor state, or a separate manual validation setup
that is allowed to sit longer than the current remote test budget.
