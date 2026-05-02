package harness

import (
	"testing"

	"barterbackup/integration/docker/gen/clirpc"
)

func TestWaitStateReadyAndReachableRequiresHealthySelfCheck(t *testing.T) {
	t.Parallel()

	readyButUnhealthy := &clirpc.StateResponse{
		PeerRuntimeState:   clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_READY,
		SelfPeerCheckState: clirpc.SelfPeerCheckState_SELF_PEER_CHECK_STATE_UNHEALTHY,
	}
	if waitStateReadyAndReachable(readyButUnhealthy) {
		t.Fatalf("expected unhealthy self-check to block readiness")
	}

	readyAndHealthy := &clirpc.StateResponse{
		PeerRuntimeState:   clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_READY,
		SelfPeerCheckState: clirpc.SelfPeerCheckState_SELF_PEER_CHECK_STATE_HEALTHY,
	}
	if !waitStateReadyAndReachable(readyAndHealthy) {
		t.Fatalf("expected healthy self-check to satisfy readiness")
	}
}
