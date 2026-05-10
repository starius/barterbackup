package harness

import (
	"testing"

	"barterbackup/integration/docker/gen/clirpc"
)

func TestWaitStatePeerRuntimeReadyIgnoresSelfCheckHealth(t *testing.T) {
	t.Parallel()

	readyButUnhealthy := &clirpc.StateResponse{
		PeerRuntimeState:   clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_READY,
		SelfPeerCheckState: clirpc.SelfPeerCheckState_SELF_PEER_CHECK_STATE_UNHEALTHY,
	}
	if !waitStatePeerRuntimeReady(readyButUnhealthy) {
		t.Fatalf("expected ready peer runtime to satisfy readiness")
	}

	startingButHealthy := &clirpc.StateResponse{
		PeerRuntimeState:   clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_STARTING,
		SelfPeerCheckState: clirpc.SelfPeerCheckState_SELF_PEER_CHECK_STATE_HEALTHY,
	}
	if waitStatePeerRuntimeReady(startingButHealthy) {
		t.Fatalf("expected non-ready peer runtime to block readiness")
	}
}
