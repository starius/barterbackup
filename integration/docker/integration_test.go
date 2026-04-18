package integration

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"barterbackup/integration/docker/gen/clirpc"
	"barterbackup/integration/docker/harness"
)

var testSuite *harness.Suite

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()

	suite, err := harness.PrepareSuite(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare integration suite: %v\n", err)
		os.Exit(1)
	}
	testSuite = suite

	code := m.Run()
	if err := suite.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close integration suite: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func TestDockerNodeLifecycle(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	node := addNode(t, scenario, "node-a", "correct horse battery staple")

	startLockedNode(t, node)
	state := waitForReadyNode(t, node)
	if state.GetStorageInitialized() {
		t.Fatalf("fresh node unexpectedly reports initialized storage")
	}

	initNode(t, node)
	state = unlockAndWaitReady(t, node)
	if !state.GetStorageInitialized() {
		t.Fatalf("unlocked node did not report initialized storage")
	}
	if state.GetServerOnion() == "" {
		t.Fatalf("unlocked node did not report its onion address")
	}

	stopNode(t, node)
	assertCLIKeysRemoved(t, node)

	startLockedNode(t, node)
	waitForReadyNode(t, node)
	state = unlockAndWaitReady(t, node)
	if state.GetServerOnion() == "" {
		t.Fatalf("restarted node did not report its onion address")
	}
	stopNode(t, node)
	assertCLIKeysRemoved(t, node)
}

func TestDockerBackupAndRecoveryOverChutney(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	recovered := addNode(t, scenario, "recovered", "correct horse battery staple")

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(512 * 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	stopNode(t, owner)

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	initNode(t, recovered)
	unlockAndWaitReady(t, recovered)
	assertNoFiles(t, recovered)

	connectPeer(t, recovered, peerOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", payload)
}

func TestDockerBackupPeerRestartAndRecover(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	recovered := addNode(t, scenario, "recovered", "correct horse battery staple")

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(384 * 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	stopNode(t, peer)
	assertCLIKeysRemoved(t, peer)
	startLockedNode(t, peer)
	waitForReadyNode(t, peer)
	unlockAndWaitReady(t, peer)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	stopNode(t, owner)

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	initNode(t, recovered)
	unlockAndWaitReady(t, recovered)
	assertNoFiles(t, recovered)

	connectPeer(t, recovered, peerOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", payload)
}

func TestDockerLogicalClockDrivesMaintenance(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addTestClockNode(t, scenario, "owner", "correct horse battery staple")
	peer := addTestClockNode(t, scenario, "peer", "peer password")

	startLockedNode(t, owner)
	waitForReadyNode(t, owner)
	setNodeTime(t, owner, 1000, 0)
	initNode(t, owner)

	startLockedNode(t, peer)
	waitForReadyNode(t, peer)
	setNodeTime(t, peer, 1000, 0)
	initNode(t, peer)
	unlockNode(t, owner)
	unlockNode(t, peer)
	readyStates := waitForTestClockNodesReady(t, owner, peer)
	ownerOnion := readyStates[0].GetServerOnion()
	peerOnion := readyStates[1].GetServerOnion()

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payloadV1 := randomPayload(128 * 1024)
	setFile(t, owner, "payload.bin", payloadV1)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payloadV1)))

	currentTime := getNodeTime(t, owner)
	stream := openTimerIntercept(t, owner, "maintenance.interval")
	defer func() {
		if err := stream.Close(); err != nil {
			t.Fatalf("close timer intercept: %v", err)
		}
	}()
	first := recvTimerEventAtOrAfter(t, stream, currentTime.GetUnixSeconds())
	if first.GetLabel() != "maintenance.interval" {
		t.Fatalf("unexpected timer label: %s", first.GetLabel())
	}

	payloadV2 := randomPayload(256 * 1024)
	advanceNodeTime(t, owner, 60, 0)
	advanceNodeTime(t, peer, 60, 0)
	second := recvTimerEventAtOrAfter(t, stream, first.GetRegisteredUnixSeconds()+60)
	if second.GetRegisteredUnixSeconds() < first.GetRegisteredUnixSeconds()+60 {
		t.Fatalf(
			"unexpected second maintenance registration time: got %d, want at least %d",
			second.GetRegisteredUnixSeconds(),
			first.GetRegisteredUnixSeconds()+60,
		)
	}
	setFile(t, owner, "payload.bin", payloadV2)

	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	peerInfo, err := peer.Peers(ctx)
	if err != nil {
		t.Fatalf("get peer inventory from peer: %v", err)
	}
	for _, info := range peerInfo.GetPeers() {
		if info.GetPeer().GetOnionServiceId() == ownerOnion && info.StoredContentBytes >= int64(len(payloadV2)) {
			t.Fatalf("peer stored the larger payload before the owner maintenance interval advanced")
		}
	}

	advanceNodeTime(t, owner, 60, 0)
	advanceNodeTime(t, peer, 60, 0)
	next := recvTimerEventAtOrAfter(t, stream, second.GetRegisteredUnixSeconds()+60)
	if next.GetLabel() != "maintenance.interval" {
		t.Fatalf("unexpected timer label after advance: %s", next.GetLabel())
	}
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payloadV2)))
}

func newScenario(t *testing.T) *harness.Scenario {
	t.Helper()
	scenario, err := testSuite.NewScenario(t)
	if err != nil {
		t.Fatalf("create scenario: %v", err)
	}
	return scenario
}

func addNode(t *testing.T, scenario *harness.Scenario, name string, password string) *harness.Node {
	t.Helper()
	node, err := scenario.AddNode(name, password)
	if err != nil {
		t.Fatalf("add node %s: %v", name, err)
	}
	return node
}

func addTestClockNode(t *testing.T, scenario *harness.Scenario, name string, password string) *harness.Node {
	t.Helper()
	node := addNode(t, scenario, name, password)
	node.EnableTestClock()
	return node
}

func startLockedNode(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.StartLocked(ctx); err != nil {
		t.Fatalf("start locked node %s: %v", node.Name(), err)
	}
}

func waitForReadyNode(t *testing.T, node *harness.Node) *clirpc.StateResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	state, err := node.WaitForState(ctx)
	if err != nil {
		t.Fatalf("wait for state on %s: %v", node.Name(), err)
	}
	return state
}

func startInitializedReadyNode(t *testing.T, node *harness.Node) string {
	t.Helper()
	startLockedNode(t, node)
	waitForReadyNode(t, node)
	initNode(t, node)
	state := unlockAndWaitReady(t, node)
	return state.GetServerOnion()
}

func initNode(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.Init(ctx); err != nil {
		t.Fatalf("init %s: %v", node.Name(), err)
	}
}

func unlockAndWaitReady(t *testing.T, node *harness.Node) *clirpc.StateResponse {
	t.Helper()
	unlockNode(t, node)
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	state, err := node.WaitForReady(ctx)
	if err != nil {
		t.Fatalf("wait for ready on %s: %v", node.Name(), err)
	}
	return state
}

func unlockNode(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.Unlock(ctx); err != nil {
		t.Fatalf("unlock %s: %v", node.Name(), err)
	}
}

func waitForTestClockNodesReady(
	t *testing.T,
	nodes ...*harness.Node,
) []*clirpc.StateResponse {
	t.Helper()
	deadline := time.Now().Add(harnessDefaultTimeout())

	for {
		states := make([]*clirpc.StateResponse, len(nodes))
		allReady := true
		for index, node := range nodes {
			ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
			state, err := node.WaitForState(ctx)
			cancel()
			if err != nil {
				t.Fatalf("wait for state on %s: %v", node.Name(), err)
			}
			states[index] = state
			if state.GetPeerRuntimeState() == clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_FAILED {
				t.Fatalf("peer runtime failed on %s: %s", node.Name(), state.GetPeerRuntimeError())
			}
			if state.GetPeerRuntimeState() != clirpc.PeerRuntimeState_PEER_RUNTIME_STATE_READY {
				allReady = false
			}
		}
		if allReady {
			return states
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for test-clock nodes to become ready")
		}
		for _, node := range nodes {
			advanceNodeTime(t, node, 5, 0)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func connectPeer(t *testing.T, node *harness.Node, peerOnion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.ConnectPeer(ctx, peerOnion); err != nil {
		t.Fatalf("connect %s to %s: %v", node.Name(), peerOnion, err)
	}
}

func setFile(t *testing.T, node *harness.Node, name string, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.SetFile(ctx, name, payload); err != nil {
		t.Fatalf("set file %s on %s: %v", name, node.Name(), err)
	}
}

func proposeContract(t *testing.T, node *harness.Node, peerOnion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	update, err := node.ProposeContractUntilSuccess(ctx, peerOnion)
	if err != nil {
		t.Fatalf("propose contract from %s to %s: %v", node.Name(), peerOnion, err)
	}
	if !update.GetSuccess() {
		t.Fatalf("proposal from %s to %s did not succeed", node.Name(), peerOnion)
	}
}

func waitForPeerStorage(t *testing.T, node *harness.Node, peerOnion string, expectedBytes int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if _, err := node.WaitForPeerStorage(ctx, peerOnion, expectedBytes); err != nil {
		t.Fatalf("wait for peer storage on %s for %s: %v", node.Name(), peerOnion, err)
	}
}

func stopNode(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.Stop(ctx); err != nil {
		t.Fatalf("stop %s: %v", node.Name(), err)
	}
}

func advanceNodeTime(t *testing.T, node *harness.Node, seconds uint64, nanoseconds uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if _, err := node.AdvanceTestTime(ctx, seconds, nanoseconds); err != nil {
		t.Fatalf("advance test time on %s: %v", node.Name(), err)
	}
}

func setNodeTime(t *testing.T, node *harness.Node, seconds uint64, nanoseconds uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if _, err := node.SetTestTime(ctx, seconds, nanoseconds); err != nil {
		t.Fatalf("set test time on %s: %v", node.Name(), err)
	}
}

func getNodeTime(t *testing.T, node *harness.Node) *clirpc.GetTestTimeResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.GetTestTime(ctx)
	if err != nil {
		t.Fatalf("get test time on %s: %v", node.Name(), err)
	}
	return response
}

func openTimerIntercept(t *testing.T, node *harness.Node, label string) *harness.TimerInterceptStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	stream, err := node.TimerIntercept(ctx, label)
	if err != nil {
		t.Fatalf("open timer intercept %s on %s: %v", label, node.Name(), err)
	}
	return stream
}

func recvTimerEvent(t *testing.T, stream *harness.TimerInterceptStream) *clirpc.TimerInterceptEvent {
	t.Helper()
	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive timer intercept event: %v", err)
	}
	return event
}

func recvTimerEventAtOrAfter(
	t *testing.T,
	stream *harness.TimerInterceptStream,
	minRegisteredSeconds uint64,
) *clirpc.TimerInterceptEvent {
	t.Helper()
	for {
		event := recvTimerEvent(t, stream)
		if event.GetRegisteredUnixSeconds() >= minRegisteredSeconds {
			return event
		}
	}
}

func assertCLIKeysRemoved(t *testing.T, node *harness.Node) {
	t.Helper()
	for _, name := range []string{"server.pub", "client.key"} {
		path := filepath.Join(node.DataDir(), "cli-keys", name)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed after stop, got %v", path, err)
		}
	}
}

func assertNoFiles(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.ListFiles(ctx)
	if err != nil {
		t.Fatalf("list files on %s: %v", node.Name(), err)
	}
	if len(response.GetName()) != 0 {
		t.Fatalf("expected %s to start empty, got %v", node.Name(), response.GetName())
	}
}

func recoverContent(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	update, err := node.RecoverContentUntilRecovered(ctx)
	if err != nil {
		t.Fatalf("recover content on %s: %v", node.Name(), err)
	}
	if !update.GetRecoveredMostRecentVersion() {
		t.Fatalf(
			"recovery on %s did not recover most recent version: peers_with_latest=%d total_versions=%d",
			node.Name(),
			update.GetNumPeersWithMostRecentVersion(),
			update.GetTotalVersionsFound(),
		)
	}
}

func assertFileEquals(t *testing.T, node *harness.Node, name string, expected []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	file, err := node.GetFile(ctx, name)
	if err != nil {
		t.Fatalf("get file %s from %s: %v", name, node.Name(), err)
	}
	if !bytes.Equal(file.GetData(), expected) {
		t.Fatalf("recovered file %s from %s does not match original bytes", name, node.Name())
	}
	response, err := node.ListFiles(ctx)
	if err != nil {
		t.Fatalf("list files on %s after recovery: %v", node.Name(), err)
	}
	if len(response.GetName()) != 1 || response.GetName()[0] != name {
		t.Fatalf("unexpected recovered file list on %s: %v", node.Name(), response.GetName())
	}
}

func randomPayload(length int) []byte {
	payload := make([]byte, length)
	rng := rand.New(rand.NewSource(int64(length)))
	if _, err := rng.Read(payload); err != nil {
		panic(err)
	}
	return payload
}

func harnessDefaultTimeout() time.Duration {
	if value := os.Getenv("BB_DOCKER_TEST_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err == nil && parsed > 0 {
			return parsed
		}
	}
	return 15 * time.Minute
}
