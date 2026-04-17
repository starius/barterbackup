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
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.Unlock(ctx); err != nil {
		t.Fatalf("unlock %s: %v", node.Name(), err)
	}
	state, err := node.WaitForReady(ctx)
	if err != nil {
		t.Fatalf("wait for ready on %s: %v", node.Name(), err)
	}
	return state
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
