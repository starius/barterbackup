package integration

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"barterbackup/integration/docker/gen/clirpc"
	"barterbackup/integration/docker/harness"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

var (
	chutneySuite     *harness.Suite
	chutneySuiteErr  error
	chutneySuiteOnce sync.Once

	publicTorSuite     *harness.Suite
	publicTorSuiteErr  error
	publicTorSuiteOnce sync.Once
)

type conflictScenario struct {
	scenario   *harness.Scenario
	owner      *harness.Node
	peerB      *harness.Node
	peerC      *harness.Node
	recovered  *harness.Node
	ownerOnion string
	peerBOnion string
	peerCOnion string
	payloadV1  []byte
	payloadV2  []byte
}

func TestMain(m *testing.M) {
	code := m.Run()
	if chutneySuite != nil {
		if err := chutneySuite.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close Chutney integration suite: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	if publicTorSuite != nil {
		if err := publicTorSuite.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close public-Tor integration suite: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func chutneyHarnessSuite(t *testing.T) *harness.Suite {
	t.Helper()
	chutneySuiteOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
		defer cancel()
		chutneySuite, chutneySuiteErr = harness.PrepareChutneySuite(ctx)
	})
	if chutneySuiteErr != nil {
		t.Fatalf("prepare Chutney integration suite: %v", chutneySuiteErr)
	}
	return chutneySuite
}

func publicTorHarnessSuite(t *testing.T) *harness.Suite {
	t.Helper()
	publicTorSuiteOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
		defer cancel()
		publicTorSuite, publicTorSuiteErr = harness.PreparePublicTorSuite(ctx)
	})
	if publicTorSuiteErr != nil {
		t.Fatalf("prepare public-Tor integration suite: %v", publicTorSuiteErr)
	}
	return publicTorSuite
}

func requireRealTorSmoke(t *testing.T) {
	t.Helper()
	if os.Getenv("BB_DOCKER_REAL_TOR") == "" {
		t.Skip("set BB_DOCKER_REAL_TOR=1 to run public-Tor Docker smoke tests")
	}
}

func TestDockerRealTorRecoverySmoke(t *testing.T) {
	requireRealTorSmoke(t)

	scenario := newPublicTorScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	recovered := addNode(t, scenario, "recovered", "correct horse battery staple")
	owner.DisableMaintenance()
	peer.DisableMaintenance()
	recovered.DisableMaintenance()

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(256 * 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	stopNode(t, owner)
	assertCLIKeysRemoved(t, owner)

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	initNode(t, recovered)
	unlockAndWaitReady(t, recovered)
	assertNoFiles(t, recovered)

	connectPeer(t, recovered, peerOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", payload)
}

func TestDockerLogicalClockAccumulatesLongTermPeerScore(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addTestClockNode(t, scenario, "owner", "correct horse battery staple")
	peer := addTestClockNode(t, scenario, "peer", "peer password")

	ownerOnion := startInitializedReadyTestClockNode(t, owner, 1000)
	peerOnion := startInitializedReadyTestClockNode(t, peer, 1000)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(96 * 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	checkContract(t, owner, peerOnion)
	waitForPeerScoreSeconds(t, owner, peerOnion, 0)

	const thirtyDays = 30 * 24 * 60 * 60

	advanceNodeTime(t, owner, thirtyDays, 0)
	advanceNodeTime(t, peer, thirtyDays, 0)
	checkContract(t, owner, peerOnion)
	waitForPeerScoreSeconds(t, owner, peerOnion, thirtyDays)

	advanceNodeTime(t, owner, thirtyDays, 0)
	advanceNodeTime(t, peer, thirtyDays, 0)
	checkContract(t, owner, peerOnion)
	waitForPeerScoreSeconds(t, owner, peerOnion, 2*thirtyDays)
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
	owner.DisableMaintenance()
	peer.DisableMaintenance()
	recovered.DisableMaintenance()

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
	owner.DisableMaintenance()
	peer.DisableMaintenance()
	recovered.DisableMaintenance()

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

func TestDockerConflictRecoveryKeepRemoteVersion(t *testing.T) {
	scenario := prepareConflictScenarioBase(t)
	localBranch := bytes.Repeat([]byte("local-branch\n"), 1536)

	advanceNodeTime(t, scenario.recovered, 10, 0)
	setFile(t, scenario.recovered, "payload.bin", localBranch)
	startLockedNode(t, scenario.peerC)
	waitForReadyNode(t, scenario.peerC)
	setNodeTime(t, scenario.peerC, 1040, 0)
	unlockTestClockAndWaitReady(t, scenario.peerC)
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(scenario.payloadV2)))
	connectPeer(t, scenario.recovered, scenario.peerCOnion)

	conflicts := waitForConflict(t, scenario.recovered)
	assertConflictBlocksFileOps(t, scenario.recovered)
	localRevision := findConflictRevision(
		t,
		conflicts,
		func(revision *clirpc.ConflictRevisionInfo) bool { return revision.GetSourceIsLocal() },
		"local conflicted revision",
	)
	remoteRevision := findConflictRevision(
		t,
		conflicts,
		func(revision *clirpc.ConflictRevisionInfo) bool {
			return revision.GetSourcePeerOnion() == scenario.peerCOnion
		},
		"remote conflicted revision",
	)
	assertCheckedOutRevision(t, scenario.recovered, localRevision.GetContentId(), "payload.bin", localBranch)
	assertCheckedOutRevision(
		t,
		scenario.recovered,
		remoteRevision.GetContentId(),
		"payload.bin",
		scenario.payloadV2,
	)

	resolveConflict(t, scenario.recovered, remoteRevision.GetContentId())
	assertFileEquals(t, scenario.recovered, "payload.bin", scenario.payloadV2)
	archived := listConflicts(t, scenario.recovered)
	assertSingleArchivedRevision(t, archived, localRevision.GetContentId())

	startLockedNode(t, scenario.peerB)
	waitForReadyNode(t, scenario.peerB)
	setNodeTime(t, scenario.peerB, 1050, 0)
	unlockTestClockAndWaitReady(t, scenario.peerB)
	postResolve := bytes.Repeat([]byte("post-resolve-remote\n"), 2048)
	advanceNodeTime(t, scenario.recovered, 10, 0)
	setFile(t, scenario.recovered, "payload.bin", postResolve)
	proposeContract(t, scenario.recovered, scenario.peerBOnion)
	proposeContract(t, scenario.recovered, scenario.peerCOnion)
	waitForPeerStorage(t, scenario.peerB, scenario.ownerOnion, int64(len(postResolve)))
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(postResolve)))
	assertCheckedOutRevision(t, scenario.recovered, localRevision.GetContentId(), "payload.bin", localBranch)
}

func TestDockerConflictRecoveryKeepLocalVersion(t *testing.T) {
	scenario := prepareConflictScenarioBase(t)
	localBranch := bytes.Repeat([]byte("local-kept-branch\n"), 1792)

	advanceNodeTime(t, scenario.recovered, 10, 0)
	setFile(t, scenario.recovered, "payload.bin", localBranch)
	startLockedNode(t, scenario.peerC)
	waitForReadyNode(t, scenario.peerC)
	setNodeTime(t, scenario.peerC, 1040, 0)
	unlockTestClockAndWaitReady(t, scenario.peerC)
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(scenario.payloadV2)))
	connectPeer(t, scenario.recovered, scenario.peerCOnion)

	conflicts := waitForConflict(t, scenario.recovered)
	assertConflictBlocksFileOps(t, scenario.recovered)
	localRevision := findConflictRevision(
		t,
		conflicts,
		func(revision *clirpc.ConflictRevisionInfo) bool { return revision.GetSourceIsLocal() },
		"local conflicted revision",
	)
	remoteRevision := findConflictRevision(
		t,
		conflicts,
		func(revision *clirpc.ConflictRevisionInfo) bool {
			return revision.GetSourcePeerOnion() == scenario.peerCOnion
		},
		"remote conflicted revision",
	)
	assertCheckedOutRevision(t, scenario.recovered, localRevision.GetContentId(), "payload.bin", localBranch)
	assertCheckedOutRevision(
		t,
		scenario.recovered,
		remoteRevision.GetContentId(),
		"payload.bin",
		scenario.payloadV2,
	)

	resolveConflict(t, scenario.recovered, localRevision.GetContentId())
	assertFileEquals(t, scenario.recovered, "payload.bin", localBranch)
	archived := listConflicts(t, scenario.recovered)
	assertSingleArchivedRevision(t, archived, remoteRevision.GetContentId())

	startLockedNode(t, scenario.peerB)
	waitForReadyNode(t, scenario.peerB)
	setNodeTime(t, scenario.peerB, 1050, 0)
	unlockTestClockAndWaitReady(t, scenario.peerB)
	postResolve := bytes.Repeat([]byte("post-resolve-local\n"), 2304)
	advanceNodeTime(t, scenario.recovered, 10, 0)
	setFile(t, scenario.recovered, "payload.bin", postResolve)
	proposeContract(t, scenario.recovered, scenario.peerBOnion)
	proposeContract(t, scenario.recovered, scenario.peerCOnion)
	waitForPeerStorage(t, scenario.peerB, scenario.ownerOnion, int64(len(postResolve)))
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(postResolve)))
	assertCheckedOutRevision(
		t,
		scenario.recovered,
		remoteRevision.GetContentId(),
		"payload.bin",
		scenario.payloadV2,
	)
}

func TestDockerMetadataOnlyRecoveryAutoResolves(t *testing.T) {
	scenario := prepareConflictScenarioBase(t)
	metadataPeer := addConflictNode(t, scenario.scenario, "metadata-peer", "metadata peer password")
	metadataPeerOnion := startInitializedReadyTestClockNode(t, metadataPeer, 1040)

	connectPeer(t, scenario.recovered, metadataPeerOnion)
	assertPeerVisible(t, scenario.recovered, metadataPeerOnion)

	startLockedNode(t, scenario.peerC)
	waitForReadyNode(t, scenario.peerC)
	setNodeTime(t, scenario.peerC, 1050, 0)
	unlockTestClockAndWaitReady(t, scenario.peerC)
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(scenario.payloadV2)))
	connectPeer(t, scenario.recovered, scenario.peerCOnion)

	recoverContent(t, scenario.recovered)
	assertFileEquals(t, scenario.recovered, "payload.bin", scenario.payloadV2)
	assertNoActiveConflict(t, scenario.recovered)
	assertPeerVisible(t, scenario.recovered, scenario.peerCOnion)
	assertPeerAbsent(t, scenario.recovered, metadataPeerOnion)

	startLockedNode(t, scenario.peerB)
	waitForReadyNode(t, scenario.peerB)
	setNodeTime(t, scenario.peerB, 1060, 0)
	unlockTestClockAndWaitReady(t, scenario.peerB)
	postResolve := bytes.Repeat([]byte("metadata-auto-resolved\n"), 1408)
	advanceNodeTime(t, scenario.recovered, 10, 0)
	setFile(t, scenario.recovered, "payload.bin", postResolve)
	proposeContract(t, scenario.recovered, scenario.peerBOnion)
	proposeContract(t, scenario.recovered, scenario.peerCOnion)
	waitForPeerStorage(t, scenario.peerB, scenario.ownerOnion, int64(len(postResolve)))
	waitForPeerStorage(t, scenario.peerC, scenario.ownerOnion, int64(len(postResolve)))
}

func TestDockerPeerExchangeGossip(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	nodeA := addNode(t, scenario, "node-a", "correct horse battery staple")
	nodeB := addNode(t, scenario, "node-b", "node-b password")
	nodeC := addNode(t, scenario, "node-c", "node-c password")

	nodeAOnion := startInitializedReadyNode(t, nodeA)
	nodeBOnion := startInitializedReadyNode(t, nodeB)
	nodeCOnion := startInitializedReadyNode(t, nodeC)

	connectPeer(t, nodeA, nodeBOnion)
	connectPeer(t, nodeB, nodeAOnion)
	connectPeer(t, nodeB, nodeCOnion)
	connectPeer(t, nodeB, nodeCOnion)

	setFile(t, nodeA, "gossip.txt", []byte("gossip-seed"))
	proposeContract(t, nodeA, nodeBOnion)

	waitForPeerVisible(t, nodeA, nodeCOnion)
	peers := getPeers(t, nodeA)
	assertPeerInventoryContainsOnce(t, peers, nodeBOnion, nodeCOnion)
	assertPeerAbsentFromInventory(t, peers, nodeAOnion)
}

func TestDockerOfflinePeerPenalizedOnCheck(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(160 * 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))

	time.Sleep(2 * time.Second)
	initialCheck := checkContractOnce(t, owner, peerOnion)
	if !initialCheck.GetSuccess() {
		t.Fatalf("expected initial contract check to succeed, got %+v", initialCheck)
	}
	previousScore := peerScoreSeconds(t, owner, peerOnion)
	if previousScore <= 0 {
		t.Fatalf("expected positive peer score after a successful check, got %d", previousScore)
	}

	stopNode(t, peer)
	assertCLIKeysRemoved(t, peer)
	time.Sleep(2 * time.Second)

	failedCheck := checkContractOnce(t, owner, peerOnion)
	if failedCheck.GetSuccess() {
		t.Fatalf("expected offline contract check to fail, got %+v", failedCheck)
	}
	if failedCheck.GetState() != clirpc.ContractState_PEER_UNAVAILABLE {
		t.Fatalf("expected peer-unavailable state, got %s", failedCheck.GetState().String())
	}

	waitForPeerStatus(t, owner, peerOnion, clirpc.PeerStatus_PEER_STATUS_OFFLINE)
	peerInfo := waitForPeerInfo(
		t,
		owner,
		peerOnion,
		"offline peer failure context",
		func(info *clirpc.PeerInfo) bool {
			return info.GetLastErrorClass() == clirpc.PeerFailureClass_PEER_FAILURE_CLASS_TRANSPORT &&
				info.GetLastFailureAt() > 0 &&
				strings.Contains(info.GetLastErrorMessage(), "transport error")
		},
	)
	if peerInfo.GetConsecutiveFailures() != 0 {
		t.Fatalf("expected manual check failure not to publish background retry streak, got %d", peerInfo.GetConsecutiveFailures())
	}
	currentScore := peerScoreSeconds(t, owner, peerOnion)
	if currentScore >= previousScore {
		t.Fatalf("expected offline check to reduce score, got before=%d after=%d", previousScore, currentScore)
	}
	time.Sleep(time.Second)
	if peerScoreSeconds(t, owner, peerOnion) != currentScore {
		t.Fatalf("peer score changed again without another logical check")
	}
	assertContractOnlineState(t, owner, peerOnion, false)
}

func TestDockerRetryAfterTransientDisconnect(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	recovered := addNode(t, scenario, "recovered", "correct horse battery staple")
	owner.DisableMaintenance()
	peer.DisableMaintenance()
	recovered.DisableMaintenance()

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	initialPayload := randomPayload(96 * 1024)
	setFile(t, owner, "payload.bin", initialPayload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(initialPayload)))

	updatedPayload := randomPayload(224 * 1024)
	setFile(t, owner, "payload.bin", updatedPayload)
	stopNode(t, peer)
	assertCLIKeysRemoved(t, peer)

	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	_, err := owner.ProposeContract(ctx, peerOnion)
	cancel()
	if err == nil {
		t.Fatalf("expected proposal to fail while the peer was offline")
	}

	startLockedNode(t, peer)
	waitForReadyNode(t, peer)
	unlockAndWaitReady(t, peer)

	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(updatedPayload)))

	stopNode(t, owner)
	assertCLIKeysRemoved(t, owner)

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	initNode(t, recovered)
	unlockAndWaitReady(t, recovered)
	connectPeer(t, recovered, peerOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", updatedPayload)
}

func TestDockerResourcePolicyRejectsOversizedPeerContent(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	owner.DisableMaintenance()
	peer.DisableMaintenance()

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	config := getStorageConfig(t, peer)
	policy := config.GetResourcePolicy()
	if policy == nil {
		t.Fatalf("expected resource policy in storage config response")
	}
	if policy.GetMaxPeerContentBytes() <= 0 {
		t.Fatalf("expected positive max peer content bytes, got %d", policy.GetMaxPeerContentBytes())
	}
	if policy.GetChunkingSupported() {
		t.Fatalf("expected chunking to remain disabled")
	}

	targetLength := int(policy.GetMaxPeerContentBytes()) + 1024
	firstChunkLength := targetLength / 2
	secondChunkLength := targetLength - firstChunkLength
	setFile(t, owner, "payload-a.bin", randomPayload(firstChunkLength))
	setFile(t, owner, "payload-b.bin", randomPayload(secondChunkLength))
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	_, err := owner.ProposeContract(ctx, peerOnion)
	cancel()
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected oversized proposal to fail with failed precondition, got %v", err)
	}
	if !strings.Contains(grpcstatus.Convert(err).Message(), "current content exceeds the peer transport limit") {
		t.Fatalf("unexpected oversized proposal message: %v", err)
	}
}

func TestDockerStorageBudgetAndEviction(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	holder := addNode(t, scenario, "holder", "correct horse battery staple")
	bestEffort := addNode(t, scenario, "best-effort", "best-effort password")
	reserved := addNode(t, scenario, "reserved", "reserved password")
	holder.DisableMaintenance()
	bestEffort.DisableMaintenance()
	reserved.DisableMaintenance()

	holderOnion := startInitializedReadyNode(t, holder)
	bestEffortOnion := startInitializedReadyNode(t, bestEffort)
	reservedOnion := startInitializedReadyNode(t, reserved)

	connectPeer(t, holder, bestEffortOnion)
	connectPeer(t, holder, reservedOnion)
	connectPeer(t, bestEffort, holderOnion)
	connectPeer(t, reserved, holderOnion)

	holderSeedPayload := bytes.Repeat([]byte("holder-seed\n"), 256)
	setFile(t, holder, "holder-seed.bin", holderSeedPayload)
	proposeContract(t, holder, reservedOnion)
	bestEffortPayload := bytes.Repeat([]byte("best-effort-payload\n"), 4096)
	setFile(t, bestEffort, "payload.bin", bestEffortPayload)
	proposeContract(t, bestEffort, holderOnion)
	bestEffortInfo := waitForPeerStorageInfo(t, holder, bestEffortOnion, 1)
	bestEffortBudget := bestEffortInfo.GetLatestCachedContentLength()
	if bestEffortBudget <= 0 {
		t.Fatalf("expected best-effort cached length to be positive, got %d", bestEffortBudget)
	}

	if !checkContractOnce(t, holder, reservedOnion).GetSuccess() {
		t.Fatalf("expected reserved peer check to succeed")
	}
	time.Sleep(2 * time.Second)
	if !checkContractOnce(t, holder, reservedOnion).GetSuccess() {
		t.Fatalf("expected repeated reserved peer check to succeed")
	}
	if peerScoreSeconds(t, holder, reservedOnion) <= 0 {
		t.Fatalf("expected reserved peer to gain positive score before storage pressure")
	}

	setStorageBudget(t, holder, bestEffortBudget)
	reservedPayloadV1 := bytes.Repeat([]byte("reserved-v1\n"), 3072)
	setFile(t, reserved, "payload.bin", reservedPayloadV1)
	proposeContract(t, reserved, holderOnion)
	reservedInfo := waitForPeerStorageInfo(t, holder, reservedOnion, 1)
	reservedCachedV1 := reservedInfo.GetLatestCachedContentLength()
	if reservedCachedV1 <= 0 {
		t.Fatalf("expected reserved peer cached length to be positive")
	}

	bestEffortAfterEviction := waitForPeerInfo(
		t,
		holder,
		bestEffortOnion,
		"best-effort cache eviction",
		func(info *clirpc.PeerInfo) bool {
			return info.GetLatestKnownContentLength() > 0 &&
				info.GetLatestCachedContentLength() == 0 &&
				info.GetStaleCache()
		},
	)
	if bestEffortAfterEviction.GetLatestKnownContentLength() <= 0 {
		t.Fatalf("expected best-effort peer latest-known length to remain tracked")
	}
	if bestEffortAfterEviction.GetLatestCachedContentLength() != 0 {
		t.Fatalf("expected best-effort cached revision to be evicted, got %d", bestEffortAfterEviction.GetLatestCachedContentLength())
	}
	if !bestEffortAfterEviction.GetStaleCache() {
		t.Fatalf("expected best-effort peer cache to be stale after eviction")
	}

	setStorageBudget(t, holder, reservedCachedV1)
	reservedPayloadV2 := randomPayload(1024 * 1024)
	setFile(t, reserved, "payload.bin", reservedPayloadV2)
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	_, err := reserved.ProposeContract(ctx, holderOnion)
	cancel()
	if grpcstatus.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected oversized reserved proposal to fail with resource exhausted, got %v", err)
	}
	if !strings.Contains(grpcstatus.Convert(err).Message(), "peer storage budget was exhausted") {
		t.Fatalf("unexpected storage-budget proposal message: %v", err)
	}

	reservedAfterOverflow := waitForPeerInfo(
		t,
		holder,
		reservedOnion,
		"reserved stale cached revision after overflow",
		func(info *clirpc.PeerInfo) bool {
			return info.GetLatestKnownContentLength() > reservedCachedV1 &&
				info.GetLatestCachedContentLength() == reservedCachedV1 &&
				info.GetStaleCache()
		},
	)
	if reservedAfterOverflow.GetLatestKnownContentLength() <= reservedCachedV1 {
		t.Fatalf(
			"expected reserved peer latest-known revision to move forward, got known=%d cached=%d",
			reservedAfterOverflow.GetLatestKnownContentLength(),
			reservedAfterOverflow.GetLatestCachedContentLength(),
		)
	}
	if reservedAfterOverflow.GetLatestCachedContentLength() != reservedCachedV1 {
		t.Fatalf(
			"expected reserved peer to keep best cached revision, got %d want %d",
			reservedAfterOverflow.GetLatestCachedContentLength(),
			reservedCachedV1,
		)
	}
	if !reservedAfterOverflow.GetStaleCache() {
		t.Fatalf("expected reserved peer cache to be stale after oversized revision")
	}
}

func TestDockerSelfPeerRejected(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	node := addNode(t, scenario, "node", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")

	nodeOnion := startInitializedReadyNode(t, node)
	peerOnion := startInitializedReadyNode(t, peer)

	err := connectPeerRPC(t, node, nodeOnion)
	assertStatusMessage(t, err, codes.FailedPrecondition, "local node cannot act as its own peer")

	connectPeer(t, node, peerOnion)
	connectPeer(t, peer, nodeOnion)
	setFile(t, node, "payload.bin", []byte("self-filter"))
	proposeContract(t, node, peerOnion)
	peers := getPeers(t, node)
	assertPeerAbsentFromInventory(t, peers, nodeOnion)
	assertPeerInventoryContainsOnce(t, peers, peerOnion)
}

func TestDockerOperatorErrorsAreHuman(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	node := addNode(t, scenario, "node", "correct horse battery staple")

	startLockedNode(t, node)
	waitForReadyNode(t, node)

	client, conn := dialNodeClient(t, node)
	_, err := client.Unlock(context.Background(), &clirpc.UnlockRequest{MainPassword: "wrong password"})
	_ = conn.Close()
	assertStatusMessage(t, err, codes.FailedPrecondition, "daemon storage is not initialized; run init first")

	stopNode(t, node)
	assertCLIKeysRemoved(t, node)

	startLockedNode(t, node)
	waitForReadyNode(t, node)
	initNode(t, node)

	client, conn = dialNodeClient(t, node)
	_, err = client.Init(context.Background(), &clirpc.InitRequest{MainPassword: "correct horse battery staple"})
	_ = conn.Close()
	assertStatusMessage(t, err, codes.FailedPrecondition, "daemon storage is already initialized")

	client, conn = dialNodeClient(t, node)
	_, err = client.Unlock(context.Background(), &clirpc.UnlockRequest{MainPassword: "wrong password"})
	_ = conn.Close()
	assertStatusMessage(t, err, codes.PermissionDenied, "invalid password for this data directory")

	state := unlockAndWaitReady(t, node)
	err = connectPeerRPC(t, node, "not-an-onion")
	assertStatusMessage(t, err, codes.InvalidArgument, "peer onion is invalid")
	err = connectPeerRPC(t, node, state.GetServerOnion())
	assertStatusMessage(t, err, codes.FailedPrecondition, "local node cannot act as its own peer")

	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	update, err := node.RecoverContentOnce(ctx)
	cancel()
	if err != nil {
		t.Fatalf("recover content with no peers: %v", err)
	}
	if update.GetRecoveredMostRecentVersion() || update.GetTotalVersionsFound() != 0 || update.GetNumPeersWithAnyVersions() != 0 {
		t.Fatalf("unexpected recovery result without peers: %+v", update)
	}
}

func TestDockerLargePayloadRoundTrip(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	owner := addNode(t, scenario, "owner", "correct horse battery staple")
	peer := addNode(t, scenario, "peer", "peer password")
	recovered := addNode(t, scenario, "recovered", "correct horse battery staple")
	owner.DisableMaintenance()
	peer.DisableMaintenance()
	recovered.DisableMaintenance()

	ownerOnion := startInitializedReadyNode(t, owner)
	peerOnion := startInitializedReadyNode(t, peer)

	connectPeer(t, owner, peerOnion)
	connectPeer(t, peer, ownerOnion)

	payload := randomPayload(3*1024*1024 + 256*1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peerOnion)
	waitForPeerStorage(t, peer, ownerOnion, int64(len(payload)))
	if !checkContractOnce(t, owner, peerOnion).GetSuccess() {
		t.Fatalf("expected large-payload contract check to succeed")
	}

	stopNode(t, owner)
	assertCLIKeysRemoved(t, owner)

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	initNode(t, recovered)
	unlockAndWaitReady(t, recovered)
	connectPeer(t, recovered, peerOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", payload)
}

func TestDockerPeerStatusInventory(t *testing.T) {
	t.Parallel()

	scenario := newScenario(t)
	requester := addTestClockNode(t, scenario, "requester", "correct horse battery staple")
	connectedPeer := addTestClockNode(t, scenario, "connected-peer", "connected password")
	onlinePeer := addTestClockNode(t, scenario, "online-peer", "online password")
	offlinePeer := addTestClockNode(t, scenario, "offline-peer", "offline password")
	requester.DisableMaintenance()
	connectedPeer.DisableMaintenance()
	onlinePeer.DisableMaintenance()
	offlinePeer.DisableMaintenance()

	requesterOnion := startInitializedReadyTestClockNode(t, requester, 1000)
	connectedOnion := startInitializedReadyTestClockNode(t, connectedPeer, 1000)
	onlineOnion := startInitializedReadyTestClockNode(t, onlinePeer, 1000)
	offlineOnion := startInitializedReadyTestClockNode(t, offlinePeer, 1000)

	connectPeer(t, requester, connectedOnion)
	connectPeer(t, requester, onlineOnion)
	connectPeer(t, requester, offlineOnion)
	connectPeer(t, connectedPeer, requesterOnion)
	connectPeer(t, onlinePeer, requesterOnion)
	connectPeer(t, offlinePeer, requesterOnion)

	setFile(t, connectedPeer, "remote.bin", randomPayload(48*1024))
	proposeContract(t, connectedPeer, requesterOnion)
	waitForPeerStorage(t, requester, connectedOnion, 1)

	payload := randomPayload(96 * 1024)
	setFile(t, requester, "payload.bin", payload)
	proposeContract(t, requester, connectedOnion)
	proposeContract(t, requester, onlineOnion)
	proposeContract(t, requester, offlineOnion)

	advanceNodeTime(t, requester, 360, 0)
	advanceNodeTime(t, connectedPeer, 360, 0)
	advanceNodeTime(t, onlinePeer, 360, 0)
	advanceNodeTime(t, offlinePeer, 360, 0)

	proposeContract(t, requester, connectedOnion)
	stopNode(t, offlinePeer)
	assertCLIKeysRemoved(t, offlinePeer)
	offlineUpdate := checkContractOnce(t, requester, offlineOnion)
	if offlineUpdate.GetSuccess() || offlineUpdate.GetState() != clirpc.ContractState_PEER_UNAVAILABLE {
		t.Fatalf("expected offline peer check to finish unavailable, got %+v", offlineUpdate)
	}

	peers := getPeers(t, requester)
	assertPeerStatus(t, peers, connectedOnion, clirpc.PeerStatus_PEER_STATUS_CONNECTED)
	assertPeerStatus(t, peers, onlineOnion, clirpc.PeerStatus_PEER_STATUS_ONLINE)
	assertPeerStatus(t, peers, offlineOnion, clirpc.PeerStatus_PEER_STATUS_OFFLINE)
	connectedInfo := peerInfoFromResponse(t, peers, connectedOnion)
	if connectedInfo.GetLatestKnownContentLength() <= 0 {
		t.Fatalf("expected connected peer to report latest-known content")
	}
	if connectedInfo.GetLatestCachedContentLength() <= 0 {
		t.Fatalf("expected connected peer to report a cached content length")
	}
	for _, onion := range []string{connectedOnion, onlineOnion} {
		if peerInfoFromResponse(t, peers, onion).GetLastLiveAt() == 0 {
			t.Fatalf("expected %s to report a live timestamp", onion)
		}
	}
}

func newScenario(t *testing.T) *harness.Scenario {
	t.Helper()
	scenario, err := chutneyHarnessSuite(t).NewScenario(t)
	if err != nil {
		t.Fatalf("create scenario: %v", err)
	}
	return scenario
}

func newPublicTorScenario(t *testing.T) *harness.Scenario {
	t.Helper()
	scenario, err := publicTorHarnessSuite(t).NewScenario(t)
	if err != nil {
		t.Fatalf("create public-Tor scenario: %v", err)
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

func addConflictNode(t *testing.T, scenario *harness.Scenario, name string, password string) *harness.Node {
	t.Helper()
	node := addTestClockNode(t, scenario, name, password)
	node.DisableMaintenance()
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

func startInitializedReadyTestClockNode(
	t *testing.T,
	node *harness.Node,
	seconds uint64,
) string {
	t.Helper()
	startLockedNode(t, node)
	waitForReadyNode(t, node)
	setNodeTime(t, node, seconds, 0)
	initNode(t, node)
	state := unlockTestClockAndWaitReady(t, node)
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

func unlockTestClockAndWaitReady(t *testing.T, node *harness.Node) *clirpc.StateResponse {
	t.Helper()
	unlockNode(t, node)
	return waitForTestClockNodesReady(t, node)[0]
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

func prepareConflictScenarioBase(t *testing.T) *conflictScenario {
	t.Helper()
	scenario := newScenario(t)
	owner := addConflictNode(t, scenario, "owner", "correct horse battery staple")
	peerB := addConflictNode(t, scenario, "peer-b", "peer-b password")
	peerC := addConflictNode(t, scenario, "peer-c", "peer-c password")
	recovered := addConflictNode(t, scenario, "recovered", "correct horse battery staple")

	ownerOnion := startInitializedReadyTestClockNode(t, owner, 1000)
	peerBOnion := startInitializedReadyTestClockNode(t, peerB, 1000)

	connectPeer(t, owner, peerBOnion)
	connectPeer(t, peerB, ownerOnion)

	payloadV1 := bytes.Repeat([]byte("payload-v1\n"), 1024)
	advanceNodeTime(t, owner, 10, 0)
	setFile(t, owner, "payload.bin", payloadV1)
	proposeContract(t, owner, peerBOnion)
	waitForPeerStorage(t, peerB, ownerOnion, int64(len(payloadV1)))

	stopNode(t, peerB)
	assertCLIKeysRemoved(t, peerB)

	peerCOnion := startInitializedReadyTestClockNode(t, peerC, 1010)
	connectPeer(t, owner, peerCOnion)
	connectPeer(t, peerC, ownerOnion)

	payloadV2 := bytes.Repeat([]byte("payload-v2\n"), 1536)
	advanceNodeTime(t, owner, 10, 0)
	setFile(t, owner, "payload.bin", payloadV2)
	proposeContract(t, owner, peerCOnion)
	waitForPeerStorage(t, peerC, ownerOnion, int64(len(payloadV2)))

	stopNode(t, peerC)
	assertCLIKeysRemoved(t, peerC)
	stopNode(t, owner)
	assertCLIKeysRemoved(t, owner)

	startLockedNode(t, peerB)
	waitForReadyNode(t, peerB)
	setNodeTime(t, peerB, 1020, 0)
	unlockTestClockAndWaitReady(t, peerB)
	waitForPeerStorage(t, peerB, ownerOnion, int64(len(payloadV1)))

	startLockedNode(t, recovered)
	waitForReadyNode(t, recovered)
	setNodeTime(t, recovered, 1020, 0)
	initNode(t, recovered)
	unlockTestClockAndWaitReady(t, recovered)
	assertNoFiles(t, recovered)
	connectPeer(t, recovered, peerBOnion)
	recoverContent(t, recovered)
	assertFileEquals(t, recovered, "payload.bin", payloadV1)
	stopNode(t, peerB)
	assertCLIKeysRemoved(t, peerB)

	return &conflictScenario{
		scenario:   scenario,
		owner:      owner,
		peerB:      peerB,
		peerC:      peerC,
		recovered:  recovered,
		ownerOnion: ownerOnion,
		peerBOnion: peerBOnion,
		peerCOnion: peerCOnion,
		payloadV1:  payloadV1,
		payloadV2:  payloadV2,
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

func checkContract(t *testing.T, node *harness.Node, peerOnion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	update, err := node.CheckContractUntilSuccess(ctx, peerOnion)
	if err != nil {
		t.Fatalf("check contract from %s to %s: %v", node.Name(), peerOnion, err)
	}
	if !update.GetSuccess() {
		t.Fatalf("contract check from %s to %s did not succeed", node.Name(), peerOnion)
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

func waitForPeerScoreSeconds(t *testing.T, node *harness.Node, peerOnion string, expected int64) {
	t.Helper()
	deadline := time.Now().Add(harnessDefaultTimeout())

	for {
		ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
		response, err := node.Peers(ctx)
		cancel()
		if err == nil {
			for _, peer := range response.GetPeers() {
				if peer.GetPeer().GetOnionServiceId() == peerOnion && peer.GetScoreSeconds() == expected {
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s score on %s to become %d", peerOnion, node.Name(), expected)
		}
		time.Sleep(500 * time.Millisecond)
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

func waitForConflict(t *testing.T, node *harness.Node) *clirpc.ListConflictsResponse {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
		_, _ = node.RecoverContentOnce(ctx)
		cancel()

		conflicts := listConflicts(t, node)
		if countUnresolvedConflicts(conflicts) >= 2 {
			return conflicts
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for conflict on %s", node.Name())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func listConflicts(t *testing.T, node *harness.Node) *clirpc.ListConflictsResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.ListConflicts(ctx)
	if err != nil {
		t.Fatalf("list conflicts on %s: %v", node.Name(), err)
	}
	return response
}

func countUnresolvedConflicts(response *clirpc.ListConflictsResponse) int {
	count := 0
	for _, revision := range response.GetRevisions() {
		if revision.GetUnresolved() {
			count++
		}
	}
	return count
}

func findConflictRevision(
	t *testing.T,
	response *clirpc.ListConflictsResponse,
	match func(*clirpc.ConflictRevisionInfo) bool,
	description string,
) *clirpc.ConflictRevisionInfo {
	t.Helper()
	for _, revision := range response.GetRevisions() {
		if match(revision) {
			return revision
		}
	}
	t.Fatalf("missing %s in %v", description, response.GetRevisions())
	return nil
}

func assertCheckedOutRevision(
	t *testing.T,
	node *harness.Node,
	contentID []byte,
	name string,
	expected []byte,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.CheckoutRevision(ctx, contentID)
	if err != nil {
		t.Fatalf("checkout revision from %s: %v", node.Name(), err)
	}
	if len(response.GetFile()) != 1 {
		t.Fatalf("unexpected checkout file count from %s: %d", node.Name(), len(response.GetFile()))
	}
	file := response.GetFile()[0]
	if file.GetName() != name {
		t.Fatalf("unexpected checkout file name from %s: %s", node.Name(), file.GetName())
	}
	if !bytes.Equal(file.GetData(), expected) {
		t.Fatalf("unexpected checkout payload from %s", node.Name())
	}
}

func resolveConflict(t *testing.T, node *harness.Node, contentID []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.ResolveConflict(ctx, contentID); err != nil {
		t.Fatalf("resolve conflict on %s: %v", node.Name(), err)
	}
}

func assertSingleArchivedRevision(
	t *testing.T,
	response *clirpc.ListConflictsResponse,
	expectedContentID []byte,
) {
	t.Helper()
	if len(response.GetRevisions()) != 1 {
		t.Fatalf("expected one archived revision, got %d", len(response.GetRevisions()))
	}
	revision := response.GetRevisions()[0]
	if revision.GetUnresolved() {
		t.Fatalf("expected archived revision, got unresolved entry")
	}
	if !bytes.Equal(revision.GetContentId(), expectedContentID) {
		t.Fatalf("unexpected archived content id")
	}
	if revision.GetResolvedAt() == 0 {
		t.Fatalf("archived revision is missing resolved_at")
	}
}

func assertConflictBlocksFileOps(t *testing.T, node *harness.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()

	_, err := node.ListFiles(ctx)
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected list files to be blocked by conflict, got %v", err)
	}
	_, err = node.GetFile(ctx, "payload.bin")
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected get file to be blocked by conflict, got %v", err)
	}
	err = node.SetFile(ctx, "payload.bin", []byte("blocked"))
	if grpcstatus.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected set file to be blocked by conflict, got %v", err)
	}
}

func assertNoActiveConflict(t *testing.T, node *harness.Node) {
	t.Helper()
	response := listConflicts(t, node)
	for _, revision := range response.GetRevisions() {
		if revision.GetUnresolved() {
			t.Fatalf("expected no active conflict on %s, got %v", node.Name(), response.GetRevisions())
		}
	}
}

func assertPeerVisible(t *testing.T, node *harness.Node, peerOnion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.Peers(ctx)
	if err != nil {
		t.Fatalf("get peers from %s: %v", node.Name(), err)
	}
	for _, peer := range response.GetPeers() {
		if peer.GetPeer().GetOnionServiceId() == peerOnion {
			return
		}
	}
	t.Fatalf("expected %s to appear in peer inventory for %s", peerOnion, node.Name())
}

func assertPeerAbsent(t *testing.T, node *harness.Node, peerOnion string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.Peers(ctx)
	if err != nil {
		t.Fatalf("get peers from %s: %v", node.Name(), err)
	}
	for _, peer := range response.GetPeers() {
		if peer.GetPeer().GetOnionServiceId() == peerOnion {
			t.Fatalf("expected %s to disappear from peer inventory for %s", peerOnion, node.Name())
		}
	}
}

func getPeers(t *testing.T, node *harness.Node) *clirpc.PeersResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.Peers(ctx)
	if err != nil {
		t.Fatalf("get peers from %s: %v", node.Name(), err)
	}
	return response
}

func peerInfoFromResponse(
	t *testing.T,
	response *clirpc.PeersResponse,
	peerOnion string,
) *clirpc.PeerInfo {
	t.Helper()
	for _, peer := range response.GetPeers() {
		if peer.GetPeer().GetOnionServiceId() == peerOnion {
			return peer
		}
	}
	t.Fatalf("missing peer %s in inventory", peerOnion)
	return nil
}

func peerInfoByOnion(t *testing.T, node *harness.Node, peerOnion string) *clirpc.PeerInfo {
	t.Helper()
	return peerInfoFromResponse(t, getPeers(t, node), peerOnion)
}

func waitForPeerStorageInfo(
	t *testing.T,
	node *harness.Node,
	peerOnion string,
	expectedBytes int64,
) *clirpc.PeerInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	info, err := node.WaitForPeerStorage(ctx, peerOnion, expectedBytes)
	if err != nil {
		t.Fatalf("wait for peer storage on %s for %s: %v", node.Name(), peerOnion, err)
	}
	return info
}

func peerScoreSeconds(t *testing.T, node *harness.Node, peerOnion string) int64 {
	t.Helper()
	return peerInfoByOnion(t, node, peerOnion).GetScoreSeconds()
}

func waitForPeerStatus(
	t *testing.T,
	node *harness.Node,
	peerOnion string,
	expected clirpc.PeerStatus,
) *clirpc.PeerInfo {
	t.Helper()
	deadline := time.Now().Add(harnessDefaultTimeout())
	for {
		info := peerInfoByOnion(t, node, peerOnion)
		if clirpc.PeerStatus(info.GetStatus()) == expected {
			return info
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s on %s to become %s", peerOnion, node.Name(), expected.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForPeerVisible(
	t *testing.T,
	node *harness.Node,
	peerOnion string,
) *clirpc.PeerInfo {
	t.Helper()
	deadline := time.Now().Add(harnessDefaultTimeout())
	for {
		response := getPeers(t, node)
		for _, peer := range response.GetPeers() {
			if peer.GetPeer().GetOnionServiceId() == peerOnion {
				return peer
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s to appear in %s peer inventory", peerOnion, node.Name())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func waitForPeerInfo(
	t *testing.T,
	node *harness.Node,
	peerOnion string,
	description string,
	predicate func(*clirpc.PeerInfo) bool,
) *clirpc.PeerInfo {
	t.Helper()
	deadline := time.Now().Add(harnessDefaultTimeout())
	for {
		info := peerInfoByOnion(t, node, peerOnion)
		if predicate(info) {
			return info
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s on %s: %+v", description, node.Name(), info)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func checkContractOnce(t *testing.T, node *harness.Node, peerOnion string) *clirpc.CheckContractUpdate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	update, err := node.CheckContract(ctx, peerOnion)
	if err != nil {
		t.Fatalf("check contract from %s to %s: %v", node.Name(), peerOnion, err)
	}
	return update
}

func setStorageBudget(t *testing.T, node *harness.Node, allocatedBytes int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if err := node.SetStorageConfig(ctx, &clirpc.StorageConfig{
		AllocatedStorageForPeers: allocatedBytes,
		MinReplicas:              0,
	}); err != nil {
		t.Fatalf("set storage budget on %s: %v", node.Name(), err)
	}
}

func getStorageConfig(t *testing.T, node *harness.Node) *clirpc.GetStorageConfigResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.GetStorageConfig(ctx)
	if err != nil {
		t.Fatalf("get storage config from %s: %v", node.Name(), err)
	}
	return response
}

func getContracts(t *testing.T, node *harness.Node) *clirpc.GetContractsResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	response, err := node.GetContracts(ctx)
	if err != nil {
		t.Fatalf("get contracts from %s: %v", node.Name(), err)
	}
	return response
}

func assertContractOnlineState(t *testing.T, node *harness.Node, peerOnion string, expected bool) {
	t.Helper()
	response := getContracts(t, node)
	for _, contract := range response.GetContracts() {
		if contract.GetPeer().GetOnionServiceId() != peerOnion {
			continue
		}
		if contract.GetOnline() != expected {
			t.Fatalf("unexpected online state for %s on %s: got %v want %v", peerOnion, node.Name(), contract.GetOnline(), expected)
		}
		return
	}
	t.Fatalf("missing contract for %s on %s", peerOnion, node.Name())
}

func dialNodeClient(
	t *testing.T,
	node *harness.Node,
) (clirpc.BarterBackupClientClient, interface{ Close() error }) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	client, conn, err := harness.DialLocalClient(ctx, node.LocalAddr(), filepath.Join(node.DataDir(), "cli-keys"))
	if err != nil {
		t.Fatalf("dial local client for %s: %v", node.Name(), err)
	}
	return client, conn
}

func connectPeerRPC(t *testing.T, node *harness.Node, onion string) error {
	t.Helper()
	client, conn := dialNodeClient(t, node)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	_, err := client.ConnectPeer(ctx, &clirpc.ConnectPeerRequest{
		Peer: &clirpc.Peer{OnionServiceId: onion},
	})
	return err
}

func assertStatusMessage(t *testing.T, err error, code codes.Code, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC error %s: %s", code.String(), message)
	}
	status, ok := grpcstatus.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if status.Code() != code {
		t.Fatalf("unexpected gRPC code: got %s want %s (%v)", status.Code(), code, err)
	}
	if status.Message() != message {
		t.Fatalf("unexpected gRPC message: got %q want %q", status.Message(), message)
	}
}

func assertPeerAbsentFromInventory(t *testing.T, response *clirpc.PeersResponse, peerOnion string) {
	t.Helper()
	for _, peer := range response.GetPeers() {
		if peer.GetPeer().GetOnionServiceId() == peerOnion {
			t.Fatalf("expected %s to be absent from peer inventory", peerOnion)
		}
	}
}

func assertPeerInventoryContainsOnce(
	t *testing.T,
	response *clirpc.PeersResponse,
	expectedOnions ...string,
) {
	t.Helper()
	for _, expected := range expectedOnions {
		count := 0
		for _, peer := range response.GetPeers() {
			if peer.GetPeer().GetOnionServiceId() == expected {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("expected peer %s to appear exactly once, got %d", expected, count)
		}
	}
}

func assertPeerStatus(
	t *testing.T,
	response *clirpc.PeersResponse,
	onion string,
	expected clirpc.PeerStatus,
) {
	t.Helper()
	info := peerInfoFromResponse(t, response, onion)
	if clirpc.PeerStatus(info.GetStatus()) != expected {
		t.Fatalf("unexpected peer status for %s: got %s want %s", onion, clirpc.PeerStatus(info.GetStatus()).String(), expected.String())
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
