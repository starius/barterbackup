package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"barterbackup/integration/docker/harness"
)

func TestManualEnvUpStatusDown(t *testing.T) {
	workRoot := t.TempDir()
	envName := manualEnvName(t, workRoot)

	upOutput := runDevEnvCommand(t, workRoot, envName, "up", "--nodes", "2")
	if !strings.Contains(upOutput, "environment: "+envName) {
		t.Fatalf("unexpected up output: %s", upOutput)
	}
	if !strings.Contains(upOutput, "chutney_healthy: true") {
		t.Fatalf("expected healthy Chutney network: %s", upOutput)
	}

	statusOutput := runDevEnvCommand(t, workRoot, envName, "status")
	if !strings.Contains(statusOutput, "clock_mode: real") {
		t.Fatalf("expected real clock mode in status: %s", statusOutput)
	}
	if !strings.Contains(statusOutput, "- [0] node0") || !strings.Contains(statusOutput, "- [1] node1") {
		t.Fatalf("expected both default nodes in status: %s", statusOutput)
	}

	downOutput := runDevEnvCommand(t, workRoot, envName, "down")
	if !strings.Contains(downOutput, "environment "+envName+" removed") {
		t.Fatalf("unexpected down output: %s", downOutput)
	}
	if _, err := os.Stat(filepath.Join(workRoot, "manual", envName)); !os.IsNotExist(err) {
		t.Fatalf("expected environment root removal, stat err=%v", err)
	}
}

func TestManualEnvCliTargetsSelectedNode(t *testing.T) {
	workRoot := t.TempDir()
	envName := manualEnvName(t, workRoot)

	runDevEnvCommand(t, workRoot, envName, "up", "--nodes", "2")
	t.Cleanup(func() {
		_ = runDevEnvCommandBestEffort(workRoot, envName, "down")
	})

	runDevEnvCommand(t, workRoot, envName, "cli", "0", "--", "init", "owner-password")
	runDevEnvCommand(t, workRoot, envName, "cli", "0", "--", "unlock", "owner-password")

	node0State := runDevEnvCommand(t, workRoot, envName, "cli", "0", "--", "state")
	if !strings.Contains(node0State, "storage_initialized: true") {
		t.Fatalf("expected initialized state for node0: %s", node0State)
	}

	node1State := runDevEnvCommand(t, workRoot, envName, "cli", "1", "--", "state")
	if !strings.Contains(node1State, "storage_initialized: false") {
		t.Fatalf("expected uninitialized state for node1: %s", node1State)
	}
}

func TestManualEnvRecreateAndRecover(t *testing.T) {
	workRoot := t.TempDir()
	envName := manualEnvName(t, workRoot)

	runDevEnvCommand(
		t,
		workRoot,
		envName,
		"up",
		"--disable-maintenance",
		"--nodes",
		"3",
		"--node-name",
		"owner",
		"--node-name",
		"peer1",
		"--node-name",
		"peer2",
	)
	t.Cleanup(func() {
		_ = runDevEnvCommandBestEffort(workRoot, envName, "down")
	})

	env, err := harness.LoadEnvironment(envName, workRoot)
	if err != nil {
		t.Fatalf("load environment: %v", err)
	}
	owner, err := env.Node("owner")
	if err != nil {
		t.Fatalf("load owner node: %v", err)
	}
	peer1, err := env.Node("peer1")
	if err != nil {
		t.Fatalf("load peer1 node: %v", err)
	}
	peer2, err := env.Node("peer2")
	if err != nil {
		t.Fatalf("load peer2 node: %v", err)
	}

	ownerOnion := initializeManualEnvNode(t, workRoot, envName, "owner", owner, "owner-password")
	peer1Onion := initializeManualEnvNode(t, workRoot, envName, "peer1", peer1, "peer1-password")
	peer2Onion := initializeManualEnvNode(t, workRoot, envName, "peer2", peer2, "peer2-password")

	connectPeer(t, owner, peer1Onion)
	connectPeer(t, owner, peer2Onion)
	connectPeer(t, peer1, ownerOnion)
	connectPeer(t, peer2, ownerOnion)

	payload := bytes.Repeat([]byte("manual-env-recovery\n"), 1024)
	setFile(t, owner, "payload.bin", payload)
	proposeContract(t, owner, peer1Onion)
	proposeContract(t, owner, peer2Onion)
	waitForPeerStorage(t, peer1, ownerOnion, int64(len(payload)))
	waitForPeerStorage(t, peer2, ownerOnion, int64(len(payload)))

	runDevEnvCommand(t, workRoot, envName, "recreate", "owner")

	postRecreateState := runDevEnvCommand(t, workRoot, envName, "cli", "owner", "--", "state")
	if !strings.Contains(postRecreateState, "storage_initialized: false") {
		t.Fatalf("expected recreated owner to start empty: %s", postRecreateState)
	}

	env, err = harness.LoadEnvironment(envName, workRoot)
	if err != nil {
		t.Fatalf("reload environment: %v", err)
	}
	owner, err = env.Node("owner")
	if err != nil {
		t.Fatalf("reload owner node: %v", err)
	}
	initializeManualEnvRecoveryNode(t, workRoot, envName, "owner", owner, "owner-password")
	assertNoFiles(t, owner)
	connectPeer(t, owner, peer1Onion)
	connectPeer(t, owner, peer2Onion)
	recoverManualEnvFileUntilPresent(t, owner, "payload.bin")
	assertFileEquals(t, owner, "payload.bin", payload)
}

func TestManualEnvSyntheticClockAdvance(t *testing.T) {
	workRoot := t.TempDir()
	envName := manualEnvName(t, workRoot)

	runDevEnvCommand(t, workRoot, envName, "up", "--nodes", "2", "--clock", "synthetic")
	t.Cleanup(func() {
		_ = runDevEnvCommandBestEffort(workRoot, envName, "down")
	})

	env, err := harness.LoadEnvironment(envName, workRoot)
	if err != nil {
		t.Fatalf("load environment: %v", err)
	}
	node0, err := env.Node("0")
	if err != nil {
		t.Fatalf("load node0: %v", err)
	}
	node1, err := env.Node("1")
	if err != nil {
		t.Fatalf("load node1: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if _, err := node0.WaitForState(ctx); err != nil {
		t.Fatalf("wait for node0 state: %v", err)
	}
	if _, err := node1.WaitForState(ctx); err != nil {
		t.Fatalf("wait for node1 state: %v", err)
	}
	before0, err := node0.GetTestTime(ctx)
	if err != nil {
		t.Fatalf("get node0 test time: %v", err)
	}
	before1, err := node1.GetTestTime(ctx)
	if err != nil {
		t.Fatalf("get node1 test time: %v", err)
	}
	if before0.GetUnixSeconds() != before1.GetUnixSeconds() || before0.GetNanoseconds() != before1.GetNanoseconds() {
		t.Fatalf("expected aligned synthetic clocks before advance: node0=%+v node1=%+v", before0, before1)
	}

	clockOutput := runDevEnvCommand(t, workRoot, envName, "clock", "advance", "5d12h")
	if !strings.Contains(clockOutput, "clock_mode: synthetic") {
		t.Fatalf("unexpected clock advance output: %s", clockOutput)
	}

	after0, err := node0.GetTestTime(ctx)
	if err != nil {
		t.Fatalf("get node0 advanced test time: %v", err)
	}
	after1, err := node1.GetTestTime(ctx)
	if err != nil {
		t.Fatalf("get node1 advanced test time: %v", err)
	}
	if after0.GetUnixSeconds() != after1.GetUnixSeconds() || after0.GetNanoseconds() != after1.GetNanoseconds() {
		t.Fatalf("expected aligned synthetic clocks after advance: node0=%+v node1=%+v", after0, after1)
	}
	advancedBy := after0.GetUnixSeconds() - before0.GetUnixSeconds()
	if advancedBy != uint64((5*24+12)*time.Hour/time.Second) {
		t.Fatalf("unexpected synthetic clock delta: got %d", advancedBy)
	}
}

func runDevEnvCommand(t *testing.T, workRoot string, envName string, args ...string) string {
	t.Helper()
	output, err := runDevEnvCommandRaw(workRoot, envName, args...)
	if err != nil {
		t.Fatalf("run bbdevenv %v: %v\n%s", args, err, output)
	}
	return output
}

func runDevEnvCommandBestEffort(workRoot string, envName string, args ...string) string {
	output, _ := runDevEnvCommandRaw(workRoot, envName, args...)
	return output
}

func runDevEnvCommandRaw(workRoot string, envName string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	commandArgs := append([]string{"run", "./cmd/bbdevenv", "--", "--workdir", workRoot, "--name", envName}, args...)
	command := exec.CommandContext(ctx, "go", commandArgs...)
	command.Dir = cwd
	output, err := command.CombinedOutput()
	return string(output), err
}

func manualEnvName(t *testing.T, workRoot string) string {
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	sum := sha256.Sum256([]byte(workRoot))
	suffix := hex.EncodeToString(sum[:3])
	return strings.ToLower(replacer.Replace(t.Name() + "-" + suffix))
}

func initializeManualEnvNode(
	t *testing.T,
	workRoot string,
	envName string,
	nodeName string,
	node *harness.Node,
	password string,
) string {
	return initializeManualEnvNodeWithRecoveryMode(t, workRoot, envName, nodeName, node, password, false)
}

func initializeManualEnvRecoveryNode(
	t *testing.T,
	workRoot string,
	envName string,
	nodeName string,
	node *harness.Node,
	password string,
) string {
	return initializeManualEnvNodeWithRecoveryMode(t, workRoot, envName, nodeName, node, password, true)
}

func initializeManualEnvNodeWithRecoveryMode(
	t *testing.T,
	workRoot string,
	envName string,
	nodeName string,
	node *harness.Node,
	password string,
	recoveryMode bool,
) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()
	if _, err := node.WaitForState(ctx); err != nil {
		t.Fatalf("wait for state on %s: %v", node.Name(), err)
	}

	if recoveryMode {
		runDevEnvCommand(t, workRoot, envName, "cli", nodeName, "--", "init", "--recovery-mode", password)
	} else {
		runDevEnvCommand(t, workRoot, envName, "cli", nodeName, "--", "init", password)
	}
	runDevEnvCommand(t, workRoot, envName, "cli", nodeName, "--", "unlock", password)

	state, err := node.WaitForReady(ctx)
	if err != nil {
		t.Fatalf("wait for ready on %s: %v", node.Name(), err)
	}
	return state.GetServerOnion()
}

func recoverManualEnvFileUntilPresent(
	t *testing.T,
	node *harness.Node,
	fileName string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), harnessDefaultTimeout())
	defer cancel()

	deadline := time.Now().Add(harnessDefaultTimeout())
	for {
		response, err := node.ListFiles(ctx)
		if err != nil {
			t.Fatalf("list files on %s after recovery: %v", node.Name(), err)
		}
		for _, file := range response.GetFile() {
			if file.GetName() == fileName {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery on %s did not restore %s", node.Name(), fileName)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
