package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	defaultBasePort     = 19000
	defaultParallelRuns = 2
	defaultDialTimeout  = 30 * time.Second
	defaultShortTimeout = 2 * time.Minute
	defaultLongTimeout  = 10 * time.Minute
)

// Suite owns the shared Docker image and Chutney network for one test run.
type Suite struct {
	repoRoot     string
	workRoot     string
	imageTag     string
	network      *ChutneyNetwork
	parallelGate chan struct{}
	nextPort     atomic.Int64
}

// Scenario owns the per-test artifacts, nodes, and cleanup behavior.
type Scenario struct {
	suite     *Suite
	rootDir   string
	logsDir   string
	keepFiles bool
	nodes     []*Node
	once      sync.Once
}

// PrepareSuite boots the shared image and private Tor network used by the
// Docker integration tests.
func PrepareSuite(ctx context.Context) (*Suite, error) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		return nil, err
	}
	workRoot, err := configuredWorkRoot()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("Docker integration tests require Linux hosts")
	}
	if _, err := execLookPath("docker"); err != nil {
		return nil, err
	}

	suite := &Suite{
		repoRoot:     repoRoot,
		workRoot:     workRoot,
		imageTag:     "barterbackup-integration:local",
		parallelGate: make(chan struct{}, configuredParallelism()),
	}
	suite.nextPort.Store(defaultBasePort)

	if err := suite.buildImage(ctx); err != nil {
		return nil, err
	}
	network, err := PrepareChutneyNetwork(ctx, workRoot)
	if err != nil {
		return nil, err
	}
	suite.network = network
	return suite, nil
}

// Close tears down the shared private Tor network.
func (s *Suite) Close() error {
	if s.network == nil {
		return nil
	}
	return s.network.Close()
}

// NewScenario allocates one per-test scenario with isolated node state.
func (s *Suite) NewScenario(t *testing.T) (*Scenario, error) {
	t.Helper()
	s.parallelGate <- struct{}{}

	rootDir, err := os.MkdirTemp(s.workRoot, sanitizeName(t.Name())+"-")
	if err != nil {
		<-s.parallelGate
		return nil, fmt.Errorf("create scenario root: %w", err)
	}
	logsDir := filepath.Join(rootDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		<-s.parallelGate
		return nil, fmt.Errorf("create scenario logs: %w", err)
	}

	scenario := &Scenario{
		suite:     s,
		rootDir:   rootDir,
		logsDir:   logsDir,
		keepFiles: os.Getenv("BB_KEEP_INTEGRATION_ARTIFACTS") != "",
	}
	t.Cleanup(func() {
		scenario.close(t)
	})
	return scenario, nil
}

// AddNode provisions one logical test node under the scenario root.
func (s *Scenario) AddNode(name string, password string) (*Node, error) {
	nodeDir := filepath.Join(s.rootDir, sanitizeName(name))
	if err := os.MkdirAll(nodeDir, 0o700); err != nil {
		return nil, fmt.Errorf("create node dir for %s: %w", name, err)
	}

	port := s.suite.nextPort.Add(1)
	node := &Node{
		suite:         s.suite,
		name:          name,
		containerName: makeContainerName(filepath.Base(s.rootDir), name),
		dataDir:       nodeDir,
		localAddr:     fmt.Sprintf("127.0.0.1:%d", port),
		password:      password,
	}
	s.nodes = append(s.nodes, node)
	return node, nil
}

func (s *Scenario) close(t *testing.T) {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultShortTimeout)
		defer cancel()
		for _, node := range s.nodes {
			_ = node.FetchLogs(ctx, filepath.Join(s.logsDir, sanitizeName(node.name)+".log"))
			node.ForceRemove(ctx)
		}
		<-s.suite.parallelGate
		if t.Failed() || s.keepFiles {
			t.Logf("integration artifacts kept in %s", s.rootDir)
			return
		}
		_ = os.RemoveAll(s.rootDir)
	})
}

func (s *Suite) buildImage(ctx context.Context) error {
	bbdBinary, err := findStaticBBDBinary(s.repoRoot)
	if err != nil {
		return err
	}
	relativeBinary, err := filepath.Rel(s.repoRoot, bbdBinary)
	if err != nil {
		return fmt.Errorf("relativize bbd binary path: %w", err)
	}

	_, err = runCommand(
		ctx,
		s.repoRoot,
		nil,
		"docker",
		"build",
		"-t",
		s.imageTag,
		"-f",
		filepath.Join("integration", "docker", "Dockerfile"),
		"--build-arg",
		"BBD_BIN="+relativeBinary,
		".",
	)
	if err != nil {
		return fmt.Errorf("build integration image: %w", err)
	}
	return nil
}

func findRepoRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(current, "flake.nix")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("could not find repository root from %s", current)
		}
		current = parent
	}
}

func findStaticBBDBinary(repoRoot string) (string, error) {
	if override := os.Getenv("BB_DOCKER_BBD_BIN"); override != "" {
		return override, nil
	}
	candidates := []string{
		filepath.Join(repoRoot, "target-static", "x86_64-unknown-linux-musl", "x86_64-unknown-linux-musl", "release", "bbd"),
		filepath.Join(repoRoot, "target-static", "aarch64-unknown-linux-musl", "aarch64-unknown-linux-musl", "release", "bbd"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not find a static bbd binary; run make build-static first")
}

func configuredParallelism() int {
	if value := os.Getenv("BB_DOCKER_TEST_PARALLEL"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultParallelRuns
}

func configuredWorkRoot() (string, error) {
	root := os.Getenv("BB_DOCKER_TEST_WORKDIR")
	if root == "" {
		root = filepath.Join(string(filepath.Separator), "tmp", "barterbackup-integration")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("create integration work root %s: %w", root, err)
	}
	return root, nil
}

func execLookPath(binary string) (string, error) {
	path, err := execLookPathFunc(binary)
	if err != nil {
		return "", fmt.Errorf("find %s in PATH: %w", binary, err)
	}
	return path, nil
}

var execLookPathFunc = func(binary string) (string, error) {
	return execLookPathStd(binary)
}
