package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseClockAdvanceDurationSupportsGoAndDaySyntax(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected time.Duration
	}{
		{name: "go duration", input: "1h5m", expected: time.Hour + 5*time.Minute},
		{name: "day duration", input: "5d", expected: 5 * 24 * time.Hour},
		{name: "mixed duration", input: "5d12h30m", expected: 5*24*time.Hour + 12*time.Hour + 30*time.Minute},
		{name: "fractional day", input: "1.5d", expected: 36 * time.Hour},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			duration, err := ParseClockAdvanceDuration(testCase.input)
			if err != nil {
				t.Fatalf("parse duration %s: %v", testCase.input, err)
			}
			if duration != testCase.expected {
				t.Fatalf("unexpected duration: got %s want %s", duration, testCase.expected)
			}
		})
	}
}

func TestParseClockAdvanceDurationRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"", "5", "d", "5x", "1h-5m"} {
		if _, err := ParseClockAdvanceDuration(input); err == nil {
			t.Fatalf("expected parse error for %q", input)
		}
	}
}

func TestValidateNodeNamesRejectsSanitizedCollisions(t *testing.T) {
	t.Parallel()

	err := validateNodeNames([]string{"peer/a", "peer-a"})
	if err == nil {
		t.Fatal("expected sanitized node-name collision error")
	}
	if !strings.Contains(err.Error(), "sanitize to the same runtime name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnvironmentNodeResolutionByNameAndIndex(t *testing.T) {
	t.Parallel()

	env := &Environment{
		manifest: EnvironmentManifest{
			ClockMode: ClockModeSynthetic,
			Nodes: []EnvironmentNodeManifest{
				{Name: "node0", Index: 0, ContainerName: "bb-node0", DataDir: "/tmp/node0", LocalAddr: "127.0.0.1:10000"},
				{Name: "node1", Index: 1, ContainerName: "bb-node1", DataDir: "/tmp/node1", LocalAddr: "127.0.0.1:10001"},
			},
		},
		suite: &Suite{imageTag: "barterbackup-integration:local"},
	}

	byIndex, err := env.Node("1")
	if err != nil {
		t.Fatalf("resolve node by index: %v", err)
	}
	if byIndex.Name() != "node1" {
		t.Fatalf("unexpected node by index: %s", byIndex.Name())
	}
	if !byIndex.testClock {
		t.Fatal("expected synthetic environment nodes to enable test clock")
	}

	byName, err := env.Node("node0")
	if err != nil {
		t.Fatalf("resolve node by name: %v", err)
	}
	if byName.LocalAddr() != "127.0.0.1:10000" {
		t.Fatalf("unexpected local addr for node0: %s", byName.LocalAddr())
	}

	if _, err := env.Node("unknown"); err == nil {
		t.Fatal("expected missing node error")
	}
}

func TestEnvironmentManifestRoundTrip(t *testing.T) {
	t.Parallel()

	workRoot := t.TempDir()
	rootDir := environmentRootDir(workRoot, "lab")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("create root dir: %v", err)
	}
	manifestPath := filepath.Join(rootDir, "manifest.json")

	env := &Environment{
		rootDir:      rootDir,
		logsDir:      filepath.Join(rootDir, "logs"),
		manifestPath: manifestPath,
		suite:        &Suite{repoRoot: "/repo", workRoot: workRoot, imageTag: "barterbackup-integration:local"},
		manifest: EnvironmentManifest{
			Version:             environmentManifestVersion,
			Name:                "lab",
			RepoRoot:            "/repo",
			ImageTag:            "barterbackup-integration:local",
			ChutneyDataDir:      filepath.Join(rootDir, "chutney"),
			ClockMode:           ClockModeSynthetic,
			SyntheticClock:      SyntheticClock{UnixSeconds: 1234, Nanoseconds: 5678},
			DisableMaintenance:  true,
			CreatedAtUnixSecond: 111,
			Nodes: []EnvironmentNodeManifest{{
				Name:          "owner",
				Index:         0,
				ContainerName: makeEnvironmentContainerName(rootDir, "lab", "owner"),
				DataDir:       filepath.Join(rootDir, "owner"),
				LocalAddr:     "127.0.0.1:19001",
			}},
		},
	}
	if err := env.saveManifest(); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	loaded, err := LoadEnvironment("lab", workRoot)
	if err != nil {
		t.Fatalf("load environment: %v", err)
	}
	if loaded.Name() != "lab" {
		t.Fatalf("unexpected environment name: %s", loaded.Name())
	}
	if loaded.ClockMode() != ClockModeSynthetic {
		t.Fatalf("unexpected clock mode: %s", loaded.ClockMode())
	}
	if loaded.SyntheticClock().UnixSeconds != 1234 || loaded.SyntheticClock().Nanoseconds != 5678 {
		t.Fatalf("unexpected synthetic clock: %+v", loaded.SyntheticClock())
	}
	expectedContainerName := makeEnvironmentContainerName(rootDir, "lab", "owner")
	if len(loaded.Nodes()) != 1 || loaded.Nodes()[0].ContainerName() != expectedContainerName {
		t.Fatalf("unexpected node manifest after load: %+v", loaded.manifest.Nodes)
	}
}

func TestEnvironmentContainerNamesIncludeRootScope(t *testing.T) {
	t.Parallel()

	firstRoot := environmentRootDir(filepath.Join(t.TempDir(), "first"), "lab")
	secondRoot := environmentRootDir(filepath.Join(t.TempDir(), "second"), "lab")

	first := makeEnvironmentContainerName(firstRoot, "lab", "owner")
	second := makeEnvironmentContainerName(secondRoot, "lab", "owner")
	if first == second {
		t.Fatalf("expected distinct container names for different roots: %s", first)
	}
	if !strings.HasPrefix(first, "bb-lab-") {
		t.Fatalf("expected readable container prefix, got %s", first)
	}
}

func TestLoadEnvironmentRejectsMalformedManifest(t *testing.T) {
	t.Parallel()

	workRoot := t.TempDir()
	rootDir := environmentRootDir(workRoot, "broken")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatalf("create root dir: %v", err)
	}
	manifestPath := filepath.Join(rootDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte("{not json}"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}

	if _, err := LoadEnvironment("broken", workRoot); err == nil {
		t.Fatal("expected malformed manifest load error")
	}
}

func TestEnvironmentManifestJSONIncludesClockState(t *testing.T) {
	t.Parallel()

	manifest := EnvironmentManifest{
		Version:        environmentManifestVersion,
		Name:           "lab",
		ClockMode:      ClockModeSynthetic,
		SyntheticClock: SyntheticClock{UnixSeconds: 42, Nanoseconds: 99},
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if !strings.Contains(string(encoded), "\"clock_mode\":\"synthetic\"") {
		t.Fatalf("missing clock mode in manifest json: %s", string(encoded))
	}
	if !strings.Contains(string(encoded), "\"unix_seconds\":42") {
		t.Fatalf("missing synthetic clock in manifest json: %s", string(encoded))
	}
}

func TestPersistentChutneyDataDirUsesStableShortTempRoot(t *testing.T) {
	t.Parallel()

	workRoot := filepath.Join(t.TempDir(), strings.Repeat("very-long-segment-", 8))
	dataDir := persistentChutneyDataDir(workRoot, "owner")
	if !strings.HasPrefix(dataDir, filepath.Join(string(filepath.Separator), "tmp", "bbmc")+string(filepath.Separator)) {
		t.Fatalf("unexpected chutney temp root: %s", dataDir)
	}
	if strings.Contains(dataDir, workRoot) {
		t.Fatalf("chutney data dir should not embed the long work root: %s", dataDir)
	}
	if other := persistentChutneyDataDir(workRoot, "owner"); other != dataDir {
		t.Fatalf("expected stable chutney data dir: got %s want %s", other, dataDir)
	}
}

func TestEnvironmentDestroyRemovesRootWithoutNetwork(t *testing.T) {
	t.Parallel()

	rootDir := t.TempDir()
	chutneyDataDir := filepath.Join(t.TempDir(), "manual-chutney")
	if err := os.MkdirAll(chutneyDataDir, 0o755); err != nil {
		t.Fatalf("create chutney data dir: %v", err)
	}
	env := &Environment{
		rootDir: rootDir,
		suite:   &Suite{artiConfig: &ChutneyNetwork{dataDir: chutneyDataDir}},
		manifest: EnvironmentManifest{
			ChutneyDataDir: chutneyDataDir,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := env.Destroy(ctx, false); err != nil {
		t.Fatalf("destroy environment: %v", err)
	}
	if _, err := os.Stat(rootDir); !os.IsNotExist(err) {
		t.Fatalf("expected root dir removal, stat err=%v", err)
	}
	if _, err := os.Stat(chutneyDataDir); !os.IsNotExist(err) {
		t.Fatalf("expected chutney data dir removal, stat err=%v", err)
	}
}

func TestResetNodeDataDirRemovesAllPriorState(t *testing.T) {
	rootDir := t.TempDir()
	dataDir := filepath.Join(rootDir, "owner")
	if err := os.MkdirAll(filepath.Join(dataDir, "tor"), 0o700); err != nil {
		t.Fatalf("create tor dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "arti-cache"), 0o700); err != nil {
		t.Fatalf("create arti-cache dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "cli-keys"), 0o700); err != nil {
		t.Fatalf("create cli-keys dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "tor", "cache.txt"), []byte("tor"), 0o600); err != nil {
		t.Fatalf("write tor cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "arti-cache", "cache.txt"), []byte("arti"), 0o600); err != nil {
		t.Fatalf("write arti cache: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "cli-keys", "client.key"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write cli key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "state.bin"), []byte("state"), 0o600); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	if err := resetNodeDataDir(dataDir); err != nil {
		t.Fatalf("reset node data dir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dataDir, "tor")); !os.IsNotExist(err) {
		t.Fatalf("expected tor dir removal, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "arti-cache")); !os.IsNotExist(err) {
		t.Fatalf("expected arti-cache dir removal, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "cli-keys")); !os.IsNotExist(err) {
		t.Fatalf("expected cli keys removal, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "state.bin")); !os.IsNotExist(err) {
		t.Fatalf("expected state file removal, stat err=%v", err)
	}
}

func TestEnvironmentStartNodeDoesNotRebuildImage(t *testing.T) {
	originalRunCommand := runCommandFunc
	t.Cleanup(func() {
		runCommandFunc = originalRunCommand
	})

	var commands []string
	runCommandFunc = func(
		ctx context.Context,
		dir string,
		env []string,
		name string,
		args ...string,
	) ([]byte, error) {
		command := name
		if len(args) > 0 {
			command += " " + strings.Join(args, " ")
		}
		commands = append(commands, command)
		if name == "docker" && len(args) >= 2 && args[0] == "inspect" && args[len(args)-1] == "bb-lab-owner" {
			return nil, fmt.Errorf("run docker inspect: No such object: bb-lab-owner")
		}
		return []byte("ok\n"), nil
	}

	rootDir := t.TempDir()
	nodeDir := filepath.Join(rootDir, "owner")
	env := &Environment{
		rootDir: rootDir,
		suite: &Suite{
			repoRoot:   rootDir,
			workRoot:   rootDir,
			imageTag:   "barterbackup-integration:local",
			artiConfig: &ChutneyNetwork{},
		},
		manifest: EnvironmentManifest{
			ClockMode: ClockModeReal,
			Nodes: []EnvironmentNodeManifest{{
				Name:          "owner",
				Index:         0,
				ContainerName: "bb-lab-owner",
				DataDir:       nodeDir,
				LocalAddr:     "127.0.0.1:19001",
			}},
		},
	}
	node, err := env.Node("owner")
	if err != nil {
		t.Fatalf("resolve owner node: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := env.StartNode(ctx, node); err != nil {
		t.Fatalf("start node: %v", err)
	}

	for _, command := range commands {
		if strings.HasPrefix(command, "docker build ") {
			t.Fatalf("StartNode unexpectedly rebuilt the image: %v", commands)
		}
	}
}
