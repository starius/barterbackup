package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

func TestTranslateChutneyConfig(t *testing.T) {
	rawBytes, err := os.ReadFile(filepath.Join("..", "testdata", "chutney-arti.toml"))
	if err != nil {
		t.Fatalf("read test fixture: %v", err)
	}

	var raw rawChutneyConfig
	if err := toml.Unmarshal(rawBytes, &raw); err != nil {
		t.Fatalf("decode raw chutney config: %v", err)
	}

	translated := translateChutneyConfig(raw)
	if translated.Storage.Keystore.Primary.Kind != "ephemeral" {
		t.Fatalf("unexpected keystore kind: %q", translated.Storage.Keystore.Primary.Kind)
	}
	if len(translated.TorNetwork.FallbackCaches) != 2 {
		t.Fatalf("unexpected fallback cache count: %d", len(translated.TorNetwork.FallbackCaches))
	}
	if len(translated.TorNetwork.Authorities.V3Idents) != 3 {
		t.Fatalf("unexpected authority count: %d", len(translated.TorNetwork.Authorities.V3Idents))
	}
	if translated.TorNetwork.Authorities.V3Idents[0] != "30A3F82DE0485F8666C05CC807FD7EDE832ABD8A" {
		t.Fatalf("unexpected first authority id: %q", translated.TorNetwork.Authorities.V3Idents[0])
	}
	if translated.TorNetwork.Authorities.V3Idents[2] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected third authority id: %q", translated.TorNetwork.Authorities.V3Idents[2])
	}
	if translated.AddressFilter["allow_local_addrs"] != true {
		t.Fatalf("allow_local_addrs was not preserved: %#v", translated.AddressFilter)
	}
	if translated.PathRules["ipv4_subnet_family_prefix"] != int64(33) {
		t.Fatalf("unexpected ipv4_subnet_family_prefix: %#v", translated.PathRules)
	}
	if len(translated.TorNetwork.Authorities.Uploads) != 2 {
		t.Fatalf("unexpected authority upload count: %d", len(translated.TorNetwork.Authorities.Uploads))
	}
	if translated.TorNetwork.Authorities.Uploads[0][0] != "127.0.0.1:7100" {
		t.Fatalf("unexpected first authority upload address: %#v", translated.TorNetwork.Authorities.Uploads)
	}
	rendered, err := toml.Marshal(translated)
	if err != nil {
		t.Fatalf("encode translated config: %v", err)
	}
	if !regexp.MustCompile(`(?m)^\s*\[path_rules\]`).Match(rendered) {
		t.Fatalf("translated config unexpectedly dropped path_rules:\n%s", string(rendered))
	}
}

func TestWriteNodeConfigUsesExplicitStateDirOverride(t *testing.T) {
	network := &ChutneyNetwork{
		baseConfig: translateChutneyConfig(rawChutneyConfig{}),
	}
	nodeDataDir := t.TempDir()

	configPath, err := network.WriteNodeConfig(nodeDataDir, ArtiConfigOptions{
		ExplicitStateDir: "/data/custom-tor-state",
	})
	if err != nil {
		t.Fatalf("write node config: %v", err)
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read node config: %v", err)
	}
	var rendered translatedArtiConfig
	if err := toml.Unmarshal(configBytes, &rendered); err != nil {
		t.Fatalf("decode node config: %v", err)
	}
	if rendered.Storage.StateDir != "/data/custom-tor-state" {
		t.Fatalf("unexpected state_dir: got %q", rendered.Storage.StateDir)
	}
}

func TestWriteNodeConfigCanOmitStateDir(t *testing.T) {
	network := &ChutneyNetwork{
		baseConfig: translateChutneyConfig(rawChutneyConfig{}),
	}
	nodeDataDir := t.TempDir()

	configPath, err := network.WriteNodeConfig(nodeDataDir, ArtiConfigOptions{
		OmitStateDir: true,
	})
	if err != nil {
		t.Fatalf("write node config: %v", err)
	}

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read node config: %v", err)
	}
	if regexp.MustCompile(`(?m)^\s*state_dir\s*=`).Match(configBytes) {
		t.Fatalf("rendered config unexpectedly contains state_dir:\n%s", string(configBytes))
	}
}

func TestWaitForHealthyStatusRetriesUntilSuccess(t *testing.T) {
	var attempts int
	network := &ChutneyNetwork{
		repoDir:      ".",
		commandEnv:   nil,
		chutneyEntry: "chutney",
	}

	originalRunCommand := runCommandFunc
	runCommandFunc = func(
		_ context.Context,
		_ string,
		_ []string,
		_ string,
		_ ...string,
	) ([]byte, error) {
		attempts++
		if attempts < 3 {
			return nil, errors.New("status failed")
		}
		return []byte("ok"), nil
	}
	defer func() {
		runCommandFunc = originalRunCommand
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := network.waitForHealthyStatus(ctx); err != nil {
		t.Fatalf("waitForHealthyStatus returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestWaitForHealthyStatusReturnsLastErrorOnTimeout(t *testing.T) {
	network := &ChutneyNetwork{
		repoDir:      ".",
		commandEnv:   nil,
		chutneyEntry: "chutney",
	}

	originalRunCommand := runCommandFunc
	expected := errors.New("status failed")
	runCommandFunc = func(
		_ context.Context,
		_ string,
		_ []string,
		_ string,
		_ ...string,
	) ([]byte, error) {
		return nil, expected
	}
	defer func() {
		runCommandFunc = originalRunCommand
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := network.waitForHealthyStatus(ctx); !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestDisableChutneyTorSandboxRewritesTorrcFiles(t *testing.T) {
	tempDir := t.TempDir()
	nodeDir := filepath.Join(tempDir, "nodes.123", "000a")
	if err := os.MkdirAll(nodeDir, 0o755); err != nil {
		t.Fatalf("create node dir: %v", err)
	}

	torrcPath := filepath.Join(nodeDir, "torrc")
	original := []byte("ClientOnly 0\nSandbox 1\nLog notice stdout\n")
	if err := os.WriteFile(torrcPath, original, 0o600); err != nil {
		t.Fatalf("write torrc: %v", err)
	}

	if err := disableChutneyTorSandbox(tempDir); err != nil {
		t.Fatalf("disableChutneyTorSandbox returned error: %v", err)
	}

	updated, err := os.ReadFile(torrcPath)
	if err != nil {
		t.Fatalf("read torrc: %v", err)
	}
	if string(updated) != "ClientOnly 0\nSandbox 0\nLog notice stdout\n" {
		t.Fatalf("unexpected torrc contents: %q", string(updated))
	}
}

func TestDisableChutneyTorSandboxLeavesMissingDirectiveUnchanged(t *testing.T) {
	tempDir := t.TempDir()
	nodeDir := filepath.Join(tempDir, "nodes.123", "001r")
	if err := os.MkdirAll(nodeDir, 0o755); err != nil {
		t.Fatalf("create node dir: %v", err)
	}

	torrcPath := filepath.Join(nodeDir, "torrc")
	original := []byte("ClientOnly 0\nLog notice stdout\n")
	if err := os.WriteFile(torrcPath, original, 0o600); err != nil {
		t.Fatalf("write torrc: %v", err)
	}

	if err := disableChutneyTorSandbox(tempDir); err != nil {
		t.Fatalf("disableChutneyTorSandbox returned error: %v", err)
	}

	updated, err := os.ReadFile(torrcPath)
	if err != nil {
		t.Fatalf("read torrc: %v", err)
	}
	if string(updated) != string(original) {
		t.Fatalf("expected unchanged torrc, got %q", string(updated))
	}
}

func TestCollectChutneyListenerPIDs(t *testing.T) {
	pids := map[int]struct{}{}
	output := []byte(`
LISTEN 0 128 127.0.0.1:5101 0.0.0.0:* users:(("tor",pid=111,fd=7))
LISTEN 0 128 127.0.0.1:9999 0.0.0.0:* users:(("ignored",pid=222,fd=7))
LISTEN 0 128 [::1]:8003 [::]:* users:(("tor",pid=333,fd=7),("python3",pid=444,fd=8))
`)

	collectChutneyListenerPIDs(pids, regexp.MustCompile(`pid=(\d+)`), output)

	if len(pids) != 3 {
		t.Fatalf("unexpected pid count: %+v", pids)
	}
	if _, ok := pids[111]; !ok {
		t.Fatalf("missing pid 111: %+v", pids)
	}
	if _, ok := pids[333]; !ok {
		t.Fatalf("missing pid 333: %+v", pids)
	}
	if _, ok := pids[444]; !ok {
		t.Fatalf("missing pid 444: %+v", pids)
	}
	if _, ok := pids[222]; ok {
		t.Fatalf("unexpected non-Chutney pid: %+v", pids)
	}
}

func TestCollectPIDList(t *testing.T) {
	pids := map[int]struct{}{}
	collectPIDList(pids, []byte("123\n456\nnot-a-pid\n123\n"))

	if len(pids) != 2 {
		t.Fatalf("unexpected pid count: %+v", pids)
	}
	if _, ok := pids[123]; !ok {
		t.Fatalf("missing pid 123: %+v", pids)
	}
	if _, ok := pids[456]; !ok {
		t.Fatalf("missing pid 456: %+v", pids)
	}
}
