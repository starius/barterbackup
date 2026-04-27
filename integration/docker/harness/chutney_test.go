package harness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
