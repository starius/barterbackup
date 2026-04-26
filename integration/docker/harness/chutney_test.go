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
	if len(translated.TorNetwork.Authorities) != 3 {
		t.Fatalf("unexpected authority count: %d", len(translated.TorNetwork.Authorities))
	}
	if translated.TorNetwork.Authorities[0].Name != "auth1" {
		t.Fatalf("unexpected first authority name: %q", translated.TorNetwork.Authorities[0].Name)
	}
	if translated.TorNetwork.Authorities[2].V3Ident != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected third authority id: %q", translated.TorNetwork.Authorities[2].V3Ident)
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
