package harness

import (
	"os"
	"path/filepath"
	"testing"

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
