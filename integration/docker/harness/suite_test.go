package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindStaticBBDBinaryForGOARCHPrefersMatchingArchitecture(t *testing.T) {
	repoRoot := t.TempDir()

	amd64Binary := filepath.Join(
		repoRoot,
		"target-static",
		"x86_64-unknown-linux-musl",
		"x86_64-unknown-linux-musl",
		"release",
		"bbd",
	)
	arm64Binary := filepath.Join(
		repoRoot,
		"target-static",
		"aarch64-unknown-linux-musl",
		"aarch64-unknown-linux-musl",
		"release",
		"bbd",
	)
	for _, binary := range []string{amd64Binary, arm64Binary} {
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			t.Fatalf("create static binary dir: %v", err)
		}
		if err := os.WriteFile(binary, []byte("bbd"), 0o755); err != nil {
			t.Fatalf("write static binary fixture: %v", err)
		}
	}

	selectedAMD64, err := findStaticBBDBinaryForGOARCH(repoRoot, "amd64")
	if err != nil {
		t.Fatalf("find amd64 binary: %v", err)
	}
	if selectedAMD64 != amd64Binary {
		t.Fatalf("expected amd64 binary %s, got %s", amd64Binary, selectedAMD64)
	}

	selectedARM64, err := findStaticBBDBinaryForGOARCH(repoRoot, "arm64")
	if err != nil {
		t.Fatalf("find arm64 binary: %v", err)
	}
	if selectedARM64 != arm64Binary {
		t.Fatalf("expected arm64 binary %s, got %s", arm64Binary, selectedARM64)
	}
}

func TestFindStaticBBDBinaryForGOARCHRejectsUnsupportedArchitecture(t *testing.T) {
	_, err := findStaticBBDBinaryForGOARCH(t.TempDir(), "riscv64")
	if err == nil {
		t.Fatal("expected unsupported architecture error")
	}
	if got := err.Error(); got != "Docker integration tests do not support GOARCH=riscv64" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestFindStaticBBCLIBinaryForGOARCHPrefersMatchingArchitecture(t *testing.T) {
	repoRoot := t.TempDir()

	amd64Binary := filepath.Join(
		repoRoot,
		"target-static",
		"x86_64-unknown-linux-musl",
		"x86_64-unknown-linux-musl",
		"release",
		"bbcli",
	)
	arm64Binary := filepath.Join(
		repoRoot,
		"target-static",
		"aarch64-unknown-linux-musl",
		"aarch64-unknown-linux-musl",
		"release",
		"bbcli",
	)
	for _, binary := range []string{amd64Binary, arm64Binary} {
		if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
			t.Fatalf("create static binary dir: %v", err)
		}
		if err := os.WriteFile(binary, []byte("bbcli"), 0o755); err != nil {
			t.Fatalf("write static binary fixture: %v", err)
		}
	}

	selectedAMD64, err := findStaticBBCLIBinaryForGOARCH(repoRoot, "amd64")
	if err != nil {
		t.Fatalf("find amd64 binary: %v", err)
	}
	if selectedAMD64 != amd64Binary {
		t.Fatalf("expected amd64 binary %s, got %s", amd64Binary, selectedAMD64)
	}

	selectedARM64, err := findStaticBBCLIBinaryForGOARCH(repoRoot, "arm64")
	if err != nil {
		t.Fatalf("find arm64 binary: %v", err)
	}
	if selectedARM64 != arm64Binary {
		t.Fatalf("expected arm64 binary %s, got %s", arm64Binary, selectedARM64)
	}
}

func TestFindStaticBBCLIBinaryForGOARCHRejectsUnsupportedArchitecture(t *testing.T) {
	_, err := findStaticBBCLIBinaryForGOARCH(t.TempDir(), "riscv64")
	if err == nil {
		t.Fatal("expected unsupported architecture error")
	}
	if got := err.Error(); got != "Docker integration tests do not support GOARCH=riscv64" {
		t.Fatalf("unexpected error: %q", got)
	}
}
