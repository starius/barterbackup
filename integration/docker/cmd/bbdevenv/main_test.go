package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"barterbackup/integration/docker/harness"
)

func TestRunWithoutCommandPrintsUsage(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), nil, bytes.NewReader(nil), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unexpected exit code: got %d want 2", code)
	}
	if !strings.Contains(stderr.String(), "Usage: bbdevenv") {
		t.Fatalf("missing usage output: %s", stderr.String())
	}
}

func TestRunAcceptsGoRunArgumentSeparator(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"--", "status", "--help"},
		bytes.NewReader(nil),
		&stdout,
		&stderr,
	)
	if code != 2 {
		t.Fatalf("unexpected exit code: got %d want 2", code)
	}
	if !strings.Contains(stderr.String(), "status does not take positional arguments") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestFindBBCLIBinaryHonorsOverride(t *testing.T) {
	override := filepath.Join(t.TempDir(), "bbcli")
	if err := os.WriteFile(override, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write override binary: %v", err)
	}
	t.Setenv("BB_DOCKER_BBCLI_BIN", override)

	binary, err := findBBCLIBinary(t.TempDir())
	if err != nil {
		t.Fatalf("find bbcli with override: %v", err)
	}
	if binary != override {
		t.Fatalf("unexpected override path: got %s want %s", binary, override)
	}
}

func TestBuildBBCLIInvocationUsesSelectedNodeContext(t *testing.T) {
	t.Parallel()

	workRoot := t.TempDir()
	repoRoot := filepath.Join(workRoot, "repo")
	if err := os.MkdirAll(repoRoot, 0o755); err != nil {
		t.Fatalf("create repo root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "flake.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write flake marker: %v", err)
	}
	bbcliBinary := filepath.Join(
		repoRoot,
		"target-static",
		testStaticTargetTriple(t),
		testStaticTargetTriple(t),
		"release",
		"bbcli",
	)
	if err := os.MkdirAll(filepath.Dir(bbcliBinary), 0o755); err != nil {
		t.Fatalf("create bbcli dir: %v", err)
	}
	if err := os.WriteFile(bbcliBinary, []byte("bbcli"), 0o755); err != nil {
		t.Fatalf("write bbcli binary fixture: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(workRoot, "manual", "lab"), 0o755); err != nil {
		t.Fatalf("create environment dir: %v", err)
	}
	manifestBytes := []byte(`{
  "version": 1,
  "name": "lab",
  "repo_root": "` + repoRoot + `",
  "image_tag": "barterbackup-integration:local",
  "chutney_data_dir": "` + filepath.Join(workRoot, "manual", "lab", "chutney") + `",
  "clock_mode": "real",
  "synthetic_clock": {"unix_seconds": 0, "nanoseconds": 0},
  "disable_maintenance": false,
  "created_at_unix_second": 0,
  "nodes": [
    {
      "name": "owner",
      "index": 0,
      "container_name": "bb-lab-owner",
      "data_dir": "` + filepath.Join(workRoot, "manual", "lab", "owner") + `",
      "local_addr": "127.0.0.1:19001"
    }
  ]
}
`)
	if err := os.WriteFile(filepath.Join(workRoot, "manual", "lab", "manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	env, err := harness.LoadEnvironment("lab", workRoot)
	if err != nil {
		t.Fatalf("load environment: %v", err)
	}
	node, err := env.Node("owner")
	if err != nil {
		t.Fatalf("load node: %v", err)
	}
	invocation, err := buildBBCLIInvocation(env, node, []string{"state"})
	if err != nil {
		t.Fatalf("build bbcli invocation: %v", err)
	}
	if invocation.binary != bbcliBinary {
		t.Fatalf("unexpected bbcli binary: got %s want %s", invocation.binary, bbcliBinary)
	}
	if len(invocation.args) != 1 || invocation.args[0] != "state" {
		t.Fatalf("unexpected bbcli args: %+v", invocation.args)
	}
	if !containsString(invocation.env, "BBCLI_LOCAL_ADDR=https://127.0.0.1:19001") {
		t.Fatalf("missing local addr env: %+v", invocation.env)
	}
	if !containsString(invocation.env, "BBCLI_DATA_DIR="+filepath.Join(workRoot, "manual", "lab", "owner")) {
		t.Fatalf("missing data dir env: %+v", invocation.env)
	}
}

func TestPrintClockStatusIncludesSyntheticFields(t *testing.T) {
	t.Parallel()

	workRoot := t.TempDir()
	repoRoot := filepath.Join(workRoot, "repo")
	if err := os.MkdirAll(repoRoot, 0o755); err != nil {
		t.Fatalf("create repo root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "flake.nix"), []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write flake marker: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workRoot, "manual", "lab"), 0o755); err != nil {
		t.Fatalf("create environment dir: %v", err)
	}
	manifestBytes := []byte(`{
  "version": 1,
  "name": "lab",
  "repo_root": "` + repoRoot + `",
  "image_tag": "barterbackup-integration:local",
  "chutney_data_dir": "` + filepath.Join(workRoot, "manual", "lab", "chutney") + `",
  "clock_mode": "synthetic",
  "synthetic_clock": {"unix_seconds": 1234, "nanoseconds": 5},
  "disable_maintenance": false,
  "created_at_unix_second": 0,
  "nodes": []
}
`)
	if err := os.WriteFile(filepath.Join(workRoot, "manual", "lab", "manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	env, err := harness.LoadEnvironment("lab", workRoot)
	if err != nil {
		t.Fatalf("load environment: %v", err)
	}
	var output bytes.Buffer
	printClockStatus(&output, env)
	if !strings.Contains(output.String(), "clock_mode: synthetic") {
		t.Fatalf("missing synthetic clock mode: %s", output.String())
	}
	if !strings.Contains(output.String(), "synthetic_time_unix_seconds: 1234") {
		t.Fatalf("missing synthetic clock seconds: %s", output.String())
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func testStaticTargetTriple(t *testing.T) string {
	t.Helper()

	switch runtime.GOARCH {
	case "amd64":
		return "x86_64-unknown-linux-musl"
	case "arm64":
		return "aarch64-unknown-linux-musl"
	default:
		t.Fatalf("unsupported GOARCH for static binary fixture: %s", runtime.GOARCH)
		return ""
	}
}
