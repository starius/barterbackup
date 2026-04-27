package harness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteContainerIdentityFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	passwdPath, groupPath, err := writeContainerIdentityFiles(root, 1234, 5678)
	if err != nil {
		t.Fatalf("write container identity files: %v", err)
	}

	passwdContents, err := os.ReadFile(passwdPath)
	if err != nil {
		t.Fatalf("read passwd file: %v", err)
	}
	if string(passwdContents) != "bbtest:x:1234:5678:BarterBackup Test User:/nonexistent:/sbin/nologin\n" {
		t.Fatalf("unexpected passwd contents: %q", string(passwdContents))
	}

	groupContents, err := os.ReadFile(groupPath)
	if err != nil {
		t.Fatalf("read group file: %v", err)
	}
	if string(groupContents) != "bbtest:x:5678:\n" {
		t.Fatalf("unexpected group contents: %q", string(groupContents))
	}
}

func TestScenarioAddNodeCreatesContainerIdentityFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	scenario := &Scenario{
		suite:   &Suite{imageTag: "barterbackup-integration:local"},
		rootDir: root,
	}

	node, err := scenario.AddNode("owner", "password")
	if err != nil {
		t.Fatalf("add node: %v", err)
	}

	if node.passwdPath == "" || node.groupPath == "" {
		t.Fatalf("expected container identity paths to be populated")
	}
	if _, err := os.Stat(node.passwdPath); err != nil {
		t.Fatalf("stat passwd path: %v", err)
	}
	if _, err := os.Stat(node.groupPath); err != nil {
		t.Fatalf("stat group path: %v", err)
	}
	if filepath.Dir(node.passwdPath) != filepath.Join(node.DataDir(), "container-etc") {
		t.Fatalf("unexpected passwd parent dir: %s", filepath.Dir(node.passwdPath))
	}
}

func TestNodeDockerRunArgsMountIdentityFiles(t *testing.T) {
	t.Parallel()

	node := &Node{
		suite:         &Suite{imageTag: "barterbackup-integration:local"},
		name:          "owner",
		containerName: "bb-owner",
		dataDir:       "/tmp/data",
		passwdPath:    "/tmp/passwd",
		groupPath:     "/tmp/group",
		localAddr:     "127.0.0.1:19001",
	}

	args := node.dockerRunArgs()
	mountedPasswd := false
	mountedGroup := false
	for index := 0; index+1 < len(args); index++ {
		if args[index] != "-v" {
			continue
		}
		if args[index+1] == "/tmp/passwd:/etc/passwd:ro" {
			mountedPasswd = true
		}
		if args[index+1] == "/tmp/group:/etc/group:ro" {
			mountedGroup = true
		}
	}
	if !mountedPasswd {
		t.Fatalf("docker args did not mount passwd file: %v", args)
	}
	if !mountedGroup {
		t.Fatalf("docker args did not mount group file: %v", args)
	}
}
