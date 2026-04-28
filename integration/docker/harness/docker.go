package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Node represents one bbd container plus its host-side bind-mounted state.
type Node struct {
	suite                         *Suite
	name                          string
	containerName                 string
	dataDir                       string
	passwdPath                    string
	groupPath                     string
	localAddr                     string
	password                      string
	testClock                     bool
	disableMaintenance            bool
	peerMetadataFlushDelaySeconds uint64
	artiConfigOptions             ArtiConfigOptions
}

// Name returns the logical test node name.
func (n *Node) Name() string {
	return n.name
}

// LocalAddr returns the node's host-side local clirpc address.
func (n *Node) LocalAddr() string {
	return n.localAddr
}

// ContainerName returns the backing Docker container name.
func (n *Node) ContainerName() string {
	return n.containerName
}

// DataDir returns the node's host-side data directory.
func (n *Node) DataDir() string {
	return n.dataDir
}

// EnableTestClock starts this node with the hidden daemon test clock enabled.
func (n *Node) EnableTestClock() {
	n.testClock = true
}

// DisableMaintenance starts this node with hidden background maintenance disabled.
func (n *Node) DisableMaintenance() {
	n.disableMaintenance = true
}

// SetPeerMetadataFlushDelaySeconds overrides the hidden low-value peer
// metadata flush delay used by this daemon instance.
func (n *Node) SetPeerMetadataFlushDelaySeconds(seconds uint64) {
	n.peerMetadataFlushDelaySeconds = seconds
}

// SetArtiStateDir renders this node's Arti config with an explicit state dir.
func (n *Node) SetArtiStateDir(path string) {
	n.artiConfigOptions = ArtiConfigOptions{ExplicitStateDir: path}
}

// OmitArtiStateDir omits storage.state_dir from this node's rendered Arti config.
func (n *Node) OmitArtiStateDir() {
	n.artiConfigOptions = ArtiConfigOptions{OmitStateDir: true}
}

// StartLocked starts the daemon container without initializing or unlocking it.
func (n *Node) StartLocked(ctx context.Context) error {
	n.ForceRemove(ctx)
	if n.suite.artiConfig != nil {
		if _, err := n.suite.artiConfig.WriteNodeConfig(n.dataDir, n.artiConfigOptions); err != nil {
			return err
		}
	}
	args := n.dockerRunArgs()
	if n.testClock {
		args = append(args, "--test-clock")
	}
	if n.disableMaintenance {
		args = append(args, "--disable-maintenance")
	}
	if n.peerMetadataFlushDelaySeconds != 0 {
		args = append(args, "--peer-metadata-flush-delay-secs", strconv.FormatUint(n.peerMetadataFlushDelaySeconds, 10))
	}
	_, err := runCommand(
		ctx,
		n.suite.repoRoot,
		nil,
		"docker",
		args...,
	)
	if err != nil {
		return fmt.Errorf("start %s container: %w", n.name, err)
	}
	return nil
}

func (n *Node) dockerRunArgs() []string {
	args := []string{
		"run",
		"-d",
		"--name",
		n.containerName,
		"--user",
		currentDockerUser(),
		"--network",
		"host",
		"-v",
		fmt.Sprintf("%s:/data", n.dataDir),
		"-v",
		fmt.Sprintf("%s:/etc/passwd:ro", n.passwdPath),
		"-v",
		fmt.Sprintf("%s:/etc/group:ro", n.groupPath),
		n.suite.imageTag,
		"--data-dir",
		"/data",
		"--local-addr",
		n.localAddr,
	}
	if n.suite.artiConfig != nil {
		args = append(args, "--arti-config", "/data/arti.toml")
	}
	return args
}

// ForceRemove removes the node container if it still exists.
func (n *Node) ForceRemove(ctx context.Context) {
	_, _ = runCommand(ctx, n.suite.repoRoot, nil, "docker", "rm", "-f", n.containerName)
}

// ContainerState returns the backing Docker container runtime state.
func (n *Node) ContainerState(ctx context.Context) (string, error) {
	output, err := runCommand(
		ctx,
		n.suite.repoRoot,
		nil,
		"docker",
		"inspect",
		"-f",
		"{{.State.Status}}",
		n.containerName,
	)
	if err != nil {
		if strings.Contains(err.Error(), "No such object") {
			return "", os.ErrNotExist
		}
		return "", err
	}
	state := string(bytesTrimSpace(output))
	if state == "" {
		return "", errors.New("docker inspect returned an empty container state")
	}
	return state, nil
}

// CurrentLogs returns the current docker logs output for the node.
func (n *Node) CurrentLogs(ctx context.Context) ([]byte, error) {
	output, err := runCommand(ctx, n.suite.repoRoot, nil, "docker", "logs", n.containerName)
	if err != nil {
		if strings.Contains(err.Error(), "No such container") {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return output, nil
}

// FetchLogs writes the node's container logs to logPath.
func (n *Node) FetchLogs(ctx context.Context, logPath string) error {
	output, err := n.CurrentLogs(ctx)
	if err != nil {
		output = []byte(err.Error())
	}
	if writeErr := os.WriteFile(logPath, output, 0o600); writeErr != nil {
		return fmt.Errorf("write %s logs: %w", n.name, writeErr)
	}
	return nil
}

func (n *Node) keysDir() string {
	return filepath.Join(n.dataDir, "cli-keys")
}

func makeContainerName(testName string, nodeName string) string {
	sanitizedTest := sanitizeName(testName)
	sanitizedNode := sanitizeName(nodeName)
	return fmt.Sprintf("bb-%s-%s", sanitizedTest, sanitizedNode)
}

func sanitizeName(value string) string {
	lower := strings.ToLower(value)
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-", ".", "-")
	cleaned := replacer.Replace(lower)
	cleaned = strings.Trim(cleaned, "-")
	if cleaned == "" {
		return "node"
	}
	return cleaned
}

func currentDockerUser() string {
	return strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
}

func writeContainerIdentityFiles(dir string, uid int, gid int) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create container identity dir: %w", err)
	}
	username := "bbtest"
	groupname := "bbtest"
	if uid == 0 {
		username = "root"
	}
	if gid == 0 {
		groupname = "root"
	}

	passwdPath := filepath.Join(dir, "passwd")
	passwdContents := fmt.Sprintf(
		"%s:x:%d:%d:BarterBackup Test User:/nonexistent:/sbin/nologin\n",
		username,
		uid,
		gid,
	)
	if err := os.WriteFile(passwdPath, []byte(passwdContents), 0o644); err != nil {
		return "", "", fmt.Errorf("write container passwd: %w", err)
	}

	groupPath := filepath.Join(dir, "group")
	groupContents := fmt.Sprintf("%s:x:%d:\n", groupname, gid)
	if err := os.WriteFile(groupPath, []byte(groupContents), 0o644); err != nil {
		return "", "", fmt.Errorf("write container group: %w", err)
	}

	return passwdPath, groupPath, nil
}
