package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Node represents one bbd container plus its host-side bind-mounted state.
type Node struct {
	suite              *Suite
	name               string
	containerName      string
	dataDir            string
	localAddr          string
	password           string
	testClock          bool
	disableMaintenance bool
}

// Name returns the logical test node name.
func (n *Node) Name() string {
	return n.name
}

// LocalAddr returns the node's host-side local clirpc address.
func (n *Node) LocalAddr() string {
	return n.localAddr
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

// StartLocked starts the daemon container without initializing or unlocking it.
func (n *Node) StartLocked(ctx context.Context) error {
	n.ForceRemove(ctx)
	if _, err := n.suite.network.WriteNodeConfig(n.dataDir); err != nil {
		return err
	}
	dockerUser := currentDockerUser()
	args := []string{
		"run",
		"-d",
		"--name",
		n.containerName,
		"--user",
		dockerUser,
		"--network",
		"host",
		"-v",
		fmt.Sprintf("%s:/data", n.dataDir),
		n.suite.imageTag,
		"--data-dir",
		"/data",
		"--local-addr",
		n.localAddr,
		"--arti-config",
		"/data/arti.toml",
	}
	if n.testClock {
		args = append(args, "--test-clock")
	}
	if n.disableMaintenance {
		args = append(args, "--disable-maintenance")
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

// ForceRemove removes the node container if it still exists.
func (n *Node) ForceRemove(ctx context.Context) {
	_, _ = runCommand(ctx, n.suite.repoRoot, nil, "docker", "rm", "-f", n.containerName)
}

// FetchLogs writes the node's container logs to logPath.
func (n *Node) FetchLogs(ctx context.Context, logPath string) error {
	output, err := runCommand(ctx, n.suite.repoRoot, nil, "docker", "logs", n.containerName)
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
