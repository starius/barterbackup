package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const environmentManifestVersion = 1

// ClockMode selects whether a persistent environment uses wall-clock time or
// the daemon's hidden logical test clock.
type ClockMode string

const (
	// ClockModeReal uses the daemon's normal wall clock.
	ClockModeReal ClockMode = "real"
	// ClockModeSynthetic uses the hidden logical test clock on every node.
	ClockModeSynthetic ClockMode = "synthetic"
)

// SyntheticClock captures one environment-wide logical timestamp.
type SyntheticClock struct {
	UnixSeconds uint64 `json:"unix_seconds"`
	Nanoseconds uint32 `json:"nanoseconds"`
}

// EnvironmentNodeManifest stores one persistent node definition.
type EnvironmentNodeManifest struct {
	Name          string `json:"name"`
	Index         int    `json:"index"`
	ContainerName string `json:"container_name"`
	DataDir       string `json:"data_dir"`
	LocalAddr     string `json:"local_addr"`
}

// EnvironmentManifest stores one persistent manual Docker environment.
type EnvironmentManifest struct {
	Version             int                       `json:"version"`
	Name                string                    `json:"name"`
	RepoRoot            string                    `json:"repo_root"`
	ImageTag            string                    `json:"image_tag"`
	ChutneyDataDir      string                    `json:"chutney_data_dir"`
	ClockMode           ClockMode                 `json:"clock_mode"`
	SyntheticClock      SyntheticClock            `json:"synthetic_clock"`
	DisableMaintenance  bool                      `json:"disable_maintenance"`
	CreatedAtUnixSecond int64                     `json:"created_at_unix_second"`
	Nodes               []EnvironmentNodeManifest `json:"nodes"`
}

// EnvironmentConfig describes one persistent manual Docker environment.
type EnvironmentConfig struct {
	Name                  string
	BaseWorkRoot          string
	NodeCount             int
	NodeNames             []string
	ClockMode             ClockMode
	ClockModeSpecified    bool
	DisableMaintenance    bool
	DisableMaintenanceSet bool
	ForceRecreate         bool
}

// Environment owns one persistent manual Docker/Chutney environment.
type Environment struct {
	suite        *Suite
	rootDir      string
	logsDir      string
	manifestPath string
	manifest     EnvironmentManifest
}

// EnvironmentStatus summarizes one persistent environment for operator output.
type EnvironmentStatus struct {
	Name           string
	RootDir        string
	ClockMode      ClockMode
	SyntheticTime  SyntheticClock
	ChutneyHealthy bool
	NodeStatuses   []NodeStatus
}

// NodeStatus summarizes one node inside a persistent environment.
type NodeStatus struct {
	Name               string
	Index              int
	ContainerName      string
	ContainerState     string
	LocalAddr          string
	StorageInitialized bool
	ServerOnion        string
	PeerRuntimeState   string
	PeerRuntimeError   string
	SelfPeerCheckState string
	SelfPeerCheckError string
	StateError         string
}

// PrepareEnvironment creates or reuses one persistent manual environment.
func PrepareEnvironment(ctx context.Context, config EnvironmentConfig) (*Environment, error) {
	if config.Name == "" {
		config.Name = "default"
	}
	if config.ClockMode == "" {
		config.ClockMode = ClockModeReal
	}
	if config.ClockMode != ClockModeReal && config.ClockMode != ClockModeSynthetic {
		return nil, fmt.Errorf("unsupported clock mode %q", config.ClockMode)
	}

	baseSuite, err := prepareBaseSuite(config.BaseWorkRoot)
	if err != nil {
		return nil, err
	}
	rootDir := environmentRootDir(baseSuite.workRoot, config.Name)
	if config.ForceRecreate {
		existing, loadErr := LoadEnvironment(config.Name, config.BaseWorkRoot)
		if loadErr == nil {
			if err := existing.Destroy(ctx, false); err != nil {
				return nil, err
			}
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			return nil, loadErr
		}
	}

	if _, err := os.Stat(filepath.Join(rootDir, "manifest.json")); err == nil {
		env, err := LoadEnvironment(config.Name, config.BaseWorkRoot)
		if err != nil {
			return nil, err
		}
		if err := env.validateConfig(config); err != nil {
			return nil, err
		}
		if err := env.ensureNetwork(ctx); err != nil {
			return nil, err
		}
		if err := env.StartAll(ctx); err != nil {
			return nil, err
		}
		return env, nil
	}
	if config.NodeCount == 0 {
		config.NodeCount = 3
	}
	if len(config.NodeNames) == 0 {
		config.NodeNames = make([]string, 0, config.NodeCount)
		for index := 0; index < config.NodeCount; index++ {
			config.NodeNames = append(config.NodeNames, fmt.Sprintf("node%d", index))
		}
	}
	if len(config.NodeNames) != config.NodeCount {
		return nil, fmt.Errorf(
			"expected %d node names, got %d",
			config.NodeCount,
			len(config.NodeNames),
		)
	}
	if err := validateNodeNames(config.NodeNames); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		return nil, fmt.Errorf("create environment root: %w", err)
	}
	logsDir := filepath.Join(rootDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create environment logs: %w", err)
	}

	manifest := EnvironmentManifest{
		Version:             environmentManifestVersion,
		Name:                config.Name,
		RepoRoot:            baseSuite.repoRoot,
		ImageTag:            baseSuite.imageTag,
		ChutneyDataDir:      persistentChutneyDataDir(baseSuite.workRoot, config.Name),
		ClockMode:           config.ClockMode,
		DisableMaintenance:  config.DisableMaintenance,
		CreatedAtUnixSecond: time.Now().Unix(),
	}
	if config.ClockMode == ClockModeSynthetic {
		now := time.Now().UTC()
		manifest.SyntheticClock = SyntheticClock{
			UnixSeconds: uint64(now.Unix()),
			Nanoseconds: uint32(now.Nanosecond()),
		}
	}
	for index, name := range config.NodeNames {
		nodeDir := filepath.Join(rootDir, sanitizeName(name))
		localAddr, err := allocateLocalAddr()
		if err != nil {
			return nil, fmt.Errorf("allocate local address for %s: %w", name, err)
		}
		manifest.Nodes = append(manifest.Nodes, EnvironmentNodeManifest{
			Name:          name,
			Index:         index,
			ContainerName: makeEnvironmentContainerName(rootDir, config.Name, name),
			DataDir:       nodeDir,
			LocalAddr:     localAddr,
		})
	}

	env := &Environment{
		suite:        baseSuite,
		rootDir:      rootDir,
		logsDir:      logsDir,
		manifestPath: filepath.Join(rootDir, "manifest.json"),
		manifest:     manifest,
	}
	if err := env.ensureBuildImage(ctx); err != nil {
		return nil, err
	}
	if err := env.ensureNetwork(ctx); err != nil {
		return nil, err
	}
	if err := env.provisionNodeFilesystems(); err != nil {
		return nil, err
	}
	if err := env.saveManifest(); err != nil {
		return nil, err
	}
	if err := env.StartAll(ctx); err != nil {
		return nil, err
	}
	return env, nil
}

// LoadEnvironment loads one persistent manual environment by name.
func LoadEnvironment(name string, baseWorkRoot string) (*Environment, error) {
	if name == "" {
		name = "default"
	}
	baseSuite, err := prepareBaseSuite(baseWorkRoot)
	if err != nil {
		return nil, err
	}
	rootDir := environmentRootDir(baseSuite.workRoot, name)
	manifestPath := filepath.Join(rootDir, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read environment manifest: %w", err)
	}
	var manifest EnvironmentManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode environment manifest: %w", err)
	}
	if manifest.Version != environmentManifestVersion {
		return nil, fmt.Errorf(
			"unsupported environment manifest version %d",
			manifest.Version,
		)
	}
	if manifest.Name == "" {
		return nil, fmt.Errorf("environment manifest is missing a name")
	}
	if manifest.RepoRoot == "" {
		manifest.RepoRoot = baseSuite.repoRoot
	}
	if manifest.ImageTag == "" {
		manifest.ImageTag = baseSuite.imageTag
	}
	if manifest.ChutneyDataDir == "" {
		manifest.ChutneyDataDir = persistentChutneyDataDir(baseSuite.workRoot, manifest.Name)
	}
	baseSuite.repoRoot = manifest.RepoRoot
	baseSuite.imageTag = manifest.ImageTag
	return &Environment{
		suite:        baseSuite,
		rootDir:      rootDir,
		logsDir:      filepath.Join(rootDir, "logs"),
		manifestPath: manifestPath,
		manifest:     manifest,
	}, nil
}

// Name returns the persistent environment name.
func (e *Environment) Name() string {
	return e.manifest.Name
}

// RootDir returns the persistent environment root directory.
func (e *Environment) RootDir() string {
	return e.rootDir
}

// RepoRoot returns the repository root recorded for this environment.
func (e *Environment) RepoRoot() string {
	return e.suite.repoRoot
}

// StoredLogPath returns the persistent log path for one node name.
func (e *Environment) StoredLogPath(nodeName string) string {
	return e.logPath(nodeName)
}

// ClockMode returns the configured environment clock mode.
func (e *Environment) ClockMode() ClockMode {
	return e.manifest.ClockMode
}

// SyntheticClock returns the current environment logical time.
func (e *Environment) SyntheticClock() SyntheticClock {
	return e.manifest.SyntheticClock
}

// Nodes returns every node defined in the environment manifest.
func (e *Environment) Nodes() []*Node {
	nodes := make([]*Node, 0, len(e.manifest.Nodes))
	for _, manifestNode := range e.manifest.Nodes {
		nodes = append(nodes, e.nodeFromManifest(manifestNode))
	}
	return nodes
}

// Node resolves one node by numeric index or logical name.
func (e *Environment) Node(selector string) (*Node, error) {
	if index, err := strconv.Atoi(selector); err == nil {
		for _, manifestNode := range e.manifest.Nodes {
			if manifestNode.Index == index {
				return e.nodeFromManifest(manifestNode), nil
			}
		}
		return nil, fmt.Errorf("no node with index %d", index)
	}
	for _, manifestNode := range e.manifest.Nodes {
		if manifestNode.Name == selector {
			return e.nodeFromManifest(manifestNode), nil
		}
	}
	return nil, fmt.Errorf("no node named %s", selector)
}

// StartAll starts every environment node.
func (e *Environment) StartAll(ctx context.Context) error {
	for _, node := range e.Nodes() {
		if err := e.StartNode(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

// StartNode starts one node if it is not already running.
func (e *Environment) StartNode(ctx context.Context, node *Node) error {
	if err := e.ensureNetwork(ctx); err != nil {
		return err
	}
	if err := e.ensureNodeFilesystem(node); err != nil {
		return err
	}
	state, err := node.ContainerState(ctx)
	if err == nil && state == "running" {
		if e.manifest.ClockMode == ClockModeSynthetic {
			if err := e.applySyntheticClock(ctx, node); err != nil {
				return err
			}
		}
		return nil
	}
	if err := node.StartLocked(ctx); err != nil {
		return err
	}
	if e.manifest.ClockMode == ClockModeSynthetic {
		if _, err := node.WaitForState(ctx); err != nil {
			return fmt.Errorf("wait for state on %s after start: %w", node.Name(), err)
		}
		if err := e.applySyntheticClock(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

// StopNode stops one node if it is running.
func (e *Environment) StopNode(ctx context.Context, node *Node) error {
	state, err := node.ContainerState(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if state != "running" {
		return nil
	}
	if err := node.FetchLogs(ctx, e.logPath(node.Name())); err != nil {
		return err
	}
	return node.Stop(ctx)
}

// RestartAll restarts every node in place.
func (e *Environment) RestartAll(ctx context.Context) error {
	for _, node := range e.Nodes() {
		if err := e.StopNode(ctx, node); err != nil {
			return err
		}
	}
	for _, node := range e.Nodes() {
		if err := e.StartNode(ctx, node); err != nil {
			return err
		}
	}
	return nil
}

// RecreateNode removes one node's data directory and starts a fresh locked node.
func (e *Environment) RecreateNode(ctx context.Context, node *Node) error {
	if err := e.captureLogsForNode(ctx, node); err != nil {
		return err
	}
	node.ForceRemove(ctx)
	if err := resetNodeDataDir(node.DataDir()); err != nil {
		return fmt.Errorf("reset data dir for %s: %w", node.Name(), err)
	}
	if err := e.StartNode(ctx, node); err != nil {
		return fmt.Errorf("start recreated node %s: %w", node.Name(), err)
	}
	if _, err := node.WaitForState(ctx); err != nil {
		return fmt.Errorf("wait for recreated node %s local state: %w", node.Name(), err)
	}
	return nil
}

// AdvanceSyntheticClock moves every running synthetic node to one new logical time.
func (e *Environment) AdvanceSyntheticClock(ctx context.Context, delta time.Duration) error {
	if e.manifest.ClockMode != ClockModeSynthetic {
		return fmt.Errorf("clock advance requires a synthetic-clock environment")
	}
	if delta < 0 {
		return fmt.Errorf("clock advance duration must be non-negative")
	}
	current := time.Unix(int64(e.manifest.SyntheticClock.UnixSeconds), int64(e.manifest.SyntheticClock.Nanoseconds)).UTC()
	updated := current.Add(delta)
	e.manifest.SyntheticClock = SyntheticClock{
		UnixSeconds: uint64(updated.Unix()),
		Nanoseconds: uint32(updated.Nanosecond()),
	}
	for _, node := range e.Nodes() {
		state, err := node.ContainerState(ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if state != "running" {
			continue
		}
		if err := e.applySyntheticClock(ctx, node); err != nil {
			return err
		}
	}
	return e.saveManifest()
}

// Status gathers the current environment and node runtime summary.
func (e *Environment) Status(ctx context.Context) (*EnvironmentStatus, error) {
	status := &EnvironmentStatus{
		Name:           e.manifest.Name,
		RootDir:        e.rootDir,
		ClockMode:      e.manifest.ClockMode,
		SyntheticTime:  e.manifest.SyntheticClock,
		ChutneyHealthy: false,
	}
	if healthy, err := e.chutneyHealthy(ctx); err != nil {
		return nil, err
	} else {
		status.ChutneyHealthy = healthy
	}
	for _, manifestNode := range e.manifest.Nodes {
		node := e.nodeFromManifest(manifestNode)
		nodeStatus := NodeStatus{
			Name:          manifestNode.Name,
			Index:         manifestNode.Index,
			ContainerName: manifestNode.ContainerName,
			LocalAddr:     manifestNode.LocalAddr,
		}
		containerState, err := node.ContainerState(ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				nodeStatus.ContainerState = "missing"
				status.NodeStatuses = append(status.NodeStatuses, nodeStatus)
				continue
			}
			return nil, err
		}
		nodeStatus.ContainerState = containerState
		if containerState == "running" {
			stateCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout)
			state, stateErr := node.State(stateCtx)
			cancel()
			if stateErr != nil {
				nodeStatus.StateError = stateErr.Error()
			} else {
				nodeStatus.StorageInitialized = state.GetStorageInitialized()
				nodeStatus.ServerOnion = state.GetServerOnion()
				nodeStatus.PeerRuntimeState = state.GetPeerRuntimeState().String()
				nodeStatus.PeerRuntimeError = state.GetPeerRuntimeError()
				nodeStatus.SelfPeerCheckState = state.GetSelfPeerCheckState().String()
				nodeStatus.SelfPeerCheckError = state.GetSelfPeerCheckError()
			}
		}
		status.NodeStatuses = append(status.NodeStatuses, nodeStatus)
	}
	return status, nil
}

// Destroy tears down the environment runtime and optionally keeps its root dir.
func (e *Environment) Destroy(ctx context.Context, keepRoot bool) error {
	for _, node := range e.Nodes() {
		if err := e.captureLogsForNode(ctx, node); err != nil {
			return err
		}
		node.ForceRemove(ctx)
	}
	if e.suite.artiConfig != nil {
		if closeErr := e.suite.artiConfig.Close(); closeErr != nil {
			return closeErr
		}
		e.suite.artiConfig = nil
	} else if e.manifest.ChutneyDataDir != "" {
		if err := e.closePersistentNetwork(); err != nil {
			return err
		}
	}
	if keepRoot {
		return nil
	}
	if e.manifest.ChutneyDataDir != "" {
		if err := os.RemoveAll(e.manifest.ChutneyDataDir); err != nil {
			return fmt.Errorf("remove chutney data dir: %w", err)
		}
	}
	if err := os.RemoveAll(e.rootDir); err != nil {
		return fmt.Errorf("remove environment root: %w", err)
	}
	return nil
}

// PrepareRuntime attaches any runtime dependencies needed for targeted
// lifecycle operations on an already-loaded environment.
func (e *Environment) PrepareRuntime(ctx context.Context) error {
	return e.ensureNetwork(ctx)
}

func (e *Environment) validateConfig(config EnvironmentConfig) error {
	if config.ClockModeSpecified && config.ClockMode != e.manifest.ClockMode {
		return fmt.Errorf(
			"environment %s already exists with clock mode %s",
			e.manifest.Name,
			e.manifest.ClockMode,
		)
	}
	if config.NodeCount != 0 && config.NodeCount != len(e.manifest.Nodes) {
		return fmt.Errorf(
			"environment %s already exists with %d nodes",
			e.manifest.Name,
			len(e.manifest.Nodes),
		)
	}
	if len(config.NodeNames) > 0 {
		if len(config.NodeNames) != len(e.manifest.Nodes) {
			return fmt.Errorf(
				"environment %s already exists with %d nodes",
				e.manifest.Name,
				len(e.manifest.Nodes),
			)
		}
		for index, name := range config.NodeNames {
			if e.manifest.Nodes[index].Name != name {
				return fmt.Errorf(
					"environment %s already exists with node %d named %s",
					e.manifest.Name,
					index,
					e.manifest.Nodes[index].Name,
				)
			}
		}
	}
	if config.DisableMaintenanceSet && config.DisableMaintenance != e.manifest.DisableMaintenance {
		return fmt.Errorf(
			"environment %s already exists with disable-maintenance=%t",
			e.manifest.Name,
			e.manifest.DisableMaintenance,
		)
	}
	return nil
}

func (e *Environment) ensureBuildImage(ctx context.Context) error {
	if err := e.suite.buildImage(ctx); err != nil {
		return err
	}
	return nil
}

func (e *Environment) ensureNetwork(ctx context.Context) error {
	if e.suite.artiConfig != nil {
		return nil
	}
	network, err := PreparePersistentChutneyNetwork(ctx, e.suite.workRoot, e.manifest.ChutneyDataDir)
	if err != nil {
		return err
	}
	e.suite.artiConfig = network
	return nil
}

func (e *Environment) chutneyHealthy(ctx context.Context) (bool, error) {
	network, err := openChutneyNetwork(e.suite.workRoot, e.manifest.ChutneyDataDir)
	if err != nil {
		return false, err
	}
	if err := network.Healthy(ctx); err != nil {
		return false, nil
	}
	return true, nil
}

func (e *Environment) closePersistentNetwork() error {
	network, err := openChutneyNetwork(e.suite.workRoot, e.manifest.ChutneyDataDir)
	if err != nil {
		return err
	}
	return network.Close()
}

func (e *Environment) provisionNodeFilesystems() error {
	for _, node := range e.Nodes() {
		if err := e.ensureNodeFilesystem(node); err != nil {
			return err
		}
	}
	return nil
}

func (e *Environment) ensureNodeFilesystem(node *Node) error {
	if err := os.MkdirAll(node.DataDir(), 0o700); err != nil {
		return fmt.Errorf("create node dir for %s: %w", node.Name(), err)
	}
	passwdPath, groupPath, err := writeContainerIdentityFiles(
		filepath.Join(node.DataDir(), "container-etc"),
		os.Getuid(),
		os.Getgid(),
	)
	if err != nil {
		return fmt.Errorf("create container identity files for %s: %w", node.Name(), err)
	}
	node.passwdPath = passwdPath
	node.groupPath = groupPath
	return nil
}

func (e *Environment) nodeFromManifest(manifestNode EnvironmentNodeManifest) *Node {
	node := &Node{
		suite:              e.suite,
		name:               manifestNode.Name,
		containerName:      manifestNode.ContainerName,
		dataDir:            manifestNode.DataDir,
		passwdPath:         filepath.Join(manifestNode.DataDir, "container-etc", "passwd"),
		groupPath:          filepath.Join(manifestNode.DataDir, "container-etc", "group"),
		localAddr:          manifestNode.LocalAddr,
		disableMaintenance: e.manifest.DisableMaintenance,
	}
	if e.manifest.ClockMode == ClockModeSynthetic {
		node.EnableTestClock()
	}
	return node
}

func (e *Environment) applySyntheticClock(ctx context.Context, node *Node) error {
	if e.manifest.ClockMode != ClockModeSynthetic {
		return nil
	}
	_, err := node.SetTestTime(
		ctx,
		e.manifest.SyntheticClock.UnixSeconds,
		e.manifest.SyntheticClock.Nanoseconds,
	)
	if err != nil {
		return err
	}
	return nil
}

func (e *Environment) saveManifest() error {
	encoded, err := json.MarshalIndent(e.manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode environment manifest: %w", err)
	}
	if err := os.WriteFile(e.manifestPath, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write environment manifest: %w", err)
	}
	return nil
}

func (e *Environment) captureLogsForNode(ctx context.Context, node *Node) error {
	state, err := node.ContainerState(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if state == "missing" {
		return nil
	}
	return node.FetchLogs(ctx, e.logPath(node.Name()))
}

func (e *Environment) logPath(nodeName string) string {
	return filepath.Join(e.logsDir, sanitizeName(nodeName)+".log")
}

func environmentRootDir(workRoot string, name string) string {
	return filepath.Join(workRoot, "manual", sanitizeName(name))
}

func persistentChutneyDataDir(workRoot string, name string) string {
	sum := sha256.Sum256([]byte(workRoot + "\x00" + name))
	return filepath.Join(
		string(filepath.Separator),
		"tmp",
		"bbmc",
		hex.EncodeToString(sum[:6]),
	)
}

func makeEnvironmentContainerName(rootDir string, environmentName string, nodeName string) string {
	sum := sha256.Sum256([]byte(rootDir))
	scope := sanitizeName(environmentName) + "-" + hex.EncodeToString(sum[:3])
	return makeContainerName(scope, nodeName)
}

func resetNodeDataDir(dataDir string) error {
	if err := os.RemoveAll(dataDir); err != nil {
		return fmt.Errorf("remove %s: %w", dataDir, err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("recreate %s: %w", dataDir, err)
	}
	return nil
}

func validateNodeNames(nodeNames []string) error {
	if len(nodeNames) == 0 {
		return fmt.Errorf("persistent environments require at least one node")
	}
	seen := map[string]struct{}{}
	seenSanitized := map[string]string{}
	for _, name := range nodeNames {
		if name == "" {
			return fmt.Errorf("node names must not be empty")
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("duplicate node name %s", name)
		}
		seen[name] = struct{}{}
		sanitized := sanitizeName(name)
		if existing, ok := seenSanitized[sanitized]; ok {
			return fmt.Errorf(
				"node names %s and %s sanitize to the same runtime name %s",
				existing,
				name,
				sanitized,
			)
		}
		seenSanitized[sanitized] = name
	}
	return nil
}

// ParseClockAdvanceDuration accepts Go durations plus a day suffix.
func ParseClockAdvanceDuration(input string) (time.Duration, error) {
	if input == "" {
		return 0, fmt.Errorf("clock duration must not be empty")
	}
	translated, err := translateDayDuration(input)
	if err != nil {
		return 0, err
	}
	duration, err := time.ParseDuration(translated)
	if err != nil {
		return 0, fmt.Errorf("parse clock duration %q: %w", input, err)
	}
	return duration, nil
}

func translateDayDuration(input string) (string, error) {
	output := make([]byte, 0, len(input)+8)
	for index := 0; index < len(input); {
		start := index
		for index < len(input) {
			current := input[index]
			if (current >= '0' && current <= '9') || current == '.' {
				index++
				continue
			}
			break
		}
		if start == index {
			return "", fmt.Errorf("parse clock duration %q: expected number at byte %d", input, index)
		}
		value, err := strconv.ParseFloat(input[start:index], 64)
		if err != nil {
			return "", fmt.Errorf("parse clock duration %q: %w", input, err)
		}
		unitStart := index
		for index < len(input) && ((input[index] >= 'a' && input[index] <= 'z') || (input[index] >= 'A' && input[index] <= 'Z')) {
			index++
		}
		if unitStart == index {
			return "", fmt.Errorf("parse clock duration %q: expected unit at byte %d", input, unitStart)
		}
		unit := input[unitStart:index]
		if unit == "d" {
			output = append(output, strconv.FormatFloat(value*24, 'f', -1, 64)...)
			output = append(output, 'h')
			continue
		}
		output = append(output, input[start:index]...)
	}
	return string(output), nil
}
