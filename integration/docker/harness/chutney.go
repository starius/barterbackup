package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
)

const (
	chutneyRepositoryURL = "https://gitlab.torproject.org/tpo/core/chutney.git"
	chutneyPinnedRef     = "9ca2446f4837c1730d31cf9be8ebb7865ebe8fc3"
)

// ChutneyNetwork manages one shared private Tor network for integration tests.
type ChutneyNetwork struct {
	repoDir      string
	dataDir      string
	artiBinary   string
	rawConfig    rawChutneyConfig
	baseConfig   translatedArtiConfig
	commandEnv   []string
	chutneyEntry string
}

type rawChutneyConfig struct {
	PathRules         map[string]any `toml:"path_rules"`
	AddressFilter     map[string]any `toml:"address_filter"`
	OverrideNetParams map[string]any `toml:"override_net_params"`
	Bridges           map[string]any `toml:"bridges"`
	TorNetwork        struct {
		FallbackCaches []fallbackCache `toml:"fallback_caches"`
		Authorities    struct {
			V3Idents  []string   `toml:"v3idents"`
			Uploads   [][]string `toml:"uploads"`
			Downloads [][]string `toml:"downloads"`
			Votes     [][]string `toml:"votes"`
		} `toml:"authorities"`
	} `toml:"tor_network"`
}

type translatedArtiConfig struct {
	Storage struct {
		CacheDir string `toml:"cache_dir"`
		StateDir string `toml:"state_dir,omitempty"`
		Keystore struct {
			Primary struct {
				Kind string `toml:"kind"`
			} `toml:"primary"`
		} `toml:"keystore"`
	} `toml:"storage"`
	PathRules         map[string]any `toml:"path_rules,omitempty"`
	AddressFilter     map[string]any `toml:"address_filter,omitempty"`
	OverrideNetParams map[string]any `toml:"override_net_params,omitempty"`
	Bridges           map[string]any `toml:"bridges,omitempty"`
	TorNetwork        struct {
		Authorities struct {
			V3Idents  []string   `toml:"v3idents"`
			Uploads   [][]string `toml:"uploads,omitempty"`
			Downloads [][]string `toml:"downloads,omitempty"`
			Votes     [][]string `toml:"votes,omitempty"`
		} `toml:"authorities"`
		FallbackCaches []fallbackCache `toml:"fallback_caches"`
	} `toml:"tor_network"`
}

type fallbackCache struct {
	RSAIdentity string   `toml:"rsa_identity"`
	EDIdentity  string   `toml:"ed_identity"`
	ORPorts     []string `toml:"orports"`
}

// PrepareChutneyNetwork ensures one pinned Chutney checkout exists, starts one
// private hs-v3-arti network, and loads the translated Arti client template.
func PrepareChutneyNetwork(ctx context.Context, workRoot string) (*ChutneyNetwork, error) {
	return prepareChutneyNetwork(ctx, workRoot, filepath.Join(workRoot, "chutney-network"), true)
}

// PreparePersistentChutneyNetwork ensures one pinned Chutney checkout exists
// and reuses or recreates one persistent private hs-v3-arti network rooted at
// dataDir.
func PreparePersistentChutneyNetwork(
	ctx context.Context,
	workRoot string,
	dataDir string,
) (*ChutneyNetwork, error) {
	return prepareChutneyNetwork(ctx, workRoot, dataDir, false)
}

func prepareChutneyNetwork(
	ctx context.Context,
	workRoot string,
	dataDir string,
	cleanStart bool,
) (*ChutneyNetwork, error) {
	network, err := openChutneyNetwork(workRoot, dataDir)
	if err != nil {
		return nil, err
	}
	if cleanStart {
		_ = cleanupStaleChutneyListeners(ctx)
		_ = network.Close()
		if err := os.MkdirAll(network.dataDir, 0o755); err != nil {
			return nil, fmt.Errorf("create chutney data dir: %w", err)
		}
		if err := network.start(ctx); err != nil {
			_ = network.Close()
			return nil, err
		}
		return network, nil
	}
	if err := network.ensureStarted(ctx); err != nil {
		_ = network.Close()
		return nil, err
	}
	return network, nil
}

func openChutneyNetwork(workRoot string, dataDir string) (*ChutneyNetwork, error) {
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create integration work root: %w", err)
	}

	chutneyDir := filepath.Join(workRoot, "chutney-src")
	if err := ensureChutneyCheckout(context.Background(), chutneyDir); err != nil {
		return nil, err
	}

	artiBinary, err := execLookPath("arti")
	if err != nil {
		return nil, err
	}
	if _, err := execLookPath("tor"); err != nil {
		return nil, err
	}
	if _, err := execLookPath("python3"); err != nil {
		return nil, err
	}

	return &ChutneyNetwork{
		repoDir:      chutneyDir,
		dataDir:      dataDir,
		artiBinary:   artiBinary,
		commandEnv:   []string{"CHUTNEY_DATA_DIR=" + dataDir, "CHUTNEY_ARTI=" + artiBinary},
		chutneyEntry: filepath.Join(chutneyDir, "chutney"),
	}, nil
}

// Close stops the private Tor network and removes its temporary state.
func (n *ChutneyNetwork) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultShortTimeout)
	defer cancel()

	_, _ = runCommand(ctx, n.repoDir, n.commandEnv, n.chutneyEntry, "stop")
	return os.RemoveAll(n.dataDir)
}

// Healthy reports whether the private Chutney network is currently responding
// to `chutney status`.
func (n *ChutneyNetwork) Healthy(ctx context.Context) error {
	return n.waitForHealthyStatus(ctx)
}

// WriteNodeConfig renders one translated Arti client config into nodeDataDir.
func (n *ChutneyNetwork) WriteNodeConfig(
	nodeDataDir string,
	options ArtiConfigOptions,
) (string, error) {
	config := n.baseConfig
	config.Storage.CacheDir = "/data/arti-cache"
	switch {
	case options.OmitStateDir:
		config.Storage.StateDir = ""
	case options.ExplicitStateDir != "":
		config.Storage.StateDir = options.ExplicitStateDir
	default:
		config.Storage.StateDir = "/data/tor"
	}

	encoded, err := toml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("encode arti config: %w", err)
	}

	configPath := filepath.Join(nodeDataDir, "arti.toml")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		return "", fmt.Errorf("write arti config: %w", err)
	}
	return configPath, nil
}

func (n *ChutneyNetwork) start(ctx context.Context) error {
	if _, err := runCommand(ctx, n.repoDir, n.commandEnv, n.chutneyEntry, "init", "--net", "hs-v3-arti"); err != nil {
		return fmt.Errorf("init chutney network: %w", err)
	}
	if _, err := runCommand(ctx, n.repoDir, n.commandEnv, n.chutneyEntry, "configure"); err != nil {
		return fmt.Errorf("configure chutney network: %w", err)
	}
	if err := disableChutneyTorSandbox(n.dataDir); err != nil {
		return fmt.Errorf("disable Tor sandbox in Chutney network: %w", err)
	}
	if _, err := runCommand(ctx, n.repoDir, n.commandEnv, n.chutneyEntry, "start"); err != nil {
		return fmt.Errorf("start chutney network: %w", err)
	}
	if err := n.waitForHealthyStatus(ctx); err != nil {
		return fmt.Errorf("check chutney network status: %w", err)
	}

	if err := n.loadTranslatedConfig(); err != nil {
		return err
	}
	return nil
}

func (n *ChutneyNetwork) ensureStarted(ctx context.Context) error {
	if _, err := os.Stat(n.dataDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat chutney data dir: %w", err)
		}
		_ = cleanupStaleChutneyListeners(ctx)
		if err := os.MkdirAll(n.dataDir, 0o755); err != nil {
			return fmt.Errorf("create chutney data dir: %w", err)
		}
		return n.start(ctx)
	}
	if err := n.waitForHealthyStatus(ctx); err == nil {
		return n.loadTranslatedConfig()
	}
	_ = n.Close()
	_ = cleanupStaleChutneyListeners(ctx)
	if err := os.MkdirAll(n.dataDir, 0o755); err != nil {
		return fmt.Errorf("create chutney data dir: %w", err)
	}
	return n.start(ctx)
}

func (n *ChutneyNetwork) loadTranslatedConfig() error {
	rawConfigPath, err := n.findRawConfigPath()
	if err != nil {
		return err
	}

	rawConfigBytes, err := os.ReadFile(rawConfigPath)
	if err != nil {
		return fmt.Errorf("read chutney arti config: %w", err)
	}
	if err := toml.Unmarshal(rawConfigBytes, &n.rawConfig); err != nil {
		return fmt.Errorf("decode chutney arti config: %w", err)
	}
	n.baseConfig = translateChutneyConfig(n.rawConfig)
	return nil
}

func (n *ChutneyNetwork) waitForHealthyStatus(ctx context.Context) error {
	deadline, cancel := context.WithTimeout(ctx, defaultShortTimeout)
	defer cancel()

	var lastErr error
	for {
		if _, err := runCommand(deadline, n.repoDir, n.commandEnv, n.chutneyEntry, "status"); err == nil {
			return nil
		} else {
			lastErr = err
		}

		timer := time.NewTimer(time.Second)
		select {
		case <-deadline.Done():
			timer.Stop()
			if lastErr != nil {
				return lastErr
			}
			return errors.New("timed out waiting for chutney network status")
		case <-timer.C:
		}
	}
}

func (n *ChutneyNetwork) findRawConfigPath() (string, error) {
	matches, err := filepath.Glob(filepath.Join(n.dataDir, "nodes.*", "arti.toml"))
	if err != nil {
		return "", fmt.Errorf("glob chutney arti config: %w", err)
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("no chutney arti config found in %s", n.dataDir)
	}
	sort.Strings(matches)
	return matches[len(matches)-1], nil
}

func ensureChutneyCheckout(ctx context.Context, chutneyDir string) error {
	if _, err := os.Stat(chutneyDir); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat chutney checkout: %w", err)
		}
		if _, err := runCommand(ctx, "", nil, "git", "clone", chutneyRepositoryURL, chutneyDir); err != nil {
			return fmt.Errorf("clone chutney: %w", err)
		}
	}

	if _, err := runCommand(ctx, chutneyDir, nil, "git", "fetch", "--depth", "1", "origin", chutneyPinnedRef); err != nil {
		return fmt.Errorf("fetch pinned chutney ref: %w", err)
	}
	if _, err := runCommand(ctx, chutneyDir, nil, "git", "checkout", "--detach", chutneyPinnedRef); err != nil {
		return fmt.Errorf("checkout pinned chutney ref: %w", err)
	}
	return nil
}

func translateChutneyConfig(raw rawChutneyConfig) translatedArtiConfig {
	var translated translatedArtiConfig
	translated.Storage.Keystore.Primary.Kind = "ephemeral"
	translated.PathRules = raw.PathRules
	translated.AddressFilter = raw.AddressFilter
	translated.OverrideNetParams = raw.OverrideNetParams
	translated.Bridges = raw.Bridges
	translated.TorNetwork.FallbackCaches = append(
		translated.TorNetwork.FallbackCaches,
		raw.TorNetwork.FallbackCaches...,
	)
	for _, v3ident := range raw.TorNetwork.Authorities.V3Idents {
		trimmed := strings.TrimSpace(v3ident)
		if trimmed == "" {
			continue
		}
		translated.TorNetwork.Authorities.V3Idents = append(
			translated.TorNetwork.Authorities.V3Idents,
			trimmed,
		)
	}
	translated.TorNetwork.Authorities.Uploads = append(
		translated.TorNetwork.Authorities.Uploads,
		raw.TorNetwork.Authorities.Uploads...,
	)
	translated.TorNetwork.Authorities.Downloads = append(
		translated.TorNetwork.Authorities.Downloads,
		raw.TorNetwork.Authorities.Downloads...,
	)
	translated.TorNetwork.Authorities.Votes = append(
		translated.TorNetwork.Authorities.Votes,
		raw.TorNetwork.Authorities.Votes...,
	)
	return translated
}

func cleanupStaleChutneyListeners(ctx context.Context) error {
	pidPattern := regexp.MustCompile(`pid=(\d+)`)
	pids := map[int]struct{}{}
	if output, err := runCommand(ctx, "", nil, "ss", "-H", "-ltnp"); err == nil {
		collectChutneyListenerPIDs(pids, pidPattern, output)
	}
	if output, err := runCommand(ctx, "", nil, "pgrep", "-f", "/tmp/bbmc/.*/torrc"); err == nil {
		collectPIDList(pids, output)
	}

	if len(pids) == 0 {
		return nil
	}

	for pid := range pids {
		_, _ = runCommand(ctx, "", nil, "kill", "-TERM", strconv.Itoa(pid))
	}
	time.Sleep(500 * time.Millisecond)
	for pid := range pids {
		_, _ = runCommand(ctx, "", nil, "kill", "-KILL", strconv.Itoa(pid))
	}
	return nil
}

func collectChutneyListenerPIDs(
	pids map[int]struct{},
	pidPattern *regexp.Regexp,
	output []byte,
) {
	targetPorts := map[int]struct{}{}
	for port := 5100; port <= 5108; port++ {
		targetPorts[port] = struct{}{}
	}
	for port := 7100; port <= 7108; port++ {
		targetPorts[port] = struct{}{}
	}
	for port := 8000; port <= 8008; port++ {
		targetPorts[port] = struct{}{}
	}

	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address := fields[3]
		portIndex := strings.LastIndex(address, ":")
		if portIndex < 0 {
			continue
		}
		portValue, err := strconv.Atoi(address[portIndex+1:])
		if err != nil {
			continue
		}
		if _, ok := targetPorts[portValue]; !ok {
			continue
		}
		for _, match := range pidPattern.FindAllStringSubmatch(line, -1) {
			pidValue, err := strconv.Atoi(match[1])
			if err == nil {
				pids[pidValue] = struct{}{}
			}
		}
	}
}

func collectPIDList(pids map[int]struct{}, output []byte) {
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		pidValue, err := strconv.Atoi(trimmed)
		if err == nil {
			pids[pidValue] = struct{}{}
		}
	}
}

func disableChutneyTorSandbox(dataDir string) error {
	torrcPaths, err := filepath.Glob(filepath.Join(dataDir, "nodes.*", "*", "torrc"))
	if err != nil {
		return fmt.Errorf("glob Chutney torrc files: %w", err)
	}

	for _, torrcPath := range torrcPaths {
		contents, err := os.ReadFile(torrcPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", torrcPath, err)
		}

		updated := bytes.ReplaceAll(contents, []byte("Sandbox 1\n"), []byte("Sandbox 0\n"))
		if !bytes.Equal(updated, contents) {
			if err := os.WriteFile(torrcPath, updated, 0o600); err != nil {
				return fmt.Errorf("write %s: %w", torrcPath, err)
			}
		}
	}

	return nil
}
