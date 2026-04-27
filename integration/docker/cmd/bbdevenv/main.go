package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"barterbackup/integration/docker/harness"
)

var execCommandContext = exec.CommandContext

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	globalFlags := flag.NewFlagSet("bbdevenv", flag.ContinueOnError)
	globalFlags.SetOutput(stderr)
	environmentName := globalFlags.String("name", "default", "persistent environment name")
	workRoot := globalFlags.String("workdir", "", "integration work root override")
	globalFlags.Usage = func() {
		printUsage(stderr)
	}
	if err := globalFlags.Parse(args); err != nil {
		return 2
	}
	rest := globalFlags.Args()
	if len(rest) == 0 {
		printUsage(stderr)
		return 2
	}

	switch rest[0] {
	case "up":
		return runUp(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "down":
		return runDown(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "restart":
		return runRestart(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "recreate":
		return runRecreate(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "status":
		return runStatus(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "ls":
		return runList(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "logs":
		return runLogs(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "onion":
		return runOnion(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "local-addr":
		return runLocalAddr(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "cli":
		return runCLI(ctx, *environmentName, *workRoot, rest[1:], stdin, stdout, stderr)
	case "clock":
		return runClock(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "start":
		return runStart(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	case "stop":
		return runStop(ctx, *environmentName, *workRoot, rest[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", rest[0])
		printUsage(stderr)
		return 2
	}
}

func runUp(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	nodeCount := flags.Int("nodes", 0, "number of nodes when creating a new environment")
	var nodeNames stringListFlag
	flags.Var(&nodeNames, "node-name", "logical node name, repeatable")
	clockMode := flags.String("clock", "", "clock mode for new environments: real or synthetic")
	disableMaintenance := flags.Bool("disable-maintenance", false, "start nodes with background maintenance disabled")
	forceRecreate := flags.Bool("force-recreate", false, "destroy any existing environment with the same name first")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if len(flags.Args()) != 0 {
		fmt.Fprintf(stderr, "up does not take positional arguments\n")
		return 2
	}

	env, err := harness.PrepareEnvironment(ctx, harness.EnvironmentConfig{
		Name:                  environmentName,
		BaseWorkRoot:          workRoot,
		NodeCount:             *nodeCount,
		NodeNames:             nodeNames.values,
		ClockMode:             harness.ClockMode(*clockMode),
		ClockModeSpecified:    flagWasPassed(flags, "clock"),
		DisableMaintenance:    *disableMaintenance,
		DisableMaintenanceSet: flagWasPassed(flags, "disable-maintenance"),
		ForceRecreate:         *forceRecreate,
	})
	if err != nil {
		fmt.Fprintf(stderr, "prepare environment: %v\n", err)
		return 1
	}
	status, err := env.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "get environment status: %v\n", err)
		return 1
	}
	printStatus(stdout, status)
	return 0
}

func runDown(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	flags := flag.NewFlagSet("down", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keepRoot := flags.Bool("keep-root", false, "stop the environment but keep its files on disk")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if len(flags.Args()) != 0 {
		fmt.Fprintf(stderr, "down does not take positional arguments\n")
		return 2
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return 1
	}
	if err := env.Destroy(ctx, *keepRoot); err != nil {
		fmt.Fprintf(stderr, "destroy environment: %v\n", err)
		return 1
	}
	if *keepRoot {
		fmt.Fprintf(stdout, "environment %s stopped; files kept at %s\n", env.Name(), env.RootDir())
	} else {
		fmt.Fprintf(stdout, "environment %s removed\n", env.Name())
	}
	return 0
}

func runRestart(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "restart does not take positional arguments\n")
		return 2
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return 1
	}
	if err := env.PrepareRuntime(ctx); err != nil {
		fmt.Fprintf(stderr, "prepare environment runtime: %v\n", err)
		return 1
	}
	if err := env.RestartAll(ctx); err != nil {
		fmt.Fprintf(stderr, "restart environment: %v\n", err)
		return 1
	}
	status, err := env.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "get environment status: %v\n", err)
		return 1
	}
	printStatus(stdout, status)
	return 0
}

func runRecreate(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := prepareNodeCommandEnvironment(ctx, environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	if err := env.RecreateNode(ctx, node); err != nil {
		fmt.Fprintf(stderr, "recreate node %s: %v\n", node.Name(), err)
		return 1
	}
	fmt.Fprintf(stdout, "recreated %s\n", node.Name())
	return 0
}

func runStatus(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "status does not take positional arguments\n")
		return 2
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return 1
	}
	status, err := env.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "get environment status: %v\n", err)
		return 1
	}
	printStatus(stdout, status)
	return 0
}

func runList(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "ls does not take positional arguments\n")
		return 2
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return 1
	}
	status, err := env.Status(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "get environment status: %v\n", err)
		return 1
	}
	for _, nodeStatus := range status.NodeStatuses {
		fmt.Fprintf(
			stdout,
			"%d\t%s\t%s\t%s\n",
			nodeStatus.Index,
			nodeStatus.Name,
			nodeStatus.ContainerState,
			nodeStatus.LocalAddr,
		)
	}
	return 0
}

func runLogs(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := prepareNodeCommandEnvironment(ctx, environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	output, err := node.CurrentLogs(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			output, err = os.ReadFile(env.StoredLogPath(node.Name()))
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "read logs for %s: %v\n", node.Name(), err)
		return 1
	}
	if _, err := stdout.Write(output); err != nil {
		fmt.Fprintf(stderr, "write logs for %s: %v\n", node.Name(), err)
		return 1
	}
	return 0
}

func runOnion(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := loadNodeCommandEnvironment(environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	_ = env
	state, err := node.State(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "get node state for %s: %v\n", node.Name(), err)
		return 1
	}
	if state.GetServerOnion() == "" {
		fmt.Fprintf(stderr, "node %s does not have an onion address yet\n", node.Name())
		return 1
	}
	fmt.Fprintln(stdout, state.GetServerOnion())
	return 0
}

func runLocalAddr(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	_, node, ok := loadNodeCommandEnvironment(environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	_ = ctx
	fmt.Fprintln(stdout, node.LocalAddr())
	return 0
}

func runCLI(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := loadEnvironmentAndNode(environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	bbcliArgs := args[1:]
	if len(bbcliArgs) > 0 && bbcliArgs[0] == "--" {
		bbcliArgs = bbcliArgs[1:]
	}
	if len(bbcliArgs) == 0 {
		fmt.Fprintf(stderr, "cli requires bbcli arguments after the node selector\n")
		return 2
	}
	if err := node.WaitForLocalRPC(ctx); err != nil {
		fmt.Fprintf(stderr, "wait for node %s local rpc readiness: %v\n", node.Name(), err)
		return 1
	}
	invocation, err := buildBBCLIInvocation(env, node, bbcliArgs)
	if err != nil {
		fmt.Fprintf(stderr, "prepare bbcli invocation: %v\n", err)
		return 1
	}
	return runExternalCommand(ctx, invocation, stdin, stdout, stderr)
}

func runClock(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "clock requires one subcommand: status or advance\n")
		return 2
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return 1
	}
	switch args[0] {
	case "status":
		printClockStatus(stdout, env)
		return 0
	case "advance":
		if len(args) != 2 {
			fmt.Fprintf(stderr, "clock advance requires one duration argument\n")
			return 2
		}
		duration, err := harness.ParseClockAdvanceDuration(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return 1
		}
		if err := env.AdvanceSyntheticClock(ctx, duration); err != nil {
			fmt.Fprintf(stderr, "advance synthetic clock: %v\n", err)
			return 1
		}
		printClockStatus(stdout, env)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown clock subcommand %q\n", args[0])
		return 2
	}
}

func runStart(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := loadNodeCommandEnvironment(environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	if err := env.StartNode(ctx, node); err != nil {
		fmt.Fprintf(stderr, "start node %s: %v\n", node.Name(), err)
		return 1
	}
	fmt.Fprintf(stdout, "started %s\n", node.Name())
	return 0
}

func runStop(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	env, node, ok := loadNodeCommandEnvironment(environmentName, workRoot, args, stderr)
	if !ok {
		return 2
	}
	if err := env.StopNode(ctx, node); err != nil {
		fmt.Fprintf(stderr, "stop node %s: %v\n", node.Name(), err)
		return 1
	}
	fmt.Fprintf(stdout, "stopped %s\n", node.Name())
	return 0
}

func loadNodeCommandEnvironment(
	environmentName string,
	workRoot string,
	args []string,
	stderr io.Writer,
) (*harness.Environment, *harness.Node, bool) {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "expected exactly one node selector argument\n")
		return nil, nil, false
	}
	return loadEnvironmentAndNode(environmentName, workRoot, args, stderr)
}

func prepareNodeCommandEnvironment(
	ctx context.Context,
	environmentName string,
	workRoot string,
	args []string,
	stderr io.Writer,
) (*harness.Environment, *harness.Node, bool) {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "expected exactly one node selector argument\n")
		return nil, nil, false
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return nil, nil, false
	}
	if err := env.PrepareRuntime(ctx); err != nil {
		fmt.Fprintf(stderr, "prepare environment runtime: %v\n", err)
		return nil, nil, false
	}
	node, err := env.Node(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve node %s: %v\n", args[0], err)
		return nil, nil, false
	}
	return env, node, true
}

func loadEnvironmentAndNode(
	environmentName string,
	workRoot string,
	args []string,
	stderr io.Writer,
) (*harness.Environment, *harness.Node, bool) {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "expected one node selector argument\n")
		return nil, nil, false
	}
	env, err := harness.LoadEnvironment(environmentName, workRoot)
	if err != nil {
		fmt.Fprintf(stderr, "load environment: %v\n", err)
		return nil, nil, false
	}
	node, err := env.Node(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "resolve node %s: %v\n", args[0], err)
		return nil, nil, false
	}
	return env, node, true
}

type bbcliInvocation struct {
	binary string
	args   []string
	env    []string
}

func buildBBCLIInvocation(
	env *harness.Environment,
	node *harness.Node,
	args []string,
) (*bbcliInvocation, error) {
	binary, err := findBBCLIBinary(env.RepoRoot())
	if err != nil {
		return nil, err
	}
	return &bbcliInvocation{
		binary: binary,
		args:   append([]string{}, args...),
		env: []string{
			"BBCLI_LOCAL_ADDR=https://" + node.LocalAddr(),
			"BBCLI_DATA_DIR=" + node.DataDir(),
		},
	}, nil
}

func findBBCLIBinary(repoRoot string) (string, error) {
	if override := os.Getenv("BB_DOCKER_BBCLI_BIN"); override != "" {
		return override, nil
	}
	if binary, err := harness.FindStaticBBCLIBinary(repoRoot); err == nil {
		return binary, nil
	}
	if binary, err := exec.LookPath("bbcli"); err == nil {
		return binary, nil
	}
	return "", fmt.Errorf("could not find bbcli; run make docker-dev-env-build or install bbcli on PATH")
}

func runExternalCommand(
	ctx context.Context,
	invocation *bbcliInvocation,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	cmd := execCommandContext(ctx, invocation.binary, invocation.args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(), invocation.env...)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "run %s: %v\n", invocation.binary, err)
		return 1
	}
	return 0
}

func printStatus(output io.Writer, status *harness.EnvironmentStatus) {
	fmt.Fprintf(output, "environment: %s\n", status.Name)
	fmt.Fprintf(output, "root_dir: %s\n", status.RootDir)
	fmt.Fprintf(output, "clock_mode: %s\n", status.ClockMode)
	if status.ClockMode == harness.ClockModeSynthetic {
		clockTime := time.Unix(int64(status.SyntheticTime.UnixSeconds), int64(status.SyntheticTime.Nanoseconds)).UTC()
		fmt.Fprintf(output, "synthetic_time_unix_seconds: %d\n", status.SyntheticTime.UnixSeconds)
		fmt.Fprintf(output, "synthetic_time_nanoseconds: %d\n", status.SyntheticTime.Nanoseconds)
		fmt.Fprintf(output, "synthetic_time_rfc3339: %s\n", clockTime.Format(time.RFC3339Nano))
	}
	fmt.Fprintf(output, "chutney_healthy: %t\n", status.ChutneyHealthy)
	fmt.Fprintln(output, "nodes:")
	for _, nodeStatus := range status.NodeStatuses {
		fmt.Fprintf(
			output,
			"- [%d] %s state=%s local_addr=%s container=%s storage_initialized=%t peer_runtime=%s self_peer_check=%s\n",
			nodeStatus.Index,
			nodeStatus.Name,
			nodeStatus.ContainerState,
			nodeStatus.LocalAddr,
			nodeStatus.ContainerName,
			nodeStatus.StorageInitialized,
			nodeStatus.PeerRuntimeState,
			nodeStatus.SelfPeerCheckState,
		)
		if nodeStatus.ServerOnion != "" {
			fmt.Fprintf(output, "  server_onion=%s\n", nodeStatus.ServerOnion)
		}
		if nodeStatus.PeerRuntimeError != "" {
			fmt.Fprintf(output, "  peer_runtime_error=%s\n", nodeStatus.PeerRuntimeError)
		}
		if nodeStatus.SelfPeerCheckError != "" {
			fmt.Fprintf(output, "  self_peer_check_error=%s\n", nodeStatus.SelfPeerCheckError)
		}
		if nodeStatus.StateError != "" {
			fmt.Fprintf(output, "  state_error=%s\n", nodeStatus.StateError)
		}
	}
}

func printClockStatus(output io.Writer, env *harness.Environment) {
	fmt.Fprintf(output, "clock_mode: %s\n", env.ClockMode())
	if env.ClockMode() != harness.ClockModeSynthetic {
		return
	}
	clockState := env.SyntheticClock()
	clockTime := time.Unix(int64(clockState.UnixSeconds), int64(clockState.Nanoseconds)).UTC()
	fmt.Fprintf(output, "synthetic_time_unix_seconds: %d\n", clockState.UnixSeconds)
	fmt.Fprintf(output, "synthetic_time_nanoseconds: %d\n", clockState.Nanoseconds)
	fmt.Fprintf(output, "synthetic_time_rfc3339: %s\n", clockTime.Format(time.RFC3339Nano))
}

type stringListFlag struct {
	values []string
}

func (f *stringListFlag) String() string {
	return strings.Join(f.values, ",")
}

func (f *stringListFlag) Set(value string) error {
	f.values = append(f.values, value)
	return nil
}

func flagWasPassed(flags *flag.FlagSet, name string) bool {
	passed := false
	flags.Visit(func(current *flag.Flag) {
		if current.Name == name {
			passed = true
		}
	})
	return passed
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage: bbdevenv [--name ENV] [--workdir PATH] <command> [args...]")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	fmt.Fprintln(output, "  up                   Create or start the persistent environment")
	fmt.Fprintln(output, "  down                 Stop and remove the persistent environment")
	fmt.Fprintln(output, "  restart              Restart all nodes in the environment")
	fmt.Fprintln(output, "  recreate <node>      Wipe one node and start it fresh for recovery testing")
	fmt.Fprintln(output, "  status               Print the environment summary")
	fmt.Fprintln(output, "  ls                   Print one short line per node")
	fmt.Fprintln(output, "  logs <node>          Print live or stored logs for one node")
	fmt.Fprintln(output, "  onion <node>         Print one node onion hostname")
	fmt.Fprintln(output, "  local-addr <node>    Print one node local clirpc address")
	fmt.Fprintln(output, "  cli <node> -- ...    Run host-side bbcli against one selected node")
	fmt.Fprintln(output, "  clock status         Show the current environment clock mode")
	fmt.Fprintln(output, "  clock advance <dur>  Advance the synthetic clock by one duration")
	fmt.Fprintln(output, "  start <node>         Start one node")
	fmt.Fprintln(output, "  stop <node>          Stop one node")
}
