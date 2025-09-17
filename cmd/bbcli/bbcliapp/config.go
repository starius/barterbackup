package bbcliapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/clitls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config holds common CLI flags and runtime.
type Config struct {
	DaemonAddr string `long:"daemon-addr" env:"BBCLI_DAEMON_ADDR" description:"Local daemon address to connect to." default:"127.0.0.1:9911"`
	CliKeysDir string `long:"cli-keys-dir" env:"BBCLI_CLI_KEYS_DIR" description:"Directory containing client.key and server.pub." default:"~/.barterbackup/cli-keys"`

	// Subcommands
	Healthcheck HealthcheckCmd `command:"healthcheck" description:"Check local daemon health"`
	Unlock      UnlockCmd      `command:"unlock" description:"Unlock daemon with a password (prompts securely or via file)"`

	// Runtime (initialized by Run) for subcommands.
	runtime *runtime
}

type runtime struct {
	ctx    context.Context
	conn   *grpc.ClientConn
	client clirpc.BarterBackupClientClient
}

// Run options
type runOptions struct{ args []string }
type RunOption func(*runOptions)

func WithOSArgs() RunOption         { return func(o *runOptions) { o.args = os.Args[1:] } }
func WithArgs(a []string) RunOption { return func(o *runOptions) { o.args = append([]string{}, a...) } }

// Run parses flags and relies on Parser.CommandHandler to open connection
// and execute the selected subcommand.
func Run(ctx context.Context, opts ...RunOption) error {
	var ro runOptions
	for _, opt := range opts {
		opt(&ro)
	}

	cfg := &Config{runtime: &runtime{ctx: ctx}}
	// Inject cfg into subcommands so Execute can access runtime/client.
	cfg.Healthcheck.cfg = cfg
	cfg.Unlock.cfg = cfg

	p := flags.NewParser(cfg, flags.Default)
	p.SubcommandsOptional = true
	p.CommandHandler = func(command flags.Commander, args []string) error {
		if command == nil {
			return errors.New("Please specify the sub-command or -h to see the list of sub-commands")
		}
		conn, client, err := openClient(ctx, cfg)
		if err != nil {
			return err
		}
		cfg.runtime.conn = conn
		cfg.runtime.client = client
		defer conn.Close()
		return command.Execute(args)
	}
	var err error
	if len(ro.args) > 0 {
		_, err = p.ParseArgs(ro.args)
	} else {
		_, err = p.Parse()
	}
	if err != nil {
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			return nil
		}
		return err
	}
	return nil
}

// Helpers shared by subcommands.

func expandPath(p string) (string, error) {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p, nil
}

// openClient prepares pinned TLS and returns a connected gRPC client.
func openClient(ctx context.Context, cfg *Config) (*grpc.ClientConn, clirpc.BarterBackupClientClient, error) {
	dir, err := expandPath(cfg.CliKeysDir)
	if err != nil {
		return nil, nil, err
	}
	serverPub, clientPriv, err := clitls.ReadKeys(dir)
	if err != nil {
		return nil, nil, err
	}
	tlsCfg, err := clitls.BuildClientTLSF(serverPub, clientPriv)
	if err != nil {
		return nil, nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dctx, cfg.DaemonAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("connect to daemon: %w", err)
	}
	client := clirpc.NewBarterBackupClientClient(conn)
	return conn, client, nil
}
