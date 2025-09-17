package bbcliapp

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/starius/barterbackup/clirpc"
	"golang.org/x/term"
)

// UnlockCmd runs `bbcli unlock`.
type UnlockCmd struct {
	cfg          *Config
	PasswordFile string `long:"password-file" description:"Path to file containing the password (single line)."`
}

func (c *UnlockCmd) Execute(_ []string) error {
	if c.cfg == nil || c.cfg.runtime == nil || c.cfg.runtime.client == nil {
		return errors.New("client not initialized; ensure daemon is running and CLI addr is correct")
	}
	pw, err := c.readPassword()
	if err != nil {
		return err
	}
	_, err = c.cfg.runtime.client.Unlock(c.cfg.runtime.ctx, &clirpc.UnlockRequest{MainPassword: pw})
	if err != nil {
		return err
	}
	fmt.Println("Unlocked.")
	return nil
}

func (c *UnlockCmd) readPassword() (string, error) {
	if c.PasswordFile != "" {
		b, err := os.ReadFile(c.PasswordFile)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	// Fallback to secure prompt from TTY.
	fmt.Fprintf(os.Stderr, "Password: ")
	// If stdin is not a terminal, read a line without disabling echo.
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		rd := bufio.NewReader(os.Stdin)
		line, err := rd.ReadString('\n')
		if err != nil && !errors.Is(err, os.ErrClosed) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
