package harness

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runCommand executes one external command and returns combined stdout/stderr.
func runCommand(
	ctx context.Context,
	dir string,
	env []string,
	name string,
	args ...string,
) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}

	output, err := cmd.CombinedOutput()
	if err == nil {
		return output, nil
	}

	trimmed := strings.TrimSpace(string(bytes.TrimSpace(output)))
	if trimmed == "" {
		return output, fmt.Errorf("run %s %s: %w", name, strings.Join(args, " "), err)
	}
	return output, fmt.Errorf(
		"run %s %s: %w: %s",
		name,
		strings.Join(args, " "),
		err,
		trimmed,
	)
}
