package harness

import "os/exec"

func execLookPathStd(binary string) (string, error) {
	return exec.LookPath(binary)
}
