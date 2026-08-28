//go:build windows

package jobs

import "os/exec"

// Windows has no process groups in the POSIX sense. Killing the launcher is
// the best that is portable here; the released windows binary is expected to
// drive a local Ghidra install, not to be the busy production path.
func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
