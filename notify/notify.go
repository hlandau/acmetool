package notify

import "os"
import "os/exec"

var DefaultHookPath = "/usr/lib/acme/hooks"

func init() {
	lePath := "/usr/libexec/acme/hooks"
	if _, err := os.Stat(lePath); err == nil {
		DefaultHookPath = lePath
	}
}

// Notifies hook programs that a live symlink has been updated.
func Notify(hookDirectory, stateDirectory, hostname string) error {
	if hookDirectory == "" {
		hookDirectory = DefaultHookPath
	}

	_, err := os.Stat(hookDirectory)
	if err != nil {
		// nothing to notify
		return nil
	}

	// TODO: emulate run-parts if not available

	err = os.Setenv("ACME_STATE_DIR", stateDirectory)
	if err != nil {
		return err
	}

	cmd := exec.Command("run-parts", "-a", "live-updated", "-a", hostname, hookDirectory)
	cmd.Dir = "/"
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run() // ignore errors
	return nil
}
