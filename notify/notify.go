// Package notify provides a function to execute a directory of executable
// hooks, used when a certificate has been updated.
package notify

import "os"
import "os/exec"
import "strings"
import "path/filepath"
import "github.com/hlandau/xlog"

var log, Log = xlog.New("acme.notify")

var DefaultHookPath = "/usr/lib/acme/hooks"

func init() {
	lePath := "/usr/libexec/acme/hooks"
	if _, err := os.Stat(lePath); err == nil {
		DefaultHookPath = lePath
	}
}

// Notifies hook programs that a live symlink has been updated.
func Notify(hookDirectory, stateDirectory string, hostnames []string) error {
	if hookDirectory == "" {
		hookDirectory = DefaultHookPath
	}

	if len(hostnames) == 0 {
		return nil
	}

	_, err := os.Stat(hookDirectory)
	if err != nil {
		// nothing to notify
		return nil
	}

	// Probably shouldn't propagate this to all child processes, but it's the
	// easiest way to not replace the entire environment when calling.
	err = os.Setenv("ACME_STATE_DIR", stateDirectory)
	if err != nil {
		return err
	}

	hostnameList := strings.Join(hostnames, "\n") + "\n"
	err = runParts(hookDirectory, []byte(hostnameList), "live-updated")
	if err != nil {
		return err
	}

	return nil
}

func runParts(directory string, stdinData []byte, args ...string) error {
	ms, err := filepath.Glob(filepath.Join(directory, "*"))
	if err != nil {
		return err
	}

	for _, m := range ms {
		log.Debugf("calling notification script: %s", m)
		cmd := exec.Command(m, args...)
		cmd.Dir = "/"

		pipeR, pipeW, err := os.Pipe()
		if err != nil {
			return err
		}

		defer pipeR.Close()
		go func() {
			defer pipeW.Close()
			pipeW.Write([]byte(stdinData))
		}()

		cmd.Stdin = pipeR
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run() // ignore errors
		log.Errore(err, "notify script: ", m)
	}

	return nil
}
