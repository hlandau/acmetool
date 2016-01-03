// Package notify provides a function to execute a directory of executable
// hooks, used when a certificate has been updated.
package notify

import (
	"fmt"
	"github.com/hlandau/xlog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Log site.
var log, Log = xlog.New("acme.notify")

// The default hook path is "/usr/lib/acme/hooks" or "/usr/libexec/acme/hooks".
// The latter is preferred if it exists.
var DefaultHookPath = "/usr/lib/acme/hooks"

func init() {
	lePath := "/usr/libexec/acme/hooks"
	if _, err := os.Stat(lePath); err == nil {
		DefaultHookPath = lePath
	}
}

// Notifies hook programs that a live symlink has been updated.
//
// If hookDirectory is "", DefaultHookPath is used. stateDirectory and
// hostnames are passed as information to the hooks.
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

// Implements functionality similar to the "run-parts" command on many distros.
// Implementations vary, so it is reimplemented here.
func runParts(directory string, stdinData []byte, args ...string) error {
	fi, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			// Not an error if the directory doesn't exist; nothing to do.
			return nil
		}

		return err
	}

	// Do not execute a world-writable directory.
	if (fi.Mode() & 02) != 0 {
		return fmt.Errorf("refusing to execute notification hooks, directory is world-writable: %s", directory)
	}

	ms, err := filepath.Glob(filepath.Join(directory, "*"))
	if err != nil {
		return err
	}

	for _, m := range ms {
		fi, err := os.Stat(m)
		if err != nil {
			log.Errore(err, "notify: ", m)
			continue
		}

		// Yes, this is vulnerable to race conditions; it's just to stop people
		// from shooting themselves in the foot.
		if (fi.Mode() & 02) != 0 {
			log.Errorf("refusing to execute world-writable notification script: %s", m)
			continue
		}

		var cmd *exec.Cmd
		if shouldSudoFile(m, fi) {
			log.Debugf("calling notification script (with sudo): %s", m)
			args2 := []string{"-n", "--", m}
			args2 = append(args2, args...)
			cmd = exec.Command("sudo", args2...)
		} else {
			log.Debugf("calling notification script: %s", m)
			cmd = exec.Command(m, args...)
		}

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

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
