package hooks

import (
	deos "github.com/hlandau/goutils/os"
	"os"
	"os/exec"
)

func runningAsRoot() bool {
	return os.Getuid() == 0
}

func fileIsScript(fn string) bool {
	f, err := os.Open(fn)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [2]byte
	n, _ := f.Read(b[:])
	if n < 2 {
		return false
	}

	return string(b[:]) == "#!"
}

// Vulnerable to race conditions, but this is just a check. sudo enforces all
// security properties.
func shouldSudoFile(fn string, fi os.FileInfo) bool {
	if runningAsRoot() {
		return false
	}

	_, err := exec.LookPath("sudo")
	if err != nil {
		return false
	}

	// Only setuid files if the setuid bit is set.
	if (fi.Mode() & os.ModeSetuid) == 0 {
		return false
	}

	// Don't sudo anything which appears to be setuid'd for a non-root user.
	// This doesn't really buy us anything security-wise, but it's not what
	// we're expecting.
	uid, err := deos.GetFileUID(fi)
	if err != nil || uid != 0 {
		return false
	}

	// Make sure the file is a script, otherwise we can just execute it directly.
	return fileIsScript(fn)
}
