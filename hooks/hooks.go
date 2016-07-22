// Package hooks provides functions to invoke a directory of executable hooks,
// used to provide arbitrary handling of significant events.
package hooks

import (
	"fmt"
	deos "github.com/hlandau/goutils/os"
	"github.com/hlandau/xlog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Log site.
var log, Log = xlog.New("acme.hooks")

// The recommended hook path is the path at which executable hooks are looked
// for. On POSIX-like systems, this is usually "/usr/lib/acme/hooks" (or
// "/usr/libexec/acme/hooks" if /usr/libexec exists).
var RecommendedPath string

// The default hook path defaults to the recommended hook path but could be
// changed at runtime.
var DefaultPath string

// Provides contextual configuration information when executing a hook.
type Context struct {
	// The hook directory to use. May be "" for the default.
	HooksDir string

	// The state directory to report. Required.
	StateDir string

	// Arbitrary environment variables to set.
	Env map[string]string
}

func init() {
	// Allow overriding at build time.
	p := DefaultPath
	if p == "" {
		p = "/usr/lib/acme/hooks"
	}

	if _, err := os.Stat("/usr/libexec"); strings.HasPrefix(p, "/usr/lib/") && err == nil {
		p = "/usr/libexec" + p[8:]
	}

	DefaultPath = p
	RecommendedPath = p
}

// Notifies hook programs that a live symlink has been updated.
//
// If hookDirectory is "", DefaultHookPath is used. stateDirectory and
// hostnames are passed as information to the hooks.
func NotifyLiveUpdated(ctx *Context, hostnames []string) error {
	if len(hostnames) == 0 {
		return nil
	}

	hostnameList := strings.Join(hostnames, "\n") + "\n"
	_, err := runParts(ctx, []byte(hostnameList), "live-updated")
	if err != nil {
		return err
	}

	return nil
}

// Invokes HTTP challenge start hooks.
//
// installed indicates whether at least one hook script indicated success. err
// could still be returned in this case if an error occurs while executing some
// other hook.
func ChallengeHTTPStart(ctx *Context, hostname, targetFileName, token, ka string) (installed bool, err error) {
	return runParts(ctx, []byte(ka),
		"challenge-http-start", hostname, targetFileName, token)
}

func ChallengeHTTPStop(ctx *Context, hostname, targetFileName, token, ka string) error {
	_, err := runParts(ctx, []byte(ka),
		"challenge-http-stop", hostname, targetFileName, token)
	return err
}

func ChallengeTLSSNIStart(ctx *Context, hostname, targetFileName, validationName1, validationName2 string, pem string) (installed bool, err error) {
	return runParts(ctx, []byte(pem),
		"challenge-tls-sni-start", hostname, targetFileName, validationName1, validationName2)
}

func ChallengeTLSSNIStop(ctx *Context, hostname, targetFileName, validationName1, validationName2 string, pem string) (installed bool, err error) {
	return runParts(ctx, []byte(pem),
		"challenge-tls-sni-stop", hostname, targetFileName, validationName1, validationName2)
}

func ChallengeDNSStart(ctx *Context, hostname, targetFileName, body string) (installed bool, err error) {
	return runParts(ctx, nil,
		"challenge-dns-start", hostname, targetFileName, body)
}

func ChallengeDNSStop(ctx *Context, hostname, targetFileName, body string) (uninstalled bool, err error) {
	return runParts(ctx, nil,
		"challenge-dns-stop", hostname, targetFileName, body)
}

func mergeEnvMap(m map[string]string, e []string) {
	for _, x := range e {
		parts := strings.SplitN(x, "=", 2)
		if len(parts) < 2 {
			continue
		}
		m[parts[0]] = parts[1]
	}
}

func flattenEnvMap(m map[string]string) []string {
	var e []string
	for k, v := range m {
		e = append(e, k+"="+v)
	}
	return e
}

func mergeEnv(envs ...[]string) []string {
	m := map[string]string{}
	for _, env := range envs {
		mergeEnvMap(m, env)
	}
	return flattenEnvMap(m)
}

// Implements functionality similar to the "run-parts" command on many distros.
// Implementations vary, so it is reimplemented here.
func runParts(ctx *Context, stdinData []byte, args ...string) (anySucceeded bool, err error) {
	directory := ctx.HooksDir
	if directory == "" {
		directory = DefaultPath
	}

	fi, err := os.Stat(directory)
	if err != nil {
		if os.IsNotExist(err) {
			// Not an error if the directory doesn't exist; nothing to do.
			return false, nil
		}

		return false, err
	}

	env := mergeEnv(os.Environ(), flattenEnvMap(ctx.Env), []string{"ACME_STATE_DIR=" + ctx.StateDir})

	// Do not execute a world-writable directory.
	if (fi.Mode() & 02) != 0 {
		return false, fmt.Errorf("refusing to execute hooks, directory is world-writable: %s", directory)
	}

	ms, err := filepath.Glob(filepath.Join(directory, "*"))
	if err != nil {
		return false, err
	}

	for _, m := range ms {
		fi, err := os.Stat(m)
		if err != nil {
			log.Errore(err, "hook: ", m)
			continue
		}

		// Ignore 'hidden' files.
		if strings.HasPrefix(fi.Name(), ".") {
			continue
		}

		mode := fi.Mode()
		mType := mode & os.ModeType

		// Make sure it's not a directory, device, socket, pipe, etc.
		if mType != 0 && mType != os.ModeSymlink {
			log.Debugf("cannot execute hook, not a file: %s", m)
			continue
		}

		// Yes, this is vulnerable to race conditions; it's just to stop people
		// from shooting themselves in the foot.
		if (mode & 02) != 0 {
			log.Errorf("refusing to execute world-writable hook: %s", m)
			continue
		}

		// This doesn't check which mode bit (user,group,world) is applicable to
		// us but avoids cluttering the log for non-executable files.
		if (mode & 0111) == 0 {
			log.Debugf("cannot execute non-executable hook: %s", m)
			continue
		}

		var cmd *exec.Cmd
		if shouldSudoFile(m, fi) {
			log.Debugf("calling hook script (with sudo): %s", m)
			args2 := []string{"-n", "--", m}
			args2 = append(args2, args...)
			cmd = exec.Command("sudo", args2...)
		} else {
			log.Debugf("calling hook script: %s", m)
			cmd = exec.Command(m, args...)
		}

		cmd.Dir = "/"
		cmd.Env = env

		pipeR, pipeW, err := os.Pipe()
		if err != nil {
			return anySucceeded, err
		}

		defer pipeR.Close()
		go func() {
			defer pipeW.Close()
			pipeW.Write([]byte(stdinData))
		}()

		cmd.Stdin = pipeR
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		logFailedExecution(m, err)
		if err == nil {
			anySucceeded = true
		}
	}

	return anySucceeded, nil
}

func logFailedExecution(hookPath string, err error) {
	if err == nil {
		return
	}

	exitCode, err2 := deos.GetExitCode(err)
	if err2 != nil {
		// Not an error code. ???
		log.Errore(err2, "hook script: ", hookPath)
		return
	}

	switch exitCode {
	case 42:
		// Unsupported event type for this hook. Don't log anything; this is OK.
	default:
		log.Errore(err, "hook script: ", hookPath)
	}
}
