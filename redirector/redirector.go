// Package redirector provides a basic HTTP server for redirecting HTTP
// requests to HTTPS requests and serving ACME HTTP challenge values.
package redirector

import (
	"errors"
	"fmt"
	deos "github.com/hlandau/goutils/os"
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/svcutils.v1/chroot"
	"gopkg.in/hlandau/svcutils.v1/passwd"
	"gopkg.in/tylerb/graceful.v1"
	"html"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var log, Log = xlog.New("acme.redirector")

// Configuration for redirector.
type Config struct {
	Bind          string        `default:":80" usage:"Bind address"`
	ChallengePath string        `default:"" usage:"Path containing HTTP challenge files"`
	ChallengeGID  string        `default:"" usage:"GID to chgrp the challenge path to (optional)"`
	ReadTimeout   time.Duration `default:"" usage:"Maximum duration before timing out read of the request"`
	WriteTimeout  time.Duration `default:"" usage:"Maximum duration before timing out write of the response"`
	StatusCode    int           `default:"308" usage:"HTTP redirect status code"`
}

// Simple HTTP to HTTPS redirector.
type Redirector struct {
	cfg          Config
	httpServer   graceful.Server
	httpListener net.Listener
	stopping     uint32
}

// Instantiate an HTTP to HTTPS redirector.
func New(cfg Config) (*Redirector, error) {
	r := &Redirector{
		cfg: cfg,
		httpServer: graceful.Server{
			Timeout:          100 * time.Millisecond,
			NoSignalHandling: true,
			Server: &http.Server{
				Addr:         cfg.Bind,
				ReadTimeout:  cfg.ReadTimeout,
				WriteTimeout: cfg.WriteTimeout,
			},
		},
	}

	if r.cfg.StatusCode == 0 {
		r.cfg.StatusCode = 308
	}

	// Try and make the challenge path if it doesn't exist.
	err := os.MkdirAll(r.cfg.ChallengePath, 0755)
	if err != nil {
		return nil, err
	}

	if r.cfg.ChallengeGID != "" {
		err := enforceGID(r.cfg.ChallengeGID, r.cfg.ChallengePath)
		if err != nil {
			return nil, err
		}
	}

	l, err := net.Listen("tcp", r.httpServer.Server.Addr)
	if err != nil {
		return nil, err
	}

	r.httpListener = l

	return r, nil
}

func enforceGID(gid, path string) error {
	newGID, err := passwd.ParseGID(gid)
	if err != nil {
		return err
	}

	// So this is a surprisingly complicated dance if we want to be free of
	// potentially hazardous race conditions. We have a path. We can't assume
	// anything about its ownership, or mode, whether it's a symlink, etc.
	//
	// The big risk is that someone is able to create a symlink pointing to
	// something they want to illicitly access. Note that since /var/run will
	// commonly be used and because this directory is world-writeable, ala /tmp,
	// this is a real risk.
	//
	// So we have to make sure we don't follow symlinks. Assume we are running
	// as root (necessary, since we're chowning), and that nothing running as
	// root is malicious.
	//
	// We open the directory as a file so we can modify it using that reference
	// without worrying about the resolution of the path changing under us. But
	// we need to make sure we don't follow symlinks. This requires special OS
	// support, alas.
	dir, err := deos.OpenNoSymlinks(path)
	if err != nil {
		return err
	}

	defer dir.Close()

	fi, err := dir.Stat()
	if err != nil {
		return err
	}

	// Attributes of the directory can still change, but its type certainly
	// can't. This guarantee is enough for our purposes.
	if (fi.Mode() & os.ModeType) != os.ModeDir {
		return fmt.Errorf("challenge path %#v is not a directory", path)
	}

	curUID, err := deos.GetFileUID(fi)
	if err != nil {
		return err
	}

	dir.Chmod((fi.Mode() | 0070) & ^os.ModeType) // Ignore errors.
	dir.Chown(curUID, newGID)                    // Ignore errors.
	return nil
}

func (r *Redirector) commonHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Server", "acmetool-redirector")
		rw.Header().Set("Content-Security-Policy", "default-src 'none'")
		h.ServeHTTP(rw, req)
	})
}

// Start the redirector.
func (r *Redirector) Start() error {
	serveMux := http.NewServeMux()
	r.httpServer.Handler = r.commonHandler(serveMux)

	challengePath, ok := chroot.Rel(r.cfg.ChallengePath)
	if !ok {
		return fmt.Errorf("challenge path is not addressible inside chroot: %s", r.cfg.ChallengePath)
	}

	serveMux.HandleFunc("/", r.handleRedirect)
	serveMux.Handle("/.well-known/acme-challenge/",
		http.StripPrefix("/.well-known/acme-challenge/", http.FileServer(nolsDir(challengePath))))

	go func() {
		err := r.httpServer.Serve(r.httpListener)
		if atomic.LoadUint32(&r.stopping) == 0 {
			log.Fatale(err, "serve")
		}
	}()

	log.Debugf("redirector running")
	return nil
}

// Stop the redirector.
func (r *Redirector) Stop() error {
	atomic.StoreUint32(&r.stopping, 1)
	r.httpServer.Stop(r.httpServer.Timeout)
	<-r.httpServer.StopChan()
	return nil
}

// Respond to a request with a redirect.
func (r *Redirector) handleRedirect(rw http.ResponseWriter, req *http.Request) {
	// Redirect.
	u := *req.URL
	u.Scheme = "https"
	if u.Host == "" {
		u.Host = req.Host
	}
	if u.Host == "" {
		rw.WriteHeader(400)
		return
	}

	us := u.String()

	rw.Header().Set("Location", us)

	// If we are receiving any cookies, these must be insecure cookies, ergo
	// cookies aren't being set securely properly. This is a security issue.
	// Deleting cookies after the fact doesn't change the fact that they were
	// sent in cleartext and are thus forever untrustworthy. But it increases
	// the probability of somebody noticing something is up.
	//
	// ... However, the HTTP specification makes it impossible to delete a cookie
	// unless we know its domain and path, which aren't transmitted in requests.

	if req.Method == "GET" {
		rw.Header().Set("Cache-Control", "public; max-age=31536000")
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	// This is a permanent redirect and the request method should be preserved.
	// It's unfortunate if the client has transmitted information in cleartext
	// via POST, etc., but there's nothing we can do about it at this stage.
	rw.WriteHeader(r.cfg.StatusCode)

	if req.Method == "GET" {
		// Redirects issued in response to GET SHOULD have a body pointing to the
		// new URL for clients which don't support redirects. (Whether the set of
		// clients supporting acceptably modern versions of TLS and not supporting
		// HTTP redirects is non-empty is another matter.)
		ue := html.EscapeString(us)
		rw.Write([]byte(fmt.Sprintf(redirBody, ue, ue)))
	}
}

const redirBody = `<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
<head><title>Permanently Moved</title></head>
<body><h1>Permanently Moved</h1>
<p>This resource has <strong>moved permanently</strong> to
 <a href="%s">%s</a>.</p>
</body></html>`

// Like http.Dir, but doesn't allow directory listings.
type nolsDir string

var errNoListing = errors.New("http: directory listing not allowed")

func (d nolsDir) Open(name string) (http.File, error) {
	f, err := http.Dir(d).Open(name)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if fi.IsDir() {
		f.Close()
		return nil, os.ErrNotExist
	}

	return f, nil
}
