package responder

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/hlandau/acmetool/responder/reshttp"
	denet "github.com/hlandau/goutils/net"
	deos "github.com/hlandau/goutils/os"
	"gopkg.in/hlandau/acmeapi.v2/acmeutils"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// For testing use only. Determines the HTTP port which is listened on. This is
// used because Pebble tries to talk to the client's HTTP responder on a
// different HTTP port than the standard one. This use of non-privileged ports
// eases testing.
var InternalHTTPPort = 80

type HTTPChallengeInfo struct {
	Hostname string
	Filename string
	Body     string
}

type httpResponder struct {
	rcfg Config

	response            []byte
	requestDetectedChan chan struct{}
	portClaims          []reshttp.PortClaim
	ka                  []byte
	validation          []byte
	filePath            string
	notifySupported     bool // is notify supported?
	listening           bool
}

func newHTTP(rcfg Config) (Responder, error) {
	s := &httpResponder{
		rcfg:                rcfg,
		requestDetectedChan: make(chan struct{}, 1),
		notifySupported:     true,
		validation:          []byte("{}"),
	}

	if rcfg.Hostname == "" {
		return nil, fmt.Errorf("must provide a hostname")
	}

	ka, err := acmeutils.KeyAuthorization(rcfg.AccountKey, rcfg.Token)
	if err != nil {
		return nil, err
	}

	s.ka = []byte(ka)
	return s, nil
}

func (s *httpResponder) notify() {
	// Notify callers that a request has been detected.
	select {
	case s.requestDetectedChan <- struct{}{}:
	default:
	}
}

// Start handling HTTP requests.
func (s *httpResponder) Start() error {
	err := s.startActual()
	if err != nil {
		return err
	}

	if !s.rcfg.ChallengeConfig.HTTPNoSelfTest {
		log.Debugf("http-01 self test for %q", s.rcfg.Hostname)
		err = s.selfTest()
		if err != nil {
			log.Infoe(err, "http-01 self test failed: ", s.rcfg.Hostname)
			s.Stop()
			return err
		}
	}

	log.Debug("http-01 started")
	return nil
}

// This is currently the validation timeout used by Let's Encrypt, so let's
// use the same value here.
var selfTestTimeout = 5 * time.Second

// Test that the challenge is reachable at the given hostname. If a hostname
// was not provided, this test is skipped.
func (s *httpResponder) selfTest() error {
	if s.rcfg.Hostname == "" {
		return nil
	}

	u := url.URL{
		Scheme: "http",
		Host:   s.rcfg.Hostname,
		Path:   "/.well-known/acme-challenge/" + s.rcfg.Token,
	}
	if InternalHTTPPort != 80 {
		u.Host = net.JoinHostPort(u.Host, fmt.Sprintf("%d", InternalHTTPPort))
	}

	trans := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Transport: trans,
		Timeout:   selfTestTimeout,
	}

	res, err := client.Get(u.String())
	if err != nil {
		return err
	}

	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("hostname %q: non-200 status code when doing self-test", s.rcfg.Hostname)
	}

	b, err := ioutil.ReadAll(denet.LimitReader(res.Body, 1*1024*1024))
	if err != nil {
		return err
	}

	b = bytes.TrimSpace(b)
	if !bytes.Equal(b, s.ka) {
		return fmt.Errorf("hostname %q: got 200 response when doing self-test, but with the wrong data", s.rcfg.Hostname)
	}

	// If we detected a request, we support notifications, otherwise we don't.
	select {
	case <-s.requestDetectedChan:
	default:
		s.notifySupported = false
	}

	// Drain the notification channel in case we somehow made several requests.
L:
	for {
		select {
		case <-s.requestDetectedChan:
		default:
			break L
		}
	}

	return nil
}

// Tries to write a challenge file to each of the directories.
func webrootWriteChallenge(webroots map[string]struct{}, token string, ka []byte) {
	log.Debugf("writing %d webroot challenge files", len(webroots))

	for wr := range webroots {
		os.MkdirAll(wr, 0755) // ignore errors
		fn := filepath.Join(wr, token)
		log.Debugf("writing webroot file %s", fn)

		// Because /var/run/acme/acme-challenge may not exist due to /var/run
		// possibly being a tmpfs, and because that tmpfs is likely to be world
		// writable, there is a risk of following a maliciously crafted symlink to
		// cause a file to be overwritten as root. Open the file using a
		// no-symlinks flag if the OS supports it, but only for /var/run paths; we
		// want to support symlinks for other paths, which are presumably properly
		// controlled.
		//
		// Unfortunately earlier components in the pathname will still be followed
		// if they are symlinks, but it looks like this is the best we can do.
		var f *os.File
		var err error
		if strings.HasPrefix(wr, "/var/run/") {
			f, err = deos.OpenFileNoSymlinks(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		} else {
			f, err = os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		}
		if err != nil {
			log.Infoe(err, "failed to open webroot file ", fn)
			continue
		}

		f.Write(ka)
		f.Close()
	}
}

// Tries to remove a challenge file from each of the directories.
func webrootRemoveChallenge(webroots map[string]struct{}, token string) {
	for wr := range webroots {
		fn := filepath.Join(wr, token)

		log.Debugf("removing webroot file %s", fn)
		os.Remove(fn) // ignore errors
	}
}

// The standard webroot path, into which the responder always tries to install
// challenges, not necessarily successfully. This is intended to be a standard,
// system-wide path to look for challenges at. On POSIX-like systems, it is
// usually "/var/run/acme/acme-challenge".
var StandardWebrootPath string

func init() {
	if StandardWebrootPath == "" {
		StandardWebrootPath = "/var/run/acme/acme-challenge"
	}
}

func (s *httpResponder) getWebroots() map[string]struct{} {
	webroots := map[string]struct{}{}
	for _, p := range s.rcfg.ChallengeConfig.WebPaths {
		if p != "" {
			webroots[strings.TrimRight(p, "/")] = struct{}{}
		}
	}

	// The webroot and redirector models both require us to drop the challenge at
	// a given path. If a webroot is not specified in the configuration, use an
	// ephemeral default that the redirector might be using anyway.
	webroots[StandardWebrootPath] = struct{}{}
	return webroots
}

func parseListenAddrs(addrs []string) map[string]struct{} {
	m := map[string]struct{}{}

	for _, s := range addrs {
		n, err := strconv.ParseUint(s, 10, 16)
		if err == nil {
			m[fmt.Sprintf("[::1]:%d", n)] = struct{}{}
			m[fmt.Sprintf("127.0.0.1:%d", n)] = struct{}{}
			continue
		}

		ta, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			log.Warnf("invalid listen addr: %q: %v", s, err)
			continue
		}

		m[ta.String()] = struct{}{}
	}

	return m
}

func addrWeight(x string) int {
	host, _, err := net.SplitHostPort(x)
	if err != nil {
		return 0
	}

	if host == "" {
		return -1
	}

	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return -1
		}
		return -2
	}

	return 0
}

type addrSorter []string

func (a addrSorter) Len() int      { return len(a) }
func (a addrSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a addrSorter) Less(i, j int) bool {
	return addrWeight(a[i]) < addrWeight(a[j])
}

func determineListenAddrs(userAddrs []string) []string {
	// Here's our brute force method: listen on everything that might work.
	addrs := parseListenAddrs(userAddrs)
	addrs[fmt.Sprintf("[::]:%d", InternalHTTPPort)] = struct{}{} // OpenBSD
	addrs[fmt.Sprintf(":%d", InternalHTTPPort)] = struct{}{}
	addrs["[::1]:402"] = struct{}{}
	addrs["127.0.0.1:402"] = struct{}{}
	addrs["[::1]:4402"] = struct{}{}
	addrs["127.0.0.1:4402"] = struct{}{}

	// Sort the strings so that 'all interfaces' addresses appear first, so that
	// they are not blocked by more specific entries such as the ones above,
	// which are always attempted.
	var addrsl []string
	for k := range addrs {
		addrsl = append(addrsl, k)
	}

	sort.Stable(addrSorter(addrsl))
	return addrsl
}

func (s *httpResponder) startActual() error {
	// Determine and listen on sorted list of addresses.
	addrs := determineListenAddrs(s.rcfg.ChallengeConfig.HTTPPorts)

	for _, a := range addrs {
		pc, err := reshttp.AcquirePort(a, s.rcfg.Token, s.ka, s.notify)
		if err == nil {
			s.portClaims = append(s.portClaims, pc)
		}
	}

	// Even if none of the listeners managed to start, the webroot or redirector
	// methods might work.
	webrootWriteChallenge(s.getWebroots(), s.rcfg.Token, s.ka)

	// Try hooks.
	if startFunc := s.rcfg.ChallengeConfig.StartHookFunc; startFunc != nil {
		err := startFunc(&HTTPChallengeInfo{
			Hostname: s.rcfg.Hostname,
			Filename: s.rcfg.Token,
			Body:     string(s.ka),
		})
		log.Errore(err, "start challenge hook")
	}

	return nil
}

// Stop handling HTTP requests.
func (s *httpResponder) Stop() error {
	for _, pc := range s.portClaims {
		pc.Close()
	}
	s.portClaims = nil

	// Try and remove challenges.
	webrootRemoveChallenge(s.getWebroots(), s.rcfg.Token)

	// Try and stop hooks.
	if stopFunc := s.rcfg.ChallengeConfig.StopHookFunc; stopFunc != nil {
		err := stopFunc(&HTTPChallengeInfo{
			Hostname: s.rcfg.Hostname,
			Filename: s.rcfg.Token,
			Body:     string(s.ka),
		})
		log.Errore(err, "stop challenge hook")
	}

	return nil
}

func (s *httpResponder) RequestDetectedChan() <-chan struct{} {
	if !s.notifySupported {
		return nil
	}

	return s.requestDetectedChan
}

func (s *httpResponder) Validation() json.RawMessage {
	return json.RawMessage(s.validation)
}

func (s *httpResponder) ValidationSigningKey() crypto.PrivateKey {
	return nil
}

func init() {
	RegisterResponder("http-01", newHTTP)
}
