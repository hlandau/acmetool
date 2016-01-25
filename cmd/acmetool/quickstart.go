package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeendpoints"
	"github.com/hlandau/acme/hooks"
	"github.com/hlandau/acme/interaction"
	"github.com/hlandau/acme/storage"
	"github.com/hlandau/acme/storageops"
	"gopkg.in/hlandau/service.v2/passwd"
	"gopkg.in/hlandau/svcutils.v1/exepath"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func cmdQuickstart() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	serverURL := promptServerURL()
	s.DefaultTarget().Request.Provider = serverURL
	err = s.SaveTarget(s.DefaultTarget())
	log.Fatale(err, "set provider URL")

	// key type
	keyType := promptKeyType()
	switch keyType {
	case "rsa":
		s.DefaultTarget().Request.Key.Type = "rsa"
		rsaKeySize := promptRSAKeySize()
		if rsaKeySize != 0 {
			s.DefaultTarget().Request.Key.RSASize = rsaKeySize
			err = s.SaveTarget(s.DefaultTarget())
			log.Fatale(err, "set preferred RSA Key size")
		}
	case "ecdsa":
		s.DefaultTarget().Request.Key.Type = "ecdsa"
		ecdsaCurve := promptECDSACurve()
		if ecdsaCurve != "" {
			s.DefaultTarget().Request.Key.ECDSACurve = ecdsaCurve
			err = s.SaveTarget(s.DefaultTarget())
			log.Fatale(err, "set preferred ECDSA curve")
		}
	}

	// hook method
	method := promptHookMethod()
	var webroot []string
	switch method {
	case "webroot":
		webroot = []string{promptWebrootDir()}
	}

	if len(webroot) != 0 {
		err = os.MkdirAll(webroot[0], 0755)
		log.Fatale(err, "couldn't create webroot path")
	}

	s.DefaultTarget().Request.Challenge.WebrootPaths = webroot
	err = s.SaveTarget(s.DefaultTarget())
	log.Fatale(err, "set webroot path")

	prog, err := interaction.Auto.Status(&interaction.StatusInfo{
		Title: "Registering account...",
	})
	log.Fatale(err, "status")
	prog.SetProgress(0, 1)

	err = storageops.EnsureRegistration(s)
	log.Fatale(err, "couldn't complete registration")

	prog.SetProgress(1, 1)
	prog.Close()

	if method == "redirector" {
		promptSystemd()
	}

	installDefaultHooks()
	if areAnyInPath("haproxy", "hitch") {
		if promptInstallHAProxyHooks() {
			installHAProxyHooks()
		}
	}

	promptCron()
	promptGettingStarted()
}

func areAnyInPath(names ...string) bool {
	for _, n := range names {
		if _, err := exec.LookPath(n); err == nil {
			return true
		}
	}
	return false
}

const reloadHookFile = `#!/bin/bash
## This file was installed by acmetool. Any updates to this script will
## overwrite changes you make. If you don't want acmetool to manage
## this file, remove the following line.
##!acmetool-managed!##

set -e
EVENT_NAME="$1"
[ "$EVENT_NAME" == "live-updated" ] || exit 42

SERVICES="httpd apache2 apache nginx tengine lighttpd postfix dovecot exim exim4 haproxy hitch"
[ -e "/etc/default/acme-reload" ] && . /etc/default/acme-reload
[ -e "/etc/conf.d/acme-reload" ] && . /etc/conf.d/acme-reload
[ -z "$ACME_STATE_DIR" ] && ACME_STATE_DIR="@@ACME_STATE_DIR@@"

# Restart services.
if which service >/dev/null 2>/dev/null; then
  for x in $SERVICES; do
    service "$x" reload >/dev/null 2>/dev/null || true
  done
  exit 0
fi

if which systemctl >/dev/null 2>/dev/null; then
  for x in $SERVICES; do
    [ -e "/lib/systemd/system/$x.service" -o -e "/etc/systemd/system/$x.service" ] && systemctl reload "$x.service" >/dev/null 2>/dev/null || true
  done
  exit 0
fi

if [ -e "/etc/init.d" ]; then
  for x in $SERVICES; do
    /etc/init.d/$x >/dev/null 2>/dev/null || true
  done
  exit 0
fi`

const haproxyReloadHookFile = `#!/bin/bash
## This file was installed by acmetool. Any updates to this script will
## overwrite changes you make. If you don't want acmetool to manage
## this file, remove the following line.
##!acmetool-managed!##

# This file should be executed before 'reload'. So long as it is named
# 'haproxy' and reload is named 'reload', that is assured.

set -e
EVENT_NAME="$1"
[ "$EVENT_NAME" == "live-updated" ] || exit 42

[ -e "/etc/default/acme-reload" ] && . /etc/default/acme-reload
[ -e "/etc/conf.d/acme-reload" ] && . /etc/conf.d/acme-reload
[ -z "$ACME_STATE_DIR" ] && ACME_STATE_DIR="@@ACME_STATE_DIR@@"

[ -z "$HAPROXY_DH_PATH" ] && HAPROXY_DH_PATH="$ACME_STATE_DIR/conf/dhparams"

# Don't do anything if neither HAProxy nor Hitch are installed.
[ -n "$HAPROXY_ALWAYS_GENERATE" ] || which haproxy &>/dev/null || which hitch &>/dev/null || exit 0

# Create coalesced files and a haproxy repository.
mkdir -p "$ACME_STATE_DIR/haproxy"
umask 0077
while read name; do
  certdir="$ACME_STATE_DIR/live/$name"
  if [ -z "$name" -o ! -e "$certdir" ]; then
    continue
  fi

  if [ -n "$HAPROXY_DH_PATH" -a -e "$HAPROXY_DH_PATH" ]; then
    cat "$certdir/privkey" "$certdir/fullchain" "$HAPROXY_DH_PATH" > "$certdir/haproxy"
  else
    cat "$certdir/privkey" "$certdir/fullchain" > "$certdir/haproxy"
  fi

  [ -h "$ACME_STATE_DIR/haproxy/$name" ] || ln -s "../live/$name/haproxy" "$ACME_STATE_DIR/haproxy/$name"
done
`

func installHook(name, value string) {
	hooks.Replace(*hooksFlag, name, strings.Replace(value, "@@ACME_STATE_DIR@@", *stateFlag, -1))
	// fail silently, allow non-root, makes travis work.
}

func installDefaultHooks() {
	installHook("reload", reloadHookFile)
}

func installHAProxyHooks() {
	installHook("haproxy", haproxyReloadHookFile)
}

var errStop = fmt.Errorf("stop")

func isCronjobInstalled() bool {
	ms, err := filepath.Glob("/etc/cron.*/*acmetool*")
	log.Fatale(err, "glob")
	if len(ms) > 0 {
		return true
	}

	installed := false
	filepath.Walk("/var/spool/cron", func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if (fi.Mode() & os.ModeType) != 0 {
			return nil
		}

		if strings.Index(fi.Name(), "acmetool") >= 0 {
			installed = true
			return errStop
		}

		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()

		b, err := ioutil.ReadAll(f)
		if err != nil {
			return nil
		}

		if bytes.Index(b, []byte("acmetool")) >= 0 {
			installed = true
			return errStop
		}

		return nil
	})

	return installed
}

func formulateCron(root bool) string {
	// Randomise cron time to avoid hammering the ACME server.
	var b [2]byte
	_, err := rand.Read(b[:])
	log.Panice(err)

	m := b[0] % 60
	h := b[1] % 24
	s := ""
	if root {
		s = "SHELL=/bin/sh\nPATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin\nMAILTO=root\n"
	}
	s += fmt.Sprintf("%d %d * * * ", m, h)
	if root {
		s += "root "
	}
	s += fmt.Sprintf("%s --batch ", exepath.Abs)
	if *stateFlag != storage.RecommendedPath {
		s += fmt.Sprintf(`--state="%s" `, *stateFlag)
	}

	s += "reconcile\n"
	return s
}

func runningAsRoot() bool {
	return os.Getuid() == 0
}

func promptCron() {
	if isCronjobInstalled() {
		return
	}

	var err error
	cronString := formulateCron(runningAsRoot())
	if runningAsRoot() {
		_, err = os.Stat("/etc/cron.d")
	} else {
		_, err = exec.LookPath("crontab")
	}
	if err != nil {
		log.Warnf("Don't know how to install a cron job on this system, please install the following job:\n%s\n", cronString)
	}

	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title:        "Install auto-renewal cronjob?",
		Body:         "Would you like to install a cronjob to renew certificates automatically? This is recommended.",
		ResponseType: interaction.RTYesNo,
		UniqueID:     "acmetool-quickstart-install-cronjob",
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		return
	}

	if runningAsRoot() {
		f, err := os.OpenFile("/etc/cron.d/acmetool", os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
		if err != nil {
			log.Errore(err, "failed to install cron job at /etc/cron.d/acmetool (does the file already exist?), wanted to install: ", cronString)
			return
		}

		defer f.Close()
		f.Write([]byte(cronString))
	} else {
		err := amendUserCron(cronString, "acmetool")
		if err != nil {
			log.Errore(err, "failed to amend user crontab to add: ", cronString)
			return
		}
	}
}

func amendUserCron(cronLine, filterString string) error {
	b, err := getUserCron()
	if err != nil {
		return err
	}

	if bytes.Index(b, []byte("acmetool")) >= 0 {
		return nil
	}

	b = append(b, '\n')
	b = append(b, []byte(cronLine)...)

	return setUserCron(b)
}

func getUserCron() ([]byte, error) {
	errBuf := bytes.Buffer{}

	listCmd := exec.Command("crontab", "-l")
	listCmd.Stderr = &errBuf
	b, err := listCmd.Output()
	if err == nil {
		return b, nil
	}

	// crontab -l returns 1 if no crontab is installed, grep stderr to identify this condition
	if bytes.Index(errBuf.Bytes(), []byte("no crontab for")) >= 0 {
		return nil, nil
	}

	return b, nil
}

func setUserCron(b []byte) error {
	setCmd := exec.Command("crontab", "-")
	setCmd.Stdin = bytes.NewReader(b)
	setCmd.Stdout = os.Stdout
	setCmd.Stderr = os.Stderr
	return setCmd.Run()
}

func promptInstallHAProxyHooks() bool {
	// Always install if the hook is already installed.
	hooksPath := *hooksFlag
	if hooksPath == "" {
		hooksPath = hooks.DefaultPath
	}

	if _, err := os.Stat(filepath.Join(hooksPath, "haproxy")); err == nil {
		return true
	}

	// Prompt.
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Install HAProxy/Hitch hooks?",
		Body: fmt.Sprintf(`You appear to have HAProxy or Hitch installed. By default, acmetool doesn't support these too well because they require the certificate chain, private key (and custom Diffie-Hellman parameters, if used) to be placed in the same file.

acmetool can install a notification hook that will generate an additional file called "haproxy" in every certificate directory. This means that you can point HAProxy to "%s/live/HOSTNAME/haproxy". These files will also be accessible in a directory of their own, as "%s/haproxy/HOSTNAME". (Despite their naming, these files work for Hitch as well as HAProxy.)

If you place a PEM-encoded DH parameter file at %s/conf/dhparams, those will also be included in each haproxy file. This is optional.

Do you want to install the HAProxy/Hitch notification hook?
    `, *stateFlag, *stateFlag, *stateFlag),
		ResponseType: interaction.RTYesNo,
		UniqueID:     "acmetool-quickstart-install-haproxy-script",
	})
	if err != nil {
		return false
	}

	return !r.Cancelled
}

var usernamesToTry = []string{"daemon", "nobody"}

func determineAppropriateUsername() (string, error) {
	for _, u := range usernamesToTry {
		_, err := passwd.ParseUID(u)
		if err == nil {
			return u, nil
		}
	}

	return "", fmt.Errorf("cannot find appropriate username")
}

func promptRSAKeySize() int {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "RSA Key Size",
		Body: `Please enter the RSA key size to use for keys and account keys.

The recommended key size is 2048. Unsupported key sizes will be clamped to the nearest supported value at generation time (the current minimum is 2048; the current maximum is 4096).

Leave blank to use the recommended value, currently 2048.`,
		ResponseType: interaction.RTLineString,
		UniqueID:     "acmetool-quickstart-rsa-key-size",
		Implicit:     !*expertFlag,
	})
	if err != nil {
		return 0
	}

	if r.Cancelled {
		os.Exit(1)
		return 0
	}

	v := strings.TrimSpace(r.Value)
	if v == "" {
		return 0
	}

	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		interaction.Auto.Prompt(&interaction.Challenge{
			Title:    "Invalid RSA Key Size",
			Body:     "The RSA key size must be an integer in decimal form.",
			UniqueID: "acmetool-quickstart-invalid-rsa-key-size",
		})
		return promptRSAKeySize()
	}

	return int(n)
}

func promptKeyType() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Key Type Selection",
		Body: `Select the type of keys you want to use for account keys and certificates.

If in doubt, select RSA.`,
		ResponseType: interaction.RTSelect,
		Options: []interaction.Option{
			{
				Title: "RSA",
				Value: "rsa",
			},
			{
				Title: "ECDSA",
				Value: "ecdsa",
			},
		},
		UniqueID: "acmetool-quickstart-key-type",
		Implicit: !*expertFlag,
	})
	if err != nil {
		return "rsa"
	}

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	return r.Value
}

func promptECDSACurve() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "ECDSA Curve Selection",
		Body: `Please select the ECDSA curve to use for keys and account keys.

NOTE: nistp521 is not as well supported as the others and is not supported
by Let's Encrypt.`,
		ResponseType: interaction.RTSelect,
		Options: []interaction.Option{
			{
				Title: "NIST P-256 (recommended)",
				Value: "nistp256",
			},
			{
				Title: "NIST P-384",
				Value: "nistp384",
			},
			{
				Title: "NIST P-521 (limited support)",
				Value: "nistp521",
			},
		},
		UniqueID: "acmetool-quickstart-ecdsa-curve",
		Implicit: !*expertFlag,
	})
	if err != nil {
		return ""
	}

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	return r.Value
}

func promptWebrootDir() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Enter Webroot Path",
		Body: `Please enter the path at which challenges should be stored.

If your webroot path is /var/www, you would enter /var/www/.well-known/acme-challenge here.
The directory will be created if it does not exist.

Webroot paths vary by OS; please consult your web server configuration.
`,
		ResponseType: interaction.RTLineString,
		UniqueID:     "acmetool-quickstart-webroot-path",
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	path := r.Value
	path = strings.TrimRight(strings.TrimSpace(path), "/")
	if !filepath.IsAbs(path) {
		interaction.Auto.Prompt(&interaction.Challenge{
			Title:    "Invalid Webroot Path",
			Body:     "The webroot path must be an absolute path.",
			UniqueID: "acmetool-quickstart-webroot-path-invalid",
		})
		return promptWebrootDir()
	}

	if !strings.HasSuffix(path, "/.well-known/acme-challenge") {
		r1 := r
		r, err = interaction.Auto.Prompt(&interaction.Challenge{
			Title: "Are you sure?",
			Body: `The webroot path you have entered does not end in "/.well-known/acme-challenge". This path will only work if you have specially configured your webserver to map requests for that path to the specified directory.

Do you want to continue? To enter a different webroot path, select No.`,
			ResponseType: interaction.RTYesNo,
			Implicit:     *batchFlag || r1.Noninteractive,
			UniqueID:     "acmetool-quickstart-webroot-path-unlikely",
		})
		if r != nil && r.Cancelled {
			return promptWebrootDir()
		}
	}

	err = os.MkdirAll(path, 0755)
	log.Fatale(err, "could not create directory: ", path)

	return path
}

func promptGettingStarted() {
	_, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Quickstart Complete",
		Body: fmt.Sprintf(`The quickstart process is complete.

Ensure your chosen challenge conveyance method is configured properly before attempting to request certificates. You can find more information about how to configure your system for each method in the acmetool documentation: https://github.com/hlandau/acme/blob/master/_doc/WSCONFIG.md

To request a certificate, run:
    
$ sudo acmetool want example.com www.example.com

If the certificate is successfully obtained, it will be placed in %s/live/example.com/{cert,chain,fullchain,privkey}.`, *stateFlag),
		UniqueID: "acmetool-quickstart-complete",
	})
	log.Fatale(err, "interaction")
}

func promptHookMethod() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Select Challenge Conveyance Method",
		Body: `acmetool needs to be able to convey challenge responses to the ACME server in order to prove its control of the domains for which you issue certificates. These authorizations expire rapidly, as do ACME-issued certificates (Let's Encrypt certificates have a 90 day lifetime), thus it is essential that the completion of these challenges is a) automated and b) functioning properly. There are several options by which challenges can be facilitated:

WEBROOT: The webroot option installs challenge files to a given directory. You must configure your web server so that the files will be available at <http://[HOST]/.well-known/acme-challenge/>. For example, if your webroot is "/var/www", specifying a webroot of "/var/www/.well-known/acme-challenge" is likely to work well. The directory will be created automatically if it does not already exist.

PROXY: The proxy option requires you to configure your web server to proxy requests for paths under /.well-known/acme-challenge/ to a special web server running on port 402, which will serve challenges appropriately.

REDIRECTOR: The redirector option runs a special web server daemon on port 80. This means that you cannot run your own web server on port 80. The redirector redirects all HTTP requests to the equivalent HTTPS URL, so this is useful if you want to enforce use of HTTPS. You will need to configure your web server to not listen on port 80, and you will need to configure your system to run "acmetool redirector" as a daemon. If your system uses systemd, an appropriate unit file can automatically be installed.

LISTEN: Directly listen on port 80 or 443, whichever is available, in order to complete challenges. This is useful only for development purposes.

HOOK: Programmatic challenge provisioning. Advanced users only. Please see documentation.`,
		ResponseType: interaction.RTSelect,
		Options: []interaction.Option{
			{
				Title: "WEBROOT - Place challenges in a directory",
				Value: "webroot",
			},
			{Title: "PROXY - I'll proxy challenge requests to an HTTP server",
				Value: "proxy",
			},
			{Title: "REDIRECTOR - I want to use acmetool's redirect-to-HTTPS functionality",
				Value: "redirector",
			},
			{Title: "LISTEN - Listen on port 80 or 443 (only useful for development purposes)",
				Value: "listen",
			},
			{Title: "HOOKS - I will write scripts to provision challenges",
				Value: "hook",
			},
		},
		UniqueID: "acmetool-quickstart-choose-method",
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	return r.Value
}

func promptServerURL() string {
	var options []interaction.Option
	acmeendpoints.Visit(func(e *acmeendpoints.Endpoint) error {
		t := e.Title
		switch e.Code {
		case "LetsEncryptLive":
			t += " - I want live certificates"
		case "LetsEncryptStaging":
			t += " - I want test certificates"
		}

		options = append(options, interaction.Option{
			Title: t,
			Value: e.DirectoryURL,
		})
		return nil
	})

	options = append(options, interaction.Option{
		Title: "Enter an ACME server URL",
		Value: "url",
	})

	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Select ACME Server",
		Body: `Please choose an ACME server from which to request certificates. Your principal choices are the Let's Encrypt Live Server, and the Let's Encrypt Staging Server.

You can use the Let's Encrypt Live Server to get real certificates.

The Let's Encrypt Staging Server does not issue publically trusted certificates. It is useful for development purposes, as it has far higher rate limits than the live server.`,
		ResponseType: interaction.RTSelect,
		Options:      options,
		UniqueID:     "acmetool-quickstart-choose-server",
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	if r.Value == "url" {
		for {
			r, err = interaction.Auto.Prompt(&interaction.Challenge{
				Title:        "Select ACME Server",
				Body:         `Please enter the "Directory URL" of an ACME server. This must be an HTTPS URL pointing to the ACME directory for the server.`,
				ResponseType: interaction.RTLineString,
				UniqueID:     "acmetool-quickstart-enter-directory-url",
			})
			log.Fatale(err, "interaction")

			if r.Cancelled {
				os.Exit(1)
				return ""
			}

			if acmeapi.ValidURL(r.Value) {
				break
			}

			interaction.Auto.Prompt(&interaction.Challenge{
				Title:        "Invalid ACME URL",
				Body:         "That was not a valid ACME Directory URL. An ACME Directory URL must be a valid HTTPS URL.",
				ResponseType: interaction.RTAcknowledge,
				UniqueID:     "acmetool-quickstart-invalid-directory-url",
			})
			log.Fatale(err, "interaction")

			if r.Cancelled {
				os.Exit(1)
				return ""
			}
		}
	}

	return r.Value
}

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
