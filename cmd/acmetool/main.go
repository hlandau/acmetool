package main

import "gopkg.in/alecthomas/kingpin.v2"
import "github.com/hlandau/acme/storage"
import "github.com/hlandau/acme/interaction"
import "github.com/hlandau/acme/acmeapi"
import "github.com/hlandau/acme/redirector"
import "github.com/hlandau/acme/notify"
import "gopkg.in/hlandau/svcutils.v1/exepath"
import "gopkg.in/hlandau/service.v2"
import "gopkg.in/hlandau/service.v2/passwd"
import "github.com/hlandau/xlog"
import "github.com/hlandau/degoutils/xlogconfig"
import "gopkg.in/hlandau/easyconfig.v1/adaptflag"
import "os"
import "strings"
import "path/filepath"
import "io"
import "io/ioutil"
import "bytes"
import sddbus "github.com/coreos/go-systemd/dbus"
import sdunit "github.com/coreos/go-systemd/unit"
import sdutil "github.com/coreos/go-systemd/util"
import "fmt"
import "github.com/square/go-jose"

var log, Log = xlog.New("acmetool")

var (
	stateFlag = kingpin.Flag("state", "Path to the state directory (env: ACME_STATE_DIR)").
			Default(storage.RecommendedPath).
			Envar("ACME_STATE_DIR").
			PlaceHolder(storage.RecommendedPath).
			String()

	batchFlag = kingpin.Flag("batch", "Do not attempt interaction; useful for cron jobs").
			Bool()

	reconcileCmd = kingpin.Command("reconcile", "Reconcile ACME state").Default()

	wantCmd = kingpin.Command("want", "Add a target with one or more hostnames").
		Arg("hostname", "hostnames for which a certificate is desired").Required().Strings()

	quickstartCmd = kingpin.Command("quickstart", "Interactively ask some getting started questions (recommended)")

	redirectorCmd      = kingpin.Command("redirector", "HTTP to HTTPS redirector with challenge response support")
	redirectorPathFlag = redirectorCmd.Flag("path", "Path to serve challenge files from").String()

	importJWKAccountCmd = kingpin.Command("import-jwk-account", "Import a JWK account key")
	importJWKURLArg     = importJWKAccountCmd.Arg("provider-url", "Provider URL (e.g. https://acme-v01.api.letsencrypt.org/directory)").Required().String()
	importJWKPathArg    = importJWKAccountCmd.Arg("private-key-file", "Path to private_key.json").Required().ExistingFile()
)

func main() {
	adaptflag.Adapt()
	cmd := kingpin.Parse()
	xlogconfig.Init()

	if *batchFlag {
		interaction.NonInteractive = true
	}

	switch cmd {
	case "reconcile":
		reconcile()
	case "want":
		want()
		reconcile()
	case "quickstart":
		quickstart()
	case "redirector":
		runRedirector()
	case "import-jwk-account":
		importJWKAccount()
	}
}

func importJWKAccount() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	f, err := os.Open(*importJWKPathArg)
	log.Fatale(err, "cannot open private key file")
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	log.Fatale(err, "cannot read file")

	k := jose.JsonWebKey{}
	err = k.UnmarshalJSON(b)
	log.Fatale(err, "cannot unmarshal key")

	err = s.ImportAccountKey(*importJWKURLArg, k.Key)
	log.Fatale(err, "cannot import account key")
}

func reconcile() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	err = s.Reconcile()
	log.Fatale(err, "reconcile")
}

func want() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	tgt := storage.Target{
		Names: *wantCmd,
	}

	err = s.AddTarget(tgt)
	log.Fatale(err, "add target")
}

func runRedirector() {
	rpath := *redirectorPathFlag
	if rpath == "" {
		rpath = determineWebroot()
	}

	service.Main(&service.Info{
		Name:          "acmetool",
		Description:   "acmetool HTTP redirector",
		DefaultChroot: rpath,
		NewFunc: func() (service.Runnable, error) {
			return redirector.New(redirector.Config{
				Bind:          ":80",
				ChallengePath: rpath,
			})
		},
	})
}

func determineWebroot() string {
	// don't use fdb for this, we don't need access to the whole db
	b, err := ioutil.ReadFile(filepath.Join(*stateFlag, "conf", "webroot-path"))
	if err == nil {
		b = bytes.TrimSpace(b)
		s := string(b)
		if s != "" {
			return s
		}
	}

	return "/var/run/acme/acme-challenge"
}

func quickstart() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	serverURL := promptServerURL()
	err = s.SetDefaultProvider(serverURL)
	log.Fatale(err, "set provider URL")

	method := promptHookMethod()
	webroot := ""
	switch method {
	case "webroot":
		webroot = promptWebrootDir()
	}

	if webroot != "" {
		err = os.MkdirAll(webroot, 0755)
		log.Fatale(err, "couldn't create webroot path")
	}

	err = s.SetWebrootPath(webroot)
	log.Fatale(err, "set webroot path")

	prog, err := interaction.Auto.Status(&interaction.StatusInfo{
		Title: "Registering account...",
	})
	log.Fatale(err, "status")
	prog.SetProgress(0, 1)

	err = s.EnsureRegistration()
	log.Fatale(err, "couldn't complete registration")

	prog.SetProgress(1, 1)
	prog.Close()

	if method == "redirector" {
		promptSystemd()
	}

	installDefaultHooks()
	promptGettingStarted()
}

const reloadHookFile = `#!/bin/sh
##!standard-reload-hook:1!##
set -e
SERVICES="httpd apache2 apache nginx tengine lighttpd postfix dovecot exim exim4"
[ -e "/etc/default/acme-reload" ] && . /etc/default/acme-reload
[ -e "/etc/conf.d/acme-reload" ] && . /etc/conf.d/acme-reload

if which systemctl >/dev/null 2>/dev/null; then
  for x in $SERVICES; do
    [ -e "/lib/systemd/system/$x.service" -o -e "/etc/systemd/system/$x.service" ] && systemctl reload "$x.service" >/dev/null 2>/dev/null || true
  done
  exit 0
fi

if which service >/dev/null 2>/dev/null; then
  for x in $SERVICES; do
    service "$x" reload >/dev/null 2>/dev/null || true
  done
  exit 0
fi

if [ -e "/etc/init.d" ]; then
  for x in $SERVICES; do
    /etc/init.d/$x >/dev/null 2>/dev/null || true
  done
  exit 0
fi`

func installDefaultHooks() {
	path := notify.DefaultHookPath

	err := os.MkdirAll(path, 0755)
	log.Fatale(err, "couldn't create hooks path")

	f, err := os.OpenFile(filepath.Join(path, "reload"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return
	}

	defer f.Close()
	f.Write([]byte(reloadHookFile))
}

func promptSystemd() {
	if !sdutil.IsRunningSystemd() {
		log.Debugf("not running systemd")
		return
	}

	conn, err := sddbus.NewSystemdConnection()
	if err != nil {
		log.Errore(err, "connect to systemd")
		return
	}

	defer conn.Close()

	props, err := conn.GetUnitProperties("acmetool-redirector.service")
	if err != nil {
		log.Errore(err, "systemd GetUnitProperties")
		return
	}

	if props["LoadState"].(string) != "not-found" {
		log.Info("acmetool-redirector.service unit already installed, skipping")
		return
	}

	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Install Redirector as systemd Service?",
		Body: `Would you like acmetool to automatically install the redirector as a systemd service?

The service name will be acmetool-redirector.`,
		ResponseType: interaction.RTYesNo,
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		return
	}

	username, err := determineAppropriateUsername()
	if err != nil {
		log.Errore(err, "determine appropriate username")
		return
	}

	f, err := os.OpenFile("/etc/systemd/system/acmetool-redirector.service", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		log.Errore(err, "acmetool-redirector.service unit file already exists?")
		return
	}
	defer f.Close()

	rdr := sdunit.Serialize([]*sdunit.UnitOption{
		sdunit.NewUnitOption("Unit", "Description", "acmetool HTTP redirector"),
		sdunit.NewUnitOption("Service", "Type", "notify"),
		sdunit.NewUnitOption("Service", "ExecStart", exepath.Abs+` redirector --service.uid=`+username),
		sdunit.NewUnitOption("Service", "Restart", "always"),
		sdunit.NewUnitOption("Service", "RestartSec", "30"),
		sdunit.NewUnitOption("Install", "WantedBy", "multi-user.target"),
	})

	_, err = io.Copy(f, rdr)
	if err != nil {
		log.Errore(err, "cannot write unit file")
		return
	}

	f.Close()
	err = conn.Reload() // softfail
	log.Warne(err, "systemctl daemon-reload failed")

	_, _, err = conn.EnableUnitFiles([]string{"acmetool-redirector.service"}, false, false)
	log.Errore(err, "failed to enable unit acmetool-redirector.service")

	_, err = conn.StartUnit("acmetool-redirector.service", "replace", nil)
	log.Errore(err, "failed to start acmetool-redirector")
	resultStr := "The acmetool-redirector service was successfully started."
	if err != nil {
		resultStr = "The acmetool-redirector service WAS NOT successfully started. You may have a web server listening on port 80. You will need to troubleshoot this yourself."
	}

	_, err = interaction.Auto.Prompt(&interaction.Challenge{
		Title: "systemd Service Installation Complete",
		Body: fmt.Sprintf(`acmetool-redirector has been installed as a systemd service.
    
    %s`, resultStr),
	})
	log.Errore(err, "interaction")
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

func promptWebrootDir() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Enter Webroot Path",
		Body: `Please enter the path at which challenges should be stored.

If your webroot path is /var/www, you would enter /var/www/.well-known/acme-challenge here.
The directory will be created if it does not exist.

Webroot paths vary by OS; please consult your web server configuration.
`,
		ResponseType: interaction.RTLineString,
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
			Title: "Invalid Webroot Path",
			Body:  "The webroot path must be an absolute path.",
		})
		return promptWebrootDir()
	}

	if !strings.HasSuffix(path, "/.well-known/acme-challenge") {
		r, err = interaction.Auto.Prompt(&interaction.Challenge{
			Title: "Are you sure?",
			Body: `The webroot path you have entered does not end in "/.well-known/acme-challenge". This path will only work if you have specially configured your webserver to map requests for that path to the specified directory.

Do you want to continue? To enter a different webroot path, select No.`,
			ResponseType: interaction.RTYesNo,
		})
		if r.Cancelled {
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
		Body: `The quickstart process is complete.

Ensure your chosen challenge conveyance method is configured properly before attempting to request certificates. You can find more information about how to configure your system for each method in the acmetool documentation: https://github.com/hlandau/acme.t/blob/master/doc/WSCONFIG.md

To request a certificate, run:
    
$ sudo acmetool want example.com www.example.com

If the certificate is successfully obtained, it will be placed in /var/lib/acme/live/example.com/{cert,chain,fullchain,privkey}.`,
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

LISTEN: Directly listen on port 80 or 443, whichever is available, in order to complete challenges. This is useful only for development purposes.`,
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
		},
	})
	log.Fatale(err, "interaction")

	if r.Cancelled {
		os.Exit(1)
		return ""
	}

	return r.Value
}

func promptServerURL() string {
	r, err := interaction.Auto.Prompt(&interaction.Challenge{
		Title: "Select ACME Server",
		Body: `Please choose an ACME server from which to request certificates. Your principal choices are the Let's Encrypt Live Server, and the Let's Encrypt Staging Server.

Until Let's Encrypt enters open beta, you can only use the Let's Encrypt Live Server if you have been invited to the closed beta, and you will only be able to request certificates for the hostnames you specified in your beta application.

The Let's Encrypt Staging Server can be used by anyone but does not issue publically trusted certificates. It is useful for development purposes.`,
		ResponseType: interaction.RTSelect,
		Options: []interaction.Option{
			{
				Title: "Let's Encrypt Live Server - I have been invited and want live certificates",
				Value: acmeapi.LELiveURL,
			},
			{
				Title: "Let's Encrypt Staging Server - I want test certificates",
				Value: acmeapi.LEStagingURL,
			},
			{
				Title: "Enter an ACME server URL",
				Value: "url",
			},
		},
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
