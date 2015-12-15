package main

import (
	"fmt"
	"github.com/hlandau/acme/interaction"
	"github.com/hlandau/acme/notify"
	"github.com/hlandau/acme/redirector"
	"github.com/hlandau/acme/storage"
	"github.com/hlandau/degoutils/xlogconfig"
	"github.com/hlandau/xlog"
	"github.com/square/go-jose"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/hlandau/easyconfig.v1/adaptflag"
	"gopkg.in/hlandau/service.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var log, Log = xlog.New("acmetool")

var (
	stateFlag = kingpin.Flag("state", "Path to the state directory (env: ACME_STATE_DIR)").
			Default(storage.RecommendedPath).
			Envar("ACME_STATE_DIR").
			PlaceHolder(storage.RecommendedPath).
			String()

	hooksFlag = kingpin.Flag("hooks", "Path to the notification hooks directory (env: ACME_HOOKS_DIR)").
			Default(notify.DefaultHookPath).
			Envar("ACME_HOOKS_DIR").
			PlaceHolder(notify.DefaultHookPath).
			String()

	batchFlag = kingpin.Flag("batch", "Do not attempt interaction; useful for cron jobs").
			Bool()

	stdioFlag = kingpin.Flag("stdio", "Don't attempt to use console dialogs; fall back to stdio prompts").Bool()

	responseFileFlag = kingpin.Flag("response-file", "Read dialog responses from the given file").ExistingFile()

	reconcileCmd = kingpin.Command("reconcile", "Reconcile ACME state").Default()

	wantCmd       = kingpin.Command("want", "Add a target with one or more hostnames")
	wantReconcile = wantCmd.Flag("reconcile", "Specify --no-reconcile to skip reconcile after adding target").Default("1").Bool()
	wantArg       = wantCmd.Arg("hostname", "hostnames for which a certifask some getting started questions (recommended)").Required().Strings()

	quickstartCmd = kingpin.Command("quickstart", "Interactively ask some getting started questions (recommended)")
	expertFlag    = quickstartCmd.Flag("expert", "Ask more questions in quickstart wizard").Bool()

	redirectorCmd      = kingpin.Command("redirector", "HTTP to HTTPS redirector with challenge response support")
	redirectorPathFlag = redirectorCmd.Flag("path", "Path to serve challenge files from").String()
	redirectorGIDFlag  = redirectorCmd.Flag("challenge-gid", "GID to chgrp the challenge path to (optional)").String()

	testNotifyCmd = kingpin.Command("test-notify", "Test-execute notification hooks as though given hostnames were updated")
	testNotifyArg = testNotifyCmd.Arg("hostname", "hostnames which have been updated").Strings()

	importJWKAccountCmd = kingpin.Command("import-jwk-account", "Import a JWK account key")
	importJWKURLArg     = importJWKAccountCmd.Arg("provider-url", "Provider URL (e.g. https://acme-v01.api.letsencrypt.org/directory)").Required().String()
	importJWKPathArg    = importJWKAccountCmd.Arg("private-key-file", "Path to private_key.json").Required().ExistingFile()

	importKeyCmd = kingpin.Command("import-key", "Import a certificate private key")
	importKeyArg = importKeyCmd.Arg("private-key-file", "Path to PEM-encoded private key").Required().ExistingFile()

	importLECmd = kingpin.Command("import-le", "Import a Let's Encrypt client state directory")
	importLEArg = importLECmd.Arg("le-state-path", "Path to Let's Encrypt state directory").Default("/etc/letsencrypt").ExistingDir()
)

func main() {
	adaptflag.Adapt()
	cmd := kingpin.Parse()
	notify.DefaultHookPath = *hooksFlag
	xlogconfig.Init()

	if *batchFlag {
		interaction.NonInteractive = true
	}

	if *stdioFlag {
		interaction.NoDialog = true
	}

	if *responseFileFlag != "" {
		err := loadResponseFile(*responseFileFlag)
		log.Errore(err, "cannot load response file, continuing anyway")
	}

	switch cmd {
	case "reconcile":
		cmdReconcile()
	case "want":
		cmdWant()
		if *wantReconcile {
			cmdReconcile()
		}
	case "quickstart":
		cmdQuickstart()
	case "redirector":
		cmdRunRedirector()
	case "test-notify":
		cmdRunTestNotify()
	case "import-key":
		cmdImportKey()
	case "import-jwk-account":
		cmdImportJWKAccount()
	case "import-le":
		cmdImportLE()
		cmdReconcile()
	}
}

func cmdImportJWKAccount() {
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

func cmdImportKey() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	err = importKey(s, *importKeyArg)
	log.Fatale(err, "import key")
}

func cmdReconcile() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	err = s.Reconcile()
	log.Fatale(err, "reconcile")
}

func cmdWant() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	tgt := storage.Target{
		Names: *wantArg,
	}

	err = s.AddTarget(tgt)
	log.Fatale(err, "add target")
}

func cmdRunRedirector() {
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
				ChallengeGID:  *redirectorGIDFlag,
			})
		},
	})
}

func determineWebroot() string {
	// don't use fdb for this, we don't need access to the whole db
	b, err := ioutil.ReadFile(filepath.Join(*stateFlag, "conf", "webroot-path"))
	if err == nil {
		s := strings.TrimSpace(strings.Split(strings.TrimSpace(string(b)), "\n")[0])
		if s != "" {
			return s
		}
	}

	return "/var/run/acme/acme-challenge"
}

func cmdRunTestNotify() {
	err := notify.Notify(*hooksFlag, *stateFlag, *testNotifyArg)
	log.Errore(err, "notify")
}

// YAML response file loading.

func loadResponseFile(path string) error {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	m := map[string]interface{}{}
	err = yaml.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	for k, v := range m {
		r, err := parseResponse(v)
		if err != nil {
			log.Errore(err, "response for ", k, " invalid")
			continue
		}
		interaction.SetResponse(k, r)
	}

	return nil
}

func parseResponse(v interface{}) (*interaction.Response, error) {
	switch x := v.(type) {
	case string:
		return &interaction.Response{
			Value: x,
		}, nil
	case int:
		return &interaction.Response{
			Value: fmt.Sprintf("%d", x),
		}, nil
	case bool:
		return &interaction.Response{
			Cancelled: !x,
		}, nil
	default:
		return nil, fmt.Errorf("unknown response value")
	}
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
