// Package cli is the command-line interface driver for acmetool. Everything begins here.
package cli

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hlandau/acmetool/hooks"
	"github.com/hlandau/acmetool/interaction"
	"github.com/hlandau/acmetool/redirector"
	"github.com/hlandau/acmetool/responder"
	"github.com/hlandau/acmetool/storage"
	"github.com/hlandau/acmetool/storageops"
	"github.com/hlandau/dexlogconfig"
	"github.com/hlandau/xlog"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/hlandau/acmeapi.v2"
	"gopkg.in/hlandau/acmeapi.v2/acmeutils"
	"gopkg.in/hlandau/easyconfig.v1/adaptflag"
	"gopkg.in/hlandau/service.v2"
	"gopkg.in/square/go-jose.v1"
	"gopkg.in/yaml.v2"
)

var log, Log = xlog.New("acmetool")

var (
	stateFlag = kingpin.Flag("state", "Path to the state directory (env: ACME_STATE_DIR)").
			Default(storage.RecommendedPath).
			Envar("ACME_STATE_DIR").
			PlaceHolder(storage.RecommendedPath).
			String()

	hooksFlag = kingpin.Flag("hooks", "Path to the notification hooks directory (env: ACME_HOOKS_DIR)").
			Default(hooks.RecommendedPaths...).
			PlaceHolder(hooks.RecommendedPaths[0]).
			Envar("ACME_HOOKS_DIR").
			Strings()

	batchFlag = kingpin.Flag("batch", "Do not attempt interaction; useful for cron jobs. (acmetool can still obtain responses from a response file, if one was provided.)").
			Bool()

	stdioFlag = kingpin.Flag("stdio", "Don't attempt to use console dialogs; fall back to stdio prompts").Bool()

	responseFileFlag = kingpin.Flag("response-file", "Read dialog responses from the given file (default: $ACME_STATE_DIR/conf/responses)").ExistingFile()

	reconcileCmd     = kingpin.Command("reconcile", reconcileHelp).Default()
	reconcileSpecArg = reconcileCmd.Arg("target-filenames", "optionally, specify one or more target file paths or filenames to reconcile only those targets").Strings()

	cullCmd          = kingpin.Command("cull", "Delete expired, unused certificates")
	cullSimulateFlag = cullCmd.Flag("simulate", "Show which certificates would be deleted without deleting any").Short('n').Bool()

	statusCmd = kingpin.Command("status", "Show active configuration")

	wantCmd       = kingpin.Command("want", "Add a target with one or more hostnames")
	wantReconcile = wantCmd.Flag("reconcile", "Specify --no-reconcile to skip reconcile after adding target").Default("1").Bool()
	wantArg       = wantCmd.Arg("hostname", "hostnames for which a certificate should be obtained").Required().Strings()

	unwantCmd = kingpin.Command("unwant", "Modify targets to remove any mentions of the given hostnames")
	unwantArg = unwantCmd.Arg("hostname", "hostnames which should be removed from all target files").Required().Strings()

	quickstartCmd = kingpin.Command("quickstart", "Interactively ask some getting started questions (recommended)")
	expertFlag    = quickstartCmd.Flag("expert", "Ask more questions in quickstart wizard").Bool()

	redirectorCmd            = kingpin.Command("redirector", "HTTP to HTTPS redirector with challenge response support")
	redirectorPathFlag       = redirectorCmd.Flag("path", "Path to serve challenge files from").String()
	redirectorGIDFlag        = redirectorCmd.Flag("challenge-gid", "GID to chgrp the challenge path to (optional)").String()
	redirectorReadTimeout    = redirectorCmd.Flag("read-timeout", "Maximum duration before timing out read of the request (default: '10s')").Default("10s").Duration()
	redirectorWriteTimeout   = redirectorCmd.Flag("write-timeout", "Maximum duration before timing out write of the request (default: '20s')").Default("20s").Duration()
	redirectorStatusCodeFlag = redirectorCmd.Flag("status-code", "HTTP status code to use when redirecting (default '308')").Default("308").Int()
	redirectorBindFlag       = redirectorCmd.Flag("bind", "Bind address for redirectory (default ':80')").Default(":80").String()

	testNotifyCmd = kingpin.Command("test-notify", "Test-execute notification hooks as though given hostnames were updated")
	testNotifyArg = testNotifyCmd.Arg("hostname", "hostnames which have been updated").Strings()

	importJWKAccountCmd = kingpin.Command("import-jwk-account", "Import a JWK account key")
	importJWKURLArg     = importJWKAccountCmd.Arg("provider-url", "Provider URL (e.g. https://acme-v02.api.letsencrypt.org/directory)").Required().String()
	importJWKPathArg    = importJWKAccountCmd.Arg("private-key-file", "Path to private_key.json").Required().ExistingFile()

	importPEMAccountCmd = kingpin.Command("import-pem-account", "Import a PEM account key")
	importPEMURLArg     = importPEMAccountCmd.Arg("provider-url", "Provider URL (e.g. https://acme-v02.api.letsencrypt.org/directory)").Required().String()
	importPEMPathArg    = importPEMAccountCmd.Arg("private-key-file", "Path to private key PEM file").Required().ExistingFile()

	importKeyCmd = kingpin.Command("import-key", "Import a certificate private key")
	importKeyArg = importKeyCmd.Arg("private-key-file", "Path to PEM-encoded private key").Required().ExistingFile()

	importLECmd = kingpin.Command("import-le", "Import a Let's Encrypt client state directory")
	importLEArg = importLECmd.Arg("le-state-path", "Path to Let's Encrypt state directory").Default("/etc/letsencrypt").ExistingDir()

	// Arguments we should probably support for revocation:
	//   A certificate ID
	//   A key ID
	//   A path to a PEM-encoded certificate - TODO
	//   A path to a PEM-encoded private key (revoke all known certificates with that key) - TODO
	//   A path to a certificate directory - TODO
	//   A path to a key directory - TODO
	//   A certificate URL - TODO
	revokeCmd = kingpin.Command("revoke", "Revoke a certificate")
	revokeArg = revokeCmd.Arg("certificate-id-or-path", "Certificate ID to revoke").String()

	accountThumbprintCmd = kingpin.Command("account-thumbprint", "Prints account thumbprints")

	accountURLCmd = kingpin.Command("account-url", "Show account URL")
)

const reconcileHelp = `Reconcile ACME state, idempotently requesting and renewing certificates to satisfy configured targets.

This is the default command.`

// Main entrypoint for the command line tool.
func Main() {
	syscall.Umask(0) // make sure webroot files can be world-readable

	adaptflag.Adapt()
	cmd := kingpin.Parse()

	var err error
	*stateFlag, err = filepath.Abs(*stateFlag)
	log.Fatale(err, "state directory path")

	hooksSlice := *hooksFlag
	for i := range hooksSlice {
		hooksSlice[i], err = filepath.Abs(hooksSlice[i])
		log.Fatale(err, "hooks directory path")
	}

	hooks.DefaultPaths = hooksSlice
	acmeapi.UserAgent = "acmetool"
	dexlogconfig.Init()

	if *batchFlag {
		interaction.NonInteractive = true
	}

	if *stdioFlag {
		interaction.NoDialog = true
	}

	if *responseFileFlag == "" {
		p := filepath.Join(*stateFlag, "conf/responses")
		if _, err := os.Stat(p); err == nil {
			*responseFileFlag = p
		}
	}

	if *responseFileFlag != "" {
		err := loadResponseFile(*responseFileFlag)
		log.Errore(err, "cannot load response file, continuing anyway")
	}

	switch cmd {
	case "reconcile":
		cmdReconcile()
	case "cull":
		cmdCull()
	case "status":
		cmdStatus()
	case "account-thumbprint":
		cmdAccountThumbprint()
	case "want":
		cmdWant()
		if *wantReconcile {
			cmdReconcile()
		}
	case "unwant":
		cmdUnwant()
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
	case "import-pem-account":
		cmdImportPEMAccount()
	case "revoke":
		cmdRevoke()
	case "account-url":
		cmdAccountURL()
	}
}

func cmdImportJWKAccount() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	f, err := os.Open(*importJWKPathArg)
	log.Fatale(err, "cannot open private key file")
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	log.Fatale(err, "cannot read file")

	k := jose.JsonWebKey{}
	err = k.UnmarshalJSON(b)
	log.Fatale(err, "cannot unmarshal key")

	_, err = s.ImportAccount(*importJWKURLArg, k.Key)
	log.Fatale(err, "cannot import account key")
}

func cmdImportPEMAccount() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	f, err := os.Open(*importPEMPathArg)
	log.Fatale(err, "cannot open private key file")
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	log.Fatale(err, "cannot read file")

	pk, err := acmeutils.LoadPrivateKey(b)
	log.Fatale(err, "cannot parse private key")

	_, err = s.ImportAccount(*importPEMURLArg, pk)
	log.Fatale(err, "cannot import account key")
}

func cmdImportKey() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	err = importKey(s, *importKeyArg)
	log.Fatale(err, "import key")
}

func cmdReconcile() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	err = storageops.Reconcile(s, storageops.ReconcileConfig{
		Targets: *reconcileSpecArg,
	})
	log.Fatale(err, "reconcile")
}

func cmdCull() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	err = storageops.Cull(s, *cullSimulateFlag)
	log.Fatale(err, "cull")
}

func cmdStatus() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	info := StatusString(s)
	log.Fatale(err, "status")

	fmt.Print(info)
}

func cmdAccountURL() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	url, err := storageops.GetAccountURL(s)
	log.Fatale(err, "get account URL")

	fmt.Print(url)
}

func importKey(s storage.Store, filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	pk, err := acmeutils.LoadPrivateKey(b)
	if err != nil {
		return err
	}

	_, err = s.ImportKey(pk)
	return err
}

func StatusString(s storage.Store) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Settings:\n")
	fmt.Fprintf(&buf, "  ACME_STATE_DIR: %s\n", s.Path())
	fmt.Fprintf(&buf, "  ACME_HOOKS_DIR: %s\n", strings.Join(hooks.DefaultPaths, "; "))
	fmt.Fprintf(&buf, "  Default directory URL: %s\n", s.DefaultTarget().Request.Provider)
	fmt.Fprintf(&buf, "  Preferred key type: %v\n", &s.DefaultTarget().Request.Key)
	fmt.Fprintf(&buf, "  Additional webroots:\n")
	for _, wr := range s.DefaultTarget().Request.Challenge.WebrootPaths {
		fmt.Fprintf(&buf, "    %s\n", wr)
	}

	fmt.Fprintf(&buf, "\nAvailable accounts:\n")
	s.VisitAccounts(func(a *storage.Account) error {
		fmt.Fprintf(&buf, "  %v\n", a)
		thumbprint, _ := acmeutils.Base64Thumbprint(a.PrivateKey)
		fmt.Fprintf(&buf, "    thumbprint: %s\n", thumbprint)
		return nil
	})

	fmt.Fprintf(&buf, "\n")
	s.VisitTargets(func(t *storage.Target) error {
		fmt.Fprintf(&buf, "%v\n", t)

		c, err := storageops.FindBestCertificateSatisfying(s, t)
		if err != nil {
			fmt.Fprintf(&buf, "  error: %v\n", err)
			return nil // continue
		}

		renewStr := ""
		if storageops.CertificateNeedsRenewing(c, t) {
			renewStr = " needs-renewing"
		}

		fmt.Fprintf(&buf, "  best: %v%s\n", c, renewStr)
		return nil
	})

	if storageops.HaveUncachedCertificates(s) {
		fmt.Fprintf(&buf, "\nThere are uncached certificates.\n")
	}

	return buf.String()
}

func cmdAccountThumbprint() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	s.VisitAccounts(func(a *storage.Account) error {
		thumbprint, _ := acmeutils.Base64Thumbprint(a.PrivateKey)
		fmt.Printf("%s\t%s\n", thumbprint, a.ID())
		return nil
	})
}

func cmdWant() {
	hostnames := *wantArg

	// Ensure all hostnames provided are valid.
	for idx := range hostnames {
		norm, err := acmeutils.NormalizeHostname(hostnames[idx])
		if err != nil {
			log.Fatalf("invalid hostname: %#v: %v", hostnames[idx], err)
			return
		}
		hostnames[idx] = norm
	}

	// Determine whether there already exists a target satisfying all given
	// hostnames or a superset thereof.
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	alreadyExists := false
	s.VisitTargets(func(t *storage.Target) error {
		nm := map[string]struct{}{}
		for _, n := range t.Satisfy.Names {
			nm[n] = struct{}{}
		}

		for _, w := range hostnames {
			if _, ok := nm[w]; !ok {
				return nil
			}
		}

		alreadyExists = true
		return nil
	})

	if alreadyExists {
		return
	}

	// Add the target.
	tgt := storage.Target{
		Satisfy: storage.TargetSatisfy{
			Names: hostnames,
		},
	}

	err = s.SaveTarget(&tgt)
	log.Fatale(err, "add target")
}

func cmdUnwant() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	for _, hn := range *unwantArg {
		err = storageops.RemoveTargetHostname(s, hn)
		log.Fatale(err, "remove target hostname ", hn)
	}
}

func cmdRunRedirector() {
	// redirector process is internet-facing and must never touch private keys
	storage.Neuter()

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
				Bind:          *redirectorBindFlag,
				ChallengePath: rpath,
				ChallengeGID:  *redirectorGIDFlag,
				ReadTimeout:   *redirectorReadTimeout,
				WriteTimeout:  *redirectorWriteTimeout,
				StatusCode:    *redirectorStatusCodeFlag,
			})
		},
	})
}

func determineWebroot() string {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	webrootPaths := s.DefaultTarget().Request.Challenge.WebrootPaths
	if len(webrootPaths) > 0 {
		return webrootPaths[0]
	}

	return responder.StandardWebrootPath
}

func cmdRunTestNotify() {
	ctx := &hooks.Context{
		HookDirs: *hooksFlag,
		StateDir: *stateFlag,
	}
	err := hooks.NotifyLiveUpdated(ctx, *testNotifyArg)
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

func cmdRevoke() {
	certSpec := *revokeArg
	f, _ := os.Open(certSpec)
	//var fi os.FileInfo
	if f != nil {
		defer f.Close()
		//var err error
		//fi, err = f.Stat()
		//log.Panice(err)
	}
	//u, _ := url.Parse(certSpec)

	switch {
	//case f != nil && !fi.IsDir(): // is a file path

	//case f != nil && fi.IsDir(): // is a directory path
	//  f, _ = os.Open(filepath.Join(certSpec, "cert"))

	//case u != nil && u.IsAbs() && acmeapi.ValidURL(certSpec): // is an URL

	case storage.IsWellFormattedCertificateOrKeyID(certSpec):
		// key or certificate ID
		revokeByCertificateID(certSpec)

	default:
		log.Fatalf("don't understand argument, must be a certificate or key ID: %q", certSpec)
	}
}

func revokeByCertificateID(certID string) {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	err = storageops.RevokeByCertificateOrKeyID(s, certID)
	log.Fatale(err, "revoke")

	err = storageops.Reconcile(s, storageops.ReconcileConfig{})
	log.Fatale(err, "reconcile")
}
